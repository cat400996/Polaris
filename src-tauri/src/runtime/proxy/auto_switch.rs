//! C3 自动换节点域：专用出口心跳 → 决策机 → 已加载 clean 候选的零重启热切事务。
//!
//! 决策全在 [`crate::runtime::auto_switch`]（`AutoSwitchMachine` + 纯选择函数，真值表 + 变异锁死）；
//! 本模块只做 I/O 编排与**单一提交事务**：D 侧只改 `selectedServerId`、R 侧只做可证明的 selector
//! 热切，两侧任一不自证即整笔回退（见 [`AutoHotSwitchOutcome`]）。与崩溃恢复解耦——进程崩溃由
//! `spawn_crash_monitor` 原地重启同节点兜底，本腿只对「核活着但代理链不通」换节点。

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use polaris_switch_engine::{HotSwitchOutcome, SwitchDecision, SwitchExecutor};

use crate::commands::speedtest::{
    current_server_fingerprints, probe_runtime_candidates, resolve_speed_test_url,
    RuntimeProbeBatch,
};
use crate::runtime::auto_switch::{
    plan_runtime_candidates, select_best_candidate, switch_payload, AutoSwitchMachine,
    CandidateLatency, HeartbeatOutcome, RuntimeCandidate, SwitchGate, CONNECTIVITY_TIMEOUT_MS,
    CONNECTIVITY_URLS, HEARTBEAT_INTERVAL_MS,
};
use crate::runtime::config::Decision;
use crate::runtime::tailscale_status::TailscaleStatusEvent;

use super::hot_switch::{selected_server_present, ClassifiedSwitch, RuntimeSelectionApi};
use super::lifecycle::monotonic_now_ms;
use super::{code, ProxyRuntime};

/// 自动故障切换的热切事务结果。它刻意没有 `Restarting`：后台故障治理只允许操作当前运行核已加载的
/// clean selector 成员；管理 API 不可用就失败，不得借一次整核重启把 D 中其他待 Apply 修改带进去。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum AutoHotSwitchOutcome {
    Applied,
    Busy,
    Superseded,
    NotEligible,
    /// D 已提交目标，但目标与旧 selector 均无法自证；后台受限对账 actor 已获恢复所有权。
    ReconcilePending {
        intent_generation: u64,
    },
    Failed,
}

impl ProxyRuntime {
    /// 自动故障切换的单一提交事务：D 只改 `selectedServerId`，R 只做可证明的 selector 热切。
    ///
    /// 与普通 `switch_mode` 的关键差异是**禁止失败回退整核重启**。普通用户 Apply 的目标就是把完整 D
    /// 入核，失败回退重启正确；后台 failover 只获授权切出口，若沿用同一回退会把 DNS/TUN/规则等
    /// 已保存未 Apply 的修改一起带入核，破坏 Save/Apply 边界。
    pub(super) async fn auto_hot_switch_transaction(
        self: &Arc<Self>,
        generation: u64,
        expected_current_id: &str,
        candidate: &RuntimeCandidate,
        expected_candidate_fingerprint: &str,
    ) -> AutoHotSwitchOutcome {
        let api = self.management_api().await;
        self.auto_hot_switch_transaction_with_api(
            generation,
            expected_current_id,
            candidate,
            expected_candidate_fingerprint,
            &api,
        )
        .await
    }

    /// 可注入管理面的事务本体。所有 generation/lifecycle/config CAS 均在拿到 `switch_serial` 后重验，
    /// 因此生产侧在锁外建立 lazy gRPC channel 不会把陈旧客户端变成一次陈旧提交。
    pub(super) async fn auto_hot_switch_transaction_with_api(
        self: &Arc<Self>,
        generation: u64,
        expected_current_id: &str,
        candidate: &RuntimeCandidate,
        expected_candidate_fingerprint: &str,
        api: &dyn RuntimeSelectionApi,
    ) -> AutoHotSwitchOutcome {
        let switch_guard = self.switch_serial.lock().await;
        if self.gate.generation() != generation || !self.core_running() {
            return AutoHotSwitchOutcome::Superseded;
        }
        let starting_intent_generation = self.selector_reconcile.intent_generation();
        if self.gate.is_busy() {
            return AutoHotSwitchOutcome::Busy;
        }
        if self.selector_reconcile.is_required() {
            return AutoHotSwitchOutcome::NotEligible;
        }
        let staged = self.config.staged_node_mask();
        if staged.pending
            && (!staged.scope_known || staged.node_ids.contains(candidate.id.as_str()))
        {
            return AutoHotSwitchOutcome::Superseded;
        }

        let Some(old_runtime) = self
            .current_config
            .read()
            .ok()
            .and_then(|guard| guard.clone())
        else {
            return AutoHotSwitchOutcome::NotEligible;
        };
        if old_runtime.get("selectedServerId").and_then(Value::as_str) != Some(expected_current_id)
        {
            return AutoHotSwitchOutcome::Superseded;
        }
        let old_tag = self.switch_snapshot.read().ok().and_then(|guard| {
            guard
                .as_ref()
                .and_then(|snapshot| snapshot.id_to_tag.get(expected_current_id).cloned())
        });
        let Some(old_tag) = old_tag else {
            return AutoHotSwitchOutcome::NotEligible;
        };

        let mut new_runtime = old_runtime.clone();
        let Some(object) = new_runtime.as_object_mut() else {
            return AutoHotSwitchOutcome::NotEligible;
        };
        object.insert(
            "selectedServerId".to_string(),
            Value::String(candidate.id.clone()),
        );

        let (hot_plan, new_cfg) = match self.classify_switch(&new_runtime, false) {
            ClassifiedSwitch::Decided {
                decision: SwitchDecision::HotSwitch(plan),
                new_cfg,
            } => (plan, *new_cfg),
            _ => return AutoHotSwitchOutcome::NotEligible,
        };
        if !hot_plan
            .puts
            .iter()
            .any(|put| put.selector_tag == "proxy-selector" && put.member_tag == candidate.tag)
        {
            return AutoHotSwitchOutcome::NotEligible;
        }

        // 在持有 switch_serial 时原子复核并只写 selectedServerId。其它 writer 仍可先写盘，但其广播会
        // 排在本事务之后；闭包再次核对当前选择、候选仍存在且连接指纹未变，任何一项漂移即让位。
        let target_id = candidate.id.clone();
        let expected_fingerprint = expected_candidate_fingerprint.to_string();
        let persisted = self.config.update(|latest| {
            // 显式用户选择也在同一个 ConfigManager 写事务内 bump；因此本检查到 claim 之间没有
            // “同目标但更新意图”可穿过。只比较 selectedServerId 无法分辨这种所有权交接。
            if self.selector_reconcile.intent_generation() != starting_intent_generation {
                return Decision::Skip(None);
            }
            if latest.get("selectedServerId").and_then(Value::as_str) != Some(expected_current_id)
                || current_server_fingerprints(latest).get(&target_id)
                    != Some(&expected_fingerprint)
            {
                return Decision::Skip(None);
            }
            let Some(object) = latest.as_object_mut() else {
                return Decision::Skip(None);
            };
            let intent_generation = self.register_selector_intent();
            object.insert(
                "selectedServerId".to_string(),
                Value::String(target_id.clone()),
            );
            Decision::Write(Some(intent_generation))
        });
        let intent_generation = match persisted {
            Ok((Some(intent_generation), Some(_))) => intent_generation,
            Ok((None, None)) => return AutoHotSwitchOutcome::Superseded,
            Ok(_) => unreachable!("auto failover persistence decision must agree"),
            Err(error) => {
                log::warn!("自动故障切换：保存目标出口失败：{error}");
                return AutoHotSwitchOutcome::Failed;
            }
        };

        let interrupt = new_cfg.interrupt_connections_on_switch == Some(true);
        let applied_disconnects = match SwitchExecutor.execute(api, &hot_plan, interrupt).await {
            HotSwitchOutcome::Applied { disconnect } => {
                Some(disconnect.map_or(0, |result| result.closed_ids.len()))
            }
            other => {
                log::warn!("自动故障切换：selector 热切失败（{other:?}），禁止回退整核重启");
                None
            }
        };
        if !self.selector_operation_is_current(generation, intent_generation) {
            self.selector_reconcile.mark_required();
            log::info!("自动故障切换：target PUT 后 selector 所有权已交接 → 不恢复、不回滚 D");
            return AutoHotSwitchOutcome::Superseded;
        }

        // PUT 回执不是最终真值：读回 sing-box 当前 group，只有实际指向目标成员才提交成功事件。
        let groups_after_target = if applied_disconnects.is_some() {
            api.groups_snapshot().await.ok()
        } else {
            None
        };
        if !self.selector_operation_is_current(generation, intent_generation) {
            self.selector_reconcile.mark_required();
            log::info!("自动故障切换：target 自证后 selector 所有权已交接 → 不恢复、不回滚 D");
            return AutoHotSwitchOutcome::Superseded;
        }
        let attested = groups_after_target.is_some_and(|groups| {
            groups
                .iter()
                .any(|group| group.tag == "proxy-selector" && group.selected == candidate.tag)
        });
        // PUT 在 await 期间配置 writer 仍可前进；因此自证不只读 selector，还要再次核对目标指纹与
        // staged 遮罩。候选若恰被订阅替换/用户编辑，哪怕 PUT 已成功也必须恢复旧出口，不能把运行核
        // 里的旧参数成员冒充成磁盘里的新节点。
        let staged_after = self.config.staged_node_mask();
        let target_still_clean = !(staged_after.pending
            && (!staged_after.scope_known
                || staged_after.node_ids.contains(candidate.id.as_str())))
            && self
                .config
                .with_current(|latest| {
                    latest.get("selectedServerId").and_then(Value::as_str)
                        == Some(candidate.id.as_str())
                        && current_server_fingerprints(latest).get(&candidate.id)
                            == Some(&expected_fingerprint)
                })
                .unwrap_or(false);
        if attested && target_still_clean {
            // 只有管理面回读与配置 CAS 双重自证后，才把候选提交为 R 的真实选择并刷新依赖出口的
            // 派生状态。PUT 成功但随后回滚的瞬态不应污染 current_config / 解锁 / 出口 IP 缓存。
            self.commit_applied(&new_runtime);
            self.mesh
                .exit_route_reconcile(&new_cfg, new_cfg.enable_ipv6.unwrap_or(false))
                .await;
            if !self.selector_operation_is_current(generation, intent_generation) {
                log::info!("自动故障切换：出口路由对账期间 selector 所有权已交接 → 抑制旧成功通知");
                return AutoHotSwitchOutcome::Superseded;
            }
            self.invalidate_unlock_cache(true, false);
            self.schedule_exit_ip_refresh(true);
            self.reconcile_login_fallback_locked(&switch_guard).await;
            if !self.selector_operation_is_current(generation, intent_generation) {
                return AutoHotSwitchOutcome::Superseded;
            }
            self.push_pending_changes();
            log::info!(
                "自动故障切换：selector 已热切并通过运行态回读，精准断连 {} 条",
                applied_disconnects.unwrap_or_default()
            );
            return AutoHotSwitchOutcome::Applied;
        }

        // 未自证成功则 best-effort 恢复旧 selector。恢复也只走管理 API，不以重启“兜底”。只有运行态
        // 确认回到旧成员后才把 D 的 selectedServerId 回滚，避免盘面声称旧节点而核仍实际指向新节点。
        log::warn!("自动故障切换：目标 selector 未通过运行态回读，尝试恢复原出口");
        let restore_put_ok = api
            .select_outbound("proxy-selector", &old_tag)
            .await
            .is_ok();
        if !self.selector_operation_is_current(generation, intent_generation) {
            self.selector_reconcile.mark_required();
            log::info!("自动故障切换：restore PUT 后 selector 所有权已交接 → 禁止回滚 D");
            return AutoHotSwitchOutcome::Superseded;
        }
        let groups_after_restore = if restore_put_ok {
            api.groups_snapshot().await.ok()
        } else {
            None
        };
        if !self.selector_operation_is_current(generation, intent_generation) {
            self.selector_reconcile.mark_required();
            log::info!("自动故障切换：restore 自证后 selector 所有权已交接 → 禁止回滚 D");
            return AutoHotSwitchOutcome::Superseded;
        }
        let restored = groups_after_restore.is_some_and(|groups| {
            groups
                .iter()
                .any(|group| group.tag == "proxy-selector" && group.selected == old_tag)
        });
        if restored {
            let rollback_target = candidate.id.clone();
            let old_id = expected_current_id.to_string();
            let _ = self.config.update(|latest| {
                if self.selector_reconcile.intent_generation() != intent_generation {
                    return Decision::Skip(false);
                }
                if latest.get("selectedServerId").and_then(Value::as_str)
                    != Some(rollback_target.as_str())
                {
                    return Decision::Skip(false);
                }
                let Some(object) = latest.as_object_mut() else {
                    return Decision::Skip(false);
                };
                object.insert(
                    "selectedServerId".to_string(),
                    Value::String(old_id.clone()),
                );
                Decision::Write(true)
            });
            self.push_pending_changes();
        } else {
            let message = "自动故障切换未能确认目标出口，恢复原出口也失败；正在后台对账运行出口";
            self.set_nonfatal_error(message, code::EXIT_MISMATCH);
            self.push_pending_changes();
            log::error!("{message}");
            return AutoHotSwitchOutcome::ReconcilePending { intent_generation };
        }
        if !self.selector_operation_is_current(generation, intent_generation) {
            AutoHotSwitchOutcome::Superseded
        } else {
            AutoHotSwitchOutcome::Failed
        }
    }

    // ════════════════ C3：自动换节点（节点不可达 → 已加载 clean 候选零重启热切）════════════════
    //
    // 决策全在 [`AutoSwitchMachine`] + 纯选择函数（`runtime/auto_switch.rs`，真值表 + 变异锁死）；
    // 本层只做「专用出口心跳 → 喂决策机 → 复用主核探测池 → selector 热切并回读 → emit」的 I/O。
    // **与崩溃恢复解耦**：
    // 进程崩溃由 `spawn_crash_monitor` 原地重启同节点兜底，本腿只对「核活着但代理链不通」换节点
    // （1:1 移植 上游 AutoSwitchService 的职责边界）。
    //
    // 当前出口经 `probe-proxy-in → proxy-selector` 钉死，不受用户流量规则影响；候选经
    // `probe-in-k → probe-selector-k` 的 CONNECT+warm-TTFB 验证完整协议链。两者均真碰宿主网络，
    // 编排/资格/结果状态用离线测试覆盖，真实数值留 bundled-core 门。

    /// **C3**：核就绪后挂自动换节点心跳（`spawn_tailscale_status_relay` 的世代范式）。
    ///
    /// **无条件挂**（与崩溃监测同接线点），开关在循环内每 tick 读原始配置 `autoSwitchNode` 动态判
    /// （对齐 上游 config-change-handler 的运行期 enable/disable，轮询版——避免动命令层加事件驱动，
    /// 本批禁区 commands/config.rs）。**世代守卫**：核被停/接管（stop/restart 先 bump 世代）→ 退场，
    /// 绝不让旧核的心跳污染新核（探测/切换均先复查世代）。
    pub(super) fn spawn_auto_switch_heartbeat(
        self: &Arc<Self>,
        my_gen: u64,
        probe_proxy_port: Option<u16>,
    ) {
        let me = Arc::clone(self);
        tokio::spawn(async move {
            let mut machine = AutoSwitchMachine::new();
            let tick = Duration::from_millis(HEARTBEAT_INTERVAL_MS);
            log::debug!("自动换节点心跳起（世代 {my_gen}，专用出口探针端口={probe_proxy_port:?}）");
            loop {
                tokio::time::sleep(tick).await;
                // 世代守卫：核被停/接管 → 退场。
                if me.gate.generation() != my_gen {
                    return;
                }
                // 动态开关（上游 config-change-handler，轮询版）：autoSwitchNode 真才启用。
                let want_enabled = me.auto_switch_enabled();
                if want_enabled && !machine.is_enabled() {
                    machine.enable();
                    log::info!("自动换节点已启用（应用层连通性检测）");
                } else if !want_enabled && machine.is_enabled() {
                    machine.disable();
                    log::info!("自动换节点已禁用");
                }
                if !machine.is_enabled() {
                    continue;
                }
                // 换节点在飞中 → 跳过本次心跳（上游 runHeartbeat isSwitching 守卫）。
                if machine.is_switching() {
                    continue;
                }
                // 核未运行 → 只复位失败计数（不动熔断），继续（等退场或恢复）。
                if !me.core_running() {
                    machine.reset_failures_only();
                    continue;
                }
                // 守卫（上游 AutoSwitchService.runHeartbeat:113-116）：选中节点须真实存在于 servers。
                // direct 模式（`__direct__` 不在 servers）/ 选中被删 / 无选中 → 跳过本 tick（不探测/不计失败/
                // 不切走）。否则 direct 下网络抖动会被当成「当前节点不通」→ 自动切到某代理节点（用户明明选的是
                // 直连），把「换节点」误用到一个根本不是节点的选择上。
                if !me.selected_server_is_real() {
                    continue;
                }
                let Some(probe_proxy_port) = probe_proxy_port else {
                    // 端口分配失败是本世代的固定事实；保持启用态但不伪造 mixed 口为等价探针。
                    machine.reset_failures_only();
                    continue;
                };
                // 应用层连通性探测（真机门：真起核 + 碰网络）。
                let alive = probe_proxy_connectivity(probe_proxy_port).await;
                // 探测耗时窗口内可能已被接管 → 复查世代。
                if me.gate.generation() != my_gen {
                    return;
                }
                match machine.on_heartbeat(alive) {
                    HeartbeatOutcome::Trigger => {
                        log::warn!(
                            "连通性连续 {} 次失败 → 触发自动换节点",
                            crate::runtime::auto_switch::MAX_CONSECUTIVE_FAILURES
                        );
                        me.run_auto_switch(&mut machine, "connectivity").await;
                    }
                    HeartbeatOutcome::Recovered { prior } => {
                        log::info!("连通性恢复正常（此前连续失败 {prior} 次）");
                    }
                    HeartbeatOutcome::Failing { failures } => {
                        log::warn!(
                            "连通性检测失败 [{failures}/{}]",
                            crate::runtime::auto_switch::MAX_CONSECUTIVE_FAILURES
                        );
                    }
                    HeartbeatOutcome::Stable => {}
                }
            }
        });
    }

    /// 原始配置 `autoSwitchNode === true`（上游 index.ts:1846 门控）。**从原始 JSON 读**——该字段不在
    /// `UserConfig` 结构体（同 `restartOnNodeChange` / `meshLoginFallbackDirect`，见 `switch_mode` 注）。
    ///
    /// 走 [`ConfigManager::with_current`](crate::runtime::config::ConfigManager::with_current) 而非 `current()`：本方法由自动换节点心跳**每 tick 无条件**
    /// 调用（`HEARTBEAT_INTERVAL_MS`，核在跑就一直跑），而它只要一个 bool —— 为此深拷贝整份配置
    /// （含 200 节点级 `servers`）纯属常驻浪费。闭包内只取字段，不回调任何子系统。
    ///
    fn auto_switch_enabled(&self) -> bool {
        self.config
            .with_current(|c| c.get("autoSwitchNode").and_then(Value::as_bool))
            .ok()
            .flatten()
            .unwrap_or(false)
    }

    /// **自动换节点心跳守卫**（上游 `AutoSwitchService.runHeartbeat`:113-116）：当前选中节点是否真实
    /// 存在于 `servers`。委托纯谓词 [`selected_server_present`]（无选中 / direct 哨兵 `__direct__` 不在
    /// servers / 选中被删 → false）。读配置失败 → false（保守跳过心跳，绝不误切）。
    ///
    /// 与 [`auto_switch_enabled`](Self::auto_switch_enabled) 同属心跳**每 tick 的无条件调用**，故同样走
    /// [`ConfigManager::with_current`](crate::runtime::config::ConfigManager::with_current)：谓词本体只需 `&Value`，不需要 owned 快照。
    fn selected_server_is_real(&self) -> bool {
        self.config
            .with_current(selected_server_present)
            .unwrap_or(false)
    }

    /// **C3 换节点执行体**。闸门（熔断/冷却/在飞）决策全在
    /// [`AutoSwitchMachine::evaluate_switch`]；放行后只测运行核 clean 候选 → 选最优 →
    /// [`Self::auto_hot_switch_transaction`] 做零重启提交并回读自证 → emit。**真机门**（真起核 + 碰网络）。
    async fn run_auto_switch(self: &Arc<Self>, machine: &mut AutoSwitchMachine, reason: &str) {
        match machine.evaluate_switch(monotonic_now_ms()) {
            SwitchGate::Proceed => {}
            SwitchGate::InFlight => return,
            SwitchGate::Breaker { remaining_ms } => {
                log::warn!(
                    "自动切换已熔断（连续切换未恢复连通），{}s 内暂停切换，请检查网络/订阅",
                    remaining_ms.div_ceil(1000)
                );
                return;
            }
            SwitchGate::Cooldown { remaining_ms } => {
                log::info!(
                    "自动换节点冷却中，{}s 后可再次触发",
                    remaining_ms.div_ceil(1000)
                );
                return;
            }
        }
        // 放行 → 进入在飞态（提前置 lastSwitchTime → 失败/无候选也进冷却，防空转，上游 :180-181）。
        machine.begin_switch(monotonic_now_ms());
        let switched = self.do_switch_io(reason).await;
        // 真发生了切换 → 记账熔断窗口（上游 :233-236）；候选空/全不可达的早退不记（对齐 上游 两个 return）。
        if switched {
            machine.record_switch_success(monotonic_now_ms());
        }
        // finally：退出在飞态（上游 :257-259）。
        machine.end_switch();
    }

    /// 换节点的纯 I/O 段：取 D/R/S 快照 → 规划运行核 clean 候选 → 经主核 probe pool 做真实协议链探测
    /// → 只热切 selector → 运行态回读 → emit。返回 `true` 仅表示整条事务已自证成功。
    async fn do_switch_io(self: &Arc<Self>, reason: &str) -> bool {
        let generation = self.core_generation();
        let config = match self.config.current() {
            Ok(c) => c,
            Err(e) => {
                log::warn!("自动换节点：读配置失败 → 跳过：{e}");
                return false;
            }
        };
        let Some(runtime_config) = self
            .current_config
            .read()
            .ok()
            .and_then(|guard| guard.clone())
        else {
            log::warn!("自动故障切换：运行核缺少 current_config 基准 → 跳过");
            return false;
        };
        let current_id = runtime_config
            .get("selectedServerId")
            .and_then(Value::as_str)
            .map(str::to_string);
        let Some(current_id) = current_id else {
            return false;
        };
        // D 与 R 的当前选择不同意味着已有保存/广播/切换在排队。自动治理不得在这个缝里另立第三个意图。
        if config.get("selectedServerId").and_then(Value::as_str) != Some(current_id.as_str()) {
            log::info!("自动故障切换：磁盘期望出口与运行核出口不同 → 让位给既有待应用事务");
            return false;
        }
        let staged = self.config.staged_node_mask();
        if staged.pending && !staged.scope_known {
            log::info!("自动故障切换：存在范围未知的未保存草稿 → 保守跳过本轮");
            return false;
        }
        let Some(targets) = self.speed_probe_targets() else {
            log::warn!("自动故障切换：主核探测池未就绪，拒绝回退裸 TCP 候选探测");
            return false;
        };
        let current_fingerprints = current_server_fingerprints(&config);
        let not_ready_ids: BTreeSet<String> = config
            .get("servers")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|server| {
                let id = server.get("id").and_then(Value::as_str)?;
                let is_tailscale =
                    server.get("protocol").and_then(Value::as_str) == Some("tailscale");
                (is_tailscale
                    && !self
                        .mesh
                        .ts_status_event(id)
                        .as_ref()
                        .is_some_and(TailscaleStatusEvent::exit_ready))
                .then(|| id.to_string())
            })
            .collect();
        let candidate_plan = plan_runtime_candidates(
            &config,
            Some(&current_id),
            &targets.id_to_tag,
            &targets.fingerprints,
            &current_fingerprints,
            &staged.node_ids,
            &not_ready_ids,
        );
        if candidate_plan.candidates.is_empty() {
            log::warn!(
                "自动故障切换：无可验证的运行态候选（草稿={} 未入核={} 参数脏={} 未就绪={}）",
                candidate_plan.staged,
                candidate_plan.not_loaded,
                candidate_plan.dirty,
                candidate_plan.not_ready
            );
            return false;
        }
        log::info!(
            "[{reason}] 经主核探测池验证 {} 个 clean 候选（排除：草稿={} 未入核={} 参数脏={} 未就绪={}）",
            candidate_plan.candidates.len(),
            candidate_plan.staged,
            candidate_plan.not_loaded,
            candidate_plan.dirty,
            candidate_plan.not_ready
        );
        let probe_input: Vec<(String, String)> = candidate_plan
            .candidates
            .iter()
            .map(|candidate| (candidate.id.clone(), candidate.tag.clone()))
            .collect();
        let url = resolve_speed_test_url(&config);
        let latencies = match probe_runtime_candidates(self, &targets, &probe_input, &url).await {
            RuntimeProbeBatch::Completed(latencies) => latencies,
            RuntimeProbeBatch::Busy => {
                log::info!("自动故障切换：用户测速正在占用 probe pool → 本轮让位");
                return false;
            }
            RuntimeProbeBatch::Interrupted => {
                log::info!("自动故障切换：候选探测期间内核世代变化 → 本轮作废");
                return false;
            }
        };
        if self.core_generation() != generation || !self.core_running() {
            return false;
        }
        let measured: Vec<CandidateLatency> = candidate_plan
            .candidates
            .iter()
            .map(|candidate| CandidateLatency {
                id: candidate.id.clone(),
                name: candidate.name.clone(),
                latency_ms: latencies.get(&candidate.id).copied().flatten(),
            })
            .collect();

        let Some(best) = select_best_candidate(&measured) else {
            log::warn!("所有运行态 clean 候选均未通过真实代理链探测，无法自动切换");
            return false;
        };
        let best_latency = best.latency_ms.unwrap_or(0);
        log::info!("选中最优节点: {} ({best_latency}ms)", best.name);

        let Some(payload) = switch_payload(best, reason) else {
            log::warn!("自动换节点：候选缺少有效延迟 → 跳过");
            return false;
        };
        let Some(candidate) = candidate_plan
            .candidates
            .iter()
            .find(|candidate| candidate.id == best.id)
        else {
            return false;
        };
        let Some(expected_fingerprint) = current_fingerprints.get(&candidate.id) else {
            return false;
        };
        match self
            .auto_hot_switch_transaction(generation, &current_id, candidate, expected_fingerprint)
            .await
        {
            AutoHotSwitchOutcome::Applied => {}
            AutoHotSwitchOutcome::Busy => {
                log::info!("自动故障切换：生命周期事务在飞 → 本轮让位");
                return false;
            }
            AutoHotSwitchOutcome::Superseded => {
                log::info!("自动故障切换：配置、草稿或内核世代已变化 → 本轮作废");
                return false;
            }
            AutoHotSwitchOutcome::NotEligible => {
                log::warn!("自动故障切换：目标不再满足零重启热切条件 → 跳过");
                return false;
            }
            AutoHotSwitchOutcome::ReconcilePending { intent_generation } => {
                self.spawn_selector_reconciliation(generation, intent_generation);
                return false;
            }
            AutoHotSwitchOutcome::Failed => return false,
        }
        log::info!("自动换节点已自证成功: {}", payload.new_server_name);

        // emit（未接线 emitter：单测 / setup 前 → 静默跳过，对齐既有 emit 腿）。
        if let Some(emitter) = self.error_emitter.get() {
            emitter.emit_auto_node_switched(&payload);
        }
        true
    }
}

/// **C3**：应用层连通性检测：只经钉死到 `proxy-selector` 的专用 HTTP 入站，以绝对 URI GET
/// generate_204，任一端点返回 2xx/3xx → 判通。该入口不经过用户路由规则，因此结果只描述当前代理出口，
/// 不会被一条 direct 分流伪装成“节点健康”。**真机门**：需真起核 + 碰网络。
async fn probe_proxy_connectivity(probe_proxy_port: u16) -> bool {
    for url in CONNECTIVITY_URLS {
        if probe_through_proxy(probe_proxy_port, url).await {
            return true;
        }
    }
    false
}

/// 经指定的本地 HTTP 探针入口以绝对 URI GET 目标，判是否拿到 2xx/3xx。调用方负责保证该入口
/// 固定路由到待测出口；这里仅实现通用 HTTP 代理握手。**真机门**：需真起核 + 碰网络，禁本机单测。
async fn probe_through_proxy(proxy_port: u16, target_url: &str) -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // 取 Host 头（`http://<host>/path` → `<host>`）。
    let host = target_url
        .strip_prefix("http://")
        .and_then(|rest| rest.split('/').next())
        .unwrap_or("");
    if host.is_empty() {
        return false;
    }
    let request = format!(
        "GET {target_url} HTTP/1.1\r\nHost: {host}\r\nProxy-Connection: close\r\nConnection: close\r\n\r\n"
    );
    let addr = format!("127.0.0.1:{proxy_port}");
    let probe = async {
        let mut stream = tokio::net::TcpStream::connect(&addr).await.ok()?;
        stream.write_all(request.as_bytes()).await.ok()?;
        // 只需状态行（`HTTP/1.1 204 No Content`）；读一小段即可解析首行。
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.ok()?;
        let text = std::str::from_utf8(&buf[..n]).ok()?;
        let code: u32 = text.split_whitespace().nth(1)?.parse().ok()?;
        Some((200..400).contains(&code))
    };
    matches!(
        tokio::time::timeout(Duration::from_millis(CONNECTIVITY_TIMEOUT_MS), probe).await,
        Ok(Some(true))
    )
}
