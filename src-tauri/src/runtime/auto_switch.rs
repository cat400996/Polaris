//! **C3 自动换节点决策层**（上游 `AutoSwitchService` 的纯逻辑镜像）。
//!
//! # 职责边界（与崩溃恢复解耦——1:1 移植 上游 头注）
//! 只负责「当前节点不可达」时换到更优节点。**进程崩溃由 [`ProxyRuntime`](crate::runtime::proxy) 的
//! 崩溃监测「原地重启同节点」兜底，绝不触发换节点**——崩溃多为瞬时/配置问题，换节点既不对症又会丢失
//! 用户选中节点（上游 AutoSwitchService.ts:4-6）。故本层**不消费** `spawn_crash_monitor`，只消费
//! 「应用层连通性」这个独立信号。
//!
//! # 为什么把决策抽成纯状态机
//! 「别过度触发（一次瞬断不该切）也别欠触发」+「重试阈值/冷却/熔断」是本任务的核心正确性，而它们
//! 全是**与网络 I/O 无关的时序决策**。抽成纯 [`AutoSwitchMachine`] + 纯选择函数 → 触发判定 / 冷却 /
//! 熔断 / 下一节点选择全部可用真值表单测 + 变异验证锁死，**无需真起核、不碰宿主网络**（网络探测 I/O
//! 留在 `proxy.rs` 驱动层，真机门）。范式对齐同仓 `CrashRecoveryMachine`（决策在 crate、I/O 在 runtime）。
//!
//! # 常量（逐一对齐 上游 AutoSwitchService.ts:29-40）
//! 阈值/冷却/熔断窗口全部照搬，偏离即语义漂移。

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

/// 心跳检测间隔（上游 `HEARTBEAT_INTERVAL_MS`，:29）。
pub const HEARTBEAT_INTERVAL_MS: u64 = 30_000;
/// 连续失败触发换节点的阈值（上游 `MAX_CONSECUTIVE_FAILURES`，:30）。
/// **别过度触发的核心**：单次瞬断只累加计数，连续 3 次才切。
pub const MAX_CONSECUTIVE_FAILURES: u32 = 3;
/// 换节点冷却窗口（上游 `SWITCH_COOLDOWN_MS`，:32）。防频繁切换。
pub const SWITCH_COOLDOWN_MS: u64 = 60_000;
/// 应用层连通性探测超时（上游 `CONNECTIVITY_TIMEOUT_MS`，:33）。
pub const CONNECTIVITY_TIMEOUT_MS: u64 = 5_000;
/// 熔断阈值：连续自动切换达此数仍未恢复 → 暂停（上游 `MAX_AUTO_SWITCHES`，:34）。
pub const MAX_AUTO_SWITCHES: u32 = 3;
/// 熔断冷却：触发后暂停切换的时长，10 分钟后放行一次重试（上游 `BREAKER_COOLDOWN_MS`，:35）。
pub const BREAKER_COOLDOWN_MS: u64 = 10 * 60_000;
/// 经代理请求的连通性探测端点（返回 204）：海外可达即证明代理链通；多个互为兜底
/// （上游 `CONNECTIVITY_URLS`，:37-40）。
pub const CONNECTIVITY_URLS: [&str; 2] = [
    "http://cp.cloudflare.com/generate_204",
    "http://www.gstatic.com/generate_204",
];

/// 一次心跳连通性检测喂入决策机后的结论（上游 `runHeartbeat` 的分支）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeartbeatOutcome {
    /// 连通且此前无失败 → 稳态，无动作。
    Stable,
    /// 连通但此前有连续失败 → 复位计数（连通性恢复正常）。`prior` = 复位前的失败次数（供日志）。
    Recovered { prior: u32 },
    /// 未连通但未达阈值 → 累加失败计数，暂不切。`failures` = 累加后的连续失败次数。
    Failing { failures: u32 },
    /// 连续失败达阈值 → 触发换节点（失败计数已在内部复位，对齐 上游 :142）。
    Trigger,
}

/// 换节点前的闸门评估结果（上游 `triggerSwitch` 前半：isSwitching / 熔断 / 冷却）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchGate {
    /// 放行——可执行换节点。
    Proceed,
    /// 已有换节点在飞 → 跳过（上游 isSwitching 守卫）。
    InFlight,
    /// 熔断中（连续切换未恢复）→ 暂停。`remaining_ms` = 距放行剩余时间。
    Breaker { remaining_ms: u64 },
    /// 冷却中 → 暂停。`remaining_ms` = 距可再触发剩余时间。
    Cooldown { remaining_ms: u64 },
}

/// 自动换节点决策状态机（上游 `AutoSwitchService` 的时序态，纯逻辑无 I/O）。
///
/// 每个运行核世代一个实例（随核就绪 `enable`、随核停/接管退场丢弃）——对齐 上游 单例但按世代重置。
#[derive(Debug)]
pub struct AutoSwitchMachine {
    enabled: bool,
    /// 连续连通性失败次数（上游 `consecutiveFailures`）。
    consecutive_failures: u32,
    /// 换节点在飞标志（上游 `isSwitching`）：同一时刻只允许一个换节点操作。
    is_switching: bool,
    /// 上次换节点的单调时钟刻度（ms）；`None` = 本世代尚未切换。
    last_switch_time: Option<u64>,
    /// 连续自动切换次数（上游 `consecutiveSwitches`），熔断计数。
    consecutive_switches: u32,
    /// 熔断触发的单调时钟刻度（ms）。
    breaker_tripped_at: Option<u64>,
}

impl Default for AutoSwitchMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl AutoSwitchMachine {
    #[must_use]
    pub fn new() -> Self {
        Self {
            enabled: false,
            consecutive_failures: 0,
            is_switching: false,
            last_switch_time: None,
            consecutive_switches: 0,
            breaker_tripped_at: None,
        }
    }

    /// 启用（上游 `enable`，:63-71）：复位失败/熔断计数。幂等（已启用则 no-op）。
    pub fn enable(&mut self) {
        if self.enabled {
            return;
        }
        self.enabled = true;
        self.consecutive_failures = 0;
        self.consecutive_switches = 0;
        self.breaker_tripped_at = None;
    }

    /// 禁用（上游 `disable`，:73-78）。幂等。
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    #[must_use]
    pub fn is_switching(&self) -> bool {
        self.is_switching
    }

    /// 核未运行时只复位失败计数、**不动熔断计数**（上游 `runHeartbeat` 的 `!running` 分支，:107-110）。
    pub fn reset_failures_only(&mut self) {
        self.consecutive_failures = 0;
    }

    /// 喂一次心跳连通性结果 → 决策（上游 `runHeartbeat` 的 alive/失败分支，:122-145）。
    ///
    /// - `alive=true`：复位连续失败 **且** 复位熔断计数（恢复联通即视为已稳定，上游 :130-132）。
    /// - `alive=false`：累加失败；达 [`MAX_CONSECUTIVE_FAILURES`] → 复位失败计数并返 [`Trigger`]
    ///   （上游 :141-143：先 `consecutiveFailures = 0` 再 `triggerSwitch`）。
    ///
    /// [`Trigger`]: HeartbeatOutcome::Trigger
    pub fn on_heartbeat(&mut self, alive: bool) -> HeartbeatOutcome {
        if alive {
            let prior = self.consecutive_failures;
            self.consecutive_failures = 0;
            // 恢复联通即视为已稳定，复位熔断计数（上游 :132）。
            self.consecutive_switches = 0;
            if prior > 0 {
                HeartbeatOutcome::Recovered { prior }
            } else {
                HeartbeatOutcome::Stable
            }
        } else {
            self.consecutive_failures += 1;
            if self.consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
                self.consecutive_failures = 0;
                HeartbeatOutcome::Trigger
            } else {
                HeartbeatOutcome::Failing {
                    failures: self.consecutive_failures,
                }
            }
        }
    }

    /// 换节点前闸门（上游 `triggerSwitch` :151-178）：**顺序即语义**——
    /// 1. 在飞 → [`InFlight`]（上游 :151-154）。
    /// 2. 熔断：连续切换达 [`MAX_AUTO_SWITCHES`] 且仍在 [`BREAKER_COOLDOWN_MS`] 内 → [`Breaker`]；
    ///    冷却结束 → 复位 `consecutive_switches` 放行一次重试（上游 :157-170）。
    /// 3. 冷却：距上次换节点 < [`SWITCH_COOLDOWN_MS`] → [`Cooldown`]（上游 :173-178）。
    /// 4. 否则 [`Proceed`]。
    ///
    /// **有副作用**（熔断冷却结束的复位），故 `&mut self`——与 上游 在 triggerSwitch 内联复位同构。
    ///
    /// [`InFlight`]: SwitchGate::InFlight
    /// [`Breaker`]: SwitchGate::Breaker
    /// [`Cooldown`]: SwitchGate::Cooldown
    /// [`Proceed`]: SwitchGate::Proceed
    pub fn evaluate_switch(&mut self, now: u64) -> SwitchGate {
        if self.is_switching {
            return SwitchGate::InFlight;
        }
        // 熔断检查（先于冷却，对齐 上游 顺序）。
        if self.consecutive_switches >= MAX_AUTO_SWITCHES {
            let since_trip = self
                .breaker_tripped_at
                .map_or(BREAKER_COOLDOWN_MS, |at| now.saturating_sub(at));
            if since_trip < BREAKER_COOLDOWN_MS {
                return SwitchGate::Breaker {
                    remaining_ms: BREAKER_COOLDOWN_MS - since_trip,
                };
            }
            // 冷却结束，复位熔断，放行一次重试（上游 :169）。
            self.consecutive_switches = 0;
        }
        // 冷却检查。
        if let Some(last_switch_time) = self.last_switch_time {
            let since_last = now.saturating_sub(last_switch_time);
            if since_last < SWITCH_COOLDOWN_MS {
                return SwitchGate::Cooldown {
                    remaining_ms: SWITCH_COOLDOWN_MS - since_last,
                };
            }
        }
        SwitchGate::Proceed
    }

    /// 闸门放行后进入换节点在飞态（上游 `triggerSwitch` :180-181：置 `isSwitching` + `lastSwitchTime`）。
    /// **无论成功与否都提前置 `lastSwitchTime`** → 失败/无候选也进入冷却，防在节点间空转（上游 同构）。
    pub fn begin_switch(&mut self, now: u64) {
        self.is_switching = true;
        self.last_switch_time = Some(now);
    }

    /// 换节点**真正执行了一次切换**后记账（上游 `triggerSwitch` :233-236）：
    /// `consecutive_switches++`，达 [`MAX_AUTO_SWITCHES`] → 记熔断触发时刻。
    ///
    /// **只在真发生切换时调**（候选空 / 全不可达的早退不调，对齐 上游 那两个 `return` 不增计数）。
    pub fn record_switch_success(&mut self, now: u64) {
        self.consecutive_switches += 1;
        if self.consecutive_switches >= MAX_AUTO_SWITCHES {
            self.breaker_tripped_at = Some(now);
        }
    }

    /// 换节点结束，退出在飞态（上游 `triggerSwitch` finally :257-259：`isSwitching = false`）。
    /// 成功/失败/早退都必须调（对齐 finally 语义）。
    pub fn end_switch(&mut self) {
        self.is_switching = false;
    }
}

/// 候选节点及其测得延迟（上游 `{ server, latency }`）。`latency_ms=None` = 不可达。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateLatency {
    pub id: String,
    pub name: String,
    pub latency_ms: Option<u32>,
}

/// 当前运行核中可做端到端探测、且参数与磁盘期望态一致的候选。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeCandidate {
    pub id: String,
    pub name: String,
    pub tag: String,
}

/// 候选规划结果。各排除计数互斥（按 staged → 未入核 → 参数脏 → 运行态未就绪的顺序裁定），
/// 只用于诊断，不把节点详情写日志。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeCandidatePlan {
    pub candidates: Vec<RuntimeCandidate>,
    pub staged: usize,
    pub not_loaded: usize,
    pub dirty: usize,
    pub not_ready: usize,
}

/// 从磁盘期望态 D 与运行核快照 R 的交集生成自动故障切换候选。
///
/// 只有同时满足以下条件的节点才进入候选：
/// - 不是当前出口；
/// - 不在渲染端未保存的节点草稿遮罩里；
/// - 已作为当前核 selector 成员加载；
/// - D 的连接指纹与起核快照一致（未编辑、未被订阅替换）；
/// - 协议运行态已就绪（目前用于排除未登录/过期的 Tailscale endpoint）。
///
/// 这样候选可以经主核 probe-selector 做真实协议链探测并只走 `SelectOutbound`；D-only/dirty 节点
/// 绝不会靠裸 TCP 猜测可用，也不会为了自动切换把未 Apply 的配置带进一次整核重启。
#[must_use]
pub fn plan_runtime_candidates(
    config: &Value,
    current_id: Option<&str>,
    id_to_tag: &BTreeMap<String, String>,
    running_fingerprints: &BTreeMap<String, String>,
    current_fingerprints: &BTreeMap<String, String>,
    staged_node_ids: &BTreeSet<String>,
    not_ready_ids: &BTreeSet<String>,
) -> RuntimeCandidatePlan {
    let Some(servers) = config.get("servers").and_then(Value::as_array) else {
        return RuntimeCandidatePlan::default();
    };
    let mut plan = RuntimeCandidatePlan::default();
    for server in servers {
        let Some(id) = server.get("id").and_then(Value::as_str) else {
            continue;
        };
        if Some(id) == current_id {
            continue;
        }
        if staged_node_ids.contains(id) {
            plan.staged += 1;
            continue;
        }
        let Some(tag) = id_to_tag.get(id) else {
            plan.not_loaded += 1;
            continue;
        };
        let clean = running_fingerprints
            .get(id)
            .zip(current_fingerprints.get(id))
            .is_some_and(|(running, current)| running == current);
        if !clean {
            plan.dirty += 1;
            continue;
        }
        if not_ready_ids.contains(id) {
            plan.not_ready += 1;
            continue;
        }
        plan.candidates.push(RuntimeCandidate {
            id: id.to_string(),
            name: server
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or(id)
                .to_string(),
            tag: tag.clone(),
        });
    }
    plan
}

/// 选最优候选（上游 :208-218：过滤不可达 → 按延迟升序 → 取 `available[0]`）。
///
/// 纯函数。入参**已排除当前节点**（由 [`plan_runtime_candidates`] 保证）。全不可达 → `None`。
/// 延迟并列取**首个**（`min_by_key` 稳定返回首元 = 上游 稳定排序取 `[0]`，保候选原序优先）。
#[must_use]
pub fn select_best_candidate(candidates: &[CandidateLatency]) -> Option<&CandidateLatency> {
    candidates
        .iter()
        .filter(|c| c.latency_ms.is_some())
        .min_by_key(|c| c.latency_ms.unwrap_or(u32::MAX))
}

/// 前端 `autoNodeSwitched` 事件 payload（上游 :243-247 `{ reason, newServerName, latency }`）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutoNodeSwitchedPayload {
    /// 触发原因（如「连通性检测」）。
    pub reason: String,
    /// 切到的目标节点显示名。
    pub new_server_name: String,
    /// 目标节点测得延迟（ms）。
    pub latency: u32,
}

/// 由选中的最优候选 + reason 构造切换成功事件（纯函数，上游 :243-247）。
///
/// 配置写入已由运行时 selector 事务单点负责，此处不得再克隆、改写整份配置。
/// `best.latency_ms` 必为 `Some`（[`select_best_candidate`] 已过滤不可达）；理论不可达的 `None`
/// 仍返回 `None`，避免发出伪造的 0ms 成功事件。
#[must_use]
pub fn switch_payload(best: &CandidateLatency, reason: &str) -> Option<AutoNodeSwitchedPayload> {
    let latency = best.latency_ms?;
    Some(AutoNodeSwitchedPayload {
        reason: reason.to_string(),
        new_server_name: best.name.clone(),
        latency,
    })
}

#[cfg(test)]
mod tests;
