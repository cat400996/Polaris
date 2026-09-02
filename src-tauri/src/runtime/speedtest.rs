//! **临时核测速**的宿主层编排（上游 `SpeedTestService.testServersViaProxy`，`SpeedTestService.ts:388-620`）。
//!
//! # 这条腿补的是什么能力
//!
//! 主核**没在跑**时（用户还没点「连接」），`server_speed_test` 此前只能返 clean error「核未运行，无法测速」。
//! 而「先测速比较延迟、再选一个最快的节点连上去」是常规使用序 —— 少了这条腿，用户必须先盲选一个节点连上、
//! 才能测别的节点。本模块起一个**独立的瞬态 sing-box**（每个可测节点一个 HTTP 入站 → 该节点出站），经各自
//! 端口量 warm-TTFB，测完即杀。
//!
//! # 与常驻主核的隔离（三条硬边界，逐条对应一个真实事故面）
//!
//! 1. **独立配置文件**：`<configDir>/speedtest-core.json`，绝不碰主核的 `singbox-runtime.json`
//!    （[`ProxyRuntime::runtime_config_path`](crate::runtime::proxy::ProxyRuntime::runtime_config_path)）。
//! 2. **独立端口**：经 [`PortAllocator::resolve_distinct_free_ports`] 现分配，且**排除**用户配置的
//!    control/http/mixed 口 —— 否则主核随后起来时会撞在临时核占着的口上，表现为「测完速就连不上」。
//! 3. **不写主核的任何生命周期槽**：child 句柄由本模块的会话独占，绝不进 `ProxyRuntime` 的 `pid`/`child`；
//!    也不置 `core_via_helper` 标记。临时核**永不经 helper 起**（无 TUN、无 root 需求）。
//!
//! # 让位语义（§15.11 gen abort 惯例的镜像腿）
//!
//! 主核和临时核**绝不能同时跑**：同一个 WG/WARP peer 被两个会话同时握手会互相踢线（上游 G1 的
//! 「双会话超时」），Tailscale 更是连第二个 tsnet 实例都建不出来。本腿只在主核未跑时开工，且全程守
//! [`is_temp_core_superseded`]：
//!
//! - `gen != gen0` —— 用户中途点了「连接」（`start` 先 bump 世代再动核）⇒ 主核来了，临时核**立刻让路**；
//! - `running == true` —— **世代腿盖不住的那一半**：起核的 bump 可能发生在本次测速取 `gen0` **之前**
//!   （此刻 `status.running` 仍是 false，因为核还在启动中），随后核就绪 ⇒ `running` 翻真而世代不再变。
//!   只查世代的话，这整段窗口里临时核与主核并存 —— 正是双会话事故的形态。
//! - `starting == true` —— **前两条腿同时为假的那整段启动期**：`start` 先置 `start_inflight`
//!   （`starting` 的源）、再跑可达数秒的 stale 清扫、才 `bump_generation`；`gen0` 落在 bump 之后、
//!   就绪之前时，世代腿与 `running` 腿双盲，而主核正在 spawn + bind 端口。
//!
//! 让路 = **中断编排 + 杀临时核 + 未测节点缺席**（不写假 `-1`），与主核池路径 [`drive_pool_waves`] 的
//! 三检查点逐字同义。收尾（杀核 + 删配置）走**无条件**路径，让位/失败/正常完成三条腿共用。
//!
//! [`drive_pool_waves`]: crate::commands::speedtest
//!
//! # 诚实边界（务必读）
//!
//! 本模块的端到端价值 = **真 sing-box + 真出站 + 真网络往返**。这条真机路径**在本 Linux 开发机上无法
//! 验证**（本仓禁跑触碰宿主网络的测试）。因此：
//! - 全部可单测面（节点分区、配置生成、端口/tag 绑定、并发分批、让位三检查点、收尾回收）都以**注入的**
//!   [`TempCoreDeps`] / 测量闭包 / 事件闭包驱动 —— 无真进程、无网络、无真 sing-box；
//! - **真 spawn + 真延迟数值**一段**在此未验证**，门槛是一次真机会话。不得据本模块宣称「临时核测速端到端可用」。

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use serde_json::{json, Value};

use polaris_config_engine::builder::endpoints::{
    build_vpn_client_endpoint, build_wireguard_endpoint,
};
use polaris_config_engine::builder::outbound::build_proxy_outbound;
use polaris_config_engine::builder::outbounds::build_shadow_tls_outbound;
use polaris_config_engine::singbox::DomainResolver;
use polaris_config_engine::user_config::server_config::{Protocol, ServerConfig};
use polaris_core_supervisor::port_bookkeeping::TokioPortProvider;
use polaris_core_supervisor::{
    wait_for_core_ready, CoreReadyDeps, CoreReadyOutcome, PortAllocator, PortExclusions, Signal,
    SpawnRequest, WaitForCoreReadyOptions,
};

use crate::events::channel::{
    EVENT_SPEED_TEST_DONE, EVENT_SPEED_TEST_PROGRESS, EVENT_SPEED_TEST_RESULT,
};
use crate::runtime::proxy::{pid_alive, send_signal, CoreBuildEnv};
// 瞬态核的进程原语**复用** `tailscale_login_core` 已建好的那一套（spawn → 装箱 child → SIGTERM/宽限/
// SIGKILL/reap）。名字带 "Login" 是历史包袱，语义是「瞬态 sing-box 子进程」，与本腿逐字相同；再写一套
// 进程管理只会多一份要各自维护的收割纪律（而收割写漏的表现是孤儿核，静默且持久）。
use crate::runtime::tailscale_login_core::{
    ConfigChecker, LoginCoreChild, LoginCoreSpawner, SingBoxConfigChecker, TokioLoginCoreSpawner,
};

/// 临时核可测节点的**滑动窗口**上限（对齐 上游 `SpeedTestService.PROXY_TEST_CONCURRENCY = 16`，`:90`）。
///
/// 不设上限时大订阅会把 N 路 TLS/QUIC 握手同时打出去 → 本机 CPU/连接数打满 → 一批**假超时**
/// （节点其实是好的）。≤上限的小订阅等价于全并行，零代价。
///
/// 语义是「**同时在飞**至多这么多」（回来一个补一个），**不是**「切成这么大的批」——
/// 见 [`drive_temp_core_measures`] 的调度形态一节。
pub const TEMP_CORE_CONCURRENCY: usize = 16;

/// 临时核就绪等待上限（对齐 上游 `waitForPortReady(ports[0], 10000)`，`:510`）。
/// 应用分流规则集/geo 资源的加载可能耗时，给 10s。
const TEMP_CORE_READY_TIMEOUT_MS: u64 = 10_000;

/// 就绪轮询间隔。
const TEMP_CORE_READY_POLL_MS: u64 = 200;

/// **在飞**让位轮询间隔（[`drive_temp_core_measures`] 的检查点②）。
///
/// 只在「发新活之前 / 每节点测完」两处查是不够的：窗口里的节点**全部不可达**时（真机上就是订阅里
/// 有 ≥16 个死节点），那两处一个都醒不过来 —— supersede 信号出现后临时核（及其**已建立的 WG/WARP
/// 会话**）还要活满一整个测量超时。Linux/macOS 靠主核 `start()` 入口的 stale sweep 顺带杀掉——那是
/// **副作用缓解、不是设计保证**；Windows 无 sweep（`scan_running_cores` 恒返空）⇒ 全程重叠。
/// 故按本间隔独立轮询（`timeout(poll, join_next())`，**不依赖任何测量返回**），命中即 `abort_all` +
/// 立即返回（调用方紧接着 `terminate()`）。
const TEMP_CORE_SUPERSEDE_POLL_MS: u64 = 200;

/// 临时核配置文件名（**独立于**主核 `singbox-runtime.json`）。
///
/// 固定名而非带时间戳（上游 `speedtest_${Date.now()}.json`）：测速已有进程级单飞闸
/// （`commands::speedtest::SpeedTestGuard`）⇒ 同时至多一个临时核，固定名不会自撞，且上次会话崩溃残留的
/// 那份会被本次直接覆盖（带时间戳反而会在 config 目录里越堆越多）。
const TEMP_CORE_CONFIG_NAME: &str = "speedtest-core.json";

/// **在飞临时核 pid 表** —— 应用退出清理的唯一真值源。
///
/// # 为什么光有 child 的 `Drop` 守卫不够
///
/// 临时核 child 由本模块的会话 future 独占持有，`TokioLoginCoreChild` 的 Drop 守卫只覆盖「future 被
/// 丢弃 / panic 展开」。**应用退出**走的是 `RunEvent::ExitRequested → run_exit_cleanup → 进程退出`，
/// 在飞的 tokio task **根本不会被 drop** ⇒ 临时核不随父进程死，留下一个持续持有 N 个回环端口 +
/// WG/WARP peer 会话的孤儿 sing-box。而兜底 sweep 只在**下次** `start()` 才跑，且 Windows 的
/// `scan_running_cores` 恒返空（`core-supervisor/src/stale_core.rs`：`tasklist` 不输出命令行，无从
/// 施加「只杀本 app 起的核」判据）⇒ **Windows 孤儿永不被清**。
///
/// 故在此登记 pid，由 `exit_lifecycle::run_exit_cleanup` 经 [`kill_inflight_temp_cores`] 收口。
static INFLIGHT_TEMP_CORES: Mutex<BTreeSet<u32>> = Mutex::new(BTreeSet::new());

/// 取 pid 表锁（临界区极短、绝不跨 await；中毒仍恢复内层，不为一条清理路径 panic 掉退出流程）。
fn temp_core_pids() -> MutexGuard<'static, BTreeSet<u32>> {
    INFLIGHT_TEMP_CORES
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

/// 排空 pid 表（**不发任何信号**）。退出清理与单测共用同一个真值源 —— 单测只走本函数即可观测
/// 注册/注销，绝不对真实进程发信号（本仓禁在单测里碰宿主进程/网络）。
fn take_inflight_temp_core_pids() -> Vec<u32> {
    std::mem::take(&mut *temp_core_pids()).into_iter().collect()
}

/// **应用退出清理**：SIGKILL 掉全部在飞临时核，返回实际发信号条数（0 = 退出时没有测速在飞）。
///
/// 直接 SIGKILL 不走 SIGTERM 宽限：退出路径不能再等一个 5s 宽限窗；临时核无状态（配置随后即删、
/// 不写主核任何生命周期槽），强杀无副作用。
pub fn kill_inflight_temp_cores() -> usize {
    kill_temp_cores_with(|pid| send_signal(pid, Signal::Sigkill))
}

/// [`kill_inflight_temp_cores`] 的可注入内核（**收割动作是唯一注入点**）：单测传记录闭包驱动整条
/// 「排空 → 逐 pid 收割 → 计数」逻辑，**不对任何真实进程发信号**（本仓禁在单测里碰宿主进程）。
fn kill_temp_cores_with(mut kill: impl FnMut(u32)) -> usize {
    let pids = take_inflight_temp_core_pids();
    for pid in &pids {
        log::warn!("退出清理：强杀在飞测速临时核 pid={pid}");
        kill(*pid);
    }
    pids.len()
}

/// pid 登记 RAII 守卫：`drive_after_spawn` 的每一条 return / panic 展开 / future 被丢弃都会注销，
/// 故表里只会留下**此刻真在飞**的 pid（退出清理据此发信号，pid 复用误杀窗口被压到最小）。
struct TempCorePidGuard(u32);

impl TempCorePidGuard {
    /// 登记一个 pid；`pid == 0`（取不到 pid / 测试假核）→ 不登记（返 `None`）。
    fn register(pid: u32) -> Option<Self> {
        (pid != 0).then(|| {
            temp_core_pids().insert(pid);
            Self(pid)
        })
    }
}

impl Drop for TempCorePidGuard {
    fn drop(&mut self) {
        temp_core_pids().remove(&self.0);
    }
}

/// 临时核**入站→出站** 1:1 绑定的一个节点（[`plan_temp_core_with_bindings`] 产出，[`build_temp_core_config`] 消费）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TempNode {
    /// 节点 id（结果回填键 + `event:speedTestResult` 的 serverId）。
    pub id: String,
    /// 临时核内的出站/端点 tag（`out-<id 前 8 位>`，见 [`temp_core_tag`]）。
    pub tag: String,
    /// 预构造的出站（普通协议）或端点（WG / 自定义 endpoint）JSON。
    pub node: Value,
    /// 主出站依赖的附属出站。当前用于 ShadowTLS 外层；它才负责公网拨号和承接网卡绑定。
    pub companion_outbounds: Vec<Value>,
    /// 是否走 `endpoints[]`（L3 端点，须额外配穿隧道 DNS，见 [`build_temp_core_config`]）。
    pub is_endpoint: bool,
    /// WG 本地地址含 IPv6（端点 DNS 族别偏好的分流，对齐 上游 `:868`）。
    ///
    /// 纯 v4 ⇒ 给该入站前置一条 AAAA `predefined` 空答复（等价旧 `ipv4_only`）；
    /// 含 v6 ⇒ 不下发任何东西（等价旧 `prefer_ipv4`，见 [`build_temp_core_config`]）。
    pub has_local_v6: bool,
}

/// [`plan_temp_core_with_bindings`] 的产出：可测节点（保序）+ 各原因的缺席列表（保序）。
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TempCorePlan {
    /// 进临时核真测的节点。
    pub testable: Vec<TempNode>,
    /// 因协议是 tailscale 而缺席（回报进响应的 `tsNotReady`，对齐 上游 L-2 `:248-250`）。
    pub tailscale: Vec<String>,
    /// 因 naive 缺 cronet / 构造失败而缺席（回报进响应的 `notInPool`：对用户同样是「本轮没测」）。
    pub unusable: Vec<String>,
}

/// 临时核里某节点的 **基础** tag（对齐 上游 `out-${s.id.slice(0, 8)}`，`:443`）。
///
/// 取 id 前 8 位而非全 id：sing-box tag 只需在**本临时核内**唯一，而 id 是 uuid ⇒ 前 8 位碰撞概率可忽略，
/// 短 tag 让核日志与 DNS 规则可读。**碰撞真发生时**由 [`unique_temp_core_tag`] 加序号消歧，绝不生成两个
/// 同 tag 的出站（那会让核启动直接 FATAL、整批测不成）。
#[must_use]
pub fn temp_core_tag(id: &str) -> String {
    let head: String = id.chars().take(8).collect();
    format!("out-{head}")
}

/// 在 `taken` 之外取一个唯一 tag：基础 tag 空着就用它，否则加序号（`out-xxxxxxxx-2`、`-3`…）。
///
/// # 为什么不是「后来者出局」
///
/// id **不保证是 uuid**：手输/导入的节点常见 `mynode-a1` / `mynode-a2` 这种前缀相同的命名，前 8 位
/// 逐字相同 ⇒ 碰撞不是「概率可忽略」而是**确定性**发生。旧的去重腿把后来者整个丢进 `unusable`，
/// 用户侧表现是那个节点**每次**都以笼统的 `notInPool` 缺席、且无从修复（他不知道要去改 id 前 8 位）。
/// 消歧后两个节点各有独立入站/出站/DNS 规则，照常各测各的。
///
/// `taken` 有限 ⇒ 循环必然终止。
fn unique_temp_core_tag(id: &str, taken: &BTreeSet<String>) -> String {
    let base = temp_core_tag(id);
    if !taken.contains(&base) {
        return base;
    }
    let mut n = 2usize;
    loop {
        let candidate = format!("{base}-{n}");
        if !taken.contains(&candidate) {
            return candidate;
        }
        n += 1;
    }
}

/// 把请求集裁成「进临时核的节点」+「缺席列表」（纯逻辑，对齐 上游 `:438-450` 的 `usable` 循环）。
///
/// 判定序（每一条都对应一个真实的整批失败面，顺序不可换）：
/// 1. **tailscale → 缺席**：临时核建不出第二个 tsnet 实例；即便建得出，它与主核共用 `tailscale-state`
///    目录，两个核同写必然把登录态写坏。这条**必须在构造之前**判 —— 构造它本身就要落状态目录。
/// 2. **naive 且无 cronet → 缺席**：进核会 FATAL 拖垮**整批**（不是只坏它自己）。
/// 3. **tag 消歧**：同 tag 两个出站 ⇒ 核启动 FATAL。id 前 8 位碰撞时加序号
///    （[`unique_temp_core_tag`]），**不丢节点**。
/// 4. **构造失败 → 缺席**：WG 缺 privateKey / 自定义 JSON 形态非法。绝不放一个半截出站进核。
#[cfg(test)]
#[must_use]
pub fn plan_temp_core(servers: &[ServerConfig], env: &CoreBuildEnv) -> TempCorePlan {
    plan_temp_core_with_bindings(servers, env, &BTreeMap::new())
}

/// `plan_temp_core` + 用户显式配置的节点/订阅/全局代理出口绑定。
///
/// 临时核只在主核停止时运行，不需要 TUN 启动前的按目的路由推导；但显式策略属于用户配置，测速路径
/// 必须与真实连接一致。映射只按节点 id 取值，空值继续交给操作系统逐目的选路。
#[must_use]
pub fn plan_temp_core_with_bindings(
    servers: &[ServerConfig],
    env: &CoreBuildEnv,
    bind_interfaces: &BTreeMap<String, String>,
) -> TempCorePlan {
    let mut out = TempCorePlan::default();
    let mut seen_tags: BTreeSet<String> = BTreeSet::new();
    for s in servers {
        if s.protocol == Protocol::Tailscale {
            out.tailscale.push(s.id.clone());
            continue;
        }
        if s.protocol == Protocol::Naive && !env.has_cronet {
            out.unusable.push(s.id.clone());
            continue;
        }
        let tag = unique_temp_core_tag(&s.id, &seen_tags);
        seen_tags.insert(tag.clone());
        match build_temp_node(s, &tag, env, bind_interfaces.get(&s.id).map(String::as_str)) {
            Some(node) => out.testable.push(node),
            None => {
                // tag 已占坑但节点没建成 → 归还，免得后一个真能建成的同 tag 节点被误判成碰撞。
                seen_tags.remove(&tag);
                out.unusable.push(s.id.clone());
            }
        }
    }
    out
}

/// 单节点的出站/端点构造（复用 config-engine 的 20 协议字段映射，**不在本层重写任何协议细节**）。
///
/// `domain_resolver` 一律指向临时核自己的 `dns-direct`（223.5.5.5）—— 那是**节点 server 地址**的解析器，
/// 与「目标域名怎么解析」是两回事（见 [`build_temp_core_config`] 的两类解析不变量）。
fn build_temp_node(
    s: &ServerConfig,
    tag: &str,
    env: &CoreBuildEnv,
    bind_interface: Option<&str>,
) -> Option<TempNode> {
    let is_custom_endpoint = s.protocol == Protocol::Custom
        && s.custom_settings
            .as_ref()
            .and_then(|c| c.is_endpoint)
            .unwrap_or(false);

    if s.protocol == Protocol::Wireguard {
        // detour 恒传 `None`：临时测速核只装被测节点自己 + `dns-direct`，前置代理那个 outbound
        // 压根不在这份配置里 —— 填了就是指向不存在的 tag ⇒ FATAL。判据同下面自定义 endpoint 腿的
        // `obj.remove("detour")`（那条注释写的就是这件事），两条腿口径一致。
        // 代价：带前置代理的 WG 节点，测得的是**直连**该 peer 的速度，不是经链路的速度。
        // dial 侧解析器传**纯 tag**，不是 #335 的结构化 `{server, strategy}` 形态：那条缺陷的根因是
        // 「顶层 `dns.strategy=ipv4_only` 连带压掉节点域名的 AAAA」，而临时测速核**恒不下发顶层
        // `dns.strategy`**（见下方 `build_temp_core_config` 的不变量注释，变异锁单测
        // `temp_core_dns_never_sets_a_legacy_or_top_level_strategy` 断言 1.16 DNS 旧形态为空，
        // 且 `dns.strategy` 必须缺席）
        // ⇒ 这份配置里没有可覆盖的顶层策略，下发结构化形态属无据的行为变更。
        let ep = build_wireguard_endpoint(
            s,
            tag,
            Some(&DomainResolver::Tag(DIRECT_DNS_TAG.to_string())),
            &env.platform,
            None,
        )
        .ok()?;
        let has_local_v6 = s
            .wireguard_settings
            .as_ref()
            .is_some_and(|w| w.local_address.iter().any(|a| a.contains(':')));
        let mut node = serde_json::to_value(ep).ok()?;
        set_bind_interface(&mut node, bind_interface)?;
        return Some(TempNode {
            id: s.id.clone(),
            tag: tag.to_string(),
            node,
            companion_outbounds: Vec::new(),
            is_endpoint: true,
            has_local_v6,
        });
    }

    if matches!(s.protocol, Protocol::Openconnect | Protocol::OpenvpnClient) {
        let has_settings = match s.protocol {
            Protocol::Openconnect => s.openconnect_settings.is_some(),
            Protocol::OpenvpnClient => s.openvpn_client_settings.is_some(),
            _ => unreachable!("protocol was guarded above"),
        };
        if !has_settings {
            return None;
        }
        let endpoint = build_vpn_client_endpoint(
            s,
            tag,
            Some(&DomainResolver::Tag(DIRECT_DNS_TAG.to_string())),
        )
        .ok()?;
        let mut node = serde_json::to_value(endpoint).ok()?;
        set_bind_interface(&mut node, bind_interface)?;
        return Some(TempNode {
            id: s.id.clone(),
            tag: tag.to_string(),
            node,
            companion_outbounds: Vec::new(),
            is_endpoint: true,
            has_local_v6: false,
        });
    }

    if is_custom_endpoint {
        // 自定义 endpoint：原样透传用户 JSON，仅覆盖 tag、剥内层 detour（对齐 config-engine
        // `build_outbounds` 的自定义 endpoint 腿；detour 在临时核里指向不存在的 tag 会 FATAL）。
        let mut val = s.custom_settings.as_ref()?.outbound.clone();
        let obj = val.as_object_mut()?;
        obj.remove("detour");
        obj.insert("tag".into(), Value::from(tag));
        set_bind_interface(&mut val, bind_interface)?;
        return Some(TempNode {
            id: s.id.clone(),
            tag: tag.to_string(),
            node: val,
            companion_outbounds: Vec::new(),
            is_endpoint: true,
            has_local_v6: false,
        });
    }

    // 纯 tag 而非 #335 的结构化形态，理由同上面 WG 那条腿（临时核无顶层 `dns.strategy` 可覆盖）。
    let ob = build_proxy_outbound(
        s,
        tag,
        &DomainResolver::Tag(DIRECT_DNS_TAG.to_string()),
        &env.arch,
        &env.platform,
    );
    // **detour 一律剥掉**：临时核只装被测节点自己，链式前置节点的 tag 在核里根本不存在 ⇒ 留着必 FATAL。
    // 代价是「代理链节点测的是它自己那一跳」——如实、且与旧行为（根本测不了）相比只增不减。
    let mut val = serde_json::to_value(ob).ok()?;
    let obj = val.as_object_mut()?;
    obj.remove("detour");
    let mut companion_outbounds = Vec::new();
    if let Some(outer) = build_shadow_tls_outbound(s, bind_interface) {
        obj.remove("bind_interface");
        obj.insert("detour".into(), Value::from(outer.tag.clone()));
        companion_outbounds.push(serde_json::to_value(outer).ok()?);
    } else {
        set_bind_interface(&mut val, bind_interface)?;
    }
    Some(TempNode {
        id: s.id.clone(),
        tag: tag.to_string(),
        node: val,
        companion_outbounds,
        is_endpoint: false,
        has_local_v6: false,
    })
}

fn set_bind_interface(node: &mut Value, bind_interface: Option<&str>) -> Option<()> {
    let object = node.as_object_mut()?;
    if let Some(interface) = bind_interface
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        object.insert("bind_interface".into(), Value::from(interface));
    } else {
        object.remove("bind_interface");
    }
    Some(())
}

/// 临时核里解析**节点 server 地址**用的 DNS server tag（223.5.5.5，本机直发）。
const DIRECT_DNS_TAG: &str = "dns-direct";

/// 生成临时核 sing-box 配置（纯逻辑，1:1 上游 `generateProxyTestConfig`，`:808-890`）。
///
/// 形状：每个可测节点一个 `http` 入站（`127.0.0.1:<port>`）→ `route.rules` 按 `inbound` 指到该节点 tag。
/// 端点类节点另进 `endpoints[]`，普通协议进 `outbounds[]`。
///
/// # 两类解析不变量（上游 issue #154 + 2026-07 端点修正，真机 debug 确证 —— 勿动）
///
/// - **代理出站**（vless/vmess/trojan/hy2/tuic/ss/…）：目标域名以 `ATYP=domain` **透传给出口远程解析**，
///   不经本机 `dns-direct`。各节点因此量到自身真实路径。⚠️ 勿引入 `sniff` / `outbound.domain_strategy` /
///   任何针对**目标**的本地解析 —— 会破坏此不变量，把所有节点测成同一条本机解析路径。
/// - **端点**（WG/WARP… L3）：内核**强制本地解析**目标域名。默认 `dns-direct` 从**本机**解析 ⇒ 拿到的是
///   本机地理的 IP，而端点出口可能在别处（境外 WARP / 国内自建 WG）⇒ 够不着 → 超时/失真。故按 `inbound`
///   键控一条 DNS 规则，把该端点的目标解析定向到**穿本隧道**的 223.5.5.5（AliDNS 有大陆 PoP + ECS，
///   按**出口地理**返 IP，境内外单形态覆盖）。`disable_cache` 必开：多端点并测时各自的答案不同，共享缓存
///   会互相污染。
///
/// `ports[i]` 与 `nodes[i]` **逐位 1:1**（调用方保证等长；短了则多出的节点不生成入站 —— 由
/// [`TempCoreSession::run`] 的等长断言挡在生成之前）。
#[must_use]
pub fn build_temp_core_config(nodes: &[TempNode], ports: &[u16], log_level: &str) -> Value {
    let mut inbounds = Vec::new();
    let mut outbounds = Vec::new();
    let mut endpoints = Vec::new();
    let mut route_rules = Vec::new();
    let mut dns_servers = vec![json!({
        "tag": DIRECT_DNS_TAG, "type": "udp", "server": "223.5.5.5", "server_port": 53,
    })];
    let mut dns_rules: Vec<Value> = Vec::new();

    for (node, port) in nodes.iter().zip(ports.iter()) {
        let inbound_tag = format!("in-{}", node.tag);
        inbounds.push(json!({
            "type": "http", "tag": inbound_tag, "listen": "127.0.0.1", "listen_port": port,
        }));
        route_rules.push(json!({
            "inbound": [inbound_tag], "action": "route", "outbound": node.tag,
        }));
        if node.is_endpoint {
            let exit_dns_tag = format!("dns-exit-{}", node.tag);
            dns_servers.push(json!({
                "tag": exit_dns_tag, "type": "udp", "server": "223.5.5.5", "server_port": 53,
                // 查询穿本端点隧道 → AliDNS 按出口地理（ECS）返 IP。
                // ⚠️ 端点级 `domain_resolver` 只管 peer 地址，**禁**指向隧道 DNS（peer 解析死锁 FATAL，实测）。
                "detour": node.tag,
            }));
            // 族别偏好（语义不变，写法迁移；1:1 上游 `0875f66`(#334)，`SpeedTestService.ts:850-881`）。
            //
            // **为什么不能留 legacy rule-action `strategy`**：sing-box 1.14.0 起 ① `run` 输出 deprecation
            // 警告、**1.16.0 移除**（`check` 静默放行 ⇒ 我们起核前那道 `sing-box check` 抓不到）；
            // ② 它与**同一份 dns 配置内**任何带 `query_type`/`ip_version` 的规则**互斥**，共存即
            // `initialize dns router` FATAL、`check` 与 `run` 双双硬拒。下方纯 v4 端点恰好明确下发
            // `query_type: ["AAAA"]`，故任何规则复活 `strategy` 都会让整批测速起核 FATAL。
            //
            //  · 旧 `prefer_ipv4`（localAddress 含 v6）→ **不下发任何东西**：本配置无顶层 `dns.strategy`
            //    （见下方 `dns` 组装），内核默认并发 A/AAAA 且把 v4 排在 v6 前（`sortAddresses` 对
            //    AsIS 与 prefer_ipv4 同一分支）。⚠️ 该等价性**依赖测速配置不带顶层 dns.strategy**，
            //    由 `temp_core_dns_never_sets_a_legacy_or_top_level_strategy` 锁死。
            //  · 旧 `ipv4_only`（纯 v4）→ 给该 inbound 的 AAAA 查询前置一条 `predefined` 空 NOERROR：
            //    AAAA 就地返空、不出网，结果集只剩 A。
            //
            // 顺序有牙：抑制规则必须排在本节点 route 规则**之前** —— DNS 规则先匹配先命中，route 规则是
            // 该 inbound 的 catch-all，排它后面则 AAAA 先被 route 吃掉、抑制静默失效（且配置照样过校验）。
            if !node.has_local_v6 {
                dns_rules.push(json!({
                    "inbound": [inbound_tag], "query_type": ["AAAA"],
                    // 空答复：等价旧 ipv4_only 的「不要 v6」，且不触发拒绝日志噪声。
                    "action": "predefined", "rcode": "NOERROR",
                }));
            }
            dns_rules.push(json!({
                "inbound": [inbound_tag], "action": "route", "server": exit_dns_tag,
                "disable_cache": true,
            }));
            endpoints.push(node.node.clone());
        } else {
            outbounds.push(node.node.clone());
            outbounds.extend(node.companion_outbounds.iter().cloned());
        }
    }

    // sing-box 启动要求至少一个 direct 出站（也是 DNS 直发腿的落点）。
    outbounds.push(json!({ "type": "direct", "tag": "direct" }));

    // ⚠️ **恒不下发顶层 `dns.strategy`**：端点族别偏好靠上面的 `query_type` 规则项表达，而「无顶层
    // strategy」正是「省略 == 旧 prefer_ipv4」这条等价性的前提（顶层若为 prefer_ipv6，端点解析会翻成
    // v6 优先）。要加顶层 strategy 必须同时重新推导端点规则，别只加一半。单测锁死本不变量。
    let mut dns = json!({ "servers": dns_servers });
    if !dns_rules.is_empty() {
        dns["rules"] = Value::Array(dns_rules);
    }
    let mut cfg = json!({
        "log": { "level": log_level, "timestamp": true },
        "dns": dns,
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {
            "rules": route_rules,
            "default_domain_resolver": DIRECT_DNS_TAG,
        },
    });
    if !endpoints.is_empty() {
        cfg["endpoints"] = Value::Array(endpoints);
    }
    cfg
}

/// **临时核让位判据**（纯逻辑；[`crate::commands::speedtest`] 的 `is_superseded` 的镜像腿）。
///
/// 三条腿的**析取**，缺一不可 —— 且后两条与主核路径**方向相反**，这不是笔误：
/// - `gen_now != gen0`：主核 start/stop/restart/regen 跃迁 ⇒ 主核来了，临时核必须让路；
/// - `running`：主核**已经跑起来了**。世代腿盖不住的窗口是「bump 发生在本次取 `gen0` **之前**」——
///   那一刻 `status.running` 还是 false（核在启动中），我们照常起了临时核；随后核就绪，`running` 翻真
///   而世代不再变化。只查世代 ⇒ 两个核并存跑同一批 WG/WARP peer（上游 G1 双会话事故的形态）。
/// - `starting`：**前两条腿都盖不住的那整段启动期**。`ProxyRuntime::start` 的顺序是
///   `start_inflight+1`（`starting` 的源）→ **stale 清扫（可达数秒）** → `bump_generation` → spawn →
///   就绪门。若本次测速的 `gen0` 恰好取在「bump 之后、核就绪之前」，世代腿与 `running` 腿**同时**为假，
///   而主核正在起：用户点「连接」后紧接点测速（或托盘/另一窗口点，UI 灰态拦不住跨窗）就是确定性命中。
///   后果有两层：① 临时核与启动中的主核并存 ⇒ 同 peer 双会话踢线；② 临时核端口只排除
///   control/http/mixed，会抢走主核刚解析、尚未 bind 的 api/update-in/probe 池口 ⇒ 主核起核
///   FATAL address-in-use（用户看到的是「连接失败」，归因极难）。
///
/// 主核池路径的第二条腿是 `!running`（守的是「核崩了」），本腿是 `running`/`starting`（守的是「核来了」）
/// —— 因为两条腿的**前提**相反：那边跑在核活着的前提上，这边跑在核不在的前提上。
#[must_use]
pub const fn is_temp_core_superseded(
    gen_now: u64,
    gen0: u64,
    running: bool,
    starting: bool,
) -> bool {
    gen_now != gen0 || running || starting
}

/// **临时核测量编排核**（测量 / 事件发射 / 让位三个 I/O 面**全部注入** ⇒ 无 `AppHandle`、无进程、
/// 不碰宿主网络、可单测）。
///
/// # 调度形态：**滑动窗口**（≤`concurrency` 在飞，回来一个补一个）
///
/// = 上游 `runWithLimit`（`SpeedTestService.ts:1331-1344`，调用点 `:530`）的固定 worker 池。
/// 此前是**批屏障**（切成 16 个一批、整批 join 完才发下一批），两者的 makespan 差 W = ⌈N/K⌉ 倍：
///
/// - worker 池的下界是 `max(单点最坏, 总功/并发)` —— 一个测不通的死节点只占住 1/K 的算力；
/// - 批屏障是 `Σ 每批最大值` —— 一个死节点把**整批 K 个**的耗时钉死在超时上限。
///
/// 而「每批至少一个死节点」的概率 = `1-(1-f)^K`，f=0.2、K=16 时是 **0.97** —— 即中等失效率的订阅
/// 几乎每一批都被超时值封顶。N=50/K=16/f=0.2 的模型：批屏障 4 批 × 8s = 32s，滑动窗口
/// `max(8, 40×0.5+10×8 /16) = 8s`。
///
/// # 让位（**这段是本函数的事故面，改前先读完**）
///
/// 主核和临时核**绝不能同时跑**：同一个 WG/WARP peer 被两个会话同时握手会互相踢线，且临时核端口
/// 只排除 control/http/mixed，会抢走主核尚未 bind 的口 ⇒ 主核起核 FATAL。所以「主核来了就立刻停」
/// 不是优化，是**正确性**。三个检查点覆盖全程，缺一即静默重叠：
///
/// 1. **发新活之前**（每轮补位一次）：主核已起 → 停发新活 + `abort_all` 已在飞的，未测节点缺席。
///    这条替代了旧的「批首」检查，粒度**更细**：旧的是每 K 个节点一次，现在是每次补位一次。
/// 2. **在飞轮询**（每 [`TEMP_CORE_SUPERSEDE_POLL_MS`] 一次）：命中即 `abort_all` + 立刻返回。
///    **这条是唯一不依赖任何测量返回的腿** —— 窗口里 16 个全挂死（真机上就是 16 个不可达节点）时，
///    上面两条都醒不过来，只有它按间隔醒。批屏障时代它挂在「批内」，现在挂在整轮，覆盖面只增不减：
///    以前批与批之间那一小段没有轮询（靠批首查兜），现在全程都在轮询窗口里。
///    实现仍用 `timeout(poll, join_next())` 而非 `select!`：`join_next()` 已借走 `set`，`select!` 的
///    另一臂里再调 `set.abort_all()` 会撞借用检查；`join_next` 是 cancel-safe（tokio 文档明载），
///    超时丢弃不丢结果。
/// 3. **每节点测完**：该节点的测量在飞期间主核起来 ⇒ 这个值量的是**与主核抢同一条 peer 会话**的
///    临时核出站，丢弃（并中止其余在飞）。
///
/// 收尾（杀核）由调用方 [`TempCoreSession`] 的**无条件**路径负责，不在本函数。
///
/// **未测节点一律缺席，绝不写假 `-1`** —— 「让位未测」与「真实超时」不可混淆，同主核路径的诚实性根基。
/// 返回 `(结果 map, outcome)`；任一检查点命中即 `interrupted`。
///
/// # 回填粒度：**逐节点**（对齐 上游 `SpeedTestService.ts:564`）
///
/// 每个节点测完那一刻就落账 + 推事件。统一回填的话首个延迟数字要等最慢的那个，屏幕先空十几秒。
/// 代价：让位③是「逐节点级」—— 已回填的不可撤回，丢弃的只是尚未回来的在飞值。这正是 上游的语义
/// （`:541-545` 的超代再检也在 worker 体内、`report()` 之前）。
///
/// # 为什么主核池路径**不**跟着改
///
/// 那边的槽 ↔ 端口是 1:1 硬绑定，跨波复用同槽必须先测完再重指，波屏障是**正确性要求**而非性能选择
/// （上游 同样是波屏障，`SpeedTestService.ts:709-776`）。本腿没有这个约束：每个节点有**自己**的
/// 入站端口，全程不复用。
/// # 终态事件的唯一出口就在本函数
///
/// 内核 [`drive_temp_core_measures_inner`] 有 4 个 `return`（让位三检查点 + 正常收尾），本薄壳把它们
/// 收成一个出口再发 [`EVENT_SPEED_TEST_DONE`] ⇒ 「中断了却没发终态」在结构上写不出来。
/// 载荷含未测集合（续测输入），判据见 [`emit_speed_test_done`]。
pub async fn drive_temp_core_measures<Meas, MeasFut>(
    nodes: &[TempNode],
    ports: &[u16],
    concurrency: usize,
    superseded: &(dyn Fn() -> bool + Sync),
    measure: Meas,
    emit: &mut (dyn FnMut(&str, Value) + Send),
) -> (serde_json::Map<String, Value>, &'static str)
where
    Meas: Fn(u16) -> MeasFut,
    MeasFut: Future<Output = Option<u32>> + Send + 'static,
{
    // 本腿「已裁定要测」的集合 = 前 `total` 个节点（`nodes`/`ports` 逐位 1:1，多出的一侧不测）。
    let intended: Vec<String> = nodes
        .iter()
        .take(nodes.len().min(ports.len()))
        .map(|n| n.id.clone())
        .collect();
    let (results, outcome) =
        drive_temp_core_measures_inner(nodes, ports, concurrency, superseded, measure, emit).await;
    emit_speed_test_done(emit, outcome, &results, &intended);
    (results, outcome)
}

async fn drive_temp_core_measures_inner<Meas, MeasFut>(
    nodes: &[TempNode],
    ports: &[u16],
    concurrency: usize,
    superseded: &(dyn Fn() -> bool + Sync),
    measure: Meas,
    emit: &mut (dyn FnMut(&str, Value) + Send),
) -> (serde_json::Map<String, Value>, &'static str)
where
    Meas: Fn(u16) -> MeasFut,
    MeasFut: Future<Output = Option<u32>> + Send + 'static,
{
    let mut results = serde_json::Map::new();
    let total = nodes.len().min(ports.len());
    let mut tested = 0usize;
    let mut ok = 0usize;

    // `concurrency == 0` → 视作 1：绝不退化成「一个都不测」（那会零事件 ⇒ 前端测速按钮永久卡灰）。
    // 0 并发是配置错误，不是「不测」的意思。
    let window = concurrency.max(1);
    let mut set = tokio::task::JoinSet::new();
    let mut next = 0usize; // 下一个待发的节点下标（ports/nodes 逐位 1:1，全程不复用）

    while !set.is_empty() || next < total {
        if next < total {
            // ── 让位①（发新活之前）：主核已起/已跃迁 → 停发新活 + 中止在飞，未测节点缺席 ──
            if superseded() {
                set.abort_all();
                return (results, "interrupted");
            }
            // 补位：起手补满窗口，此后回来一个补一个。
            while next < total && set.len() < window {
                let node_id = nodes[next].id.clone();
                let fut = measure(ports[next]);
                set.spawn(async move { (node_id, fut.await) });
                next += 1;
            }
        }

        let poll = Duration::from_millis(TEMP_CORE_SUPERSEDE_POLL_MS);
        match tokio::time::timeout(poll, set.join_next()).await {
            // 窗口已空且无待发（上面刚补过位）⇒ 全部收尾。
            Ok(None) => break,
            Ok(Some(Ok((id, latency)))) => {
                // ── 让位③（每节点测完即查）──
                if superseded() {
                    set.abort_all();
                    return (results, "interrupted");
                }
                record_measured(
                    &mut results,
                    &mut tested,
                    &mut ok,
                    emit,
                    &id,
                    latency,
                    total,
                );
            }
            // JoinError（panic / 本函数自己 abort 掉的）→ 该节点无数值，缺席，绝不补 -1。
            Ok(Some(Err(_))) => {}
            // ── 让位②（在飞轮询）：**不依赖任何测量返回**，窗口全挂死时也照样醒 ──
            Err(_elapsed) => {
                if superseded() {
                    set.abort_all();
                    return (results, "interrupted");
                }
            }
        }
    }

    (results, "completed")
}

/// 单个节点的落账 + 推事件（`result` 与 `progress` 成对，计数在此处自增 ⇒ 恒单调）。
///
/// 与主核池路径 [`crate::commands::speedtest`] 的同名函数逐字同义 —— 两条腿的事件形状必须一致，
/// 前端 `use-latency-store` / `NodesScreen` 只有一套消费逻辑。
///
/// `latency == None` ⇒ 记 -1（**真实**不可测：超时 / 传输错）。「让位未测」的节点根本不会走到这里。
fn record_measured(
    results: &mut serde_json::Map<String, Value>,
    tested: &mut usize,
    ok: &mut usize,
    emit: &mut (dyn FnMut(&str, Value) + Send),
    node_id: &str,
    latency: Option<u32>,
    total: usize,
) {
    let latency_val = latency.map_or(-1_i64, i64::from);
    if latency.is_none() {
        log::debug!(
            "临时核测速未取得有效延迟：nodeId={node_id}（可能为冷建链/复用请求超时、传输错误或测速端点非 2xx）"
        );
    }
    results.insert(node_id.to_string(), json!(latency_val));
    emit(
        EVENT_SPEED_TEST_RESULT,
        json!({ "serverId": node_id, "latency": latency_val }),
    );
    *tested += 1;
    if latency.is_some() {
        *ok += 1;
    }
    emit(
        EVENT_SPEED_TEST_PROGRESS,
        json!({ "tested": *tested, "ok": *ok, "total": total }),
    );
}

/// 一轮测速的结果口径三分（供 [`log_speed_test_summary`]；纯函数，可单测）。
///
/// **`-1` 与「缺席」是两件不同的事，混起来就没法排查**：
/// - `ok`：真测出了值（毫秒 ≥ 0）；
/// - `failed`：真测了但没通（`-1` —— 超时 / 传输错 / 非 2xx，见 `measure_via_local_proxy`）；
/// - `absent`：**根本没测**（波前让位 / 中断 / 起测即知不可测）——绝不写假 `-1`，故不在 `results` 里。
///
/// 非数值 / 越界的值一律计入 `failed`（宁可报多也不静默丢：这一层不该有非数值，出现即是缺陷信号）。
#[derive(Debug, PartialEq, Eq)]
pub struct SpeedTestSummary {
    pub ok: usize,
    pub failed: usize,
    pub absent: usize,
}

#[must_use]
pub fn summarize_speed_test(
    results: &serde_json::Map<String, Value>,
    intended: &[String],
    absent: usize,
) -> SpeedTestSummary {
    let ok = results
        .values()
        .filter(|v| v.as_i64().is_some_and(|ms| ms >= 0))
        .count();
    SpeedTestSummary {
        ok,
        failed: results.len() - ok,
        absent,
    }
    .also_assert_total(intended.len())
}

impl SpeedTestSummary {
    /// 三类之和必须等于请求数 —— 不等即口径漏了一类（debug 构型下当场炸，release 只记警告）。
    fn also_assert_total(self, total: usize) -> Self {
        let sum = self.ok + self.failed + self.absent;
        debug_assert_eq!(sum, total, "测速结果三分之和必须等于请求数");
        if sum != total {
            log::warn!("测速结果口径不自洽：ok+failed+absent={sum} ≠ 请求 {total}（{self:?}）");
        }
        self
    }
}

/// 一轮测速的**结果级**日志（唯一出口，三条腿共用 —— 挂在 [`emit_speed_test_done`] 里）。
///
/// # 这条补的是什么洞
///
/// 本链此前**零结果级日志**：机器上只有「测速临时核已 spawn：126 个节点」和「已回收：
/// outcome=completed」两行，中间什么都没有。陈先生 2026-08-02 报「全部测速全部显示 -1，跟实际不符」
/// 时，磁盘上拿不出任何东西能分辨三种完全不同的成因 ——
/// ① 网络真的全失败；② 本轮被让位/中断（节点根本没测，前端把**缺席**画成了 `-1`）；
/// ③ 少数失败但 UI 全渲染成 `-1`。`latency` 又不落 `config.json`（纯渲染端 map），
/// 事后无从复盘。汇总一行即可把三者分开。
///
/// 失败样本只带前 5 个 id：全量在 126 节点时是一行几 KB 的日志，而排查只需要「是不是集中在某一类」。
fn log_speed_test_summary(
    outcome: &str,
    results: &serde_json::Map<String, Value>,
    intended: &[String],
    pending: &[&String],
) {
    let s = summarize_speed_test(results, intended, pending.len());
    let samples: Vec<&str> = results
        .iter()
        .filter(|(_, v)| !v.as_i64().is_some_and(|ms| ms >= 0))
        .map(|(k, _)| k.as_str())
        .take(5)
        .collect();
    let tail = if samples.is_empty() {
        String::new()
    } else {
        format!("；失败样本 {}", samples.join(", "))
    };
    log::info!(
        "测速一轮完成：outcome={outcome}，请求 {}，成功 {}，超时/失败 {}，未测（让位或中断）{}{tail}",
        intended.len(),
        s.ok,
        s.failed,
        s.absent
    );
}

/// 一轮测速的**终态事件**（[`EVENT_SPEED_TEST_DONE`]）——三条腿各自在**唯一出口**调一次。
///
/// # 为什么放在这里、并且只有一个调用点/腿
///
/// 三条腿（主核池 [`crate::commands::speedtest`]、回退腿、临时核腿）各有 2~4 个 `return`
/// （让位检查点 + 正常收尾）。逐个 `return` 前手动 emit 必然漏 —— 漏掉的那条正是「中断」路径，
/// 而中断恰恰是本事件唯一不可替代的用途。故三条腿一律改成「内核函数照旧多点 return + 薄壳在
/// 唯一出口调本函数」，漏发在结构上写不出来。
///
/// `intended` = 本腿**已裁定要测**的节点 id（波前预筛之后的可测集）。据此派生三个字段：
///  - `total` = `intended.len()`（与该腿进度事件里的 `total` 同一口径，两者失配会让前端的
///    `tested/total` 与终态对不上）；
///  - `tested` = `results.len()`（已出值的，含真实 `-1`）；
///  - `serverIds` = `intended`（本轮原始可测范围，= 中断后「重新测速」的输入）；
///  - `pending` = `intended − results`（**没拿到值**的，= 中断后「继续剩余」的输入）。
///
/// 判据与「差集为什么必须由后端算 / 波前缺席的三类为什么不算 pending」见
/// [`EVENT_SPEED_TEST_DONE`] 的常量文档。
pub fn emit_speed_test_done(
    emit: &mut (dyn FnMut(&str, Value) + Send),
    outcome: &str,
    results: &serde_json::Map<String, Value>,
    intended: &[String],
) {
    // 「缺席即未测」——复用既有诚实性根基（让位未测的节点根本不进 `results`，绝不写假 -1）。
    let pending: Vec<&String> = intended
        .iter()
        .filter(|id| !results.contains_key(id.as_str()))
        .collect();
    log_speed_test_summary(outcome, results, intended, &pending);
    emit(
        EVENT_SPEED_TEST_DONE,
        json!({
            "outcome": outcome,
            "tested": results.len(),
            "total": intended.len(),
            "serverIds": intended,
            "pending": pending,
        }),
    );
}

// ══════════════════════════════════════════════════════════════════════════════
//  生产接线：起临时核 → 就绪门 → 编排 → 无条件收尾。全部 I/O 经注入点，测试用 mock 驱动。
// ══════════════════════════════════════════════════════════════════════════════

/// 临时核会话的注入依赖（生产 [`TempCoreDeps::production`]，测试注入 mock spawner / 假核路径）。
pub struct TempCoreDeps {
    /// 瞬态 sing-box spawn（复用 `tailscale_login_core` 的瞬态核进程抽象）。
    pub spawner: Arc<dyn LoginCoreSpawner>,
    /// spawn 前的 `sing-box check`（fail-fast，复用瞬态登录核那条已建好的抽象）。
    ///
    /// **不是洁癖**：临时核配置里唯一不由本仓完全掌控的部分是 `custom` 协议的**用户原样 JSON**。它形态
    /// 非法时核会预初始化 FATAL、立即退出，而没有这道 check 的话，用户看到的是就绪门那句「10s 内未监听」
    /// —— 把「你那个自定义节点的 JSON 写错了」误报成「网络/端口有问题」，且白等 10 秒。
    pub checker: Arc<dyn ConfigChecker>,
    /// 核二进制解析（生产 = `resolve_core_binary`，与主核**同一份**解析逻辑，禁重复实现）。
    pub resolve_binary: Arc<dyn Fn() -> Result<PathBuf, String> + Send + Sync>,
    /// 临时配置落盘目录（= 主核 config 目录；文件名另用 [`TEMP_CORE_CONFIG_NAME`]，绝不同名）。
    pub config_dir: PathBuf,
    /// 端口分配（生产 = `PortAllocator` + `TokioPortProvider`；测试注入确定性序列）。
    pub allocate_ports: Arc<dyn Fn(usize) -> Vec<u16> + Send + Sync>,
    /// 就绪探测：能连上 `127.0.0.1:<port>` ⇒ 临时核已开始 listen。
    pub probe_port: Arc<dyn Fn(u16) -> bool + Send + Sync>,
    /// 核日志级别（跟随用户配置；诊断态调高时临时核一并抬级，便于复现）。
    pub log_level: String,
    /// 就绪等待上限（生产 [`TEMP_CORE_READY_TIMEOUT_MS`]；测试调小以免 gate 空等一个真实超时）。
    pub ready_timeout_ms: u64,
}

impl TempCoreDeps {
    /// 生产装配：真 spawn + 真核解析 + 真端口分配 + 真 TCP 就绪探测。
    ///
    /// `exclusions` = 用户配置的 control/http/mixed 口 —— **必须排除**，否则临时核占了主核随后要 bind
    /// 的口，用户测完速再点连接就起不来（表现为「测速把代理搞坏了」，归因极难）。
    #[must_use]
    pub fn production(config_dir: PathBuf, exclusions: PortExclusions, log_level: String) -> Self {
        Self {
            spawner: Arc::new(TokioLoginCoreSpawner),
            checker: Arc::new(SingBoxConfigChecker),
            resolve_binary: Arc::new(crate::runtime::proxy::resolve_core_binary),
            config_dir,
            allocate_ports: Arc::new(move |n| {
                PortAllocator::new(TokioPortProvider).resolve_distinct_free_ports(&exclusions, n)
            }),
            probe_port: Arc::new(|port| {
                std::net::TcpStream::connect_timeout(
                    &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
                    Duration::from_millis(300),
                )
                .is_ok()
            }),
            log_level,
            ready_timeout_ms: TEMP_CORE_READY_TIMEOUT_MS,
        }
    }
}

/// 一次临时核测速的结局（命令层折成响应信封）。
#[derive(Debug)]
pub enum TempCoreOutcome {
    /// 跑完了（可能部分节点 `-1` = 真实不可测）。`outcome` 同主核路径语义。
    Ran {
        results: serde_json::Map<String, Value>,
        outcome: &'static str,
    },
    /// 起核前/就绪前失败（解析不到核 / 端口分配失败 / 写配置失败 / spawn 失败 / 未就绪）。
    /// **整批一个数值都不产出**（绝不把「核没起来」写成一批 `-1`）。
    Failed(String),
    /// 起核前就已被主核接管 → 一个节点都没测，未测节点缺席。
    Superseded,
}

/// 一次临时核测速会话：起核 → 就绪门 → 编排 → **无条件**收尾（杀核 + 删配置）。
pub struct TempCoreSession;

impl TempCoreSession {
    /// 跑一次临时核测速。
    ///
    /// - `nodes`：[`plan_temp_core_with_bindings`] 裁出的可测节点（保序）；空 → 调用方不该进来（此处防御性返 `Ran` 空）。
    /// - `superseded`：让位判据（生产 = [`is_temp_core_superseded`] 闭包，见模块文档）。
    /// - `measure`：按端口量 warm-TTFB（命令层注入，复用与主核路径**同一个**测量口径 ⇒ 两条腿的数值可比）。
    /// - `emit`：逐节点事件（命令层注入 `AppHandle::emit`）。
    ///
    /// # 收尾纪律
    ///
    /// 杀核 + 删配置走**无条件**路径（正常完成 / 让位 / 就绪失败 / 编排 panic 之外的一切分支共用）——
    /// 漏一条腿的表现是**孤儿 sing-box 常驻**，占着 N 个回环端口且用户完全看不见。
    pub async fn run<Meas, MeasFut>(
        deps: &TempCoreDeps,
        nodes: &[TempNode],
        superseded: &(dyn Fn() -> bool + Sync),
        measure: Meas,
        emit: &mut (dyn FnMut(&str, Value) + Send),
    ) -> TempCoreOutcome
    where
        Meas: Fn(u16) -> MeasFut,
        MeasFut: Future<Output = Option<u32>> + Send + 'static,
    {
        if nodes.is_empty() {
            return TempCoreOutcome::Ran {
                results: serde_json::Map::new(),
                outcome: "completed",
            };
        }
        // ── 让位（起核前）：主核已在跑/已跃迁 → 根本不起临时核（双会话从源头掐掉）──
        if superseded() {
            return TempCoreOutcome::Superseded;
        }

        let binary = match (deps.resolve_binary)() {
            Ok(b) => b,
            Err(e) => return TempCoreOutcome::Failed(e),
        };

        // 端口：整批原子（任一槽拿不到互异空闲口 → 空 vec）。部分池不可用 —— 槽↔端口 1:1 一旦错位，
        // 量到的就是**别的节点**的延迟，比测不了更糟。
        let ports = (deps.allocate_ports)(nodes.len());
        if ports.len() != nodes.len() {
            return TempCoreOutcome::Failed(format!(
                "测速临时核端口分配失败（需 {} 个互异空闲口，实得 {}）",
                nodes.len(),
                ports.len()
            ));
        }

        let config_path = deps.config_dir.join(TEMP_CORE_CONFIG_NAME);
        let cfg = build_temp_core_config(nodes, &ports, &deps.log_level);
        let bytes = match serde_json::to_vec_pretty(&cfg) {
            Ok(b) => b,
            Err(e) => return TempCoreOutcome::Failed(format!("序列化测速临时核配置失败: {e}")),
        };
        if let Err(e) = std::fs::write(&config_path, bytes) {
            return TempCoreOutcome::Failed(format!(
                "写测速临时核配置失败 {}: {e}",
                config_path.display()
            ));
        }

        // `sing-box check` 先验配置形态（fail-fast，同瞬态登录核的既定手法）。没有这道门时，`custom`
        // 协议里用户写错的原样 JSON 会让核预初始化 FATAL ⇒ 用户白等 10s 再看到「未监听」这个指错方向的
        // 报错。check 的诊断原文冒泡给用户 —— 那句话里直接写着哪个字段错了。
        if let Err(e) = deps.checker.check(&binary, &config_path).await {
            remove_temp_config(&config_path);
            return TempCoreOutcome::Failed(e);
        }

        let mut req = SpawnRequest::new(&binary, &config_path);
        // 核输出进日志 sink（非 TTY）；不加 flag 会混入 ANSI 转义。CWD 设可写 config 目录，
        // 理由同主核 spawner（GUI 从 launchd 拉起时父进程 CWD=`/` 只读）。
        req.extra_args = vec!["--disable-color".to_string()];
        req.working_dir = Some(deps.config_dir.clone());
        let child = match deps.spawner.spawn(&req) {
            Ok(c) => c,
            Err(e) => {
                remove_temp_config(&config_path);
                return TempCoreOutcome::Failed(format!("测速临时核 spawn 失败: {e}"));
            }
        };

        // 起核之后的一切分支都必须经收尾（杀核 + 删配置），故从此处起收束到一个 helper。
        let outcome =
            Self::drive_after_spawn(deps, nodes, &ports, superseded, measure, emit, child).await;
        remove_temp_config(&config_path);
        outcome
    }

    /// spawn 之后的编排（就绪门 → 测量 → **无条件杀核**）。抽出以保证「起了核就一定会被杀」这条纪律
    /// 只有一个出口：本函数的每一条 `return` 之前都已 `terminate()`。
    #[allow(clippy::too_many_arguments)]
    async fn drive_after_spawn<Meas, MeasFut>(
        deps: &TempCoreDeps,
        nodes: &[TempNode],
        ports: &[u16],
        superseded: &(dyn Fn() -> bool + Sync),
        measure: Meas,
        emit: &mut (dyn FnMut(&str, Value) + Send),
        mut child: Box<dyn LoginCoreChild>,
    ) -> TempCoreOutcome
    where
        Meas: Fn(u16) -> MeasFut,
        MeasFut: Future<Output = Option<u32>> + Send + 'static,
    {
        let pid = child.pid().unwrap_or(0);
        // 登记进在飞表：应用退出时 `run_exit_cleanup` 据此强杀（本 future 届时不会被 drop，Drop 守卫
        // 覆盖不到那条路径）。守卫在本函数返回/展开时自动注销。
        let _pid_guard = TempCorePidGuard::register(pid);
        log::info!(
            "测速临时核已 spawn：pid={pid}，{} 个节点 / 端口 {:?}",
            nodes.len(),
            ports
        );

        // ── 就绪门（复用 core-supervisor `wait_for_core_ready`；本层只注入真实 I/O）──
        // 就绪信号 = 第一个 HTTP 入站端口可连（对齐 上游 `waitForPortReady(ports[0], 10000)`）。
        let probe = Arc::clone(&deps.probe_port);
        let first_port = ports[0];
        let ready_deps = CoreReadyDeps {
            is_alive: Box::new(move || pid == 0 || pid_alive(pid)),
            is_ready: Box::new(move || {
                let probe = Arc::clone(&probe);
                Box::pin(async move {
                    tokio::task::spawn_blocking(move || probe(first_port))
                        .await
                        .unwrap_or(false)
                })
            }),
            sleep: Box::new(|d| Box::pin(tokio::time::sleep(d))),
            // 就绪等待期同样守让位：临时核起到一半用户点了「连接」⇒ 立刻停等 + 杀核，
            // 而不是先傻等满 10s 再发现要让路（那 10s 里两个核并存）。
            is_superseded: Some(Box::new(superseded)),
            on_retry: None,
        };
        let ready = wait_for_core_ready(
            WaitForCoreReadyOptions {
                timeout_ms: deps.ready_timeout_ms,
                poll_ms: TEMP_CORE_READY_POLL_MS,
            },
            &ready_deps,
        )
        .await;
        match ready {
            CoreReadyOutcome::Ready => {}
            CoreReadyOutcome::Superseded => {
                child.terminate().await;
                return TempCoreOutcome::Superseded;
            }
            other => {
                child.terminate().await;
                // 整批一个数值都不产出：核没起来 ≠ 每个节点都超时。写一批 -1 就是伪造 N 次真实测量。
                return TempCoreOutcome::Failed(format!(
                    "测速临时核未就绪（{other:?}，{}ms 内 127.0.0.1:{first_port} 未监听）",
                    deps.ready_timeout_ms
                ));
            }
        }

        let (results, outcome) = drive_temp_core_measures(
            nodes,
            ports,
            TEMP_CORE_CONCURRENCY,
            superseded,
            measure,
            emit,
        )
        .await;
        child.terminate().await;
        log::info!("测速临时核已回收：pid={pid}，outcome={outcome}");
        TempCoreOutcome::Ran { results, outcome }
    }
}

/// 删临时配置（失败只记日志：删不掉不影响正确性，下次同名覆盖）。
fn remove_temp_config(path: &std::path::Path) {
    if let Err(e) = std::fs::remove_file(path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            log::warn!("删测速临时核配置失败 {}: {e}", path.display());
        }
    }
}

#[cfg(test)]
mod tests;
