//! sing-box 核就绪门控 —— 上游 `core-readiness.ts` 的 1:1 Rust 移植。
//!
//! 移植锚点（行为不变式见 capability-registry-special-logic.md §1 #2 / #10）：
//! - [`CoreReadyOutcome`] = `'ready' | 'dead' | 'timeout' | 'superseded'`（core-readiness.ts:63）。
//! - [`wait_for_core_ready`] = `waitForCoreReady`（core-readiness.ts:81-100）：每轮 supersede → ready → alive 顺序判定。
//! - [`CoreStartRetryError`] / [`CoreStartSupersededError`] = core-readiness.ts:18 / :32 的标记错误类型。
//!
//! 关键不变式（issue #176 / #159）：
//! 1. supersede 先于一切判定（被更新的 start/stop 接管后继续等就绪有害——抢适配器/撞端口）。
//! 2. isReady（异步）先于 isAlive（同步探活）：成功路径（API 早绑）即返回，绝不触发阻塞探活。
//!    顺序安全：API 监听随核进程而生灭，端口可连 ⟹ 核存活。
//! 3. 满轮后末轮再判一次（boundary check），不漏判就绪/退出。
//!
//! 纯逻辑：所有 I/O（is_ready/is_alive/sleep/is_superseded）由调用方注入，便于无进程/端口/计时器单测。

use std::future::Future;

/// 核就绪轮询结局（core-readiness.ts:63 `CoreReadyOutcome`）。
///
/// - `Ready`：管理 API 端口可连（核已就绪）。
/// - `Dead`：进程已退出（起核期死，立即判定，不等满 timeout）。
/// - `Timeout`：进程在但管理 API 未在预期内绑定。
/// - `Superseded`：就绪等待期内被更新的 start/stop 接管（issue #176），应静默让位（不重试、不清理）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreReadyOutcome {
    Ready,
    Dead,
    Timeout,
    Superseded,
}

/// 「核已起但起核期未就绪/退出，应交 retry 静默重起」的标记错误（core-readiness.ts:18）。
///
/// 文案不含不可重试关键词（找不到/权限/permission/enoent/...）→ 调用方 should_retry 判可重试。
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct CoreStartRetryError {
    pub message: String,
}

impl CoreStartRetryError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// issue #176：本次起核在就绪等待期内被「更新的 start/stop」接管（lifecycle_generation 变化）的让位标记错误
/// （core-readiness.ts:32）。
///
/// 关键区别于 [`CoreStartRetryError`]：**不重试、不清理**——接管方拥有进程/系统代理/适配器状态，本腿必须静默退场，
/// 绝不调 stop/cleanup（会清掉接管方的 refs）。start() 包装层捕获本类型后直接 return（不 rethrow）。
#[derive(Debug, thiserror::Error)]
#[error("sing-box 起核已被更新的启动/停止操作接管，本腿让位")]
pub struct CoreStartSupersededError;

/// wait_for_core_ready 注入依赖（core-readiness.ts:66 `CoreReadyDeps`，单测可替换为桩）。
///
/// 所有闭包以 `&self` 借用调用，故用 trait object 风格的结构体持有闭包。生产路径注入真实 TCP 探测 + 进程探活；
/// 测试路径注入桩函数 + 计数器。
pub struct CoreReadyDeps<'a> {
    /// 核进程是否存活（isAlive）。
    pub is_alive: Box<dyn Fn() -> bool + Send + Sync + 'a>,
    /// 管理 API 是否可连（就绪信号，isReady）——异步 TCP 探测。
    pub is_ready: Box<dyn Fn() -> PinReadyFuture<'a> + Send + Sync + 'a>,
    /// sleep（轮询间隔）。
    pub sleep: Box<dyn Fn(Duration) -> PinSleepFuture<'a> + Send + Sync + 'a>,
    /// 本次起核是否已被更新的 start/stop 接管（issue #176，可选；缺省视作未接管）。
    pub is_superseded: Option<Box<dyn Fn() -> bool + Send + Sync + 'a>>,
    /// 每次「未就绪 + 进程仍活 → 即将 sleep 重试」时回调一次（上游 `onRetry`，core-readiness.ts:906）。
    /// 供上层累计「本次 start 的就绪重试次数」（DiagnosticCounters 慢起轴 `lastStartReadyRetries`）。
    /// 可选；缺省不计。**纯观测回调**：绝不参与轮询判定/顺序——本状态机逻辑与既有测试完全不变。
    pub on_retry: Option<Box<dyn Fn() + Send + Sync + 'a>>,
}

type PinReadyFuture<'a> = Pin<Box<dyn Future<Output = bool> + Send + 'a>>;
type PinSleepFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

use std::pin::Pin;
use std::time::Duration;

impl<'a> CoreReadyDeps<'a> {
    /// 构造一个最小的依赖集（is_superseded = None）。
    pub fn new(
        is_alive: impl Fn() -> bool + Send + Sync + 'a,
        is_ready: impl Fn() -> PinReadyFuture<'a> + Send + Sync + 'a,
        sleep: impl Fn(Duration) -> PinSleepFuture<'a> + Send + Sync + 'a,
    ) -> Self {
        Self {
            is_alive: Box::new(is_alive),
            is_ready: Box::new(is_ready),
            sleep: Box::new(sleep),
            is_superseded: None,
            on_retry: None,
        }
    }
}

/// wait_for_core_ready 配置（core-readiness.ts:82 `{ timeoutMs, pollMs }`）。
#[derive(Debug, Clone, Copy)]
pub struct WaitForCoreReadyOptions {
    /// 总超时（ms）。
    pub timeout_ms: u64,
    /// 轮询间隔（ms）。
    pub poll_ms: u64,
}

/// 本次起核是否已被更新的 start/stop 接管（`is_superseded` 缺省视作未接管）。
fn is_superseded(deps: &CoreReadyDeps<'_>) -> bool {
    deps.is_superseded.as_ref().map(|f| f()).unwrap_or(false)
}

/// 失败结局收口：报 `fallback`（Dead/Timeout）**之前**再判一次 supersede。
///
/// # 为什么不能直接返回 fallback（与 TS 的**刻意分歧**，非移植疏漏）
///
/// 不变式 #1 说「supersede 先于一切判定」，但轮首那一次检查只在**轮首**成立：`is_ready` 是 async，
/// 一次 await 就是一段可被抢占的窗口。真实竞态（用户在起核途中点「停止」）：
/// 轮首判 supersede=false → await is_ready 期间 stop 跑完（bump 世代 + 取走 child）→ 本轮 is_ready
/// 失败、is_alive 见 child=None → 返 `Dead` → 调用方 `set_error(STARTUP_FAILED)` → 用户主动停核却
/// 收到「启动失败」错误弹窗。
///
/// 即：进程「死」的**死因恰恰是接管本身**，此时结局是让位（Superseded：不重试、不清理），不是失败。
/// 故把两条失败腿的返回收口到此处统一复判——判定顺序不变（supersede 仍先于 ready/alive），只是补上
/// 「判定期间世界变了」这一路。TS 原版（core-readiness.ts:93/:99）无此复判，是同一个误报面。
fn settle_failure(deps: &CoreReadyDeps<'_>, fallback: CoreReadyOutcome) -> CoreReadyOutcome {
    if is_superseded(deps) {
        CoreReadyOutcome::Superseded
    } else {
        fallback
    }
}

/// 轮询等核就绪（core-readiness.ts:81 `waitForCoreReady`）。
///
/// 每轮：被接管 → `Superseded`（立即让位，#176）；API 可连 → `Ready`；进程死 → `Dead`（立即，不等满 timeout）；
/// 否则 sleep。满 max_polls 仍未就绪 → 末轮再判一次 → `Timeout`。
///
/// 两条失败腿（Dead/Timeout）返回前经 `settle_failure` 复判 supersede —— 见该函数文档。
///
/// `max_polls = max(1, ceil(timeout_ms / poll_ms))`，与 TS 实现逐字一致（`Math.max(1, Math.ceil(...))`）。
pub async fn wait_for_core_ready(
    opts: WaitForCoreReadyOptions,
    deps: &CoreReadyDeps<'_>,
) -> CoreReadyOutcome {
    let poll_ms = opts.poll_ms.max(1);
    let max_polls = (opts.timeout_ms.div_ceil(poll_ms)).max(1);

    for _ in 0..max_polls {
        // supersede 先于一切判定（#176）。
        if is_superseded(deps) {
            return CoreReadyOutcome::Superseded;
        }
        // isReady（异步）先于 isAlive（同步探活）：成功路径即返回。
        if (deps.is_ready)().await {
            return CoreReadyOutcome::Ready;
        }
        if !(deps.is_alive)() {
            return settle_failure(deps, CoreReadyOutcome::Dead);
        }
        // 未就绪 + 进程仍活 → 即将 sleep 后重试：计一次就绪重试（上游 onRetry，:906）。
        // 纯观测，位于判定之后、sleep 之前，绝不改变任何 return 分支。
        if let Some(cb) = deps.on_retry.as_ref() {
            cb();
        }
        (deps.sleep)(Duration::from_millis(poll_ms)).await;
    }

    // 末轮 boundary check（core-readiness.ts:96-99）。
    if is_superseded(deps) {
        return CoreReadyOutcome::Superseded;
    }
    if (deps.is_ready)().await {
        return CoreReadyOutcome::Ready;
    }
    if !(deps.is_alive)() {
        return settle_failure(deps, CoreReadyOutcome::Dead);
    }
    settle_failure(deps, CoreReadyOutcome::Timeout)
}

#[cfg(test)]
mod tests;
