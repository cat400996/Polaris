//! 全部经 mock spawner/checker/emitter/STATUS 订阅器驱动——**无真进程、无网络、无真 sing-box、
//! 无真 gRPC**（唯一的真系统调用是端口簿记的 `bind(127.0.0.1:0)`，回环、立即释放）。
//!
//! 覆盖：relogin 杀旧核 / cancel 杀+注销 / 超时杀 / 自然退出 reap / STATUS→URL 事件（含去重与换 URL）/
//! **stdout 不再是 URL 来源** / Running→收核 / 幽灵 tag 丢弃 / 流终止→收核 / 订阅失败不留孤儿核 /
//! api 端口与 secret 的解析 / check-fail 不 spawn / spawn-fail 不留表项 / 双写守卫拦截。
//! 真 spawn+控制面路径**不在此覆盖**（真机门槛，见模块头）。

use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, watch};

use polaris_config_engine::user_config::server_config::Protocol;

// ── 假子进程 ──
struct FakeChildState {
    terminated: AtomicBool,
}

struct FakeLoginCoreChild {
    stdout: Option<BoxRead>,
    state: Arc<FakeChildState>,
    exited_rx: watch::Receiver<bool>,
    exited_tx: watch::Sender<bool>,
}

#[async_trait]
impl LoginCoreChild for FakeLoginCoreChild {
    fn pid(&self) -> Option<u32> {
        Some(4242)
    }
    fn take_stdout(&mut self) -> Option<BoxRead> {
        self.stdout.take()
    }
    fn take_stderr(&mut self) -> Option<BoxRead> {
        None
    }
    async fn wait(&mut self) {
        // 直到「退出」信号（自然退出或被终止）才返回；否则永挂（模拟核仍在等认证）。
        let mut rx = self.exited_rx.clone();
        let _ = rx.wait_for(|v| *v).await;
    }
    async fn terminate(&mut self) {
        self.state.terminated.store(true, Ordering::SeqCst);
        let _ = self.exited_tx.send(true);
    }
}

// ── 假 spawner（记录每次 spawn 的 child 状态供断言；可脚本化 stdout / 自然退出 / spawn 失败）──
struct FakeSpawner {
    lines: Vec<String>,
    self_exit: bool,
    fail: bool,
    spawned: Arc<Mutex<Vec<Arc<FakeChildState>>>>,
    count: Arc<AtomicUsize>,
}

impl LoginCoreSpawner for FakeSpawner {
    fn spawn(&self, _req: &SpawnRequest) -> Result<Box<dyn LoginCoreChild>, SpawnError> {
        self.count.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(SpawnError::Spawn {
                bin: PathBuf::from("/fake/sing-box"),
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "fake spawn fail"),
            });
        }
        let (mut writer, reader) = tokio::io::duplex(4096);
        let (exited_tx, exited_rx) = watch::channel(false);
        let state = Arc::new(FakeChildState {
            terminated: AtomicBool::new(false),
        });
        self.spawned.lock().unwrap().push(state.clone());
        let lines = self.lines.clone();
        let self_exit = self.self_exit;
        let exit_signal = exited_tx.clone();
        // 内存写端：把脚本行写进 duplex，然后按需触发自然退出，最后 drop（EOF）。无真进程。
        tokio::spawn(async move {
            for l in &lines {
                let _ = writer.write_all(l.as_bytes()).await;
                let _ = writer.write_all(b"\n").await;
            }
            if self_exit {
                let _ = exit_signal.send(true);
            }
            drop(writer);
        });
        Ok(Box::new(FakeLoginCoreChild {
            stdout: Some(Box::new(reader)),
            state,
            exited_rx,
            exited_tx,
        }))
    }
}

// ── 假 checker / emitter ──
struct FakeChecker {
    ok: bool,
}
#[async_trait]
impl ConfigChecker for FakeChecker {
    async fn check(&self, _binary: &Path, _config_path: &Path) -> Result<(), String> {
        if self.ok {
            Ok(())
        } else {
            Err("fake check 判定配置无效".to_string())
        }
    }
}

struct ConcurrentChecker {
    active: AtomicUsize,
    max_active: AtomicUsize,
}

#[async_trait]
impl ConfigChecker for ConcurrentChecker {
    async fn check(&self, _binary: &Path, _config_path: &Path) -> Result<(), String> {
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_active.fetch_max(active, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(20)).await;
        self.active.fetch_sub(1, Ordering::SeqCst);
        Ok(())
    }
}

#[derive(Default)]
struct FakeEmitter {
    captured: Mutex<Vec<(String, String, String)>>,
}
impl AuthUrlEmitter for FakeEmitter {
    fn emit_auth_url(&self, server_id: &str, node_name: &str, url: &str) {
        self.captured.lock().unwrap().push((
            server_id.to_string(),
            node_name.to_string(),
            url.to_string(),
        ));
    }
}

// ── 假 STATUS 订阅器（测试可随时推帧 / 关流；并记录被要求订阅的端口与 secret）──
//
// 帧由测试**事后**推送而非订阅时一次给定：登录是时序问题（先 URL 后 Running、同 URL 连来两帧、
// 幽灵 tag 夹在中间），一次性给定的脚本表达不了「先断言没发生、再推一帧证明确实发得出来」这种
// 带正向对照的观察。
struct FakeStatusSubscriber {
    /// true → `subscribe` 直接返 Err（驱动「订阅失败」腿）。
    fail: bool,
    /// 每次订阅记一条 `(port, secret)`。
    seen: Arc<Mutex<Vec<(u16, String)>>>,
    /// 各次订阅的推帧句柄（测试持它推帧；drop 掉即关流）。
    senders: Arc<Mutex<Vec<mpsc::UnboundedSender<daemon::TailscaleStatusUpdate>>>>,
}

struct FakeStatusStream {
    rx: mpsc::UnboundedReceiver<daemon::TailscaleStatusUpdate>,
}

#[async_trait]
impl LoginStatusStream for FakeStatusStream {
    async fn recv(&mut self) -> Option<daemon::TailscaleStatusUpdate> {
        self.rx.recv().await
    }
}

#[async_trait]
impl LoginStatusSubscriber for FakeStatusSubscriber {
    async fn subscribe(
        &self,
        port: u16,
        secret: &str,
    ) -> Result<Box<dyn LoginStatusStream>, String> {
        self.seen.lock().unwrap().push((port, secret.to_string()));
        if self.fail {
            return Err("fake subscribe fail".to_string());
        }
        let (tx, rx) = mpsc::unbounded_channel();
        self.senders.lock().unwrap().push(tx);
        Ok(Box::new(FakeStatusStream { rx }))
    }
}

impl FakeStatusSubscriber {
    /// 往第 `idx` 次订阅的流里推一帧。
    fn push(&self, idx: usize, update: daemon::TailscaleStatusUpdate) {
        let g = self.senders.lock().unwrap();
        g[idx].send(update).expect("流未关闭");
    }
    /// 关掉第 `idx` 次订阅的流（drop sender → `recv` 返 None）。
    fn close(&self, idx: usize) {
        self.senders.lock().unwrap().remove(idx);
    }
}

fn fake_subscriber(fail: bool) -> Arc<FakeStatusSubscriber> {
    Arc::new(FakeStatusSubscriber {
        fail,
        seen: Arc::new(Mutex::new(Vec::new())),
        senders: Arc::new(Mutex::new(Vec::new())),
    })
}

/// 一帧全量端点快照（单端点）。`auth_url` 空串 = 该帧不带 URL（与真核同语义）。
fn frame(tag: &str, backend_state: &str, auth_url: &str) -> daemon::TailscaleStatusUpdate {
    daemon::TailscaleStatusUpdate {
        endpoints: vec![daemon::TailscaleEndpointStatus {
            endpoint_tag: tag.to_string(),
            backend_state: backend_state.to_string(),
            auth_url: auth_url.to_string(),
            ..Default::default()
        }],
    }
}

// ── 测试脚手架 ──
fn ts_server(id: &str, name: &str) -> ServerConfig {
    ServerConfig {
        id: id.to_string(),
        name: name.to_string(),
        protocol: Protocol::Tailscale,
        ..Default::default()
    }
}

fn temp_ud() -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::SeqCst);
    let p = std::env::temp_dir().join(format!("polaris-tslogin-{}-{}", std::process::id(), n));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn fake_spawner(lines: Vec<String>, self_exit: bool, fail: bool) -> Arc<FakeSpawner> {
    Arc::new(FakeSpawner {
        lines,
        self_exit,
        fail,
        spawned: Arc::new(Mutex::new(Vec::new())),
        count: Arc::new(AtomicUsize::new(0)),
    })
}

fn reg_with(
    spawner: Arc<FakeSpawner>,
    subscriber: Arc<FakeStatusSubscriber>,
    check_ok: bool,
    timeout: Duration,
) -> LoginCoreRegistry {
    LoginCoreRegistry::with_deps(
        spawner,
        Arc::new(FakeChecker { ok: check_ok }),
        subscriber,
        Arc::new(|| Ok(PathBuf::from("/fake/sing-box"))),
        timeout,
    )
}

/// 目录里**唯一**那份登录 config（文件名带代次，故不能写死）。顺带是「一次登录只留一份 config」
/// 的判据：多出来就是有代次没被收掉。
fn login_configs(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("tailscale-login-"))
        })
        .collect()
}

fn sole_login_config(dir: &Path) -> PathBuf {
    let mut files = login_configs(dir);
    assert_eq!(files.len(), 1, "在飞登录应恰好留一份 config：{files:?}");
    files.pop().unwrap()
}

/// 有界轮询等待条件成立（无真进程/网络，条件毫秒级达成；总预算 ~2s）。
async fn wait_until(mut cond: impl FnMut() -> bool) {
    for _ in 0..400 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("等待条件超时未成立");
}

/// 曾经的 URL 来源：核 stdout 的这行日志。现在它**只应进日志**。
const AUTH_LINE: &str =
    "endpoint/tailscale[myts]: Waiting for authentication: https://login.tailscale.com/a/abc123";
const URL_1: &str = "https://login.tailscale.com/a/abc123";
const URL_2: &str = "https://login.tailscale.com/a/def456";

/// 起核 + 拿到 emitter/subscriber 句柄的公共开场（双写守卫不命中、主核未运行）。
async fn started(reg: &LoginCoreRegistry, ud: &Path, server: &ServerConfig) -> Arc<FakeEmitter> {
    let emitter = Arc::new(FakeEmitter::default());
    let outcome = reg
        .start_login(server, ud, false, None, 0, emitter.clone())
        .await;
    assert!(matches!(outcome, StartLoginOutcome::Started));
    emitter
}

fn captured(em: &FakeEmitter) -> Vec<String> {
    em.captured
        .lock()
        .unwrap()
        .iter()
        .map(|(_, _, u)| u.clone())
        .collect()
}

/// STATUS 帧的 `authURL` → 登录 URL 事件（serverId/nodeName/url 三元组齐全）。
///
/// 变异（逐条真跑过）：把 `apply_status_frame` 里的 `emit_auth_url` 删 → 转红；
/// 把 `ev.auth_url` 换成读 `ev.backend_state` → 转红。
#[tokio::test]
async fn status_auth_url_emits_event() {
    let spawner = fake_spawner(vec![], false, false);
    let sub = fake_subscriber(false);
    let reg = reg_with(spawner, sub.clone(), true, Duration::from_secs(60));
    let ud = temp_ud();
    let server = ts_server("ts1", "myts");
    let emitter = started(&reg, &ud, &server).await;
    sub.push(0, frame("myts", "NeedsLogin", URL_1));
    wait_until(|| !emitter.captured.lock().unwrap().is_empty()).await;
    let cap = emitter.captured.lock().unwrap();
    assert_eq!(cap.len(), 1);
    assert_eq!(cap[0].0, "ts1");
    assert_eq!(cap[0].1, "myts");
    assert_eq!(cap[0].2, URL_1);
    drop(cap);
    reg.cancel_login("ts1");
    let _ = std::fs::remove_dir_all(&ud);
}

/// **stdout 不再是 URL 来源**（本批的核心行为改动）。
///
/// 负向断言配正向对照：先喂那行历史 stdout 日志并确认**没有**事件，再从 STATUS 推同一个 URL 并
/// 确认事件到达 —— 后半段证明「没发事件」不是因为夹具根本发不出事件。
/// 变异：把 stdout→URL 的解析加回 supervise → 前半段的 `assert!(cap.is_empty())` 转红。
#[tokio::test]
async fn stdout_auth_line_is_no_longer_a_url_source() {
    let spawner = fake_spawner(vec![AUTH_LINE.to_string()], false, false);
    let sub = fake_subscriber(false);
    let reg = reg_with(spawner, sub.clone(), true, Duration::from_secs(60));
    let ud = temp_ud();
    let server = ts_server("ts1", "myts");
    let emitter = started(&reg, &ud, &server).await;
    // 核已把那行吐完（duplex 写端随即 drop），给 relay 充分时间；仍不得有任何事件。
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert!(
        captured(&emitter).is_empty(),
        "stdout 的 Waiting for authentication 行不得再产出登录 URL 事件"
    );
    // 正向对照：同一个 URL 走 STATUS 就必须发得出来。
    sub.push(0, frame("myts", "NeedsLogin", URL_1));
    wait_until(|| !captured(&emitter).is_empty()).await;
    assert_eq!(captured(&emitter), vec![URL_1.to_string()]);
    reg.cancel_login("ts1");
    let _ = std::fs::remove_dir_all(&ud);
}

/// 同一 URL 每帧都来 → 只通知一次；URL 变了（重开授权）→ 再通知一次。
/// 变异：把 `if next != state` 去掉（无条件 emit）→ 第一条断言从 1 变 2 转红。
#[tokio::test]
async fn repeated_auth_url_emits_once_changed_url_emits_again() {
    let spawner = fake_spawner(vec![], false, false);
    let sub = fake_subscriber(false);
    let reg = reg_with(spawner, sub.clone(), true, Duration::from_secs(60));
    let ud = temp_ud();
    let server = ts_server("ts1", "myts");
    let emitter = started(&reg, &ud, &server).await;
    sub.push(0, frame("myts", "NeedsLogin", URL_1));
    sub.push(0, frame("myts", "NeedsLogin", URL_1));
    wait_until(|| !captured(&emitter).is_empty()).await;
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert_eq!(
        captured(&emitter),
        vec![URL_1.to_string()],
        "同 URL 只发一次"
    );
    sub.push(0, frame("myts", "NeedsLogin", URL_2));
    wait_until(|| captured(&emitter).len() == 2).await;
    assert_eq!(
        captured(&emitter),
        vec![URL_1.to_string(), URL_2.to_string()]
    );
    reg.cancel_login("ts1");
    let _ = std::fs::remove_dir_all(&ud);
}

/// `backendState == "Running"` = 登录成功（控制面终局肯定）→ 主动收核 + 注销。
/// 这正是「登录成功判据从『无法判定』升级」的那一格：此前核要空跑到 5 分钟超时。
///
/// 变异：把 `ExitReason::LoggedIn` 那条 `break` 删 → 核不被终止、表项还在 → 两条断言都转红；
/// 把判据从 `== "Running"` 换成 `ev.logged_in` → 下面 `Starting` 那格会提前收核 → 转红。
#[tokio::test]
async fn running_backend_state_reaps_core_but_starting_does_not() {
    let spawner = fake_spawner(vec![], false, false);
    let sub = fake_subscriber(false);
    let reg = reg_with(spawner.clone(), sub.clone(), true, Duration::from_secs(60));
    let ud = temp_ud();
    let server = ts_server("ts1", "myts");
    let _emitter = started(&reg, &ud, &server).await;
    // Starting（`logged_in` 谓词会把它算作已登录）**不是**收核判据：那只是「在连」。
    sub.push(0, frame("myts", "Starting", ""));
    tokio::time::sleep(Duration::from_millis(120)).await;
    let st = spawner.spawned.lock().unwrap()[0].clone();
    assert!(
        !st.terminated.load(Ordering::SeqCst),
        "Starting 不得当成登录成功"
    );
    assert!(reg.shared.contains("ts1"));
    // Running → 收核 + 注销。
    sub.push(0, frame("myts", "Running", ""));
    wait_until(|| st.terminated.load(Ordering::SeqCst)).await;
    wait_until(|| !reg.shared.contains("ts1")).await;
    let _ = std::fs::remove_dir_all(&ud);
}

/// 端点 tag 不是本节点（幽灵/历史端点）→ 整条丢弃，既不发 URL 也不算登录成功。
/// 变异：把 `tag_to_id` 换成空映射之外的任何「兜底放行」→ 第一段断言转红。
#[tokio::test]
async fn frame_for_other_endpoint_tag_is_ignored() {
    let spawner = fake_spawner(vec![], false, false);
    let sub = fake_subscriber(false);
    let reg = reg_with(spawner.clone(), sub.clone(), true, Duration::from_secs(60));
    let ud = temp_ud();
    let server = ts_server("ts1", "myts");
    let emitter = started(&reg, &ud, &server).await;
    sub.push(0, frame("别人的节点", "Running", URL_1));
    tokio::time::sleep(Duration::from_millis(120)).await;
    let st = spawner.spawned.lock().unwrap()[0].clone();
    assert!(captured(&emitter).is_empty(), "不在册 tag 不得产出 URL");
    assert!(
        !st.terminated.load(Ordering::SeqCst),
        "不在册 tag 的 Running 不得当成本节点登录成功"
    );
    // 正向对照：换成本节点 tag 就必须两样都发生。
    sub.push(0, frame("myts", "NeedsLogin", URL_1));
    wait_until(|| !captured(&emitter).is_empty()).await;
    let _ = std::fs::remove_dir_all(&ud);
}

/// STATUS 流终止 = 判据来源没了（不回退 stdout）→ 就地收核 + 注销，不让核空跑到超时。
/// 变异：把 `StatusStreamEnded` 腿改成继续循环 → 两条 `wait_until` 超时 panic 转红。
#[tokio::test]
async fn status_stream_end_reaps_core() {
    let spawner = fake_spawner(vec![], false, false);
    let sub = fake_subscriber(false);
    let reg = reg_with(spawner.clone(), sub.clone(), true, Duration::from_secs(60));
    let ud = temp_ud();
    let server = ts_server("ts1", "myts");
    let _emitter = started(&reg, &ud, &server).await;
    wait_until(|| !spawner.spawned.lock().unwrap().is_empty()).await;
    let st = spawner.spawned.lock().unwrap()[0].clone();
    sub.close(0);
    wait_until(|| st.terminated.load(Ordering::SeqCst)).await;
    wait_until(|| !reg.shared.contains("ts1")).await;
    let _ = std::fs::remove_dir_all(&ud);
}

/// 订阅失败 → 硬失败（不回退 stdout），且**必须先收掉已 spawn 的核**、不留表项，
/// 否则留下一个谁都不认识的孤儿 sing-box。
/// 变异：把订阅失败腿里的 `child.terminate()` 删 → `terminated` 断言转红。
#[tokio::test]
async fn subscribe_failure_kills_spawned_core_and_reports_failure() {
    let spawner = fake_spawner(vec![], false, false);
    let sub = fake_subscriber(true); // 订阅必失败
    let reg = reg_with(spawner.clone(), sub, true, Duration::from_secs(60));
    let ud = temp_ud();
    let server = ts_server("ts1", "myts");
    let outcome = reg
        .start_login(
            &server,
            &ud,
            false,
            None,
            0,
            Arc::new(FakeEmitter::default()),
        )
        .await;
    assert!(matches!(outcome, StartLoginOutcome::Failed(_)));
    assert!(!reg.shared.contains("ts1"), "订阅失败不得留表项");
    let st = spawner.spawned.lock().unwrap()[0].clone();
    assert!(
        st.terminated.load(Ordering::SeqCst),
        "订阅失败必须收掉已起的核，禁留孤儿"
    );
    assert!(
        login_configs(&ud).is_empty(),
        "订阅失败不得遗留含 secret 的 config"
    );
    let _ = std::fs::remove_dir_all(&ud);
}

/// 瞬态核管理 API 的端口与 secret：端口非 0、避开主核 api 端口；secret 是 32 位 hex（非空）。
/// 空 secret = 同机任意进程都能读该核的 tailnet 拓扑，故「有 secret」本身就是判据。
/// 变异：把 `TailscaleLoginApiService.secret` 传空串 → hex 断言转红；把 `primary_api_port`
/// 从排除集里删 → 端口断言在撞上时转红（撞概率低，故另有 `port_bookkeeping` 的确定性桩测）。
#[tokio::test]
async fn login_api_port_and_secret_are_resolved_and_handed_to_subscriber() {
    let spawner = fake_spawner(vec![], false, false);
    let sub = fake_subscriber(false);
    let reg = reg_with(spawner, sub.clone(), true, Duration::from_secs(60));
    let ud = temp_ud();
    let server = ts_server("ts1", "myts");
    // 主核 api 端口占着 9099 → 瞬态核不得选它。
    let outcome = reg
        .start_login(
            &server,
            &ud,
            false,
            None,
            9099,
            Arc::new(FakeEmitter::default()),
        )
        .await;
    assert!(matches!(outcome, StartLoginOutcome::Started));
    let seen = sub.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    let (port, secret) = &seen[0];
    assert_ne!(*port, 0, "必须解析出真实端口");
    assert_ne!(*port, 9099, "不得与运行主核的管理 API 端口相撞");
    assert_eq!(secret.len(), 32, "16 字节 CSPRNG → 32 位 hex");
    assert!(secret.chars().all(|c| c.is_ascii_hexdigit()));
    // 写盘的配置里也必须带着这一对（否则核根本不会 listen 在这个口上）。
    let config_path = sole_login_config(&ud);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&config_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600,
            "含管理 API secret 的瞬态 config 必须仅属主可读写"
        );
    }
    let cfg: serde_json::Value =
        serde_json::from_slice(&std::fs::read(config_path).unwrap()).unwrap();
    assert_eq!(cfg["services"][0]["listen_port"], u64::from(*port));
    assert_eq!(cfg["services"][0]["secret"], *secret);
    reg.cancel_login("ts1");
    let _ = std::fs::remove_dir_all(&ud);
}

/// 临时 config 里有一次性 secret → 生命周期必须跟核一致：核在时在盘上，收核后不留。
/// 且 kill-on-relogin 下**两代不共用同一个文件名**——否则旧代 supervisor 的删除会打在新代刚写好
/// 的那份上（它的 terminate 有最长 5s 宽限，删除随时可能晚于新核 spawn）。
///
/// 变异：把文件名里的 `-{epoch}` 去掉 → 两代同名，`assert_ne!` 转红；
/// 把收核后的 `remove_login_config` 删掉 → 末条断言转红。
#[tokio::test]
async fn login_config_holds_secret_so_it_dies_with_the_core() {
    let spawner = fake_spawner(vec![], false, false);
    let sub = fake_subscriber(false);
    let reg = reg_with(spawner.clone(), sub.clone(), true, Duration::from_secs(60));
    let ud = temp_ud();
    let server = ts_server("ts1", "myts");
    let _em = started(&reg, &ud, &server).await;
    let first_cfg = sole_login_config(&ud);
    // relogin：新一代必须写到**另一个**文件名下。
    let _em2 = started(&reg, &ud, &server).await;
    wait_until(|| spawner.count.load(Ordering::SeqCst) == 2).await;
    // 旧代被杀 → 它删自己那份；新代那份留着。剩下的这一份必须不是旧的那份。
    wait_until(|| !first_cfg.exists()).await;
    let second_cfg = sole_login_config(&ud);
    assert_ne!(first_cfg, second_cfg, "两代不得共用同一个 config 文件名");
    // 收掉新代 → 盘上不再留任何带 secret 的 config。
    reg.cancel_login("ts1");
    wait_until(|| !second_cfg.exists()).await;
    let _ = std::fs::remove_dir_all(&ud);
}

#[tokio::test]
async fn check_failure_returns_error_without_spawning() {
    let spawner = fake_spawner(vec![], false, false);
    let reg = reg_with(
        spawner.clone(),
        fake_subscriber(false),
        false,
        Duration::from_secs(60),
    );
    let ud = temp_ud();
    let server = ts_server("ts1", "myts");
    let outcome = reg
        .start_login(
            &server,
            &ud,
            false,
            None,
            0,
            Arc::new(FakeEmitter::default()),
        )
        .await;
    assert!(matches!(outcome, StartLoginOutcome::Failed(_)));
    assert_eq!(
        spawner.count.load(Ordering::SeqCst),
        0,
        "check 失败不得 spawn"
    );
    assert!(!reg.shared.contains("ts1"));
    assert!(
        login_configs(&ud).is_empty(),
        "check 失败不得遗留含 secret 的 config"
    );
    let _ = std::fs::remove_dir_all(&ud);
}

#[tokio::test]
async fn spawn_failure_returns_error_and_no_entry() {
    let spawner = fake_spawner(vec![], false, true);
    let reg = reg_with(
        spawner,
        fake_subscriber(false),
        true,
        Duration::from_secs(60),
    );
    let ud = temp_ud();
    let server = ts_server("ts1", "myts");
    let outcome = reg
        .start_login(
            &server,
            &ud,
            false,
            None,
            0,
            Arc::new(FakeEmitter::default()),
        )
        .await;
    assert!(matches!(outcome, StartLoginOutcome::Failed(_)));
    assert!(!reg.shared.contains("ts1"), "spawn 失败不得留表项");
    assert!(
        login_configs(&ud).is_empty(),
        "spawn 失败不得遗留含 secret 的 config"
    );
    let _ = std::fs::remove_dir_all(&ud);
}

#[test]
fn secure_config_create_refuses_to_truncate_an_existing_path() {
    let ud = temp_ud();
    let path = ud.join("tailscale-login-preexisting.json");
    std::fs::write(&path, b"do-not-touch").unwrap();
    let error = write_login_config_secure(&path, b"secret").unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read(&path).unwrap(), b"do-not-touch");
    let _ = std::fs::remove_dir_all(&ud);
}

#[tokio::test]
async fn guard_blocks_duplicate_endpoint_login() {
    let spawner = fake_spawner(vec![], false, false);
    let reg = reg_with(
        spawner.clone(),
        fake_subscriber(false),
        true,
        Duration::from_secs(60),
    );
    let ud = temp_ud();
    let server = ts_server("ts1", "myts");
    // 运行主核配置里已含该 TS 节点 → 双写守卫命中。
    let running = UserConfig {
        servers: vec![ts_server("ts1", "myts")],
        ..Default::default()
    };
    let outcome = reg
        .start_login(
            &server,
            &ud,
            true,
            Some(&running),
            0,
            Arc::new(FakeEmitter::default()),
        )
        .await;
    assert!(matches!(outcome, StartLoginOutcome::InMainCore));
    assert_eq!(
        spawner.count.load(Ordering::SeqCst),
        0,
        "守卫命中不得 spawn"
    );
    assert!(!reg.shared.contains("ts1"));
    let _ = std::fs::remove_dir_all(&ud);
}

#[tokio::test]
async fn cancel_kills_and_deregisters() {
    let spawner = fake_spawner(vec![], false, false);
    let reg = reg_with(
        spawner.clone(),
        fake_subscriber(false),
        true,
        Duration::from_secs(60),
    );
    let ud = temp_ud();
    let server = ts_server("ts1", "myts");
    assert!(matches!(
        reg.start_login(
            &server,
            &ud,
            false,
            None,
            0,
            Arc::new(FakeEmitter::default())
        )
        .await,
        StartLoginOutcome::Started
    ));
    wait_until(|| reg.shared.contains("ts1")).await;
    assert!(reg.cancel_login("ts1"), "取消在飞登录返 true");
    assert!(!reg.shared.contains("ts1"), "cancel 立即注销");
    let st = spawner.spawned.lock().unwrap()[0].clone();
    wait_until(|| st.terminated.load(Ordering::SeqCst)).await;
    // 幂等：再取消不存在的登录 → false（非错误）。
    assert!(!reg.cancel_login("ts1"));
    let _ = std::fs::remove_dir_all(&ud);
}

#[tokio::test]
async fn relogin_kills_prior_child() {
    let spawner = fake_spawner(vec![], false, false);
    let reg = reg_with(
        spawner.clone(),
        fake_subscriber(false),
        true,
        Duration::from_secs(60),
    );
    let ud = temp_ud();
    let server = ts_server("ts1", "myts");
    let em = Arc::new(FakeEmitter::default());
    assert!(matches!(
        reg.start_login(&server, &ud, false, None, 0, em.clone())
            .await,
        StartLoginOutcome::Started
    ));
    wait_until(|| reg.shared.contains("ts1")).await;
    // 同 server 再登录 → 先杀旧核。
    assert!(matches!(
        reg.start_login(&server, &ud, false, None, 0, em.clone())
            .await,
        StartLoginOutcome::Started
    ));
    wait_until(|| spawner.count.load(Ordering::SeqCst) == 2).await;
    let first = spawner.spawned.lock().unwrap()[0].clone();
    wait_until(|| first.terminated.load(Ordering::SeqCst)).await;
    // 新核仍在册且未被终止。
    assert!(reg.shared.contains("ts1"));
    let second = spawner.spawned.lock().unwrap()[1].clone();
    assert!(!second.terminated.load(Ordering::SeqCst));
    reg.cancel_login("ts1");
    let _ = std::fs::remove_dir_all(&ud);
}

#[tokio::test]
async fn concurrent_relogin_serializes_spawn_registration_transaction() {
    let spawner = fake_spawner(vec![], false, false);
    let checker = Arc::new(ConcurrentChecker {
        active: AtomicUsize::new(0),
        max_active: AtomicUsize::new(0),
    });
    let reg = LoginCoreRegistry::with_deps(
        spawner.clone(),
        checker.clone(),
        fake_subscriber(false),
        Arc::new(|| Ok(PathBuf::from("/fake/sing-box"))),
        Duration::from_secs(60),
    );
    let ud = temp_ud();
    let server = ts_server("ts1", "myts");
    let emitter = Arc::new(FakeEmitter::default());
    let (first, second) = tokio::join!(
        reg.start_login(&server, &ud, false, None, 0, emitter.clone()),
        reg.start_login(&server, &ud, false, None, 0, emitter),
    );
    assert!(matches!(first, StartLoginOutcome::Started));
    assert!(matches!(second, StartLoginOutcome::Started));
    assert_eq!(
        checker.max_active.load(Ordering::SeqCst),
        1,
        "同一注册表的 start 事务不得交叠"
    );
    assert_eq!(spawner.count.load(Ordering::SeqCst), 2);
    let first_child = spawner.spawned.lock().unwrap()[0].clone();
    wait_until(|| first_child.terminated.load(Ordering::SeqCst)).await;
    assert!(reg.shared.contains("ts1"), "新代仍须在册");
    reg.cancel_login("ts1");
    let _ = std::fs::remove_dir_all(&ud);
}

#[tokio::test]
async fn active_login_cores_are_hard_capped() {
    let spawner = fake_spawner(vec![], false, false);
    let reg = reg_with(
        spawner.clone(),
        fake_subscriber(false),
        true,
        Duration::from_secs(60),
    );
    let ud = temp_ud();
    let emitter = Arc::new(FakeEmitter::default());
    let mut ids = Vec::new();
    for index in 0..MAX_ACTIVE_LOGIN_CORES {
        let id = format!("ts-{index}");
        let server = ts_server(&id, &format!("node-{index}"));
        assert!(matches!(
            reg.start_login(&server, &ud, false, None, 0, emitter.clone())
                .await,
            StartLoginOutcome::Started
        ));
        ids.push(id);
    }

    let overflow = ts_server("overflow", "overflow");
    let outcome = reg
        .start_login(&overflow, &ud, false, None, 0, emitter)
        .await;
    assert!(matches!(outcome, StartLoginOutcome::Failed(_)));
    assert_eq!(
        spawner.count.load(Ordering::SeqCst),
        MAX_ACTIVE_LOGIN_CORES,
        "超限请求不得再 spawn 子进程"
    );
    for id in ids {
        reg.cancel_login(&id);
    }
    let _ = std::fs::remove_dir_all(&ud);
}

#[tokio::test]
async fn timeout_fires_kill_and_deregisters() {
    let spawner = fake_spawner(vec![], false, false);
    let reg = reg_with(
        spawner.clone(),
        fake_subscriber(false),
        true,
        Duration::from_millis(80),
    );
    let ud = temp_ud();
    let server = ts_server("ts1", "myts");
    assert!(matches!(
        reg.start_login(
            &server,
            &ud,
            false,
            None,
            0,
            Arc::new(FakeEmitter::default())
        )
        .await,
        StartLoginOutcome::Started
    ));
    wait_until(|| !spawner.spawned.lock().unwrap().is_empty()).await;
    let st = spawner.spawned.lock().unwrap()[0].clone();
    wait_until(|| st.terminated.load(Ordering::SeqCst)).await; // 超时触发 kill
    wait_until(|| !reg.shared.contains("ts1")).await; // 注销
    let _ = std::fs::remove_dir_all(&ud);
}

#[tokio::test]
async fn child_self_exit_reaps_registry() {
    let spawner = fake_spawner(vec![], true, false); // 自然退出
    let reg = reg_with(
        spawner.clone(),
        fake_subscriber(false),
        true,
        Duration::from_secs(60),
    );
    let ud = temp_ud();
    let server = ts_server("ts1", "myts");
    assert!(matches!(
        reg.start_login(
            &server,
            &ud,
            false,
            None,
            0,
            Arc::new(FakeEmitter::default())
        )
        .await,
        StartLoginOutcome::Started
    ));
    wait_until(|| !reg.shared.contains("ts1")).await; // 自然退出后 reap
    let st = spawner.spawned.lock().unwrap()[0].clone();
    assert!(
        !st.terminated.load(Ordering::SeqCst),
        "自然退出不应触发主动 terminate"
    );
    let _ = std::fs::remove_dir_all(&ud);
}
