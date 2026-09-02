use super::*;

/// ⑩ stale-core 清扫：**本 app** 孤儿被清 + **非本 app** 的 sing-box **不被误杀**（最关键的安全点）。
///
/// - 「本 app 孤儿」= 用 `POLARIS_SINGBOX_PATH` 指向的核二进制直接 spawn（不经 ProxyRuntime → 无句柄管理）。
/// - 「非本 app」= 把同一核**复制到另一路径**再起 → argv[0] 路径不同 → `is_our_core` 判 false → 存活。
#[tokio::test(flavor = "multi_thread")]
#[ignore = "真机验证：需 POLARIS_SINGBOX_PATH 指向真实 sing-box；非 CI 门"]
async fn real_core_stale_cleanup_kills_own_orphan_spares_foreign() {
    let _real_core_guard = lock_real_core_tests().await;
    use std::process::Stdio;
    let (rt, dir, core) = real_core_runtime();
    crate::logging::init(&dir);

    // ── 孤儿①（本 app）：用本 app 核路径直接 spawn，不经 ProxyRuntime → 成孤儿 ──
    let ours_cfg = dir.join("orphan-ours.json");
    write_bare_singbox_config(&ours_cfg, free_port());
    let mut ours_orphan = tokio::process::Command::new(&core)
        .args(["run", "-c", ours_cfg.to_str().unwrap(), "--disable-color"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn 本 app 孤儿核");
    let ours_pid = ours_orphan.id().expect("本 app 孤儿 pid");
    // 清扫器在 SIGKILL 后会再次探活。若测试自己一直持有未 wait 的 Child，Linux 会把已死进程
    // 留成 zombie，`kill(pid, 0)` 仍会报存在，清扫器便会误判为 EPERM/root survivor。
    // 独立 reaper 从一开始就等待：既不参与杀进程，也能在清扫杀掉它后立即收割。
    let ours_reaper = tokio::spawn(async move { ours_orphan.wait().await });

    // ── 「非本 app」sing-box：复制核到异路径再起 → 路径不同 → 绝不该被误杀 ──
    let foreign_bin = dir.join("foreign-sing-box");
    std::fs::copy(&core, &foreign_bin).expect("复制核到异路径（std::fs::copy 保留可执行位）");
    let foreign_cfg = dir.join("foreign.json");
    write_bare_singbox_config(&foreign_cfg, free_port());
    let mut foreign = tokio::process::Command::new(&foreign_bin)
        .args([
            "run",
            "-c",
            foreign_cfg.to_str().unwrap(),
            "--disable-color",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn 非本 app sing-box（异路径）");
    let foreign_pid = foreign.id().expect("非本 app sing-box pid");

    // 等两个核都真正起来。
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert!(ps_alive(ours_pid), "[⑩] 前提：本 app 孤儿在跑");
    assert!(ps_alive(foreign_pid), "[⑩] 前提：非本 app sing-box 在跑");
    println!("[⑩] 本 app 孤儿 pid={ours_pid}（{}）", core.display());
    println!(
        "[⑩] 非本 app sing-box pid={foreign_pid}（{}）",
        foreign_bin.display()
    );

    // ── stale 清扫：按本 app 二进制路径精确判定 ──
    // 同用户起的孤儿用户态就杀得动 → 不该走到 T3 提权腿，必须干净返回 Ok。
    assert!(
        rt.cleanup_stale_cores().await.is_ok(),
        "[⑩] 同用户孤儿用户态可杀 → 不得落 ROOT_ORPHAN_BLOCKED"
    );
    tokio::time::sleep(Duration::from_millis(500)).await;

    // reaper 应在清扫后立即拿到退出状态；超时表示进程其实仍在跑。
    tokio::time::timeout(Duration::from_secs(3), ours_reaper)
        .await
        .expect("[⑩] 本 app 孤儿必须在清扫后被 reaper 收割（超时=仍在跑）")
        .expect("[⑩] reaper 任务不应 panic")
        .expect("[⑩] wait 本 app 孤儿不应失败");
    // 非本 app sing-box（异路径）genuinely 存活（未被杀、非 zombie）→ ps_alive 判据可靠。
    assert!(
        ps_alive(foreign_pid),
        "[⑩] **核心安全点**：非本 app 的 sing-box pid={foreign_pid}（异路径）绝不能被误杀"
    );
    println!(
        "[⑩] 本 app 孤儿已清（wait 收割确认退出）+ 非本 app sing-box 存活 → 只杀自己、不误杀他人 ✓"
    );

    // 收尾：清掉 foreign（本 app 孤儿已收割）。
    send_signal(foreign_pid, Signal::Sigkill);
    let _ = foreign.wait().await;
}

// ─── P1-b：起核收口腿必须让 daemon 停掉它自己的受管 child ──────────────────────────

use std::sync::atomic::AtomicUsize;

/// 可观测的 [`HelperStopOps`] 替身：记调用次数 + 每次带的身份 pid，并可被指定成失败腿。
///
/// `during_call` 在「IPC 往返中」执行 —— 用来**确定性**地复现「停核请求在飞、期间新会话起了新核」
/// 那条时序（真机上它是 helper 无响应 + 用户重装 helper 的窗口，靠 sleep 撞不出来）。
struct RecordingStop {
    calls: Arc<AtomicUsize>,
    wants: Arc<Mutex<Vec<Option<u32>>>>,
    result: Result<(), String>,
    during_call: Option<Box<dyn Fn() + Send + Sync>>,
}
type StopProbe = (
    Arc<RecordingStop>,
    Arc<AtomicUsize>,
    Arc<Mutex<Vec<Option<u32>>>>,
);
impl RecordingStop {
    fn new(result: Result<(), String>) -> StopProbe {
        Self::with_hook(result, None)
    }
    fn with_hook(
        result: Result<(), String>,
        during_call: Option<Box<dyn Fn() + Send + Sync>>,
    ) -> StopProbe {
        let calls = Arc::new(AtomicUsize::new(0));
        let wants = Arc::new(Mutex::new(Vec::new()));
        let ops = Arc::new(Self {
            calls: Arc::clone(&calls),
            wants: Arc::clone(&wants),
            result,
            during_call,
        });
        (ops, calls, wants)
    }
}
impl HelperStopOps for RecordingStop {
    fn stop_managed_core(&self, want_pid: Option<u32>) -> Result<(), String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.wants.lock().unwrap().push(want_pid);
        if let Some(f) = self.during_call.as_ref() {
            f();
        }
        self.result.clone()
    }
}

// ─── 停核的受管 pid 身份：app 侧下发 + 记账收口 ────────────────────────────────

/// **变异门（下发侧）**：helper 停核腿必须把「本腿意图停的那个 pid」**随请求带下去**。
///
/// 判据只能在 helper 进程里执行（真正杀进程的是它），app 不下发 = 判据永远拿不到 want =
/// daemon 退回「反正要停就杀当前的」。
///
/// 变异（逃逸面穷举）：
/// - `stop_managed_core(intended)` 改回 `stop_managed_core(None)` → 首条断言转红。
/// - 把 `let intended = ...` 挪到 await **之后**再读 → 读到的是新会话的 pid → 首条转红
///   （那等于把「我要停谁」交给接管方决定）。
#[tokio::test]
async fn helper_stop_leg_sends_the_pid_it_intends_to_stop() {
    let (rt, _dir) = test_runtime();
    *rt.pid.lock().unwrap() = Some(4242);
    rt.core_via_helper.store(true, Ordering::SeqCst);
    let (ops, calls, wants) = RecordingStop::new(Ok(()));

    rt.kill_core_via_helper(ops as Arc<dyn HelperStopOps>)
        .await
        .expect("helper 停核应成功");

    assert_eq!(
        *wants.lock().unwrap(),
        vec![Some(4242)],
        "停核请求必须携带受管 pid 身份 —— 这是 helper 侧唯一能据以拒杀的依据"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1, "恰调一次");
    // 无人接管 → 记账照常清（反向失效：留着会让下次 kill_core 走错腿）。
    assert!(rt.pid.lock().unwrap().is_none());
    assert!(!rt.core_via_helper.load(Ordering::SeqCst));
}

/// **结果未知门**：通信失败时不能清 helper 记账。请求可能根本没到，也可能已停但回包丢失；
/// 两种情况都只能保留身份，让上层停止失败而不是伪造 stopped。
#[tokio::test]
async fn helper_stop_failure_preserves_managed_identity() {
    let (rt, _dir) = test_runtime();
    *rt.pid.lock().unwrap() = Some(4242);
    rt.core_via_helper.store(true, Ordering::SeqCst);
    let (ops, calls, wants) = RecordingStop::new(Err("mock transport timeout".to_owned()));

    let error = rt
        .kill_core_via_helper(ops as Arc<dyn HelperStopOps>)
        .await
        .expect_err("没有确定停核回执时必须向上报错");

    assert!(error.contains("timeout"));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(*wants.lock().unwrap(), vec![Some(4242)]);
    assert_eq!(
        *rt.pid.lock().unwrap(),
        Some(4242),
        "结果未知时清 pid 会让仍在跑的 SYSTEM/root 核失联"
    );
    assert!(
        rt.core_via_helper.load(Ordering::SeqCst),
        "结果未知时必须保留 helper 受管路径"
    );
}

/// 组合路径：`stop` 收到 helper 通信失败后，不清运行态、不发成功终态所依赖的 `Ok(())`。
/// `test_runtime` 的 helper 被结构性禁止连接真实 daemon，因此此测零宿主副作用。
#[tokio::test]
async fn active_stop_keeps_running_state_when_helper_stop_is_unconfirmed() {
    let (rt, _dir) = test_runtime();
    *rt.pid.lock().unwrap() = Some(4242);
    rt.core_via_helper.store(true, Ordering::SeqCst);
    {
        let mut status = rt.status.write().unwrap();
        status.running = true;
        status.started_via_helper = true;
    }

    let error = rt
        .stop()
        .await
        .expect_err("helper 未确认停核时 stop 必须失败");

    assert!(error.contains("helper"));
    assert!(rt.status().running, "不得伪造 stopped 运行态");
    assert_eq!(*rt.pid.lock().unwrap(), Some(4242));
    assert!(rt.core_via_helper.load(Ordering::SeqCst));
}

/// **变异门（记账侧）**：IPC 往返期间受管 pid 记账被新会话换人 → 收口腿**不得**清它。
///
/// 清了不是「多清一次」而是让新核**失联**：`status()` 的 helper 腿据 `pid` 探活、诊断据它报 pid、
/// `cleanup_stale_cores` 的「受管 pid 排除表」也据它 —— 排除表里少了新核，下一次起核的孤儿清扫
/// 就把它当孤儿杀掉（换个地方杀错进程）；`core_via_helper` 被清则让此后的停核走本地 child 腿
/// （child 恒 None）= 停核变 no-op = root 孤儿。
///
/// 变异：`clear_helper_core_bookkeeping` 退回无条件 `*g = None; store(false)` → 两条断言全红。
#[tokio::test]
async fn helper_stop_leg_does_not_wipe_bookkeeping_taken_over_mid_flight() {
    let (rt, _dir) = test_runtime();
    *rt.pid.lock().unwrap() = Some(4242);
    rt.core_via_helper.store(true, Ordering::SeqCst);
    // 「IPC 在飞时新会话起了新核并提交 pid」——真机上这正是老 stop 腿醒来后会杀错人的那一刻。
    let pid_slot = Arc::clone(&rt.pid);
    let (ops, _calls, wants) = RecordingStop::with_hook(
        Ok(()),
        Some(Box::new(move || {
            *pid_slot.lock().unwrap() = Some(9001);
        })),
    );

    rt.kill_core_via_helper(ops as Arc<dyn HelperStopOps>)
        .await
        .expect("老核已停且新会话记账应保留");

    assert_eq!(
        *wants.lock().unwrap(),
        vec![Some(4242)],
        "下发的身份仍是老腿意图停的那个（不是接管方的）"
    );
    assert_eq!(
        *rt.pid.lock().unwrap(),
        Some(9001),
        "新会话的受管 pid 记账必须原样保留 —— 清它 = 新核在 status/诊断/孤儿清扫排除表里集体失联"
    );
    assert!(
        rt.core_via_helper.load(Ordering::SeqCst),
        "helper 受管标记同样属新会话：清它会让此后的停核走本地 child 腿（child 恒 None）= 停核变 no-op"
    );
}

/// **变异门（逃逸面穷举）**：探活判死的收口腿**必须**调 daemon stop，且**恰调一次**。
///
/// - 删掉 `spawn_blocking(stop_managed_core)` → calls==0 → 转红（这就是孤儿的成因）。
/// - 改成循环/重复调用 → calls!=1 → 转红（重复停核会误伤后续世代的核）。
/// - 把返回消息改掉丢了 pid → 末条断言转红（用户拿不到可 `sudo kill` 的 pid）。
/// - 把 `stop_managed_core(Some(pid))` 退回不带身份的 `None` → 身份断言转红（那等于让 daemon
///   「停它此刻手里的随便哪个」，本方法整段可与新会话并发 ⇒ 杀错进程）。
#[tokio::test]
async fn rejected_helper_start_asks_daemon_to_stop_its_child() {
    let (ops, calls, wants) = RecordingStop::new(Ok(()));
    let msg = ProxyRuntime::reject_helper_start(ops, 6439).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "探活判死时必须请 daemon 收口它自己的受管 child，恰一次——否则活着的 root 核就此失联成孤儿"
    );
    assert_eq!(
        *wants.lock().unwrap(),
        vec![Some(6439)],
        "收口请求必须**指名道姓**停那个 pid：不带身份 = 授权 daemon 杀它当前受管的任何核，\
             而这条腿完全可能与新会话的起核并发"
    );
    assert!(msg.contains("6439"), "失败消息须带 pid，用户才可能手动收拾");
}

/// **反向失效门**：stop 失败**不得**改判成功、也不得吞掉错误消息。
///
/// 核确实可能真死了（那时 daemon stop 返 notrunning/错误是正常的），故这条腿是 best-effort：
/// 打断（stop 返 Err 时改成 `return Ok`/返回空串/panic）→ 本测转红。
#[tokio::test]
async fn reject_leg_still_reports_failure_when_daemon_stop_errors() {
    let (ops, calls, _wants) = RecordingStop::new(Err("daemon 说 notrunning".to_owned()));
    let msg = ProxyRuntime::reject_helper_start(ops, 777).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1, "失败腿也必须真尝试过 stop");
    assert!(
        msg.contains("777") && msg.contains("进程不存在"),
        "stop 失败不改判：起核失败的结论与消息原样返回，不得被 stop 的结果污染"
    );
}

/// **P1-a 不变式门（有牙版）**：**每一次** `start` 都必须走 stale 清扫腿，不是只走首次。
///
/// 直接驱动**两次真 start** 并数清扫实跑次数——不是读那个开关（读开关的写法对
/// `swap(true)` 一次性门闩免疫 = 没门）。
///
/// **变异门（逃逸面穷举）**：
/// - 调用点退回 `swap(true, ...)` 一次性门闩 → 第二次 start 不清扫 → runs==1 → 转红。
/// - 删掉整个清扫调用 → runs==0 → 转红。
/// - 把计数挪到 `resolve_core_binary` 成功之后 → 本测（核不可解析）恒 0 → 转红。
///
/// **本机零副作用**：`POLARIS_SINGBOX_PATH` 指向目录 → `resolve_core_binary` 必 Err → 清扫在
/// 计数后立刻早退，**不扫 /proc、不发任何信号**。
// 跨 await 持 `ENV_LOCK`：同 `start_emits_invalid_nodes_on_real_start_path`，见该测说明。
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn stale_sweep_runs_on_every_start_not_only_the_first() {
    let (rt, dir) = test_runtime();
    assert!(
        !rt.stale_sweep_disabled.load(Ordering::SeqCst),
        "生产默认必须开启清扫（该开关仅单测置位）"
    );
    // 端口解析都到不了就失败的最小配置：本测只关心清扫腿被走到几次。
    let config = serde_json::json!({ "servers": [], "proxyModeType": "systemProxy" });

    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("POLARIS_SINGBOX_PATH", &*dir);
    let first = rt.start(config.clone()).await;
    assert_eq!(
        rt.stale_sweep_runs.load(Ordering::SeqCst),
        1,
        "首次 start 必清扫一次"
    );
    let second = rt.start(config).await;
    std::env::remove_var("POLARIS_SINGBOX_PATH");
    drop(_g);

    assert!(
        first.is_err() && second.is_err(),
        "核二进制解析失败 → 两次均失败"
    );
    assert_eq!(
        rt.stale_sweep_runs.load(Ordering::SeqCst),
        2,
        "第二次 start 也必须清扫——一次性门闩会让本会话中途产生的孤儿永远落在射程外，\
             那正是真机把用户卡死的放大器"
    );
}

// ─── T1：pid 探活的 errno 语义（真机 TUN 卡死链的判定侧根因）────────────────────────

/// **变异门①（复现缺陷）**：`EPERM` 必须判**存活**。
///
/// 把 [`alive_from_probe`] 退回成 `r.is_ok()` → EPERM 落进 false → 本测转红。那正是真机
/// 「helper 报告已启动但进程不存在」的判定侧根因：helper 以 root 起核，app 以普通用户
/// `kill(pid,0)` 探活收 EPERM（进程活得好好的，只是没权限发信号）。
///
/// **变异门②（反向失效）**：`ESRCH` 必须判**不存活**。
/// 把 `Err(_) => true` 写成无条件 true（改过头，连 ESRCH 也算活）→ 本测转红。
/// 没有这一半，崩溃监测就永远发现不了核真的死了，孤儿也永远清不掉。
#[cfg(unix)] // 用 nix::errno / alive_from_probe（均 unix-only），windows 排除
#[test]
fn alive_probe_treats_eperm_as_alive_and_only_esrch_as_dead() {
    use nix::errno::Errno;
    assert!(alive_from_probe(Ok(())), "有权发信号且进程在 → 存活");
    assert!(
        alive_from_probe(Err(Errno::EPERM)),
        "[变异门①] EPERM = 进程存在但不属本用户（root 核）→ 必须判存活"
    );
    assert!(
        !alive_from_probe(Err(Errno::ESRCH)),
        "[变异门②] ESRCH = 内核确认无此进程 → 唯一的不存活判据"
    );
    // 其余 errno 不是死亡证据 → 保守判活（绝不据此宣告核已崩）。
    assert!(alive_from_probe(Err(Errno::EINVAL)), "非死亡证据 → 判存活");
}

/// 端到端接线：真跑 `kill(pid,0)` 三种现实情形，锁死 [`pid_alive`] 确实用了新判据。
///
/// **pid 1**（launchd/systemd）是现成的 **root 且非本用户**进程 —— 正是 helper 起的 root 核那一类。
/// 打断（`pid_alive` 绕开 `alive_from_probe` 直接 `.is_ok()`）→ 非 root 运行时本测转红。
#[cfg(unix)] // 用 nix::sys::signal::kill / nix::unistd::Pid（unix-only），windows 排除
#[test]
fn pid_alive_reports_root_owned_process_as_alive() {
    use nix::errno::Errno;
    // 自身必存活（任何实现都该过——防呆基线）。
    assert!(pid_alive(std::process::id()), "自身进程必判存活");
    // 不存在的 pid 必判死（取一个合法但不可能被占用的值）。
    assert!(!pid_alive(i32::MAX as u32), "不存在的 pid 必判不存活");

    // **广播语义门**：0 与越 i32 回绕的 pid 必须判不活，且不得走到 kill 的广播语义上。
    // 打断（去掉 `checked_pid` 直接 `pid as i32`）→ `kill(-1,0)`/`kill(0,0)` 恒 Ok → 本测转红。
    // 同一个 cast 也喂 `send_signal`，在那边等价于 `SIGKILL` 全场，故这是安全门不是洁癖。
    assert!(
        !pid_alive(0),
        "pid 0 = 当前进程组广播，绝不可判为某个进程存活"
    );
    assert!(
        !pid_alive(u32::MAX),
        "u32::MAX 回绕成 -1 = 全体广播，绝不可判存活"
    );

    // pid 1 的属主判定：非 root 用户探它必得 EPERM。若本次恰以 root 运行（CI 容器），
    // 这一腿没有 EPERM 可验 —— 照实跳过，不伪装成验过。
    let probe = nix::sys::signal::kill(nix::unistd::Pid::from_raw(1), None);
    if probe == Err(Errno::EPERM) {
        assert!(
            pid_alive(1),
            "[变异门①端到端] root 所有的 pid 1 探活收 EPERM，必须判存活"
        );
    } else {
        // 以 root 运行 → kill(1,0) 返 Ok，EPERM 腿在本环境无从构造。
        assert_eq!(probe, Ok(()), "非 EPERM 时只可能是 root 运行下的 Ok");
    }
}

/// Windows 探活必须走原生 API，禁止退回每轮启动 `tasklist` 的高延迟实现。
/// 本机 Linux 不编译 Windows 模块，故以源码契约锁住 FFI 与安全判据；Windows Package gate
/// 另会编译并运行模块内的 liveness 真值表测试。
#[test]
fn windows_pid_probe_uses_native_process_handle_not_tasklist() {
    let source = crate::test_support::crate_code("runtime/windows_process.rs");
    for required in ["OpenProcess(", "GetExitCodeProcess(", "GetProcessTimes("] {
        assert!(source.contains(required), "缺原生探活锚点：{required}");
    }
    assert!(source.contains("ERROR_INVALID_PARAMETER"));
    assert!(!source.contains("Command::new(\"tasklist\")"));
}

/// `/proc/<pid>/stat` 的 starttime 取材腿（helper 腿 pid 身份令牌的 linux 侧）。
///
/// 打断（改成对整行 `split_whitespace().nth(21)`，即不从最后一个 `)` 之后切）→ 第二个断言转红：
/// comm 含空格/右括号的进程会整体错位。这不是理论角落 —— 进程名由启动方控制，
/// 而本令牌一旦取到**错字段**，要么恒变（假崩溃 + 无谓重启）要么恒不变（门形同虚设），
/// 两种都比没有这道复核更坏。
#[test]
fn proc_stat_starttime_survives_comm_with_spaces_and_parens() {
    // 真实形状：pid (comm) state ppid pgrp session tty tpgid flags minflt cminflt majflt
    // cmajflt utime stime cutime cstime priority nice num_threads itrealvalue starttime …
    let fields: Vec<String> = (3..=22).map(|i| i.to_string()).collect();
    let tail = fields.join(" ");
    let plain = format!("6439 (sing-box) {tail} 上略");
    assert_eq!(
        parse_proc_stat_starttime(&plain).as_deref(),
        Some("22"),
        "starttime 是第 22 字段"
    );

    let nasty = format!("6439 (we ird) (name) {tail} 上略");
    assert_eq!(
        parse_proc_stat_starttime(&nasty).as_deref(),
        Some("22"),
        "comm 含空格与右括号时仍须取到第 22 字段（必须从最后一个 `)` 之后切）"
    );

    // 字段不够（读到半截 / 不是 stat）→ None，不返回一个错位的值。
    assert_eq!(
        parse_proc_stat_starttime("6439 (sing-box) S 1").as_deref(),
        None
    );
    // 连 `)` 都没有 → None。
    assert_eq!(parse_proc_stat_starttime("garbage").as_deref(), None);
}

/// **本次修复要防住的那件事的回放**：pid 还在（`pid_alive` 恒真）、但号码上换了进程。
///
/// 三条断言各锁一个方向：
/// - 令牌变 ⇒ `Mismatch`（崩溃监测据此判退出 → 自愈；此前这一格恒 `Alive`，自愈永不触发）；
/// - 取不到材料 ⇒ `Unobservable` 而**非** `Mismatch` —— 折成不匹配等于把一次读失败变成一次
///   假崩溃，下游是自动重启；
/// - 令牌未变 ⇒ `Match`。
///
/// 打断（把 `pid_identity_verdict` 的 `_ => Unobservable` 改成 `_ => Mismatch`）→ 第二组转红。
#[test]
fn pid_identity_flags_reuse_but_never_invents_a_crash() {
    assert_eq!(
        pid_identity_verdict(Some("998877"), Some("112233")),
        PidIdentity::Mismatch,
        "同一 pid 上令牌变了 = 换了进程"
    );
    assert_eq!(
        pid_identity_verdict(Some("998877"), Some("998877")),
        PidIdentity::Match
    );
    for (base, cur) in [(None, Some("x")), (Some("x"), None), (None, None)] {
        assert_eq!(
            pid_identity_verdict(base, cur),
            PidIdentity::Unobservable,
            "缺任一侧材料一律 Unobservable（没观测到 ≠ 观测到没问题）"
        );
    }
}

/// Windows TUN 真机回放：helper 核身份观察开始后，用户 stop 在另一 worker 上先 bump 世代并停核；
/// 观察最终拿到 Exited。分类必须读取**观察完成后的**世代，因此 Retire，绝不能触发崩溃自愈。
///
/// 变异：生产调用点改回「观察前 `let gen_now = ...`，观察后直接喂旧值」时，本 seam 不再被使用；
/// 相邻 `crash_monitor_classification_is_wired_after_observation` 会转红。这里则锁住 seam 自身的语义。
#[test]
fn active_stop_during_helper_observation_retires_instead_of_recovering() {
    let gate = LifecycleGate::default();
    let my_gen = gate.bump_generation();

    // 模拟同步 process_identity/pid_alive 观察期间，另一 runtime worker 执行 stop 入口。
    gate.bump_generation();
    let verdict = classify_observed_child_exit(&gate, my_gen, ChildObservation::Exited);

    assert_eq!(
        verdict,
        ExitClassification::Retire,
        "观察期间发生的主动 stop 必须按最新世代让旧监测退场，不能把 TUN 自动拉回"
    );
}

/// 接线顺序门：分类调用必须位于 `let observation = ...` 之后，且生产方法不得再在观察前缓存
/// `gen_now`。纯函数测试只能证明判据会算，守不住调用点重新喂陈旧快照的回归，故这里对方法体锁序。
#[test]
fn crash_monitor_classification_is_wired_after_observation() {
    const HEAD: &str = "    pub(super) fn spawn_crash_monitor(self: &Arc<Self>, my_gen: u64) {";
    let body = method_body(&module_source("runtime/proxy"), HEAD);
    let observation_at = body
        .find("let observation =")
        .expect("崩溃监测必须形成一次完整 observation");
    let classify_at = body
        .find("classify_observed_child_exit(&me.gate, my_gen, observation)")
        .expect("崩溃监测必须走观察后读世代的分类 seam");
    assert!(
        classify_at > observation_at,
        "分类必须发生在观察完成后，否则主动停核仍可能与旧世代拼成假崩溃"
    );
    assert!(
        !body[..observation_at].contains("let gen_now ="),
        "观察前不得缓存世代；Windows 同步身份查询期间 stop 可在另一 worker 上推进世代"
    );
}

/// `CrashRecoveryMachine` 的主动停/新起方法此前只有状态机单测，没有生产写侧。这里从公开入口回放：
/// stop 置 abort；下一次 start（即便配置随后校验失败）先复位，避免“一次停过、永不再自愈”。
#[tokio::test]
async fn public_stop_marks_recovery_aborted_and_next_start_resets_it() {
    let (rt, _dir) = test_runtime();
    rt.stop().await.expect("空闲态 stop 应幂等成功");
    assert!(
        rt.crash_lock().auto_restart_aborted(),
        "主动 stop 必须中止退避中的崩溃自愈"
    );

    rt.stale_sweep_disabled.store(true, Ordering::SeqCst);
    let _ = rt.start(bad_config()).await;
    assert!(
        !rt.crash_lock().auto_restart_aborted(),
        "下一次显式 start 必须复位旧 stop 的 abort 标记"
    );
}

/// **接线门**：纯逻辑对了不代表崩溃监测真的去问了它。
///
/// 本仓两天内被同一形状骗过两次（判据落在「这个词出现过吗」，而词的来源包含判据自身）⇒
/// 判据取的是 [`method_body`] 截出的 `spawn_crash_monitor` **方法体**（剥掉整行注释、
/// 到方法末尾封顶），既排除本测试模块自身，也排除方法内注释里的同名文本。
///
/// 打断（把复核那段删掉、只留 `pid_alive`）→ 三条断言全红。
#[test]
fn crash_monitor_actually_consults_the_pid_identity() {
    const HEAD: &str = "    pub(super) fn spawn_crash_monitor(self: &Arc<Self>, my_gen: u64) {";
    let src = module_source("runtime/proxy");
    // 切在「锚点之后的第一个顶层 `#[cfg(test)]`」：本文件里生产码与测试模块**交替**出现
    // （实测顶层 cfg(test) 有 5 处，最后一处还在本测试之后）⇒ 切第一处会把待验方法切掉、
    // 切最后一处会把本测试留在判据区域里。两种都实测过。
    let at = src
        .find(HEAD)
        .unwrap_or_else(|| panic!("锚点 `{HEAD}` 消失，源码型守卫已失去判据"));
    let cut = src[at..]
        .find("\n#[cfg(test)]\n")
        .map_or(src.len(), |i| at + i);
    let prod = &src[..cut];
    // 切点自检：判据区域里若还留着本测试自身，下面三条就会被自己写的字面量喂饱（生产调用点
    // 删光也照样绿）。本仓两天内被这个形状骗过两次，故显式锁住。
    assert!(
        !prod.contains("fn crash_monitor_actually_consults_the_pid_identity"),
        "判据区域包含本测试自身 —— 切点选错，断言会被自己的字面量污染"
    );
    let body = method_body(prod, HEAD);
    assert!(
        body.contains("pid_identity_verdict("),
        "崩溃监测没有调用 pid_identity_verdict —— 身份复核没接线，pid 复用仍不可发现"
    );
    assert!(
        body.contains("process_identity(p)"),
        "崩溃监测没有取当前令牌 —— 复核会拿基线跟自己比，恒 Match"
    );
    assert!(
        body.contains("PidIdentity::Mismatch"),
        "崩溃监测没有据不匹配改判退出 —— 复核结果被丢弃"
    );
    assert!(
        body.contains("helper.managed_core_status()"),
        "本地无法观察特权核时必须查询 helper 权威状态"
    );
    assert!(
        body.contains("ManagedCoreStatus::Stopped"),
        "helper 明确报告 stopped 时必须改判核退出"
    );
}
