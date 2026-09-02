use super::super::*;
use std::future::Future;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::thread;

use polaris_net_stack::ssrf::DnsLookup;

use crate::runtime::http::HttpRuntime;

/// 起一个回环 HTTP server，服一次 `body`（url-list 订阅正文）后退出。
fn spawn_sub_server(body: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind 回环端口");
    let addr = listener.local_addr().expect("取端口");
    thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf);
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = sock.write_all(resp.as_bytes());
            let _ = sock.flush();
        }
    });
    addr
}

/// mock DnsLookup：把订阅 hostname 解析到指定 IP（放行/拒绝由 IP 是否公网决定）。
///
/// **注**：生产用 `SystemDnsLookup`（真系统解析），其正确性由 `runtime::http` 的
/// `system_dns_*` 单测独立守。此处 mock 只为「把 SSRF 判定对象钉在一个已知公网 IP 上」，
/// 从而**同时**证明「guard 真在生产路径跑」——传输落点另由 client 的 resolve 钉到回环。
struct FixedLookup(&'static str);
impl DnsLookup for FixedLookup {
    fn lookup_all(&self, _host: &str) -> impl Future<Output = Result<Vec<String>, String>> + Send {
        let ip = self.0.to_string();
        async move { Ok(vec![ip]) }
    }
}

/// 两条合法 vless（url-list）：解析器接受 → nodeCount=2。
const SUB_BODY: &str =
    "vless://11111111-1111-1111-1111-111111111111@a.com:443?encryption=none&type=tcp#nodeA\n\
vless://11111111-1111-1111-1111-111111111111@b.com:443?encryption=none&type=ws#nodeB";

#[tokio::test]
async fn preview_gate_real_client_injected_and_called_returns_real_nodes() {
    // ── 门 ①：真 HttpRuntime（真 reqwest）→ preview_core（生产唯一路径）→ 真 socket → 真解析 ──
    let addr = spawn_sub_server(SUB_BODY);
    // 真 client，DNS 钉定：sub.example.com 的传输落到回环 server。
    let client =
        HttpRuntime::with_resolve_overrides(&[("sub.example.com", addr)]).expect("建真 client");
    // SSRF guard 判定对象 = sub.example.com，解析到公网 IP → 放行（guard 真的跑了）。
    let lookup = FixedLookup("93.184.216.34");

    let result = preview_core(
        std::sync::Arc::new(client),
        &lookup,
        "http://sub.example.com/sub",
        false,
        None,
    )
    .await;

    assert_eq!(
        result.get("ok").and_then(Value::as_bool),
        Some(true),
        "真 client 注入 + command 核心真调 → 应拿到真数据，实得: {result}"
    );
    assert_eq!(
        result.get("nodeCount").and_then(Value::as_u64),
        Some(2),
        "应解析出 2 个真节点（真 socket 收的真正文），实得: {result}"
    );
}

#[tokio::test]
async fn preview_gate_mutation_broken_client_injection_turns_red() {
    // ── 门 ②（变异验证）：打断真 client 注入 → 门必须转红 ──
    // 「打断」= 真 client 但传输落点被钉到**回环死端口**（127.0.0.1:1，无 listener）→ 连接立即被拒。
    // 这模拟「注入了一个连不到目标的 client」：证明门①的绿是**真的依赖成功传输**，不是恒绿摆设。
    // 刻意用回环死端口（非真公网 IP）：确定性拒连、零宿主网络触碰、无 15s 超时悬挂。
    let server_addr = spawn_sub_server(SUB_BODY);
    let _ = server_addr; // server 起了但 client 不连它 —— 正是「注入断裂」
    let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let client = HttpRuntime::with_resolve_overrides(&[("sub.example.com", dead)])
        .expect("建真 client（钉到死端口）");
    let lookup = FixedLookup("93.184.216.34"); // guard 放行，但传输落点是死端口

    let result = preview_core(
        std::sync::Arc::new(client),
        &lookup,
        "http://sub.example.com/sub",
        false,
        None,
    )
    .await;

    assert_eq!(
        result.get("ok").and_then(Value::as_bool),
        Some(false),
        "断开真 client 的传输可达性后，门必须转红（ok:false），实得: {result}"
    );
}

#[tokio::test]
async fn preview_gate_ssrf_guard_runs_on_production_path() {
    // ── 门 ③：SSRF guard 真在生产路径跑 —— hostname 解析到内网 IP → 生产路径拒绝 ──
    // 这守的是「guard 没被接线时会静默放行内网」这类缺口（H1 DNS rebinding 防线在生产路径上活着）。
    let addr = spawn_sub_server(SUB_BODY);
    let client =
        HttpRuntime::with_resolve_overrides(&[("sub.example.com", addr)]).expect("建真 client");
    let lookup = FixedLookup("169.254.169.254"); // 云元数据地址 = 内网 → guard 必拒

    let result = preview_core(
        std::sync::Arc::new(client),
        &lookup,
        "http://sub.example.com/sub",
        false,
        None,
    )
    .await;

    assert_eq!(
        result.get("ok").and_then(Value::as_bool),
        Some(false),
        "解析到内网 IP 必须被 SSRF guard 拒（生产路径），实得: {result}"
    );
    assert_eq!(
        result.get("errorKind").and_then(Value::as_str),
        Some("ssrf"),
        "内网命中应归类 ssrf，实得: {result}"
    );
}
