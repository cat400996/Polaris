use super::*;
use polaris_config_engine::user_config::server_config::Protocol;

mod fetch_tests;
mod provider_tests;

/// 供 fetch_tests 复用的 base64 编码。
pub(super) fn b64(s: &str) -> String {
    base64_encode(s)
}

#[test]
fn detect_clash_format() {
    let yaml = "proxies:\n  - name: x\n    type: ss\n    server: 1.2.3.4\n    port: 8388\n";
    assert_eq!(detect_format(yaml), SubscriptionFormat::Clash);
    assert_eq!(
        detect_format("proxy-providers:\n  p:\n    url: x"),
        SubscriptionFormat::Clash
    );
}

// ── JSON 编码的 Clash 订阅（此前整类不可用：落 Unknown → 「暂不支持的订阅格式」）──────
//
// 变异验证：把 `detect_format` 的 `is_json_clash` 分支删掉 → 三条 detect 断言 + 解析断言全红；
// 把 `try_load_clash_doc` 的 JSON 分支删掉 → 解析断言红（serde_yaml 也能吃多数 JSON，但
// `json_clash_with_json_only_escape_parses` 这条专挑 YAML 1.1 不认的转义，必红）。

/// 一份最小 JSON 编码 Clash 订阅（两个 ss 节点）。
const JSON_CLASH: &str = r#"{"proxies":[
        {"name":"J-1","type":"ss","server":"1.2.3.4","port":8388,"cipher":"aes-256-gcm","password":"pw1"},
        {"name":"J-2","type":"ss","server":"5.6.7.8","port":8389,"cipher":"aes-256-gcm","password":"pw2"}
    ]}"#;

#[test]
fn detect_json_encoded_clash() {
    assert_eq!(detect_format(JSON_CLASH), SubscriptionFormat::Clash);
    // 只有 proxy-providers 的 JSON 形态同样算 Clash。
    assert_eq!(
        detect_format(r#"{"proxy-providers":{"p":{"type":"http","url":"https://e.com/p"}}}"#),
        SubscriptionFormat::Clash
    );
    // 结构不符不得误判（`proxies` 不是数组 / `proxy-providers` 不是对象）。
    assert_eq!(
        detect_format(r#"{"proxies":"not-an-array"}"#),
        SubscriptionFormat::Unknown
    );
    // sing-box JSON 仍走 sing-box 分支（分支顺序：outbounds 优先，对齐 上游）。
    assert_eq!(
        detect_format(r#"{"outbounds":[{"type":"vless","server":"a.com"}]}"#),
        SubscriptionFormat::SingboxJson
    );
}

#[test]
fn json_encoded_clash_parses_into_nodes() {
    let mut gen = {
        let mut n = 0u32;
        move || {
            n += 1;
            format!("id-{n}")
        }
    };
    let r = parse_subscription(
        JSON_CLASH,
        "sub-json",
        "2026-01-01T00:00:00Z",
        &mut gen,
        ImportOrigin::RemoteSubscription,
    );
    assert_eq!(
        r.servers.len(),
        2,
        "JSON 编码的 Clash 应解析出 2 个节点，实得 {} + warnings {:?}",
        r.servers.len(),
        r.warnings
    );
    assert_eq!(r.servers[0].name, "J-1");
    assert_eq!(r.servers[1].address, "5.6.7.8");
    assert_eq!(r.servers[0].subscription_id.as_deref(), Some("sub-json"));
}

#[test]
fn json_clash_with_json_only_escape_parses() {
    // `\/` 是合法 JSON 转义、**YAML 1.1（libyaml）不认** —— 这条钉死「必须走真 JSON 解析器」，
    // 而不是靠「YAML 是 JSON 超集」把正文直接喂给 serde_yaml。
    let text = r#"{"proxies":[{"name":"a\/b","type":"ss","server":"1.2.3.4","port":8388,"cipher":"aes-256-gcm","password":"pw"}]}"#;
    assert_eq!(detect_format(text), SubscriptionFormat::Clash);
    let mut gen = || "id-1".to_string();
    let r = parse_subscription(
        text,
        "s",
        "2026-01-01T00:00:00Z",
        &mut gen,
        ImportOrigin::RemoteSubscription,
    );
    assert_eq!(r.servers.len(), 1, "warnings: {:?}", r.warnings);
    assert_eq!(r.servers[0].name, "a/b");
}

#[test]
fn extract_proxy_providers_covers_json_encoding() {
    // 此前 `extract_proxy_providers` 单独判 `is_clash_probe`（YAML 行首探测）→ JSON 编码的
    // provider 一个都拉不到、节点全丢。改走 detect_format（单一真值）后两种编码同覆盖。
    let json = r#"{"proxy-providers":{"P1":{"type":"http","url":"https://e.com/p1"}}}"#;
    let got = extract_proxy_providers(json).expect("JSON 编码的 proxy-providers 必须被提取到");
    let map = got.as_mapping().expect("providers 应是 mapping");
    assert_eq!(map.len(), 1);
    assert_eq!(
        got.get("P1")
            .and_then(|p| p.get("url"))
            .and_then(serde_yaml::Value::as_str),
        Some("https://e.com/p1")
    );
    // YAML 编码不回归。
    assert!(extract_proxy_providers(
        "proxy-providers:\n  P1:\n    type: http\n    url: https://e.com/p1\n"
    )
    .is_some());
    // 非 Clash 正文仍返 None（不得把任意 JSON 当 Clash 拆）。
    assert!(extract_proxy_providers(r#"{"outbounds":[]}"#).is_none());
    assert!(extract_proxy_providers("vless://x@a.com:443#n").is_none());
}

#[test]
fn detect_singbox_json_format() {
    let json = r#"{"outbounds":[{"type":"direct"}]}"#;
    assert_eq!(detect_format(json), SubscriptionFormat::SingboxJson);
    let json2 = r#"{"endpoints":[]}"#;
    assert_eq!(detect_format(json2), SubscriptionFormat::SingboxJson);
}

#[test]
fn detect_xray_json_format() {
    // outbound 有 protocol、无 type → xray（与 sing-box 区分）。
    let json = r#"{"outbounds":[{"protocol":"vless","settings":{}}]}"#;
    assert_eq!(detect_format(json), SubscriptionFormat::XrayJson);
    // 有 type 的同键 JSON 仍判 sing-box（不误判 xray）。
    let singbox = r#"{"outbounds":[{"type":"vless","server":"a.com"}]}"#;
    assert_eq!(detect_format(singbox), SubscriptionFormat::SingboxJson);
}

#[test]
fn parse_subscription_xray_yields_nodes() {
    let json = r#"{"outbounds":[
            {"protocol":"freedom"},
            {"protocol":"vless","tag":"n1","settings":{"vnext":[{"address":"a.com","port":443,"users":[{"id":"u1"}]}]},
             "streamSettings":{"network":"ws","security":"tls","wsSettings":{"path":"/p"}}}
        ]}"#;
    let mut n = 0;
    let mut id_gen = || {
        n += 1;
        format!("id-{n}")
    };
    let parsed = parse_subscription(
        json,
        "sub-x",
        "2026-07-18T00:00:00Z",
        &mut id_gen,
        ImportOrigin::RemoteSubscription,
    );
    assert_eq!(parsed.servers.len(), 1, "vless 入库、freedom 忽略");
    assert_eq!(parsed.servers[0].address, "a.com");
    assert_eq!(parsed.servers[0].network.as_deref(), Some("ws"));
    assert_eq!(
        parsed.servers[0].subscription_id.as_deref(),
        Some("sub-x"),
        "订阅路径挂 sub id"
    );
}

/// endpoints-only 的 sing-box 原生订阅（机场下发 WireGuard 组网）—— 此前恒 0 节点 + warning，
/// 现按 endpoint 建模映射入库。语料 `sing-box check` rc=0（随包核 1.14.0-beta.7）。
#[test]
fn parse_subscription_singbox_endpoints_only_yields_wireguard() {
    let json = r#"{"endpoints":[{
            "type":"wireguard","tag":"WG-HK","mtu":1408,
            "address":["172.16.0.2/32"],
            "private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEk=",
            "peers":[{"address":"wg.example.com","port":2408,
                      "public_key":"bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                      "allowed_ips":["0.0.0.0/0","::/0"],
                      "persistent_keepalive_interval":25}]
        }]}"#;
    assert_eq!(detect_format(json), SubscriptionFormat::SingboxJson);
    let mut n = 0;
    let mut id_gen = || {
        n += 1;
        format!("id-{n}")
    };
    let r = parse_subscription(
        json,
        "sub-wg",
        "2026-07-18T00:00:00Z",
        &mut id_gen,
        ImportOrigin::RemoteSubscription,
    );
    assert_eq!(r.servers.len(), 1, "endpoints[] 不再被整份丢弃");
    assert_eq!((r.skipped, r.failed), (0, 0));
    let s = &r.servers[0];
    assert_eq!(s.protocol, Protocol::Wireguard);
    assert_eq!(s.name, "WG-HK");
    assert_eq!((s.address.as_str(), s.port), ("wg.example.com", 2408));
    assert_eq!(s.subscription_id.as_deref(), Some("sub-wg"));
    let wg = s.wireguard_settings.as_ref().unwrap();
    assert_eq!(wg.allow_internet, Some(true));
    assert!(wg.allowed_ips.is_empty(), "catch-all 全抽进 allowInternet");
}

/// `outbounds[]` + `endpoints[]` 同时在场：两条腿的结果合并，不互相吞。
#[test]
fn parse_subscription_singbox_merges_outbounds_and_endpoints() {
    let json = r#"{
          "outbounds":[
            {"type":"direct","tag":"direct"},
            {"type":"trojan","tag":"T","server":"t.example.com","server_port":443,"password":"p"}
          ],
          "endpoints":[
            {"type":"wireguard","tag":"WG","address":["10.0.0.2/32"],"private_key":"pk",
             "peers":[{"address":"1.2.3.4","port":51820,"public_key":"pub","allowed_ips":["10.0.0.0/24"]}]},
            {"type":"tailscale","tag":"TS","auth_key":"tskey-auth-SECRET"}
          ]
        }"#;
    let mut n = 0;
    let mut id_gen = || {
        n += 1;
        format!("id-{n}")
    };
    let r = parse_subscription(
        json,
        "sub-mix",
        "2026-07-18T00:00:00Z",
        &mut id_gen,
        ImportOrigin::RemoteSubscription,
    );
    let protos: Vec<Protocol> = r.servers.iter().map(|s| s.protocol).collect();
    assert_eq!(
        protos,
        vec![Protocol::Trojan, Protocol::Wireguard],
        "outbounds 的节点在前、endpoints 的在后；direct 忽略、tailscale 跳过"
    );
    assert_eq!(r.skipped, 1, "tailscale endpoint");
    assert_eq!(r.failed, 0);
    assert!(r.warnings.iter().any(|w| w.contains("tailscale endpoint")));
}

#[test]
fn detect_url_list_format() {
    assert_eq!(
        detect_format("vless://uuid@host:443\nss://..."),
        SubscriptionFormat::UrlList
    );
}

#[test]
fn detect_base64_format() {
    // "vless://..." 的 base64
    let b64 = base64_encode("vless://abc@host:443#name");
    assert_eq!(detect_format(&b64), SubscriptionFormat::Base64);
}

#[test]
fn detect_unknown_format() {
    assert_eq!(
        detect_format("just some random text"),
        SubscriptionFormat::Unknown
    );
    assert_eq!(detect_format(""), SubscriptionFormat::Unknown);
}

#[test]
fn parse_clash_subscription_full() {
    let yaml = "proxies:\n  - name: x\n    type: ss\n    server: 1.2.3.4\n    port: 8388\n    cipher: aes-256-gcm\n    password: pw\n";
    let mut counter = 0u32;
    let mut id_gen = || {
        counter += 1;
        format!("id-{counter}")
    };
    let r = parse_subscription(
        yaml,
        "sub-1",
        "2024-01-01",
        &mut id_gen,
        ImportOrigin::RemoteSubscription,
    );
    assert_eq!(r.servers.len(), 1);
    assert_eq!(r.servers[0].name, "x");
}

#[test]
fn parse_unknown_format_warns() {
    let mut id_gen = || "id".to_string();
    let r = parse_subscription(
        "random",
        "sub-1",
        "now",
        &mut id_gen,
        ImportOrigin::RemoteSubscription,
    );
    assert!(r.servers.is_empty());
    assert!(r.warnings.iter().any(|w| w.contains("暂不支持")));
}

#[test]
fn parse_invalid_clash_yaml_warns() {
    let mut id_gen = || "id".to_string();
    let r = parse_subscription(
        "proxies: [bad",
        "sub-1",
        "now",
        &mut id_gen,
        ImportOrigin::RemoteSubscription,
    );
    assert!(r.servers.is_empty());
    assert!(r.warnings[0].contains("Clash YAML 解析失败"));
}

#[test]
fn base64_roundtrip() {
    let orig = "vless://abc@example.com:443#节点";
    let encoded = base64_encode(orig);
    assert_eq!(base64_decode(&encoded).unwrap(), orig);
}

#[test]
fn base64_url_safe() {
    // 含 +/ → 转成 -_ 的 URL-safe 形式也应可解码
    let orig = "ss://aes-256-gcm:pass@host:8388";
    let std = base64_encode(orig);
    let urlsafe: String = std
        .chars()
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            _ => c,
        })
        .collect();
    assert_eq!(base64_decode(&urlsafe).unwrap(), orig);
}

/// 测试用 base64 编码（标准字母表）。
fn base64_encode(input: &str) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(n & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}
