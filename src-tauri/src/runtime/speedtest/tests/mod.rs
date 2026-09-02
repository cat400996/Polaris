use super::*;
use crate::test_support::crate_source;
use async_trait::async_trait;
use std::sync::atomic::{AtomicUsize, Ordering};

fn env() -> CoreBuildEnv {
    CoreBuildEnv {
        platform: "linux".to_string(),
        arch: "x86_64".to_string(),
        has_cronet: true,
    }
}

/// 🔴 **`-1`（真测了没通）与「未测」必须分开计**（陈先生 2026-08-02：「全部测速全部显示 -1，
/// 跟实际不符」）。两者在日志里混成一类，就再也分不出「网络真挂了」和「本轮压根没测、
/// 前端把缺席画成了 -1」——而这两件事的修法完全相反。
///
/// **变异锁**：
/// - 把 `ms >= 0` 写成 `ms > 0` → 第 2 组转红（0ms 是合法的本地极速值，不是失败）；
/// - 把 `failed` 算成 `results.len()`（不减 ok）→ 第 1 组转红；
/// - 把 `absent` 并进 `failed` → 第 1 组转红且三分之和溢出（`also_assert_total` 在 debug 下当场炸）。
#[test]
fn speed_test_summary_splits_timeout_from_never_measured() {
    let m = |pairs: &[(&str, i64)]| -> serde_json::Map<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), json!(v)))
            .collect()
    };
    let intended: Vec<String> = ["a", "b", "c", "d"].iter().map(|s| (*s).into()).collect();

    // 2 个出值（1 成功 1 超时）+ 2 个根本没测。
    let s = summarize_speed_test(&m(&[("a", 120), ("b", -1)]), &intended, 2);
    assert_eq!(
        s,
        SpeedTestSummary {
            ok: 1,
            failed: 1,
            absent: 2
        }
    );

    // 0ms 是合法测量值（本地/极近节点），不是失败。
    let s = summarize_speed_test(&m(&[("a", 0)]), &["a".to_string()], 0);
    assert_eq!(
        s,
        SpeedTestSummary {
            ok: 1,
            failed: 0,
            absent: 0
        }
    );

    // 全员未测（让位/中断）：一个 `-1` 都不该被伪造出来。
    let s = summarize_speed_test(&serde_json::Map::new(), &intended, 4);
    assert_eq!(
        s,
        SpeedTestSummary {
            ok: 0,
            failed: 0,
            absent: 4
        }
    );
}

fn srv(id: &str, protocol: Protocol) -> ServerConfig {
    ServerConfig {
        id: id.to_string(),
        name: format!("node-{id}"),
        protocol,
        address: "example.com".to_string(),
        port: 443,
        uuid: Some("u-1".to_string()),
        ..Default::default()
    }
}

// ══════════════════════════════════════════════════════════════════════════
// temp_core_tag / plan_temp_core：进核前的裁定。每条盯一个「整批测不成」的面。
// ══════════════════════════════════════════════════════════════════════════

/// tag = `out-<id 前 8 位>`（1:1 上游 `:443`）。变异（取全 id / 换前缀）→ 转红：
/// tag 是入站路由规则与出站的**唯一绑定键**，两侧算法不一致 ⇒ 核里没有匹配出站 → 整批 FATAL。
#[test]
fn temp_core_tag_takes_first_eight_chars() {
    assert_eq!(temp_core_tag("0123456789abcdef"), "out-01234567");
    assert_eq!(temp_core_tag("abc"), "out-abc", "短 id 不得 panic / 补位");
}

/// **tailscale 一律缺席**：临时核建不出第二个 tsnet 实例，且会与主核抢同一份 tailscale-state。
///
/// **变异锁**：删掉这条腿 → `testable` 多出 ts 节点、`tailscale` 列表空 → 两条断言全红。
/// 那不是「多测一个」——它会去写主核的登录态目录，把用户已登录的 TS 节点写坏。
#[test]
fn plan_excludes_tailscale_nodes() {
    let plan = plan_temp_core(
        &[
            srv("a1111111", Protocol::Vless),
            srv("t1111111", Protocol::Tailscale),
        ],
        &env(),
    );
    assert_eq!(plan.testable.len(), 1);
    assert_eq!(plan.testable[0].id, "a1111111");
    assert_eq!(plan.tailscale, vec!["t1111111".to_string()]);
}

/// **naive 缺 cronet → 缺席**（进核会预初始化 FATAL 拖垮**整批**，不是只坏它自己）。
/// **变异锁**：删掉 `!env.has_cronet` 判据 → naive 节点进 testable → 转红。
#[test]
fn plan_excludes_naive_when_cronet_missing() {
    let mut e = env();
    e.has_cronet = false;
    let plan = plan_temp_core(
        &[
            srv("n1111111", Protocol::Naive),
            srv("v1111111", Protocol::Vless),
        ],
        &e,
    );
    assert_eq!(plan.unusable, vec!["n1111111".to_string()]);
    assert_eq!(plan.testable.len(), 1);
}

/// cronet 可用时 naive 照常进核（预筛不得误伤正常路径）。
#[test]
fn plan_keeps_naive_when_cronet_available() {
    let plan = plan_temp_core(&[srv("n1111111", Protocol::Naive)], &env());
    assert_eq!(plan.testable.len(), 1);
    assert!(plan.unusable.is_empty());
}

/// **tag 碰撞消歧**：两个 id 前 8 位相同的节点 → 各拿一个唯一 tag，**都照常进核测**。
///
/// 旧行为是「后来者出局记 `unusable`」。而 id **不保证是 uuid**：手输/导入常见 `mynode-a1` /
/// `mynode-a2`，前 8 位逐字相同 ⇒ 碰撞是**确定性**的，那个节点于是每次都以笼统的 `notInPool`
/// 缺席、用户无从修复（他不知道要去改 id 的前 8 位）。
///
/// **变异锁**：① 退回「后来者出局」→ `testable.len()` / `unusable` 两条断言转红；② 干脆不消歧
/// （两个同 tag 出站）→ tag 互异断言转红，真机则是核启动 FATAL ⇒ **整批**一个都测不成。
#[test]
fn plan_disambiguates_colliding_tags_instead_of_dropping_the_node() {
    let plan = plan_temp_core(
        &[
            srv("dup00000-a", Protocol::Vless),
            srv("dup00000-b", Protocol::Vless),
            srv("dup00000-c", Protocol::Vless),
        ],
        &env(),
    );
    assert_eq!(plan.testable.len(), 3, "碰撞不得让任何节点出局");
    assert!(plan.unusable.is_empty(), "碰撞不再是「不可用」");
    let tags: Vec<&str> = plan.testable.iter().map(|n| n.tag.as_str()).collect();
    assert_eq!(
        tags,
        vec!["out-dup00000", "out-dup00000-2", "out-dup00000-3"],
        "碰撞按序号消歧（同 tag 两个出站 ⇒ 核启动 FATAL）"
    );
    // 入站路由键 `in-<tag>` 随之互异 —— 否则两个入站同 tag，同样 FATAL。
    assert_eq!(
        tags.iter().collect::<BTreeSet<_>>().len(),
        3,
        "tag 必须两两互异"
    );
}

/// **构造失败 → 缺席**（WG 缺 privateKey）。绝不放半截出站进核。
/// **变异锁**：把构造失败腿改成「塞个空 outbound 进去」→ `testable` 非空 → 转红。
#[test]
fn plan_reports_build_failure_as_unusable() {
    let plan = plan_temp_core(&[srv("w1111111", Protocol::Wireguard)], &env());
    assert!(plan.testable.is_empty(), "缺 wireguardSettings 应构造失败");
    assert_eq!(plan.unusable, vec!["w1111111".to_string()]);
}

/// 构造失败后 tag 必须**归还**：否则同 tag 的下一个（能建成的）节点会被误判成碰撞而白白出局。
/// **变异锁**：删掉 `seen_tags.remove(&tag)` → 第二个节点落进 unusable → 转红。
#[test]
fn plan_returns_tag_slot_when_build_failed() {
    let plan = plan_temp_core(
        &[
            srv("dup00000-w", Protocol::Wireguard), // 构造必失败
            srv("dup00000-v", Protocol::Vless),     // 同 tag，但能建成
        ],
        &env(),
    );
    assert_eq!(plan.testable.len(), 1);
    assert_eq!(plan.testable[0].id, "dup00000-v");
}

/// 出站里的 `detour` 必须剥掉：链式前置节点的 tag 在临时核里不存在 ⇒ 留着必 FATAL。
/// **变异锁**：删掉 `obj.remove("detour")` → 断言转红。
#[test]
fn plan_strips_detour_from_outbound() {
    let mut s = srv("d1111111", Protocol::Vless);
    s.detour = Some("some-other-node".to_string());
    let plan = plan_temp_core(&[s], &env());
    assert_eq!(plan.testable.len(), 1);
    assert!(
        plan.testable[0].node.get("detour").is_none(),
        "detour 指向临时核里不存在的 tag ⇒ 核启动 FATAL ⇒ 整批测不成"
    );
}

/// 停核测速必须继承真实连接使用的显式网卡；ShadowTLS 的绑定要落在真正拨号的外层，不能留在
/// Shadowsocks 内层。否则测速与连接会走不同出口，所得数值没有决策价值。
#[test]
fn plan_applies_explicit_bindings_to_the_physical_dialer() {
    use polaris_config_engine::user_config::protocol_settings::{
        OpenconnectSettings, ShadowTlsSettings, ShadowsocksSettings,
    };

    let plain = srv("plain111", Protocol::Vless);
    let vpn = ServerConfig {
        id: "vpn11111".into(),
        name: "VPN".into(),
        protocol: Protocol::Openconnect,
        openconnect_settings: Some(Box::new(OpenconnectSettings {
            server: Some("vpn.example.com:443".into()),
            ..Default::default()
        })),
        ..Default::default()
    };
    let mut shadow = srv("shadow11", Protocol::Shadowsocks);
    shadow.shadowsocks_settings = Some(Box::new(ShadowsocksSettings {
        method: "aes-128-gcm".into(),
        password: "inner-secret".into(),
        ..Default::default()
    }));
    shadow.shadow_tls_settings = Some(ShadowTlsSettings {
        password: "secret".into(),
        sni: "tls.example.com".into(),
        fingerprint: Some("Chrome".into()),
        port: Some(8443),
    });
    let bindings = BTreeMap::from([
        (plain.id.clone(), "eth-plain".to_string()),
        (vpn.id.clone(), "eth-vpn".to_string()),
        (shadow.id.clone(), "eth-shadow".to_string()),
    ]);
    let plan = plan_temp_core_with_bindings(&[plain, vpn, shadow], &env(), &bindings);
    assert_eq!(plan.testable.len(), 3);

    assert_eq!(plan.testable[0].node["bind_interface"], json!("eth-plain"));
    assert_eq!(plan.testable[1].node["bind_interface"], json!("eth-vpn"));
    assert!(plan.testable[1].is_endpoint);

    let shadow = &plan.testable[2];
    assert!(shadow.node.get("bind_interface").is_none());
    assert_eq!(shadow.node["detour"], json!("stls-out-shadow11"));
    assert_eq!(shadow.companion_outbounds.len(), 1);
    let outer = &shadow.companion_outbounds[0];
    assert_eq!(outer["type"], json!("shadowtls"));
    assert_eq!(outer["server_port"], json!(8443));
    assert_eq!(outer["tls"]["utls"]["fingerprint"], json!("chrome"));
    assert_eq!(outer["bind_interface"], json!("eth-shadow"));

    let config = build_temp_core_config(&plan.testable, &[20001, 20002, 20003], "warn");
    assert!(config["outbounds"]
        .as_array()
        .is_some_and(|items| items.iter().any(|item| item["tag"] == outer["tag"])));
}

/// 真内核静态验收：ShadowTLS 复合出站 + 显式网卡必须被随包 sing-box 接受。
///
/// 运行示例：
/// `POLARIS_SINGBOX_PATH="$PWD/resources/linux/sing-box" POLARIS_TEST_INTERFACE=eno1 cargo test -p polaris --bin polaris real_core_accepts_bound_shadow_tls_temp_config -- --ignored --nocapture`
#[tokio::test]
#[ignore = "真机验证：需 POLARIS_SINGBOX_PATH 与 POLARIS_TEST_INTERFACE；非 CI 门"]
async fn real_core_accepts_bound_shadow_tls_temp_config() {
    let _real_core_guard = crate::runtime::REAL_CORE_TEST_LOCK.lock().await;
    use polaris_config_engine::user_config::protocol_settings::{
        ShadowTlsSettings, ShadowsocksSettings,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    let core = PathBuf::from(
        std::env::var("POLARIS_SINGBOX_PATH")
            .expect("POLARIS_SINGBOX_PATH 必须指向待验收的真实 sing-box"),
    );
    assert!(core.is_file(), "sing-box 不存在：{}", core.display());
    let interface = std::env::var("POLARIS_TEST_INTERFACE")
        .expect("POLARIS_TEST_INTERFACE 必须是本机真实 InterfaceAlias/接口名");
    let mut server = srv("shadow-real", Protocol::Shadowsocks);
    server.shadowsocks_settings = Some(Box::new(ShadowsocksSettings {
        method: "aes-128-gcm".into(),
        password: "inner-secret".into(),
        ..Default::default()
    }));
    server.shadow_tls_settings = Some(ShadowTlsSettings {
        password: "shape-only-secret".into(),
        sni: "tls.example.com".into(),
        fingerprint: Some("Chrome".into()),
        port: Some(8443),
    });
    let plan = plan_temp_core_with_bindings(
        &[server],
        &env(),
        &BTreeMap::from([("shadow-real".into(), interface)]),
    );
    let config = build_temp_core_config(&plan.testable, &[39191], "warn");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "polaris-shadowtls-check-{}-{nonce}.json",
        std::process::id()
    ));
    tokio::fs::write(&path, serde_json::to_vec_pretty(&config).unwrap())
        .await
        .expect("write temporary config");
    let result = SingBoxConfigChecker.check(&core, &path).await;
    let _ = tokio::fs::remove_file(&path).await;
    result.expect("真实 sing-box 必须接受临时测速配置");
}

// ══════════════════════════════════════════════════════════════════════════
// build_temp_core_config：临时核配置形状。每条盯一个「核起不来 / 数值属于别人」的面。
// ══════════════════════════════════════════════════════════════════════════

fn plain_nodes() -> Vec<TempNode> {
    plan_temp_core(
        &[
            srv("a1111111", Protocol::Vless),
            srv("b1111111", Protocol::Trojan),
        ],
        &env(),
    )
    .testable
}

/// **入站↔端口↔出站三者逐位 1:1**。这是本模块最致命的不变式：错位一格 ⇒ 量到的是**别的节点**的
/// 延迟并挂在这个节点名下（失真数值，比测不了更糟）。
///
/// **变异锁**：把 `zip` 换成对 ports 的独立索引 / 把 route 规则的 outbound 写成固定 tag → 转红。
#[test]
fn config_binds_inbound_port_and_outbound_one_to_one() {
    let nodes = plain_nodes();
    let cfg = build_temp_core_config(&nodes, &[20001, 20002], "warn");
    let inbounds = cfg["inbounds"].as_array().unwrap();
    assert_eq!(inbounds.len(), 2);
    assert_eq!(inbounds[0]["listen_port"], json!(20001));
    assert_eq!(inbounds[1]["listen_port"], json!(20002));
    assert_eq!(inbounds[0]["listen"], json!("127.0.0.1"), "只许监听回环");
    let rules = cfg["route"]["rules"].as_array().unwrap();
    for (i, node) in nodes.iter().enumerate() {
        assert_eq!(rules[i]["outbound"], json!(node.tag));
        assert_eq!(rules[i]["inbound"][0], json!(format!("in-{}", node.tag)));
    }
}

/// 必有 `direct` 出站（sing-box 启动要求）+ `default_domain_resolver` 指向 dns-direct。
/// **变异锁**：删掉任一 → 核启动 FATAL / 节点域名解析不了 → 整批 -1。
#[test]
fn config_has_direct_outbound_and_default_resolver() {
    let cfg = build_temp_core_config(&plain_nodes(), &[20001, 20002], "warn");
    let outbounds = cfg["outbounds"].as_array().unwrap();
    assert!(outbounds.iter().any(|o| o["type"] == json!("direct")));
    assert_eq!(cfg["route"]["default_domain_resolver"], json!("dns-direct"));
    assert_eq!(cfg["dns"]["servers"][0]["tag"], json!("dns-direct"));
}

/// **endpoint 腿的 VPN 客户端必须进 `endpoints[]`** —— 塞进 `outbounds[]` 内核 decode 阶段判
/// `unknown outbound type`，**整个临时核起不来**，同批被测的其它节点一并测不成。
///
/// 判据故意走 `plan_temp_core` 全链路而不是直接构造 `TempNode`：主核与临时核必须共同调用
/// `build_vpn_client_endpoint`，否则临时核很容易只留下 `type/tag` 空壳。手搓
/// `TempNode { is_endpoint: true }` 会绕开构造路径，无法锁住 server/port/TLS 载荷。
///
/// **变异锁**：删掉 VPN 客户端专用构造腿，或丢掉 endpoint 载荷 ⇒ 本条转红。
#[test]
fn endpoint_leg_vpn_clients_go_into_endpoints_not_outbounds() {
    use polaris_config_engine::user_config::protocol_settings::{
        OpenconnectSettings, OpenvpnClientSettings, OpenvpnTlsSettings,
    };
    let servers = vec![
        ServerConfig {
            id: "oc111111".into(),
            name: "OC".into(),
            protocol: Protocol::Openconnect,
            openconnect_settings: Some(Box::new(OpenconnectSettings {
                server: Some("vpn.example.com:443".into()),
                ..Default::default()
            })),
            ..Default::default()
        },
        ServerConfig {
            id: "ov111111".into(),
            name: "OV".into(),
            protocol: Protocol::OpenvpnClient,
            openvpn_client_settings: Some(Box::new(OpenvpnClientSettings {
                server: Some("vpn.example.com".into()),
                server_port: Some(1194),
                tls: Some(OpenvpnTlsSettings::default()),
                ..Default::default()
            })),
            ..Default::default()
        },
    ];
    let plan = plan_temp_core(&servers, &env());
    assert_eq!(plan.testable.len(), 2, "两个节点都该可测");
    for n in &plan.testable {
        assert!(
            n.is_endpoint,
            "{} 没被判成 endpoint 腿 —— 它会被塞进临时核的 outbounds[]",
            n.tag
        );
    }
    let cfg = build_temp_core_config(&plan.testable, &[20001, 20002], "warn");
    assert_eq!(
        cfg["endpoints"].as_array().map(Vec::len),
        Some(2),
        "两个 VPN 客户端都必须落 endpoints[]"
    );
    let ob_types: Vec<&str> = cfg["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|o| o["type"].as_str())
        .collect();
    assert!(
        !ob_types.contains(&"openconnect") && !ob_types.contains(&"openvpn-client"),
        "它们出现在 outbounds[] 里 ⇒ 内核 unknown outbound type，整核起不来。实得 {ob_types:?}"
    );
    let endpoints = cfg["endpoints"].as_array().unwrap();
    assert_eq!(endpoints[0]["server"], json!("vpn.example.com:443"));
    assert_eq!(endpoints[1]["server"], json!("vpn.example.com"));
    assert_eq!(endpoints[1]["server_port"], json!(1194));
    assert!(
        endpoints[1].get("tls").is_some(),
        "OpenVPN TLS 载荷不得丢失"
    );
    assert!(
        cfg["route"].get("auto_detect_interface").is_none(),
        "无 TUN 的临时核必须保留 OS 逐目的路由"
    );
}

#[test]
fn vpn_client_without_settings_is_excluded_before_temp_core_start() {
    for protocol in [Protocol::Openconnect, Protocol::OpenvpnClient] {
        let node = ServerConfig {
            id: format!("missing-{protocol:?}"),
            name: "missing settings".into(),
            protocol,
            ..Default::default()
        };
        let plan = plan_temp_core(std::slice::from_ref(&node), &env());
        assert!(plan.testable.is_empty());
        assert_eq!(plan.unusable, vec![node.id]);
    }
}

/// **纯代理配置零端点噪声**：没有端点节点时不得下发 `endpoints[]` / `dns.rules`
/// （空数组会让核对 schema 更挑剔，且掩盖「到底有没有端点」这件事）。
/// **变异锁**：无条件写 `endpoints`/`dns.rules` → 转红。
#[test]
fn config_omits_endpoint_sections_for_plain_proxies() {
    let cfg = build_temp_core_config(&plain_nodes(), &[20001, 20002], "warn");
    assert!(cfg.get("endpoints").is_none());
    assert!(cfg["dns"].get("rules").is_none());
}

/// **不得引入 sniff / 目标域名的本地解析**（issue #154 的两类解析不变量之一）：
/// 代理出站的目标域名必须 `ATYP=domain` 透传给出口远程解析，否则所有节点测的是同一条本机解析路径。
///
/// **变异锁**：加 `"sniff": true` 或给 route 规则加 `domain_strategy` → 转红。
#[test]
fn config_never_enables_sniff_or_local_target_resolution() {
    let cfg = build_temp_core_config(&plain_nodes(), &[20001, 20002], "warn");
    let raw = serde_json::to_string(&cfg).unwrap();
    assert!(
        !raw.contains("sniff"),
        "sniff 会破坏「目标域名由出口远程解析」不变量"
    );
    assert!(
        !raw.contains("domain_strategy"),
        "针对目标的本地解析会把各节点测成同一条本机路径"
    );
}

/// 日志级别透传（诊断态抬级用）。变异（硬编码 warn）→ 转红。
#[test]
fn config_passes_through_log_level() {
    let cfg = build_temp_core_config(&plain_nodes(), &[1, 2], "debug");
    assert_eq!(cfg["log"]["level"], json!("debug"));
}

/// 端点节点：进 `endpoints[]` + 配一条**按 inbound 键控**的穿隧道 DNS 规则（`disable_cache` 必开）。
///
/// **变异锁**：① 把端点塞进 `outbounds` → `endpoints` 缺失转红；② 删掉 dns.rules → 转红
/// （端点目标解析回落本机 geo IP，境外出口够不着 → 全批超时）；③ 关掉 `disable_cache` → 转红
/// （多端点并测时共享缓存互相污染，量到的是别人出口解析出来的 IP）。
#[test]
fn config_wires_endpoint_nodes_with_tunneled_dns() {
    let node = TempNode {
        id: "e1111111".to_string(),
        tag: "out-e1111111".to_string(),
        node: json!({ "type": "wireguard", "tag": "out-e1111111" }),
        companion_outbounds: Vec::new(),
        is_endpoint: true,
        has_local_v6: false,
    };
    let cfg = build_temp_core_config(&[node], &[20001], "warn");
    assert_eq!(cfg["endpoints"].as_array().unwrap().len(), 1);
    // 纯 v4 端点：rules[0] 是 AAAA 抑制（见下一条），route 规则排在它**后面**。
    let rule = &cfg["dns"]["rules"][1];
    assert_eq!(rule["inbound"][0], json!("in-out-e1111111"));
    assert_eq!(rule["server"], json!("dns-exit-out-e1111111"));
    assert_eq!(rule["disable_cache"], json!(true));
    // 穿隧道 DNS server 必须 detour 到本端点 tag（否则查询从本机发，等于没穿隧道）。
    let exit = cfg["dns"]["servers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["tag"] == json!("dns-exit-out-e1111111"))
        .expect("端点必须配自己的穿隧道 DNS server");
    assert_eq!(exit["detour"], json!("out-e1111111"));
}

/// 🔴 **纯 v4 端点：AAAA 前置一条 `predefined` 空 NOERROR，且必须排在 route 规则之前**
/// （旧 legacy `strategy: ipv4_only` 的等价写法，1:1 上游 `0875f66`(#334)）。
///
/// 顺序有牙：DNS 规则先匹配先命中，route 规则是该 inbound 的 catch-all —— 抑制规则排它后面则
/// AAAA 先被 route 吃掉、抑制**静默失效**，而配置照样通过 `sing-box check`。
///
/// **变异锁**：① 删掉抑制规则 → 长度断言红；② 两条规则顺序颠倒 → 顺序断言红；
/// ③ 键名写错（`query_types` / `rcode` 拼错）→ 形状断言红。
#[test]
fn config_suppresses_aaaa_before_routing_for_v4_only_endpoints() {
    let node = TempNode {
        id: "e1111111".to_string(),
        tag: "out-e1111111".to_string(),
        node: json!({ "type": "wireguard", "tag": "out-e1111111" }),
        companion_outbounds: Vec::new(),
        is_endpoint: true,
        has_local_v6: false,
    };
    let cfg = build_temp_core_config(&[node], &[20001], "warn");
    let rules = cfg["dns"]["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 2, "纯 v4 端点 = 抑制规则 + route 规则");
    assert_eq!(
        rules[0],
        json!({
            "inbound": ["in-out-e1111111"],
            "query_type": ["AAAA"],
            "action": "predefined",
            "rcode": "NOERROR",
        }),
        "抑制规则形状必须逐字对齐（键名写错 = 静默失效）"
    );
    assert_eq!(
        rules[1]["action"],
        json!("route"),
        "抑制规则必须排在同 inbound 的 route（catch-all）之前，否则 AAAA 先被 route 吃掉"
    );
}

/// WG 本地地址含 v6 → **不下发任何族别偏好**（等价旧 `prefer_ipv4`：无顶层 strategy 时内核默认
/// 并发 A/AAAA 且 v4 排前）。对齐 上游 `:868-877`。
///
/// **变异锁**：把抑制规则无条件下发（丢掉 `!node.has_local_v6` 判据）→ 规则数变 2 → 转红；
/// 那在真机上的后果是双栈 WG 端点的 v6 解析被砍掉。
#[test]
fn config_emits_no_family_preference_for_dual_stack_endpoints() {
    let node = TempNode {
        id: "e2222222".to_string(),
        tag: "out-e2222222".to_string(),
        node: json!({ "type": "wireguard" }),
        companion_outbounds: Vec::new(),
        is_endpoint: true,
        has_local_v6: true,
    };
    let cfg = build_temp_core_config(&[node], &[20001], "warn");
    let rules = cfg["dns"]["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 1, "含 v6 的端点只有 route 规则，无抑制规则");
    assert_eq!(rules[0]["action"], json!("route"));
}

/// 🔴 **全配置禁 1.16 DNS 旧形态**：legacy rule-action `strategy` 与未启用
/// `match_response` 的 address-filter。前者与同一份 DNS 配置内任何
/// 带 `query_type`/`ip_version` 的规则**互斥**，共存即 `initialize dns router` FATAL —— 而
/// `check` 静默放行，我们起核前那道 check 抓不到）。
///
/// **前置断言防平凡通过**：先证明本配置**确实**含 `query_type`（否则「无 strategy」这条在一个空
/// 规则集上恒真、门是假的），再用 config-engine 的同一个上下文谓词断言零命中。
///
/// **变异锁**：把 `"strategy": ...` 写回任一规则 → 转红；偷加顶层 `dns.strategy` → 转红。
#[test]
fn temp_core_dns_never_sets_a_legacy_or_top_level_strategy() {
    use polaris_config_engine::legacy_keys::removed_in_1_16_config_paths;

    let node = TempNode {
        id: "e1111111".to_string(),
        tag: "out-e1111111".to_string(),
        node: json!({ "type": "wireguard", "tag": "out-e1111111" }),
        companion_outbounds: Vec::new(),
        is_endpoint: true,
        has_local_v6: false,
    };
    let cfg = build_temp_core_config(&[node], &[20001], "warn");
    let raw = serde_json::to_string(&cfg["dns"]).unwrap();
    assert!(
        raw.contains("query_type"),
        "前置断言：本配置必须确实带 query_type，否则下面的「禁 strategy」是空集平凡通过"
    );
    let hits = removed_in_1_16_config_paths(&cfg);
    assert!(
        hits.is_empty(),
        "临时核配置命中 1.16 DNS 旧形态：{hits:?}\n{raw}"
    );
    assert!(
        cfg["dns"].get("strategy").is_none(),
        "顶层 dns.strategy 是「省略 == prefer_ipv4」这条等价性的前提，不得下发"
    );
}

// ══════════════════════════════════════════════════════════════════════════
// 让位判据 + 分批。
// ══════════════════════════════════════════════════════════════════════════

/// 主核没起、没在起、世代未变 → 未让位（正常临时核测速全程走这条，误判即一个节点都测不成）。
///
/// **反向变异锁**：把判据写成恒真（或多加一条恒真的腿）→ 本测转红。没有这条，下面三条「必要性」
/// 断言可以被一个 `true` 全部满足。
#[test]
fn temp_core_not_superseded_when_main_core_absent() {
    assert!(!is_temp_core_superseded(7, 7, false, false));
}

/// 🔴 **第一腿（世代）的必要性**：只有世代跃迁（用户点了连接 / 停止），另两腿都为假。
///
/// 交错窗口：`start` 已 bump 完世代且核已**停**（stop→start 序列 / 起核失败回落）——此刻
/// `running` 与 `starting` 都可能是 false，唯一可见的证据就是世代变了。
/// **变异锁**：删掉 `gen_now != gen0` 这条腿 → 本测转红。
#[test]
fn temp_core_superseded_on_generation_change_alone() {
    assert!(is_temp_core_superseded(8, 7, false, false));
}

/// 🔴 **第二腿（running）的必要性**：主核**已经跑起来了**，而世代与本次基准相同、也不在启动中。
///
/// 交错窗口：bump 发生在本次取 `gen0` **之前**（那一刻 running 还是 false，核在启动中），随后核就绪
/// ⇒ running 翻真、starting 归假、世代不再动。三腿里只剩这一条能看见主核。
/// **变异锁**：删掉 `running` 腿 → 本测转红；真机表现是**两个核并存**跑同一批 WG/WARP peer
/// （上游 G1 的双会话超时事故）。
#[test]
fn temp_core_superseded_once_main_core_is_running_alone() {
    assert!(is_temp_core_superseded(7, 7, true, false));
}

/// 🔴 **第三腿（starting）的必要性**：主核**正在启动**——世代已 bump 完（⇒ 与本次 `gen0` 相同）、
/// 核尚未就绪（⇒ `running == false`）。前两腿在这一整段里**同时**为假。
///
/// 窗口有多宽：`ProxyRuntime::start` 的顺序是 `start_inflight+1`（`starting` 的源）→ **stale 清扫
/// （真机可达数秒）** → `bump_generation` → spawn → 就绪门（最长 10s 级）。用户点「连接」后紧接点
/// 测速（或托盘/另一窗口点——UI 灰态拦不住跨窗）就确定性落在这段里。
///
/// **变异锁**：删掉 `starting` 腿 → 本测转红；真机表现有两层：① 临时核与启动中的主核同 peer 双会话
/// 踢线；② 临时核端口只排除 control/http/mixed，会抢走主核刚解析、尚未 bind 的 api/update-in/probe
/// 池口 ⇒ 主核起核 FATAL address-in-use（用户看到的是「连接失败」）。
#[test]
fn temp_core_superseded_while_main_core_is_starting_alone() {
    assert!(is_temp_core_superseded(7, 7, false, true));
}

// ══════════════════════════════════════════════════════════════════════════
// drive_temp_core_measures：滑动窗口调度 + 让位三检查点（全注入，无进程无网络）。
//
// 此前这里还有 `plan_temp_batches`（纯逻辑切批）的两条单测。批屏障换成滑动窗口后**没有批这个
// 概念了**，那个函数与它的两条测试一并删除 —— 不是放宽，是把断言下移到真正的调度器上：
//  · 「N/limit 切批」→ 由 `never_exceeds_the_concurrency_limit`（真实在飞峰值 ≤ 上限）替代，
//    这条比切批断言强：它测的是实际并发，而切批只测了一个不再被消费的纯函数；
//  · 「limit==0 退化成 1、绝不吞掉节点」→ 由 `zero_concurrency_degrades_to_serial_not_to_nothing`
//    保留同名同义，只是从「测 plan 的返回值」改成「测 drive 真的把每个节点都测了」。
// ══════════════════════════════════════════════════════════════════════════

/// 按「第几次询问」脚本化让位信号（0 = 从不让位）。
fn superseded_at(trip: usize) -> impl Fn() -> bool {
    let calls = AtomicUsize::new(0);
    move || {
        let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
        trip != 0 && n >= trip
    }
}

fn three_nodes() -> Vec<TempNode> {
    ["a1111111", "b1111111", "c1111111"]
        .iter()
        .map(|id| TempNode {
            id: (*id).to_string(),
            tag: temp_core_tag(id),
            node: json!({}),
            companion_outbounds: Vec::new(),
            is_endpoint: false,
            has_local_v6: false,
        })
        .collect()
}

/// 全程未让位 → 全部节点有结果 + `completed` + 每节点恰一条 result/progress。
/// 这是「让位检查不得误伤正常路径」的基准。
#[tokio::test]
async fn measures_all_nodes_when_never_superseded() {
    let mut events: Vec<String> = Vec::new();
    let (results, outcome) = drive_temp_core_measures(
        &three_nodes(),
        &[1, 2, 3],
        2,
        &superseded_at(0),
        |_| async { Some(120_u32) },
        &mut |ev, _| events.push(ev.to_string()),
    )
    .await;
    assert_eq!(outcome, "completed");
    assert_eq!(results.len(), 3);
    assert_eq!(results["a1111111"], json!(120));
    assert_eq!(
        events
            .iter()
            .filter(|e| *e == EVENT_SPEED_TEST_RESULT)
            .count(),
        3
    );
    assert_eq!(
        events
            .iter()
            .filter(|e| *e == EVENT_SPEED_TEST_PROGRESS)
            .count(),
        3
    );
}

/// **真实超时仍记 -1**（测不通是真的）→ 让位检查不得把它吞成缺席。
/// 与下一条成对：把「真实 -1」与「让位缺席」钉成两种结局，正是本腿诚实性的全部意义。
#[tokio::test]
async fn genuine_timeout_is_recorded_as_minus_one() {
    let (results, outcome) = drive_temp_core_measures(
        &three_nodes(),
        &[1, 2, 3],
        8,
        &superseded_at(0),
        |_| async { None },
        &mut |_, _| {},
    )
    .await;
    assert_eq!(outcome, "completed");
    assert_eq!(results["a1111111"], json!(-1));
}

/// 让位①（发新活之前）：第 1 次询问即让位 → 一个节点都不测、零**逐节点**事件、`interrupted`。
///
/// # 断言从「零事件」改成「零逐节点事件 + 恰一条终态事件」的理由
///
/// 本条原文是 `events.is_empty()`。终态事件（2026-07-31 B 批）落地后，**中断路径恰恰必须发一条**
/// —— 原断言留着等于禁止本批的核心行为。守的那条诚实性根基不变：逐节点 result/progress 一条不许有。
/// 顺带钉住载荷：一个都没测 ⇒ `pending` 必须是**全集**（这也是续测的输入）。
#[tokio::test]
async fn interrupts_before_dispatching_without_measuring() {
    let mut events: Vec<(String, Value)> = Vec::new();
    let (results, outcome) = drive_temp_core_measures(
        &three_nodes(),
        &[1, 2, 3],
        8,
        &superseded_at(1),
        |_| async { Some(120_u32) },
        &mut |ev, payload| events.push((ev.to_string(), payload)),
    )
    .await;
    assert_eq!(outcome, "interrupted");
    assert!(results.is_empty(), "让位下未测节点必须缺席，绝不写假 -1");
    assert!(
        events
            .iter()
            .all(|(ev, _)| ev != EVENT_SPEED_TEST_RESULT && ev != EVENT_SPEED_TEST_PROGRESS),
        "让位轮不得推逐节点事件：{events:?}"
    );
    let done: Vec<&Value> = events
        .iter()
        .filter(|(ev, _)| ev == EVENT_SPEED_TEST_DONE)
        .map(|(_, p)| p)
        .collect();
    assert_eq!(done.len(), 1, "中断也必须**恰好**发一条终态事件");
    assert_eq!(done[0]["outcome"], json!("interrupted"));
    assert_eq!(done[0]["tested"], json!(0));
    assert_eq!(
        done[0]["serverIds"],
        json!(["a1111111", "b1111111", "c1111111"]),
        "重新测速必须拿到本轮原始范围"
    );
    assert_eq!(
        done[0]["pending"],
        json!(["a1111111", "b1111111", "c1111111"]),
        "一个都没测 ⇒ pending 必须是全集"
    );
}

/// 让位②（测量后）：在飞期间主核起来 → 丢弃在飞值（它与主核抢同一条 peer 会话，数值不可信）。
///
/// **变异锁**：删掉这道检查 → 那批值被写进 results、outcome 变 completed → 两条断言全红。
/// 最危险的假绿形态：双会话下测量多半失败，`None → -1` 恰好「看起来很合理」。
#[tokio::test]
async fn discards_in_flight_values_when_main_core_arrives() {
    let (results, outcome) = drive_temp_core_measures(
        &three_nodes(),
        &[1, 2, 3],
        8,
        &superseded_at(2), // 批首过、测量后命中
        |_| async { Some(999_u32) },
        &mut |_, _| {},
    )
    .await;
    assert_eq!(outcome, "interrupted");
    assert!(results.is_empty(), "跨核在飞值必须丢弃，不得写入结果集");
}

/// 前两个节点正常、第三个之前让位 → 已测部分**保留**，未测缺席。中断 ≠ 丢弃已拿到的真值。
///
/// **trip 编号随调度形态变化（不是放宽门槛）**：3 节点 / 窗口 2 的询问序列是
/// `发活①(补 a,b) → 节点a → 发活②(补 c) → 节点b → 节点c`，第 5 次落在**节点 c 测完那一刻**
/// ⇒ c 的值被丢弃、a/b 保留。命中语义与改前逐字相同：先测完的两个留下，第三个缺席。
#[tokio::test]
async fn keeps_measured_prefix_on_later_interruption() {
    let (results, outcome) = drive_temp_core_measures(
        &three_nodes(),
        &[1, 2, 3],
        2,
        &superseded_at(5),
        |_| async { Some(120_u32) },
        &mut |_, _| {},
    )
    .await;
    assert_eq!(outcome, "interrupted");
    assert_eq!(results.len(), 2, "先测完的两个节点应保留");
    assert!(!results.contains_key("c1111111"), "最后一个未落账 → 缺席");
}

/// 🔴 **worker 池（滑动窗口）而非批屏障**：一个慢节点只占住 1/K 的算力，绝不把整批钉死。
///
/// 这是 S2 的**收益本体**。批屏障下 `Σ 每批最大值` —— 一个 8s 的死节点让同批 15 个健康节点也等
/// 8s；worker 池下界是 `max(单点最坏, 总功/K)`，死节点只堵一个槽。f=0.2/K=16 时「每批至少一个
/// 死节点」的概率是 0.97 ⇒ 几乎每批都被封顶，两者相差 W=⌈N/K⌉ 倍。
///
/// 构造：窗口 2，节点① 慢（400ms），节点②③④ 秒回。滑动窗口下 ②③④ 全部在 ① 之前回来；
/// 批屏障下 ③④ 属第二批，必须等 ① 收尾 ⇒ 落在 ① 之后。
/// **变异锁**：改回 `plan_temp_batches` 批屏障 → `slow-done` 跑到 ③④ 前面 → 转红。
#[tokio::test]
async fn a_slow_node_does_not_block_the_rest_of_the_queue() {
    let nodes: Vec<TempNode> = ["s1111111", "f2222222", "f3333333", "f4444444"]
        .iter()
        .map(|id| TempNode {
            id: (*id).to_string(),
            tag: temp_core_tag(id),
            node: json!({}),
            companion_outbounds: Vec::new(),
            is_endpoint: false,
            has_local_v6: false,
        })
        .collect();
    let log = Arc::new(Mutex::new(Vec::<String>::new()));
    let mlog = Arc::clone(&log);
    let elog = Arc::clone(&log);
    let (results, outcome) = drive_temp_core_measures(
        &nodes,
        &[1, 2, 3, 4],
        2, // 窗口 2：慢节点占住一个槽，另一个槽必须继续轮转
        &superseded_at(0),
        move |port| {
            let mlog = Arc::clone(&mlog);
            async move {
                if port == 1 {
                    tokio::time::sleep(Duration::from_millis(400)).await;
                    mlog.lock().unwrap().push("slow-done".to_string());
                }
                Some(120_u32)
            }
        },
        &mut |ev, payload| {
            if ev == EVENT_SPEED_TEST_RESULT {
                let id = payload["serverId"].as_str().unwrap().to_string();
                elog.lock().unwrap().push(format!("emit:{id}"));
            }
        },
    )
    .await;

    assert_eq!(outcome, "completed");
    assert_eq!(results.len(), 4, "四个节点全部要有结果");
    let log = log.lock().unwrap();
    let slow = log
        .iter()
        .position(|l| l == "slow-done")
        .expect("慢节点必须测完");
    for id in ["f3333333", "f4444444"] {
        let fast = log
            .iter()
            .position(|l| *l == format!("emit:{id}"))
            .unwrap_or_else(|| panic!("{id} 必须回填"));
        assert!(
            fast < slow,
            "队尾的健康节点必须在慢节点之前测完（批屏障会让它等满一整批）：{log:?}"
        );
    }
}

/// 🔴 **在飞并发不得超过窗口上限**：不设上限时大订阅会把 N 路 TLS/QUIC 握手同时打出去
/// → 本机 CPU/连接数打满 → 一批**假超时**（节点其实是好的）。
///
/// **变异锁**：把补位条件里的 `set.len() < window` 去掉（一次性全 spawn）→ 峰值 6 > 2 → 转红。
#[tokio::test]
async fn never_exceeds_the_concurrency_limit() {
    let nodes: Vec<TempNode> = ["n1111111", "n2222222", "n3333333", "n4444444", "n5555555"]
        .iter()
        .map(|id| TempNode {
            id: (*id).to_string(),
            tag: temp_core_tag(id),
            node: json!({}),
            companion_outbounds: Vec::new(),
            is_endpoint: false,
            has_local_v6: false,
        })
        .collect();
    let live = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let peak = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (m_live, m_peak) = (Arc::clone(&live), Arc::clone(&peak));
    let (results, outcome) = drive_temp_core_measures(
        &nodes,
        &[1, 2, 3, 4, 5],
        2,
        &superseded_at(0),
        move |_| {
            let (live, peak) = (Arc::clone(&m_live), Arc::clone(&m_peak));
            async move {
                let now = live.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(20)).await;
                live.fetch_sub(1, Ordering::SeqCst);
                Some(120_u32)
            }
        },
        &mut |_, _| {},
    )
    .await;

    assert_eq!(outcome, "completed");
    assert_eq!(results.len(), 5, "全部节点都要测到");
    assert!(
        peak.load(Ordering::SeqCst) <= 2,
        "在飞峰值 {} 超过窗口上限 2",
        peak.load(Ordering::SeqCst)
    );
}

/// `concurrency == 0` 必须退化成 1，**绝不一个都不测**（零事件 ⇒ 前端测速按钮永久卡灰）。
/// **变异锁**：去掉 `.max(1)` → 窗口恒 0、一个都不 spawn、`results` 空 → 转红。
#[tokio::test]
async fn zero_concurrency_degrades_to_serial_not_to_nothing() {
    let (results, outcome) = drive_temp_core_measures(
        &three_nodes(),
        &[1, 2, 3],
        0,
        &superseded_at(0),
        |port| async move { Some(u32::from(port)) },
        &mut |_, _| {},
    )
    .await;
    assert_eq!(outcome, "completed");
    assert_eq!(results.len(), 3, "0 并发是配置错误，不是「不测」的意思");
    assert_eq!(results["a1111111"], json!(1), "串行也不得让结果与端口错位");
}

/// 🔴 **让位②（在飞轮询）：supersede 命中即 `abort_all` + 立刻返回，不等在飞测量收尾。**
///
/// **本腿守的是真事故面**：窗口里的节点全部不可达时，「发新活之前」与「每节点测完」两个检查点
/// 一个都醒不过来 —— 信号出现后临时核（**及其已建立的 WG/WARP 会话**）还要活满一整个测量超时，
/// 与启动中的主核同 peer 双会话踢线、并抢主核尚未 bind 的端口。Linux/macOS 靠主核 `start()` 入口
/// 的 stale sweep 顺带杀掉——那是副作用缓解、不是设计保证；Windows 无 sweep
/// （`scan_running_cores` 恒返空）⇒ 全程重叠。
///
/// 牙：删掉 `Err(_elapsed)` 那条轮询臂（或把 `timeout(poll, join_next())` 换回裸 `join_next()`）
/// → 本测的**时限**断言转红：注入的测量要 30s 才结束，而本测只给 5s。
#[tokio::test]
async fn aborts_in_flight_measurements_instead_of_waiting_for_them() {
    let started = std::time::Instant::now();
    let out = tokio::time::timeout(
        Duration::from_secs(5),
        drive_temp_core_measures(
            &three_nodes(),
            &[1, 2, 3],
            8,
            // 发活（第 1 次询问）放行 → 全部进入在飞；在飞轮询（第 2 次）命中。
            &superseded_at(2),
            // 测量 30s 不返回：只有真 abort 才能让本函数在 5s 内收场。
            |_| async {
                tokio::time::sleep(Duration::from_secs(30)).await;
                Some(120_u32)
            },
            &mut |_, _| {},
        ),
    )
    .await
    .expect("在飞让位必须中断在飞测量：等它收尾 = 临时核与主核重叠一整个测量超时");
    let (results, outcome) = out;
    assert_eq!(outcome, "interrupted");
    assert!(
        results.is_empty(),
        "被中断的在飞测量必须缺席，绝不补 -1（让位未测 ≠ 真实超时）"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "必须在轮询间隔量级内返回，而不是等满 30s 的在飞测量"
    );
}

/// 在飞轮询**不得误伤正常路径**：从不让位时，全部节点照常测完（轮询只是旁路）。
#[tokio::test]
async fn in_flight_polling_does_not_disturb_slow_but_uninterrupted_measurements() {
    let (results, outcome) = drive_temp_core_measures(
        &three_nodes(),
        &[1, 2, 3],
        8,
        &superseded_at(0),
        // 比轮询间隔长 → 至少触发一次轮询，且必须不影响结果。
        |port| async move {
            tokio::time::sleep(Duration::from_millis(TEMP_CORE_SUPERSEDE_POLL_MS + 120)).await;
            Some(u32::from(port))
        },
        &mut |_, _| {},
    )
    .await;
    assert_eq!(outcome, "completed");
    assert_eq!(results.len(), 3);
    assert_eq!(results["a1111111"], json!(1), "轮询不得让结果与端口错位");
}

/// 🔴 **逐节点回填**：先测完的节点必须在**其它节点还在飞**的时候就上屏。
///
/// 按批统一回填时，首个延迟数字要等整批最慢的那个（一批里有一个死节点就是一个完整超时），
/// 屏幕先空十几秒。总耗时一点没变，主观耗时天差地别（差异分析 R3）。
///
/// **变异锁**：改回「先 drain 完整批 → 收集循环统一 emit」→ `emit:a1111111` 落到 `c-measured`
/// 之后 → 转红。
#[tokio::test]
async fn reports_each_node_as_soon_as_it_finishes() {
    let log = Arc::new(Mutex::new(Vec::<String>::new()));
    let mlog = Arc::clone(&log);
    let elog = Arc::clone(&log);
    let (_results, outcome) = drive_temp_core_measures(
        &three_nodes(),
        &[1, 2, 3],
        8,
        &superseded_at(0),
        move |port| {
            let mlog = Arc::clone(&mlog);
            async move {
                // 第三个节点慢：它还没回来时，第一个节点的结果就必须已经推出去了。
                if port == 3 {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    mlog.lock().unwrap().push("c-measured".to_string());
                }
                Some(120_u32)
            }
        },
        &mut |ev, payload| {
            if ev == EVENT_SPEED_TEST_RESULT {
                let id = payload["serverId"].as_str().unwrap().to_string();
                elog.lock().unwrap().push(format!("emit:{id}"));
            }
        },
    )
    .await;

    assert_eq!(outcome, "completed");
    let log = log.lock().unwrap();
    let emit_a = log
        .iter()
        .position(|l| l == "emit:a1111111")
        .expect("首个节点必须回填");
    let c_done = log
        .iter()
        .position(|l| l == "c-measured")
        .expect("慢节点必须测完");
    assert!(
        emit_a < c_done,
        "首个节点的结果必须在慢节点回来之前就上屏（实际顺序：{log:?}）"
    );
}

/// 🔴 **进度计数恒单调**：`tested` 严格 1,2,…,N，`ok` 非降。
///
/// 前端 `NodesScreen` 靠 `tested >= total` 复位测速灰态 —— 计数一旦回退或跳号，要么按钮永久卡灰，
/// 要么进度条倒着走。**变异锁**：把 `tested` 改成按批内下标计算（或在 emit 之后才自增）→ 转红。
#[tokio::test]
async fn progress_counter_is_strictly_monotonic() {
    let mut tested_seq: Vec<i64> = Vec::new();
    let mut ok_seq: Vec<i64> = Vec::new();
    let (_results, outcome) = drive_temp_core_measures(
        &three_nodes(),
        &[1, 2, 3],
        2, // 跨批也必须连续计数
        &superseded_at(0),
        |port| async move {
            if port == 1 {
                None // 真实超时 → -1，不计入 ok
            } else {
                Some(120_u32)
            }
        },
        &mut |ev, payload| {
            if ev == EVENT_SPEED_TEST_PROGRESS {
                tested_seq.push(payload["tested"].as_i64().unwrap());
                ok_seq.push(payload["ok"].as_i64().unwrap());
            }
        },
    )
    .await;

    assert_eq!(outcome, "completed");
    assert_eq!(tested_seq, vec![1, 2, 3], "tested 必须严格递增且不跳号");
    assert!(
        ok_seq.windows(2).all(|w| w[1] >= w[0]),
        "ok 必须非降：{ok_seq:?}"
    );
}

/// **端口按节点索引取**：并发乱序回收不得让结果与端口错位。
/// 注入「端口 → 延迟」的一一映射，断言每个节点拿到的正是**自己**那个端口的值。
///
/// **变异锁**：把 `measure(ports[*i])` 换成 `ports[0]` / 用批内序号取端口 → 转红。
/// 这条盯的是本模块最贵的失真面：数值属于别的节点。
#[tokio::test]
async fn each_node_measures_through_its_own_port() {
    let (results, _) = drive_temp_core_measures(
        &three_nodes(),
        &[10, 20, 30],
        8,
        &superseded_at(0),
        |port| async move { Some(u32::from(port)) },
        &mut |_, _| {},
    )
    .await;
    assert_eq!(results["a1111111"], json!(10));
    assert_eq!(results["b1111111"], json!(20));
    assert_eq!(results["c1111111"], json!(30));
}

// ══════════════════════════════════════════════════════════════════════════
// TempCoreSession：起核 → 就绪门 → 编排 → **无条件收尾**（mock spawner，无真进程）。
// ══════════════════════════════════════════════════════════════════════════

/// 假瞬态核：记录 terminate 次数，永不真起进程。
struct FakeChild {
    terminated: Arc<AtomicUsize>,
    /// 假 pid（`None` = 取不到 → 就绪门 is_alive 恒真）。仅退出清理登记表那条测试用。
    pid: Option<u32>,
}

#[async_trait]
impl LoginCoreChild for FakeChild {
    fn pid(&self) -> Option<u32> {
        // 默认 None → pid=0 → 就绪门的 is_alive 恒真（假核不死），把判定压到 is_ready 那条腿上
        self.pid
    }
    fn take_stdout(&mut self) -> Option<Box<dyn tokio::io::AsyncRead + Unpin + Send>> {
        None
    }
    fn take_stderr(&mut self) -> Option<Box<dyn tokio::io::AsyncRead + Unpin + Send>> {
        None
    }
    async fn wait(&mut self) {}
    async fn terminate(&mut self) {
        self.terminated.fetch_add(1, Ordering::SeqCst);
    }
}

struct FakeSpawner {
    terminated: Arc<AtomicUsize>,
    spawns: Arc<AtomicUsize>,
    fail: bool,
    child_pid: Option<u32>,
}

impl LoginCoreSpawner for FakeSpawner {
    fn spawn(
        &self,
        _req: &SpawnRequest,
    ) -> Result<Box<dyn LoginCoreChild>, polaris_core_supervisor::SpawnError> {
        self.spawns.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(polaris_core_supervisor::SpawnError::Spawn {
                bin: PathBuf::from("/nonexistent"),
                source: std::io::Error::from(std::io::ErrorKind::NotFound),
            });
        }
        Ok(Box::new(FakeChild {
            terminated: Arc::clone(&self.terminated),
            pid: self.child_pid,
        }))
    }
}

/// 假 `sing-box check`：`ok=false` 模拟核判定配置无效（**绝不**真起 sing-box）。
struct FakeChecker {
    ok: bool,
}

#[async_trait]
impl ConfigChecker for FakeChecker {
    async fn check(
        &self,
        _binary: &std::path::Path,
        _config: &std::path::Path,
    ) -> Result<(), String> {
        if self.ok {
            Ok(())
        } else {
            Err("sing-box check 判定测速配置无效: bad custom outbound".to_string())
        }
    }
}

struct Harness {
    deps: TempCoreDeps,
    terminated: Arc<AtomicUsize>,
    spawns: Arc<AtomicUsize>,
    dir: PathBuf,
}

/// 造一个全 mock 的会话依赖：假 spawner + 假 check + 假核路径 + 确定性端口 + 可控就绪。
/// **零真进程、零网络**（`probe_port` 是纯闭包，绝不 connect；`checker` 不 exec 任何东西）。
fn harness(ready: bool, spawn_fail: bool, ports: Vec<u16>) -> Harness {
    harness_with_pid(ready, spawn_fail, ports, None)
}

/// 同 [`harness`]，但给假核一个 pid（退出清理登记表那条测试用；其余一律 `None`）。
fn harness_with_pid(
    ready: bool,
    spawn_fail: bool,
    ports: Vec<u16>,
    child_pid: Option<u32>,
) -> Harness {
    let dir = std::env::temp_dir().join(format!(
        "polaris-tempcore-test-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let terminated = Arc::new(AtomicUsize::new(0));
    let spawns = Arc::new(AtomicUsize::new(0));
    let fake_bin = dir.join("fake-sing-box");
    std::fs::write(&fake_bin, b"#!/bin/sh\n").unwrap();
    Harness {
        deps: TempCoreDeps {
            spawner: Arc::new(FakeSpawner {
                terminated: Arc::clone(&terminated),
                spawns: Arc::clone(&spawns),
                fail: spawn_fail,
                child_pid,
            }),
            checker: Arc::new(FakeChecker { ok: true }),
            resolve_binary: Arc::new(move || Ok(fake_bin.clone())),
            config_dir: dir.clone(),
            allocate_ports: Arc::new(move |n| ports.iter().copied().take(n).collect()),
            probe_port: Arc::new(move |_| ready),
            log_level: "warn".to_string(),
            ready_timeout_ms: 400,
        },
        terminated,
        spawns,
        dir,
    }
}

static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);

fn cleanup(dir: &PathBuf) {
    let _ = std::fs::remove_dir_all(dir);
}

/// 正常路径：起核 → 就绪 → 测完 → **杀核 + 删配置**。
///
/// **变异锁**：删掉 `child.terminate()` → `terminated == 0` 转红（真机表现 = 孤儿 sing-box 常驻，
/// 占着 N 个回环端口且用户完全看不见）；删掉 `remove_temp_config` → 配置文件残留断言转红。
#[tokio::test]
async fn session_kills_core_and_removes_config_on_success() {
    let h = harness(true, false, vec![20001, 20002, 20003]);
    let nodes = three_nodes();
    let out = TempCoreSession::run(
        &h.deps,
        &nodes,
        &|| false,
        |_| async { Some(50_u32) },
        &mut |_, _| {},
    )
    .await;
    match out {
        TempCoreOutcome::Ran { results, outcome } => {
            assert_eq!(outcome, "completed");
            assert_eq!(results.len(), 3);
        }
        other => panic!("应跑完，得到 {other:?}"),
    }
    assert_eq!(h.terminated.load(Ordering::SeqCst), 1, "临时核必须被杀");
    assert!(
        !h.dir.join(TEMP_CORE_CONFIG_NAME).exists(),
        "临时配置必须删掉（残留会让下次导出诊断报告读到一份不属于任何在跑核的配置）"
    );
    cleanup(&h.dir);
}

/// 配置**落的是独立文件**，绝不是主核的 `singbox-runtime.json`。
///
/// **变异锁**：把文件名改成 `singbox-runtime.json` → 转红。那会在主核起来前**覆盖掉主核的运行配置**，
/// 表现为「测完速再点连接，代理行为莫名其妙」——归因极难。
#[test]
fn temp_config_name_is_isolated_from_the_main_core() {
    assert_eq!(TEMP_CORE_CONFIG_NAME, "speedtest-core.json");
    assert_ne!(TEMP_CORE_CONFIG_NAME, "singbox-runtime.json");
}

/// 就绪门失败 → 杀核 + **整批一个数值都不产出**（核没起来 ≠ 每个节点都超时）。
///
/// **变异锁**：把未就绪腿改成「给每个节点记 -1」→ 本测转红：那是伪造 N 次真实测量。
#[tokio::test]
async fn session_reports_failure_without_faking_results_when_not_ready() {
    let h = harness(false, false, vec![20001, 20002, 20003]);
    let out = TempCoreSession::run(
        &h.deps,
        &three_nodes(),
        &|| false,
        |_| async { Some(50_u32) },
        &mut |_, _| {},
    )
    .await;
    assert!(matches!(out, TempCoreOutcome::Failed(_)), "得到 {out:?}");
    assert_eq!(h.terminated.load(Ordering::SeqCst), 1, "未就绪也必须杀核");
    assert!(!h.dir.join(TEMP_CORE_CONFIG_NAME).exists());
    cleanup(&h.dir);
}

/// **起核前就让位 → 根本不 spawn**（双会话从源头掐掉，而不是起了再杀）。
/// **变异锁**：删掉起核前那道检查 → `spawns == 1` 转红。
#[tokio::test]
async fn session_never_spawns_when_already_superseded() {
    let h = harness(true, false, vec![20001, 20002, 20003]);
    let out = TempCoreSession::run(
        &h.deps,
        &three_nodes(),
        &|| true,
        |_| async { Some(50_u32) },
        &mut |_, _| {},
    )
    .await;
    assert!(matches!(out, TempCoreOutcome::Superseded), "得到 {out:?}");
    assert_eq!(h.spawns.load(Ordering::SeqCst), 0, "让位态绝不许起临时核");
    cleanup(&h.dir);
}

/// **端口不够 → 整批失败，绝不部分起核**：槽↔端口 1:1 一旦错位，量到的就是别的节点的延迟。
/// **变异锁**：把等长断言放宽成 `ports.len() >= 1` → 转红。
#[tokio::test]
async fn session_fails_atomically_when_ports_are_short() {
    let h = harness(true, false, vec![20001]); // 只给 1 个，需 3 个
    let out = TempCoreSession::run(
        &h.deps,
        &three_nodes(),
        &|| false,
        |_| async { Some(50_u32) },
        &mut |_, _| {},
    )
    .await;
    assert!(matches!(out, TempCoreOutcome::Failed(_)), "得到 {out:?}");
    assert_eq!(h.spawns.load(Ordering::SeqCst), 0, "端口不齐就不该起核");
    cleanup(&h.dir);
}

/// **配置形态非法 → 根本不 spawn**，且 check 的诊断**原文冒泡**（那句话里写着哪个字段错了）。
///
/// 唯一不由本仓完全掌控的配置片段是 `custom` 协议的用户原样 JSON。没有这道 fail-fast 门时，用户看到
/// 的是就绪门那句「10s 内未监听」—— 把「你的自定义节点 JSON 写错了」误报成「网络/端口有问题」，
/// 还白等 10 秒。
///
/// **变异锁**：删掉 `deps.checker.check(...)` 那段 → `spawns == 1` + outcome 变成就绪失败 → 转红。
#[tokio::test]
async fn session_rejects_invalid_config_before_spawning() {
    let mut h = harness(true, false, vec![20001, 20002, 20003]);
    h.deps.checker = Arc::new(FakeChecker { ok: false });
    let out = TempCoreSession::run(
        &h.deps,
        &three_nodes(),
        &|| false,
        |_| async { Some(50_u32) },
        &mut |_, _| {},
    )
    .await;
    match out {
        TempCoreOutcome::Failed(e) => assert!(
            e.contains("bad custom outbound"),
            "check 的诊断必须原文冒泡（吞成通用文案 = 用户无从知道哪个字段错了），得到：{e}"
        ),
        other => panic!("非法配置应 fail-fast，得到 {other:?}"),
    }
    assert_eq!(h.spawns.load(Ordering::SeqCst), 0, "配置无效就不该起核");
    assert!(!h.dir.join(TEMP_CORE_CONFIG_NAME).exists());
    cleanup(&h.dir);
}

/// spawn 失败 → 失败信封 + **临时配置照样删掉**（残留文件会被诊断导出当成在跑核的配置）。
#[tokio::test]
async fn session_cleans_up_config_when_spawn_fails() {
    let h = harness(true, true, vec![20001, 20002, 20003]);
    let out = TempCoreSession::run(
        &h.deps,
        &three_nodes(),
        &|| false,
        |_| async { Some(50_u32) },
        &mut |_, _| {},
    )
    .await;
    assert!(matches!(out, TempCoreOutcome::Failed(_)), "得到 {out:?}");
    assert!(!h.dir.join(TEMP_CORE_CONFIG_NAME).exists());
    cleanup(&h.dir);
}

/// 空节点集 → 不起核、不失败（调用方本不该进来；防御性返 completed 空）。
#[tokio::test]
async fn session_is_noop_for_empty_node_set() {
    let h = harness(true, false, vec![]);
    let out = TempCoreSession::run(
        &h.deps,
        &[],
        &|| false,
        |_| async { Some(1_u32) },
        &mut |_, _| {},
    )
    .await;
    assert!(matches!(out, TempCoreOutcome::Ran { .. }));
    assert_eq!(h.spawns.load(Ordering::SeqCst), 0);
    cleanup(&h.dir);
}

/// 🔵 **结构守卫**：生产装配必须复用主核的 `resolve_core_binary`，绝不另写一份核路径解析。
///
/// 另写一份的失效方式是静默的：换核（core-swap）后主核用新核、临时核仍指旧核路径 ⇒ 测速结果来自
/// 一个**版本不同**的内核，而两边都「能跑」。
///
/// 🔴 **二次封顶**：`top_level_fn_body` 按**列 0** 的 `\n}\n` 收尾，对 `production` 这种 4 空格缩进
/// 的方法实际扫到的是 `impl TempCoreDeps` 的结尾。将来在该 impl 里追加任何含 `resolve_core_binary`
/// 字样的方法，本守卫就会**照绿**（哪怕 `production` 自己已经不再复用它）。故在此把切片再收到
/// 「下一个同级方法之前」，把判据钉回 `production` **自己的**函数体。
#[test]
fn production_deps_reuse_the_main_core_binary_resolver() {
    let src = crate_source("runtime/speedtest.rs");
    // 取材器换成 `impl_method_body`（按 `"\n    }\n"` 封顶，正是为 impl 方法设计的）。
    // 此前这里用的是 `top_level_fn_body` + 手搓的二次封顶：那个组合能工作，但它是在**错误的
    // 工具**上打补丁 —— 同一形态在 `proxy/tests/mod.rs` 上没打补丁，于是切出了 98 倍超宽片
    // 与一个可证明的假绿。补丁不该各写各的，封顶要由取材器自己负责。
    let body = crate::commands::guard_scan::impl_method_body(
        &src,
        "    pub fn production(config_dir: PathBuf",
    );
    // 自检：封顶真的生效（切片里不得混进同 impl 的下一个方法）。
    assert!(
        !body.contains("\n    pub fn "),
        "封顶失效：切片里混进了同 impl 的其它方法 ⇒ 下面的断言可被「删这里、加那里」骗过"
    );
    assert!(
        body.contains("crate::runtime::proxy::resolve_core_binary"),
        "临时核必须与主核共用同一份核二进制解析（另写一份 ⇒ 换核后两边指向不同内核，静默）"
    );
    assert!(
        body.contains("resolve_distinct_free_ports"),
        "端口必须走 core-supervisor 的批分配（自己 bind 一圈会丢掉排除集，撞主核端口）"
    );
}

// ══════════════════════════════════════════════════════════════════════════
// 在飞临时核 pid 表（应用退出清理的收口）。**任何一条都不对真实进程发信号**。
// ══════════════════════════════════════════════════════════════════════════

/// pid 表是**进程级**共享状态 ⇒ 触碰它的用例必须串行，否则彼此排空对方的登记。
static REGISTRY_LOCK: Mutex<()> = Mutex::new(());

fn registry_guard() -> MutexGuard<'static, ()> {
    REGISTRY_LOCK.lock().unwrap_or_else(PoisonError::into_inner)
}

/// 🔴 会话必须把在飞 pid 登记进表（**退出清理唯一能杀到它的途径**），并在收尾时注销。
///
/// 为什么不能只靠 child 的 `Drop` 守卫：应用退出走 `ExitRequested → run_exit_cleanup → 进程退出`，
/// 在飞的 tokio task **根本不会被 drop** ⇒ Drop 守卫够不着 ⇒ 留下持有 N 个回环端口 + WG peer 会话
/// 的孤儿 sing-box（Windows 无 stale sweep 兜底，永不被清）。
///
/// 牙：① 删掉 `TempCorePidGuard::register(pid)` → 在飞断言转红；② 把守卫换成裸 insert（不注销）
/// → 收尾断言转红（表里留着死 pid，退出时可能误杀一个 pid 复用的无关进程）。
///
/// 用**本进程自己的 pid** 当假核 pid：就绪门的 `is_alive` 需要一个真存活的 pid，而本测**只读**表、
/// 绝不调用发信号的那条路径（`kill_inflight_temp_cores`）。
// `await_holding_lock`：`REGISTRY_LOCK` 是**测试串行闸**，语义上就必须罩住整个 async 测试体
// （否则并发的排空用例会把本测登记的 pid 抽走）。不会死锁：`#[tokio::test]` 默认单线程运行时，
// 而另一个持锁者是普通同步 `#[test]`（跑在别的线程上），两边各自推进；换 async Mutex 反而要求
// 同步那条用例也变 async，为一个纯串行闸把射程搞大。
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn session_registers_inflight_pid_so_app_exit_cleanup_can_reach_it() {
    let _lock = registry_guard();
    let self_pid = std::process::id();
    let h = harness_with_pid(true, false, vec![20001, 20002, 20003], Some(self_pid));
    let seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let probe = Arc::clone(&seen);
    let out = TempCoreSession::run(
        &h.deps,
        &three_nodes(),
        &|| false,
        move |_| {
            let probe = Arc::clone(&probe);
            async move {
                if temp_core_pids().contains(&self_pid) {
                    probe.store(true, Ordering::SeqCst);
                }
                Some(50_u32)
            }
        },
        &mut |_, _| {},
    )
    .await;
    assert!(matches!(out, TempCoreOutcome::Ran { .. }), "得到 {out:?}");
    assert!(
        seen.load(Ordering::SeqCst),
        "测量在飞期间 pid 必须在表里 —— 否则应用退出时清理路径根本看不见这个核"
    );
    assert!(
        !temp_core_pids().contains(&self_pid),
        "会话收尾必须注销 pid（留着 = 退出时对一个已死 pid 发信号，pid 复用即误杀无关进程）"
    );
    cleanup(&h.dir);
}

/// 排空语义：逐 pid 收割一次 + 计数 + **幂等**（第二次调用返 0，绝不重复发信号）。
///
/// 收割动作经注入闭包 ⇒ 零真实信号。假 pid 取 `> i32::MAX`：即便有人把它接到真 `send_signal` 上，
/// `checked_pid` 也会挡掉（负数 pid 是 kill 的**广播**语义 —— 那是全场 SIGKILL）。
#[test]
fn kill_inflight_temp_cores_drains_table_once_and_counts_each_pid() {
    let _lock = registry_guard();
    let fake: u32 = 0xDEAD_BEEF;
    temp_core_pids().insert(fake);
    let mut killed: Vec<u32> = Vec::new();
    let n = kill_temp_cores_with(|pid| killed.push(pid));
    assert_eq!(n, killed.len(), "返回值必须等于实际收割条数");
    assert!(killed.contains(&fake), "在飞 pid 必须被收割");
    // 幂等：表已排空 → 再调零收割（重复发信号 = 对复用了该 pid 的无关进程动手）。
    let mut again: Vec<u32> = Vec::new();
    assert_eq!(kill_temp_cores_with(|pid| again.push(pid)), 0);
    assert!(again.is_empty());
}

/// 🔵 **调用点守卫**：退出生命周期 owner 必须真的调 [`kill_inflight_temp_cores`]。
///
/// 没有这条，「登记了 pid」与「退出时会被杀」之间是断的，而断了的表现**恰好是静默的**：
/// 用户看不到孤儿核，只在下次起核时莫名 address-in-use（Windows 连那次兜底都没有）。
/// 牙：把 `exit_lifecycle::run_exit_cleanup` 里那行删掉 / 挪出该函数 → 转红。
#[test]
fn app_exit_cleanup_kills_inflight_temp_cores() {
    let body = crate::commands::guard_scan::top_level_fn_body(
        &crate_source("exit_lifecycle.rs"),
        "fn run_exit_cleanup(",
    );
    assert!(
            body.contains("kill_inflight_temp_cores()"),
            "退出清理必须收掉在飞测速临时核：它不在 ProxyRuntime 的任何生命周期槽里，proxy.stop() 碰不到它"
        );
}
