//! 订阅 URL 安全校验 + 拉取 + 解析调度（Polaris SubscriptionService 的纯逻辑切片 1:1 移植）。
//!
//! 纯逻辑：真实 HTTP 请求由注入的 [`crate::safe_redirect::HttpClient`] trait 承载（测试 mock /
//! 本地 HTTP server，不触碰宿主网络）。职责：
//! - [`fetch_subscription_full`]：起始 URL 协议校验 + SSRF guard + safe-redirect-fetch（逐跳复检）
//!   + HTTP 状态校验 + 体积闸，**返回正文文本**。
//! - [`parse_subscription`]：判定格式（Clash / sing-box JSON / base64 / url-list）后分发解析；
//!   Clash 走 [`crate::clash_parser`]，其余格式由调用方（运行时层）按需扩展。
//! - 错误分类见 [`crate::subscription_error`]（审计 §C4）。
//!
//! proxy-providers 在本层完成“并发拉取、按声明序解析”的编排；真实 HTTP 与超时仍由运行时注入。
//! 这样网络等待取最慢一项而非逐项相加，同时保持节点顺序与 ID 分配顺序稳定。
//!
//! **已移植**：条件 GET（`If-None-Match` / `If-Modified-Since` → 304 短路，见 [`Conditional`] 与
//! [`fetch_subscription_with_meta`]）与 `subscription-userinfo`（流量/到期元数据，见
//! [`parse_user_info`] / [`SubscriptionUserInfo`]）。304 **不再**归
//! [`SubscriptionErrorKind::Http`]，而是短路成 `not_modified=true` —— 且带 fail-safe：
//! 本次未发条件头却收 304 一律不认（见 `fetch_core` 步骤 3.5）。

#![forbid(unsafe_code)]

use url::Url;

use polaris_config_engine::user_config::server_config::ServerConfig;

use crate::clash_parser::{self, ClashParseResult};
use crate::safe_redirect::{
    safe_redirect_fetch, HttpClient, SafeFetchRejectReason, SafeRedirectFetchOptions,
};
use crate::singbox_import::ImportOrigin;
use crate::ssrf::DnsLookup;
use crate::subscription_error::{
    classify_subscription_error, SubscriptionErrorKind, SubscriptionErrorSignal,
};

/// 订阅响应体上限（10 MB）。上游 `SubscriptionService.MAX_BODY_BYTES` 同口径，
/// 与 `local_import_parse` 的体积闸一致（同一份正文，两条入口不该有两个阈值）。
///
/// 双闸：content-length 预检（早拒）+ 读取侧字节累计（content-length 可缺失/撒谎）。
/// 兼作 YAML 锚点炸弹的输入面收窄。
pub const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;

/// 主订阅拉取超时（30s）。上游 `MAIN_FETCH_TIMEOUT_MS`。
/// 防 slow-loris 挂死拉取流水线（scheduler `isRunning` 永真 → 后续更新全卡）。
pub const MAIN_FETCH_TIMEOUT_MS: u64 = 30_000;

/// proxy-provider 拉取超时（15s，比主订阅紧）。Polaris provider 编排口径。
pub const PROVIDER_FETCH_TIMEOUT_MS: u64 = 15_000;

/// 默认订阅 UA：中性 `Polaris/<version>`（不带 clash.meta/mihomo 标识）。
///
/// **勿用于 GitHub API / 资源下载**：带版本号会泄漏客户端指纹，那条链路应使用应用自标识 UA。
pub fn default_subscription_user_agent(version: &str) -> String {
    format!("Polaris/{version}")
}

/// 订阅流量/到期元数据（`Subscription-UserInfo` 响应头解析）。上游 `SubscriptionConfig['userInfo']`。
///
/// 字节数与到期时间戳均以 `u64` 承载（上游 用 `number`；流量总量可超 `u32`）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SubscriptionUserInfo {
    /// 已上传字节。
    pub upload: Option<u64>,
    /// 已下载字节。
    pub download: Option<u64>,
    /// 总流量字节。
    pub total: Option<u64>,
    /// 到期时间（Unix 秒）。
    pub expire: Option<u64>,
}

impl SubscriptionUserInfo {
    /// 至少解出一个字段才算「有」（对齐 上游 `Object.keys(result).length > 0`）。
    fn is_present(&self) -> bool {
        self.upload.is_some()
            || self.download.is_some()
            || self.total.is_some()
            || self.expire.is_some()
    }

    /// 序列化为前端 `userInfo` 形态（缺省字段不落键，对齐 TS `skip_serializing_if`）。
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        let mut m = serde_json::Map::new();
        if let Some(v) = self.upload {
            m.insert("upload".into(), v.into());
        }
        if let Some(v) = self.download {
            m.insert("download".into(), v.into());
        }
        if let Some(v) = self.total {
            m.insert("total".into(), v.into());
        }
        if let Some(v) = self.expire {
            m.insert("expire".into(), v.into());
        }
        serde_json::Value::Object(m)
    }
}

/// 解析 `Subscription-UserInfo` 头（`upload=..; download=..; total=..; expire=..`）。
///
/// 上游 `SubscriptionService.parseUserInfo` 1:1：分号分段、`key=value`、`parseInt` 容错
/// （非数字段跳过），全缺 → `None`。`parseInt` 语义 = 取前导十进制数字（`"123abc"` → 123），
/// 用 `u64` 承载（负数/溢出 → 跳过该字段，不整体失败）。
#[must_use]
pub fn parse_user_info(header: Option<&str>) -> Option<SubscriptionUserInfo> {
    let header = header?;
    let mut result = SubscriptionUserInfo::default();
    for part in header.split(';') {
        let part = part.trim();
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        let Some(num) = parse_int_prefix(value.trim()) else {
            continue;
        };
        match key.trim() {
            "upload" => result.upload = Some(num),
            "download" => result.download = Some(num),
            "total" => result.total = Some(num),
            "expire" => result.expire = Some(num),
            _ => {}
        }
    }
    result.is_present().then_some(result)
}

/// JS `parseInt(s, 10)` 的窄化：取前导十进制数字（首个非数字截断），无前导数字 → `None`。
/// 机场偶尔在 total 后带单位/注释（`"107374182400 bytes"`）；忠实 `parseInt` 只取数字段。
fn parse_int_prefix(s: &str) -> Option<u64> {
    let digits: String = s.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse::<u64>().ok()
    }
}

/// 条件 GET 验证器（上次 200 响应的 `ETag` / `Last-Modified`）。上游 `{ etag, lastModified }`。
///
/// 缓存验证器非凭据（逐跳携带无泄漏面）；缺省 = 首次/无验证器 → 全量 GET（零回归）。
#[derive(Debug, Clone, Default)]
pub struct Conditional {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

impl Conditional {
    fn has_any(&self) -> bool {
        self.etag.is_some() || self.last_modified.is_some()
    }
}

/// 订阅拉取产出（正文 + 元数据）。上游 `fetchSubscriptionText` 返回体。
///
/// `not_modified=true`（304 命中，仅当本次确实发了条件头）→ `text` 空、调用方短路 parse/reconcile。
#[derive(Debug, Clone, Default)]
pub struct FetchedSubscription {
    pub text: String,
    pub user_info: Option<SubscriptionUserInfo>,
    /// 本次 200 响应的验证器（回写 sub，下次条件 GET 用）。
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    /// 304 Not Modified（条件 GET 命中）。
    pub not_modified: bool,
}

/// 脱敏 URL 供错误文案/日志使用：**去掉 query 与 userinfo**。
///
/// 订阅 token 就在 query 里（`?token=xxx`），原样进错误文案 = 凭据进日志/上报。
/// 上游 `SubscriptionService.redactUrl` 同职责；此处额外清 userinfo（`user:pass@`），
/// 且不走 `origin`——`origin` 对非特殊 scheme（如 `ftp:`）会序列化成 `null`，
/// 而「协议不支持」的错误文案恰恰需要显示原始 scheme 才有诊断价值。
pub fn redact_url(url: &str) -> String {
    match Url::parse(url) {
        Ok(mut u) => {
            let had_query = u.query().is_some();
            u.set_query(None);
            u.set_fragment(None);
            let _ = u.set_username("");
            let _ = u.set_password(None);
            if had_query {
                format!("{u}?<redacted>")
            } else {
                u.to_string()
            }
        }
        // 非法 URL 无法结构化处理：截到 `?` 前兜底去 query。
        Err(_) => match url.find('?') {
            Some(q) => format!("{}?<redacted>", &url[..q]),
            None => url.to_string(),
        },
    }
}

/// 订阅拉取失败。`kind` 在**抛出点**即确定（不回头 re-parse 自己的字符串），
/// `http_status` 仅 [`SubscriptionErrorKind::Http`] 时有值。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionFetchError {
    pub kind: SubscriptionErrorKind,
    pub message: String,
    pub http_status: Option<u16>,
}

impl SubscriptionFetchError {
    fn new(kind: SubscriptionErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            http_status: None,
        }
    }
}

impl std::fmt::Display for SubscriptionFetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for SubscriptionFetchError {}

/// 订阅内容格式探测结果。上游 `ImportFormat`（订阅侧子集）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionFormat {
    /// Clash / mihomo YAML（含 proxies 或 proxy-providers）。
    Clash,
    /// sing-box JSON outbound 数组（outbound 用扁平 `type`）。
    SingboxJson,
    /// Xray / v2ray JSON（outbound 用 `protocol`+`settings`+`streamSettings`）。
    XrayJson,
    /// base64 编码的分享链接列表。
    Base64,
    /// 纯文本分享链接列表（vless://... 等，每行一条）。
    UrlList,
    /// 无法识别。
    Unknown,
}

/// 拉取订阅正文（协议校验 → SSRF guard 逐跳复检 → HTTP 状态校验 → 体积闸 → 正文）。
///
/// **这是拉取流水线拿到正文的唯一入口**，产出直接喂 [`parse_subscription`]。
///
/// 安全与健壮性逐层（顺序即优先级）：
/// 1. **协议闸**：起始 URL 须 http(s) —— `file://`/`ftp://` 直接拒（错误文案带脱敏 URL）。
/// 2. **SSRF guard**：首跳 + **每一跳 Location** 都过 [`crate::ssrf::assert_host_allowed`]
///    （由 [`safe_redirect_fetch`] 内部执行）。首跳单独再 guard 一次是多余的——
///    旧实现那次重复调用已随本次重写移除。`exempt_fake_ip` **仅实际经代理时**传 true。
/// 3. **重定向**：`redirect: manual` 自管链，上限 5 跳（[`safe_redirect_fetch`] 默认）。
/// 4. **HTTP 状态**：非 2xx → [`SubscriptionErrorKind::Http`] 并带 status。
/// 5. **体积闸**：content-length 预检 + 正文字节复检，双闸 [`MAX_BODY_BYTES`]。
///    （实现侧还须在**流式读取**时截断，见 [`FetchInit::max_body_bytes`](crate::safe_redirect::FetchInit::max_body_bytes)——
///    到了这层 body 已在内存里，此闸只是纵深防御，防不住恶意实现。）
/// 6. **超时**：`timeout_ms` 透传实现侧（[`MAIN_FETCH_TIMEOUT_MS`] / [`PROVIDER_FETCH_TIMEOUT_MS`]）。
///
/// 上游 `SubscriptionService.fetchSubscriptionText` 的对位实现。
pub async fn fetch_subscription_full<H: HttpClient, L: DnsLookup>(
    client: &H,
    lookup: &L,
    url: &str,
    user_agent: &str,
    headers: Option<Vec<(String, String)>>,
    exempt_fake_ip: bool,
    timeout_ms: u64,
) -> Result<String, SubscriptionFetchError> {
    // 文本-only 入口（proxy-provider 子拉取等复用同一安全管线，不消费元数据/条件 GET）。
    // conditional=None → 不发条件头 → 304 走非 2xx Http 分支（fail-safe：无验证器不认 304）。
    fetch_core(
        client,
        lookup,
        url,
        user_agent,
        headers,
        None,
        exempt_fake_ip,
        timeout_ms,
    )
    .await
    .map(|f| f.text)
}

/// 拉取订阅正文 **+ 元数据**（`Subscription-UserInfo` 流量/到期 + `ETag`/`Last-Modified` 验证器
/// + 304 条件 GET 短路）。上游 `SubscriptionService.fetchSubscriptionText` 的完整对位。
///
/// 与 [`fetch_subscription_full`] 同一安全管线（协议闸 / SSRF 逐跳 / 状态 / 体积闸），仅额外：
/// - `conditional` 非空 → 发 `If-None-Match` / `If-Modified-Since`；304（**仅当确实发了条件头**）→
///   `not_modified=true`、`text` 空，调用方短路 parse/reconcile（零节点扰动、省流省渲染）。
/// - 200 → 解析 `Subscription-UserInfo`（流量/到期）+ 回传 `etag`/`last-modified` 供回写 sub。
///
/// # Errors
///
/// 协议不支持 / SSRF 拒绝 / 非 2xx（含 304 但**未**发条件头）/ 网络错误 / 体积超限。
pub async fn fetch_subscription_with_meta<H: HttpClient, L: DnsLookup>(
    client: &H,
    lookup: &L,
    url: &str,
    user_agent: &str,
    conditional: Option<&Conditional>,
    exempt_fake_ip: bool,
    timeout_ms: u64,
) -> Result<FetchedSubscription, SubscriptionFetchError> {
    fetch_core(
        client,
        lookup,
        url,
        user_agent,
        None,
        conditional,
        exempt_fake_ip,
        timeout_ms,
    )
    .await
}

/// 拉取管线核心（协议闸 → SSRF 逐跳 → 条件 GET/304 → 状态 → 体积闸 → 元数据）。
///
/// `extra_headers`（provider 子拉取的透传头）与 `conditional`（条件 GET）合并后交
/// [`safe_redirect_fetch`]。`sent_conditional` 仅在实际追加了条件头时为真——用于 304 fail-safe：
/// 未发条件头却收 304（某些 CDN 违规）绝不认作 not_modified（会得空 body→0 节点→误删存量）。
#[allow(clippy::too_many_arguments)]
async fn fetch_core<H: HttpClient, L: DnsLookup>(
    client: &H,
    lookup: &L,
    url: &str,
    user_agent: &str,
    extra_headers: Option<Vec<(String, String)>>,
    conditional: Option<&Conditional>,
    exempt_fake_ip: bool,
    timeout_ms: u64,
) -> Result<FetchedSubscription, SubscriptionFetchError> {
    // 1) 协议闸：仅 http(s)。非法 URL 同归 scheme（用户可见原因一致：地址不对）。
    let parsed = Url::parse(url).map_err(|_| {
        SubscriptionFetchError::new(
            SubscriptionErrorKind::Scheme,
            format!("订阅地址非法: {}", redact_url(url)),
        )
    })?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(SubscriptionFetchError::new(
            SubscriptionErrorKind::Scheme,
            format!(
                "订阅地址协议不支持（仅允许 http/https）: {}",
                redact_url(url)
            ),
        ));
    }

    // 条件 GET 头拼装（缓存验证器非凭据，逐跳携带无泄漏面）。与调用方透传头合并。
    let mut headers = extra_headers.unwrap_or_default();
    let sent_conditional = conditional.is_some_and(Conditional::has_any);
    if let Some(c) = conditional {
        if let Some(etag) = &c.etag {
            headers.push(("If-None-Match".to_string(), etag.clone()));
        }
        if let Some(lm) = &c.last_modified {
            headers.push(("If-Modified-Since".to_string(), lm.clone()));
        }
    }
    let headers = if headers.is_empty() {
        None
    } else {
        Some(headers)
    };

    // 2~3) SSRF guard（首跳 + 逐跳）+ 手动重定向链。
    let response = safe_redirect_fetch(SafeRedirectFetchOptions {
        fetch_impl: client,
        url,
        user_agent: user_agent.to_string(),
        headers,
        exempt_fake_ip,
        max_redirects: None,
        timeout_ms: Some(timeout_ms),
        max_body_bytes: Some(MAX_BODY_BYTES),
        lookup,
    })
    .await
    .map_err(|e| match e.reason {
        // 安全拒绝：原文案冒泡（含 hostname / 解析结果，诊断需要）。
        SafeFetchRejectReason::Ssrf | SafeFetchRejectReason::TooManyRedirects => {
            SubscriptionFetchError::new(SubscriptionErrorKind::Ssrf, e.message)
        }
        SafeFetchRejectReason::RedirectProtocol => {
            SubscriptionFetchError::new(SubscriptionErrorKind::Scheme, e.message)
        }
        // 网络错误：message 不透明（实现侧的 io 错误串）→ 交 §C4 分类器判 dns/timeout/refused。
        SafeFetchRejectReason::Network => {
            let cls = classify_subscription_error(&SubscriptionErrorSignal {
                message: Some(e.message.clone()),
                ..Default::default()
            });
            SubscriptionFetchError {
                kind: cls.kind,
                message: e.message,
                http_status: None,
            }
        }
    })?;

    // 3.5) 条件 GET 命中（304）——**仅当本次确实发了条件头**才认（fail-safe，见函数 doc）。
    //      短路：不读 body、不 parse/reconcile（零节点扰动）；仍回传验证器供刷新。
    if response.status == 304 && sent_conditional {
        return Ok(FetchedSubscription {
            not_modified: true,
            etag: response.header("etag").map(str::to_string),
            last_modified: response.header("last-modified").map(str::to_string),
            ..Default::default()
        });
    }

    // 4) HTTP 状态校验。
    if !(200..300).contains(&response.status) {
        return Err(SubscriptionFetchError {
            kind: SubscriptionErrorKind::Http,
            message: format!("订阅服务器返回 HTTP {}", response.status),
            http_status: Some(response.status),
        });
    }

    // 5) 体积闸：content-length 预检（实现侧若已流式截断则到不了这里；此为纵深防御）。
    if let Some(cl) = response.header("content-length") {
        if let Ok(n) = cl.trim().parse::<usize>() {
            if n > MAX_BODY_BYTES {
                return Err(SubscriptionFetchError::new(
                    SubscriptionErrorKind::TooLarge,
                    format!("订阅响应体积 {n} 字节超过上限 {MAX_BODY_BYTES}，已拒绝"),
                ));
            }
        }
    }
    if response.body.len() > MAX_BODY_BYTES {
        return Err(SubscriptionFetchError::new(
            SubscriptionErrorKind::TooLarge,
            format!(
                "订阅响应体积 {} 字节超过上限 {MAX_BODY_BYTES}，已拒绝",
                response.body.len()
            ),
        ));
    }

    // 6) 元数据：Subscription-UserInfo（流量/到期）+ 验证器（下次条件 GET）。
    let user_info = parse_user_info(response.header("subscription-userinfo"));
    let etag = response.header("etag").map(str::to_string);
    let last_modified = response.header("last-modified").map(str::to_string);

    // 正文：lossy 解码（对齐 上游 `TextDecoder` 语义）。订阅正文是 base64/YAML/JSON（ASCII 面），
    // 为个别坏字节整单失败会把「能用的订阅」判死；坏字节最终由解析层按格式拒。
    Ok(FetchedSubscription {
        text: String::from_utf8_lossy(&response.body).into_owned(),
        user_info,
        etag,
        last_modified,
        not_modified: false,
    })
}

/// 探测订阅内容格式。Polaris 订阅内容格式判定（Clash YAML/JSON / sing-box JSON / xray JSON /
/// base64 / url-list）。**格式判定的单一真值**——`parse_subscription` 与 [`extract_proxy_providers`]
/// 都以它为准，不得各自另判一套（此前 `extract_proxy_providers` 单独判 `is_clash_probe` 就漏了 JSON 编码）。
pub fn detect_format(trimmed: &str) -> SubscriptionFormat {
    let t = trimmed.trim_start();
    // Clash：proxies: 或 proxy-providers: 行。
    if clash_parser::is_clash_probe(t) {
        return SubscriptionFormat::Clash;
    }
    // JSON：sing-box（outbound 用扁平 `type`）/ xray（outbound 用 `protocol`+`settings`，无 `type`）。
    // 二者共用 `outbounds` 键，靠 [`crate::xray_import::looks_like_xray`] 区分（对齐 上游 parseLocalContent
    // 的 `looksXray` 判定）；`endpoints`（wireguard/tailscale）唯 sing-box。
    if t.starts_with('{') || t.starts_with('[') {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(t) {
            if let Some(outbounds) = v.get("outbounds").and_then(serde_json::Value::as_array) {
                return if crate::xray_import::looks_like_xray(outbounds) {
                    SubscriptionFormat::XrayJson
                } else {
                    SubscriptionFormat::SingboxJson
                };
            }
            if v.get("endpoints").is_some() {
                return SubscriptionFormat::SingboxJson;
            }
            // **JSON 编码的 Clash**（`{"proxies":[…]}` / `{"proxy-providers":{…}}`）。少数机场按
            // `Content-Type: application/json` 下发同一份 Clash 配置。判定放在 outbounds/endpoints
            // **之后**，与 上游 `parseLocalContent` 的分支顺序一致（sing-box 优先）。
            // 此前无此分支 → 落 `Unknown` → 用户侧只看到「暂不支持的订阅格式」。
            if clash_parser::is_json_clash(&v) {
                return SubscriptionFormat::Clash;
            }
        }
        // JSON 解析失败但形似 → 保守判 sing-box（其解析分支返回 warning，不误吞进 url-list/base64）。
        if t.contains("\"outbounds\"") || t.contains("\"endpoints\"") {
            return SubscriptionFormat::SingboxJson;
        }
    }
    // url-list：以协议 scheme 开头（vless:// vmess:// ss:// trojan:// ...）。
    let first_line = t.lines().next().unwrap_or("");
    if first_line.contains("://") {
        return SubscriptionFormat::UrlList;
    }
    // base64：尝试解码；含分享链 scheme 即 url-list。
    if let Ok(decoded) = base64_decode(trimmed) {
        if decoded.contains("://") {
            return SubscriptionFormat::Base64;
        }
    }
    SubscriptionFormat::Unknown
}

/// 解析订阅正文（按探测格式分发）。已建：Clash（YAML **与 JSON** 两种编码）/ base64 / url-list /
/// Xray JSON / sing-box JSON。
///
/// - **Clash**：走 [`crate::clash_parser`]（既有实现，不重写）。JSON 编码（`{"proxies":[…]}`）由
///   [`crate::clash_parser::try_load_clash_doc`] 转成 `serde_yaml::Value` 后复用同一条解析路径。
/// - **Base64**：解码后按 url-list 处理（多数机场订阅的实际形态）。
/// - **UrlList**：逐行 [`crate::share_link::parse_share_url`]。
/// - **XrayJson**：outbounds[] 走 [`crate::xray_import::parse_xray_outbounds`]（vmess/vless/trojan/ss）。
/// - **SingboxJson**：`outbounds[]` 走 [`crate::singbox_import::parse_singbox_outbounds`]，
///   **`endpoints[]` 走 [`crate::singbox_import::parse_singbox_endpoints`]**，两者结果合并
///   （两个数组的 type 域不相交，见后者文档）。endpoints-only 的配置（机场下发 WireGuard 组网）
///   此前恒 0 节点，现按 endpoint 建模映射入库。
///
/// `id_gen` 注入 UUID 生成（对齐 Polaris randomUUID）。
/// `origin` 决定未建模 type 是否透传 custom，见 [`ImportOrigin`]。
pub fn parse_subscription(
    trimmed: &str,
    subscription_id: &str,
    now: &str,
    id_gen: &mut impl FnMut() -> String,
    origin: ImportOrigin,
) -> ClashParseResult {
    let format = detect_format(trimmed);
    match format {
        SubscriptionFormat::Clash => {
            let doc = match clash_parser::try_load_clash_doc(trimmed) {
                Ok(d) => d,
                Err(e) => {
                    return ClashParseResult {
                        warnings: vec![e],
                        ..Default::default()
                    };
                }
            };
            let proxies = doc
                .get(serde_yaml::Value::String("proxies".to_string()))
                .cloned()
                .unwrap_or(serde_yaml::Value::Null);
            clash_parser::parse_clash_proxies(&proxies, subscription_id, now, id_gen)
        }
        SubscriptionFormat::UrlList => {
            crate::share_link::parse_url_list(trimmed, subscription_id, now, id_gen)
        }
        SubscriptionFormat::Base64 => match base64_decode(trimmed) {
            Ok(decoded) => {
                crate::share_link::parse_url_list(&decoded, subscription_id, now, id_gen)
            }
            // detect_format 已试解成功才判 Base64，此分支理论不可达；仍不 panic（订阅是外部输入）。
            Err(()) => ClashParseResult {
                warnings: vec!["订阅 base64 解码失败".to_string()],
                ..Default::default()
            },
        },
        SubscriptionFormat::XrayJson => match serde_json::from_str::<serde_json::Value>(trimmed) {
            // detect_format 已确认是含 outbounds 数组的合法 JSON；此处取 outbounds 交 xray 解析器。
            Ok(v) => crate::xray_import::parse_xray_outbounds(
                v.get("outbounds").unwrap_or(&serde_json::Value::Null),
                subscription_id,
                now,
                id_gen,
            ),
            Err(e) => ClashParseResult {
                warnings: vec![format!("Xray JSON 解析失败: {e}")],
                ..Default::default()
            },
        },
        SubscriptionFormat::SingboxJson => match serde_json::from_str::<serde_json::Value>(trimmed)
        {
            // detect_format 已确认形似 sing-box JSON；`outbounds[]` 与 `endpoints[]` 各交对应解析器
            // 后合并 —— 两个数组由内核定义为不相交的 type 域（`wireguard` 作 outbound 已于 1.13 移除、
            // `tailscale` 作 outbound 即 unknown），故不存在同一节点被两条腿各数一次。
            Ok(v) => {
                let null = serde_json::Value::Null;
                let mut r = crate::singbox_import::parse_singbox_outbounds(
                    v.get("outbounds").unwrap_or(&null),
                    subscription_id,
                    now,
                    id_gen,
                    origin,
                );
                let ep = crate::singbox_import::parse_singbox_endpoints(
                    v.get("endpoints").unwrap_or(&null),
                    subscription_id,
                    now,
                    id_gen,
                    origin,
                );
                r.servers.extend(ep.servers);
                r.skipped += ep.skipped;
                r.failed += ep.failed;
                r.warnings.extend(ep.warnings);
                r
            }
            Err(e) => ClashParseResult {
                warnings: vec![format!("sing-box JSON 解析失败: {e}")],
                ..Default::default()
            },
        },
        SubscriptionFormat::Unknown => ClashParseResult {
            warnings: vec![format!("暂不支持的订阅格式: {format:?}")],
            ..Default::default()
        },
    }
}

/// provider 子拉取失败 —— **带永久性分类**。
///
/// # 为什么 `Result<_, String>` 不够（这是修掉的真实缺陷）
///
/// `permanent` 决定该 provider 进不进 `failed_providers`，而 `failed_providers` 非空
/// 会让 reconcile 对**无 `providerName` 的节点**（主正文内联 `proxies` / 迁移前存量）一律保留
/// （见命令层 `leftover_survives_partial` 规则 2）。于是「provider URL **永久**坏掉」
/// （404 / 域名注销 / SSRF 拒绝）会把整条订阅钉死在 partial：
///  - 主正文里**真下架**的内联节点永不删除；
///  - 每轮更新都判「内容变了」→ 每轮 save + 广播 `config:changed` → 每轮整核评估 + 前端全量重渲染。
///
/// 分类判据（由运行时层填，那里才有 HTTP 状态/错误种类）：
///  - `permanent = true`：重试不会变好 —— 4xx（404/403/410…）、SSRF guard 拒绝、URL 非法/协议不支持。
///    仅 warn，**不**置 `any_failed` → 该 provider 名下节点按真下架正常删除（它确实拿不回来了）。
///  - `permanent = false`：瞬时 —— 超时、连不上、5xx、正文解析失败（WAF 错误页可能下轮就好）。
///    置 `any_failed` + 进 `failed_providers` → 该 provider 名下存量**保留**，防穿仓。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderFetchError {
    pub message: String,
    /// `true` = 重试不转好（不触发 merge-only 保护）；`false` = 瞬时（触发 merge-only 保护）。
    pub permanent: bool,
}

impl ProviderFetchError {
    /// 瞬时失败（默认方向：**宁滞留不误删**）。
    #[must_use]
    pub fn transient(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            permanent: false,
        }
    }

    /// 永久失败（重试不转好 → 不保护存量）。
    #[must_use]
    pub fn permanent(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            permanent: true,
        }
    }
}

impl std::fmt::Display for ProviderFetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// 注入的正文拉取闭包类型（返回 boxed future，便于运行时层包装 safe-redirect-fetch + read body）。
pub type FetchTextFn = Box<
    dyn Fn(
            &str,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<String, ProviderFetchError>> + Send>,
        > + Send
        + Sync,
>;

/// 拉取并解析单个 proxy-provider（http type）。
///
/// Polaris resolveProxyProviders 单 provider 切片：fetch（SSRF guard）→ parse（allowProviders:false）
/// → filter/exclude-filter → override。失败返回 Err（供调用方判 partial / merge-only）。
///
/// 参数与 Polaris ProviderDeps + provider 配置项 1:1 对齐（刻意 8 参数，不强制收敛）。
/// `fetch_text` 注入正文拉取（含安全校验，由运行时层实现 safe-redirect-fetch + read body）。
#[allow(clippy::too_many_arguments)]
pub async fn fetch_and_parse_provider(
    url: &str,
    filter: Option<&str>,
    exclude_filter: Option<&str>,
    override_val: Option<&serde_yaml::Value>,
    subscription_id: &str,
    now: &str,
    fetch_text: &(impl Fn(
        &str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<String, ProviderFetchError>> + Send>,
    > + Send
          + Sync),
    id_gen: &mut impl FnMut() -> String,
) -> Result<ClashParseResult, ProviderFetchError> {
    let text = fetch_text(url).await?;
    parse_provider_text(
        &text,
        filter,
        exclude_filter,
        override_val,
        subscription_id,
        now,
        url,
        id_gen,
    )
}

/// 解析已经取得的 provider 正文。独立于网络腿，使多 provider 可以先并发拉取，再按声明序在单线程
/// 内完成解析与 ID 分配；后者保留历史顺序，也避免给 `id_gen` 外包一层共享锁。
#[allow(clippy::too_many_arguments)]
fn parse_provider_text(
    text: &str,
    filter: Option<&str>,
    exclude_filter: Option<&str>,
    override_val: Option<&serde_yaml::Value>,
    subscription_id: &str,
    now: &str,
    source: &str,
    id_gen: &mut impl FnMut() -> String,
) -> Result<ClashParseResult, ProviderFetchError> {
    let trimmed = text.trim();
    let mut parsed = clash_parser::parse_clash_proxies(
        &clash_parser::try_load_clash_doc(trimmed)
            .map_err(ProviderFetchError::transient)?
            .get(serde_yaml::Value::String("proxies".to_string()))
            .cloned()
            .unwrap_or(serde_yaml::Value::Null),
        subscription_id,
        now,
        id_gen,
    );

    if filter.is_some() || exclude_filter.is_some() {
        let mut warns = Vec::new();
        let filtered = clash_parser::apply_provider_filters(
            std::mem::take(&mut parsed.servers),
            filter,
            exclude_filter,
            &mut |m| warns.push(m),
            source,
        );
        parsed.servers = filtered;
        parsed.warnings.extend(warns);
    }

    if let Some(ov) = override_val {
        clash_parser::apply_override(&mut parsed.servers, ov);
    }

    Ok(parsed)
}

/// 节点稳定指纹（对账/去重键）：`protocol|address|port|cred|network`（**排除 name/detour**）。
/// 上游 `SubscriptionService.serverFingerprint`。
///
/// 排除显示名：订阅方常改名/调顺序，用 name 做键会把同一物理节点误判「删旧增新」→ id 抖动、
/// selectedServerId 丢失、本地编辑被清。cred（uuid / password / 嵌套 ss·ssh password / username /
/// wg peerPublicKey）区分同 host:port 并列节点；network 维度区分同 host:port:cred 但传输不同
/// （tcp/ws/grpc）的节点，缺此维度会被误并静默吞节点。
///
/// **与命令层 `node_fingerprint(&Value)` 是同一公式的两侧**（typed / json），由跨类型等价单测锁定同步。
#[must_use]
pub fn server_fingerprint(s: &ServerConfig) -> String {
    let protocol = serde_json::to_value(s.protocol)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
        .to_ascii_lowercase();
    let cred = non_empty(s.uuid.clone())
        .or_else(|| non_empty(s.password.clone()))
        .or_else(|| {
            non_empty(
                s.shadowsocks_settings
                    .as_ref()
                    .map(|ss| ss.password.clone()),
            )
        })
        .or_else(|| non_empty(s.username.clone()))
        .or_else(|| non_empty(s.ssh_settings.as_ref().and_then(|ssh| ssh.password.clone())))
        .or_else(|| {
            non_empty(
                s.wireguard_settings
                    .as_ref()
                    .and_then(|w| w.peer_public_key.clone()),
            )
        })
        .unwrap_or_default();
    let network = s.network.as_deref().unwrap_or("tcp").to_ascii_lowercase();
    format!("{protocol}|{}|{}|{cred}|{network}", s.address, s.port)
}

/// `Option<String>` 里的空串归 `None`（对齐 上游 `x || ...` 的 falsy 空串语义）。
fn non_empty(v: Option<String>) -> Option<String> {
    v.filter(|s| !s.is_empty())
}

/// 同指纹去重（首见保留）。上游 `dedupeByFingerprint`：内联在前、provider 按声明序在后 →
/// 同节点多源留内联那份。
#[must_use]
pub fn dedupe_by_fingerprint(servers: Vec<ServerConfig>) -> Vec<ServerConfig> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(servers.len());
    for s in servers {
        if seen.insert(server_fingerprint(&s)) {
            out.push(s);
        }
    }
    out
}

/// 从 Clash 订阅正文提取 `proxy-providers` 映射（非 Clash / 无 providers → `None`）。
///
/// 供命令层判定「是否需 provider 编排」并取出 provider 配置（供 [`resolve_proxy_providers`]）。
/// 判定走 [`detect_format`]（**单一真值**）→ YAML 与 JSON 两种编码同覆盖，与 [`parse_subscription`]
/// 的 Clash 分支严格同口径。此前这里单独判 `is_clash_probe`（纯 YAML 行首探测），JSON 编码的
/// `{"proxy-providers":{…}}` 会被漏掉 → provider 一个都不拉、节点全丢。
#[must_use]
pub fn extract_proxy_providers(text: &str) -> Option<serde_yaml::Value> {
    let trimmed = text.trim();
    if detect_format(trimmed) != SubscriptionFormat::Clash {
        return None;
    }
    let doc = clash_parser::try_load_clash_doc(trimmed).ok()?;
    let providers = doc.get(serde_yaml::Value::String("proxy-providers".to_string()))?;
    providers.as_mapping().is_some().then(|| providers.clone())
}

/// proxy-providers 编排产出。上游 `ResolveProvidersResult`。
#[derive(Debug, Default)]
pub struct ProviderResolveResult {
    /// 各 provider 解析出的节点（已标 `provider_name`，供调用方按 provider 精确 merge-only）。
    pub servers: Vec<ServerConfig>,
    pub warnings: Vec<String>,
    /// 任一 provider **transient** 失败（拉取/解析异常）→ 调用方 reconcile 改 merge-only 防穿仓。
    pub any_failed: bool,
    /// transient 失败的 provider 名（供 provider 级精确 merge-only）。
    pub failed_providers: Vec<String>,
}

/// 多源 proxy-providers 编排（上游 `resolveProxyProviders` 1:1，运行时层）。
///
/// 逐 provider 验证 `type:http` + `url` 后，**所有合法正文并发拉取**；结果再按声明序解析、分配 ID、
/// 应用 filter/override。网络墙钟因此由最慢 provider 决定，而不是最多 8 个超时串行相加；声明顺序、
/// 节点顺序和 `&mut id_gen` 的既有语义不变。成功节点标 `provider_name` 供精确 merge-only。
///
/// # 「进不进 `failed_providers`」的唯一判据：**这一轮拿不到它的节点，是不是意味着它真下架了**
///
/// 进名单 = 该 provider 名下的存量节点本轮**不删**（宁滞留不误删）。三类必须进：
///
/// | 形态 | 为什么不能当「真下架」 |
/// |---|---|
/// | transient 拉取/解析失败 | 超时/5xx/WAF 错误页，下轮可能就好 |
/// | **被 `max_providers` 截断**（第 9+ 个） | 我们**压根没拉**它 —— 拿不到 ≠ 下架。此前不进名单 → 它名下节点**每轮都被真删**（且下轮又被截断，永远删不完/删了白删） |
/// | **0 节点** | 机场返 200 空正文 / `filter` 因上游改名临时滤尽 —— 与主正文「0 节点 → merge-only」（命令层 `perform_subscription_update` 第 4 步）**同口径**，不能一边保守一边激进 |
///
/// 不进名单的只有 permanent：配置面非法（`type` 不支持 / 缺 `url` / 配置非对象）与
/// permanent 拉取失败（4xx / SSRF 拒绝）—— 这些重试不转好，硬保留只会让下架节点无限滞留。
///
/// **残留（如实登记）**：一个**永久**变空的 provider（机场真的清空了它）会让存量节点一直留着。
/// 无 per-provider 持久状态就实现不了「宽限 N 轮」，而两害相权：误删是**不可逆**的（用户丢节点 id +
/// 选中项 + 本地编辑），滞留是**用户可见且可手动删**的。方向与主正文一致。
///
/// `fetch_text` 注入正文拉取（含安全校验，由运行时层实现 safe-redirect-fetch + read body）。
pub async fn resolve_proxy_providers<F>(
    providers: &serde_yaml::Value,
    subscription_id: &str,
    now: &str,
    max_providers: usize,
    fetch_text: &F,
    id_gen: &mut impl FnMut() -> String,
) -> ProviderResolveResult
where
    F: Fn(
            &str,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<String, ProviderFetchError>> + Send>,
        > + Send
        + Sync,
{
    let mut out = ProviderResolveResult::default();
    let Some(map) = providers.as_mapping() else {
        return out;
    };

    let total = map.len();
    if total > max_providers {
        // 被截断的 provider **一个都没拉过** → 它们名下的存量节点本轮必须保住（见函数文档表格）。
        let truncated: Vec<String> = map
            .iter()
            .skip(max_providers)
            .map(|(name_v, _)| provider_name_of(name_v))
            .collect();
        out.warnings.push(format!(
            "proxy-providers 数量 {total} 超上限 {max_providers}，已截断（未拉取: {}；\
             其名下存量节点本轮保留，不作下架处理）",
            truncated.join(", ")
        ));
        out.any_failed = true;
        out.failed_providers.extend(truncated);
    }

    enum PreparedProvider {
        Invalid {
            name: String,
            reason: String,
        },
        Fetch {
            name: String,
            url: String,
            filter: Option<String>,
            exclude: Option<String>,
            override_val: Option<serde_yaml::Value>,
        },
    }

    let mut prepared = Vec::with_capacity(map.len().min(max_providers));
    for (name_v, prov) in map.iter().take(max_providers) {
        let name = provider_name_of(name_v);
        if prov.as_mapping().is_none() {
            prepared.push(PreparedProvider::Invalid {
                name,
                reason: "配置非对象".to_string(),
            });
            continue;
        }
        let ty = prov
            .get("type")
            .and_then(serde_yaml::Value::as_str)
            .map(str::to_ascii_lowercase);
        match ty.as_deref() {
            Some("file") => {
                prepared.push(PreparedProvider::Invalid {
                    name,
                    reason: "type:file 不支持，安全面忽略".to_string(),
                });
                continue;
            }
            Some("http") => {}
            other => {
                prepared.push(PreparedProvider::Invalid {
                    name,
                    reason: format!("不支持的 type: {}", other.unwrap_or("(缺省)")),
                });
                continue;
            }
        }
        let Some(url) = prov
            .get("url")
            .and_then(serde_yaml::Value::as_str)
            .filter(|s| !s.is_empty())
        else {
            prepared.push(PreparedProvider::Invalid {
                name,
                reason: "缺 url".to_string(),
            });
            continue;
        };
        prepared.push(PreparedProvider::Fetch {
            name,
            url: url.to_string(),
            filter: prov
                .get("filter")
                .and_then(serde_yaml::Value::as_str)
                .map(str::to_string),
            exclude: prov
                .get("exclude-filter")
                .and_then(serde_yaml::Value::as_str)
                .map(str::to_string),
            override_val: prov.get("override").cloned(),
        });
    }

    // `join_all` 保持输入顺序；各 future 同时被 poll。这里只并发网络 I/O，正文解析留在下方串行腿，
    // 因而不需要把 `id_gen` 变成锁，也不会让完成先后的抖动渗入节点顺序。
    let fetched = futures::future::join_all(prepared.iter().filter_map(|entry| match entry {
        PreparedProvider::Fetch { url, .. } => Some(fetch_text(url)),
        PreparedProvider::Invalid { .. } => None,
    }))
    .await;
    let mut fetched = fetched.into_iter();

    let mut succeeded = 0usize;
    let attempted = prepared.len();
    let mut failures: Vec<String> = Vec::new();

    for entry in prepared {
        let (name, url, filter, exclude, override_val) = match entry {
            PreparedProvider::Invalid { name, reason } => {
                // 配置面非法是 permanent：只记 warning，不触发 merge-only。
                failures.push(format!("{name}({reason})"));
                continue;
            }
            PreparedProvider::Fetch {
                name,
                url,
                filter,
                exclude,
                override_val,
            } => (name, url, filter, exclude, override_val),
        };
        let fetched_text = fetched
            .next()
            .expect("每个合法 provider 必须恰有一个并发拉取结果");
        let parsed = fetched_text.and_then(|text| {
            parse_provider_text(
                &text,
                filter.as_deref(),
                exclude.as_deref(),
                override_val.as_ref(),
                subscription_id,
                now,
                &url,
                id_gen,
            )
        });
        match parsed {
            Ok(mut parsed) => {
                if parsed.servers.is_empty() {
                    // HTTP 成功但解析/过滤后 0 节点 —— **不判 permanent**（此前如此，是本条 review 的缺陷）。
                    // 机场返 200 空正文、或 `filter` 因上游改名临时滤尽，都会走到这里；判 permanent
                    // 意味着该 provider 名下**全部存量节点当场删光**，而主正文遇到同样的「0 节点」
                    // 是走 merge-only 不删的（命令层 `perform_subscription_update` 第 4 步）——
                    // 同一现象两套方向，保守的那套才对（误删不可逆，滞留可手删）。
                    out.any_failed = true;
                    out.failed_providers.push(name.clone());
                    failures.push(format!("{name}(0 节点，存量保留不作下架)"));
                    continue;
                }
                succeeded += 1;
                for s in &mut parsed.servers {
                    s.provider_name = Some(name.clone());
                }
                for w in parsed.warnings {
                    out.warnings.push(format!("[{name}] {w}"));
                }
                out.servers.append(&mut parsed.servers);
            }
            // permanent（4xx / SSRF 拒绝 / URL 非法）→ 仅 warn，**不**保护存量：它确实拿不回来了，
            // 硬保留会把整条订阅永久钉在 partial（连主正文内联的真下架节点都删不掉，且每轮 save+广播）。
            Err(e) if e.permanent => {
                failures.push(format!("{name}({} · 永久失败)", e.message));
            }
            Err(e) => {
                out.any_failed = true;
                out.failed_providers.push(name.clone());
                failures.push(format!("{name}({})", e.message));
            }
        }
    }

    if !failures.is_empty() {
        out.warnings.push(format!(
            "proxy-providers {succeeded}/{attempted} 成功，失败: {}",
            failures.join(", ")
        ));
    }
    // 相邻去重：截断腿（`skip`）与失败腿（`take`）不相交，唯一的重复来源是**非字符串键**
    // 全被 [`provider_name_of`] 归一成 `(unnamed)` —— 那些恰好是相邻 push 的，`dedup` 够用。
    // （`leftover_survives_partial` 只做 `any` 匹配，重复不影响判定，只是让告警文案出现两遍同名。）
    out.failed_providers.dedup();
    out
}

/// provider 名（非字符串键 → `(unnamed)`）。截断腿与失败腿共用同一取名口径，不容许两处漂移。
fn provider_name_of(name_v: &serde_yaml::Value) -> String {
    name_v
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| "(unnamed)".to_string())
}

/// 轻量 base64 解码（容忍换行/空白，URL-safe 与标准均支持）。失败返回 Err。
///
/// `pub(crate)`：[`crate::share_link`] 的 vmess base64-JSON / ss base64-userinfo /
/// shadow-tls base64-JSON 三处复用同一份解码器（Node `Buffer.from(x,'base64')` 同样兼容
/// 标准与 URL-safe 两套字母表）——不另造第二份。
pub(crate) fn base64_decode(input: &str) -> Result<String, ()> {
    let clean: String = input
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            _ => c,
        })
        .collect();
    // 补齐 padding。
    let mut s = clean;
    while !s.len().is_multiple_of(4) {
        s.push('=');
    }
    base64_decode_inner(&s)
}

/// 最小 base64 解码（避免引入新依赖；订阅 base64 体量小，纯实现可接受）。
fn base64_decode_inner(s: &str) -> Result<String, ()> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes: Vec<u8> = s
        .as_bytes()
        .iter()
        .filter(|&&b| b != b'=')
        .copied()
        .collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &b in &bytes {
        let v = u32::from(val(b).ok_or(())?);
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    String::from_utf8(out).map_err(|_| ())
}

#[cfg(test)]
mod tests;
