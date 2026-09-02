use super::*;
use crate::ssrf::DnsLookup;
use std::collections::HashMap;
use std::sync::Mutex;

/// 测试用 mock DnsLookup：默认公网，可注入特定 hostname 的内网解析。
struct MockLookup {
    private: HashMap<String, Vec<String>>,
}

impl DnsLookup for MockLookup {
    fn lookup_all(&self, host: &str) -> impl Future<Output = Result<Vec<String>, String>> + Send {
        let res = self
            .private
            .get(host)
            .cloned()
            .unwrap_or_else(|| vec!["8.8.8.8".to_string()]);
        async move { Ok(res) }
    }
}

/// 测试用 mock HttpClient：按脚本返回预设 (status, location) 序列。
#[allow(clippy::type_complexity)]
struct MockFetch {
    /// url → 重定向链脚本（按请求序逐个弹出）。Mutex 保 Sync（HttpClient: Send + Sync）。
    scripts: Mutex<HashMap<String, Vec<(u16, Option<String>)>>>,
}

impl MockFetch {
    fn new() -> Self {
        Self {
            scripts: Mutex::new(HashMap::new()),
        }
    }
    fn set(&self, url: &str, chain: Vec<(u16, Option<String>)>) {
        self.scripts.lock().unwrap().insert(url.to_string(), chain);
    }
}

impl HttpClient for MockFetch {
    fn fetch(
        &self,
        url: &str,
        _init: &FetchInit,
    ) -> impl Future<Output = Result<MinimalResponse, String>> + Send {
        let mut scripts = self.scripts.lock().unwrap();
        let chain = scripts.get_mut(url);
        let resp = if let Some(c) = chain {
            if c.is_empty() {
                MinimalResponse {
                    status: 500,
                    ..Default::default()
                }
            } else {
                let (status, location) = c.remove(0);
                MinimalResponse {
                    status,
                    location,
                    ..Default::default()
                }
            }
        } else {
            MinimalResponse {
                status: 404,
                ..Default::default()
            }
        };
        async move { Ok(resp) }
    }
}

fn opts<'a, H: HttpClient, L: DnsLookup>(
    fetch_impl: &'a H,
    lookup: &'a L,
    url: &'a str,
) -> SafeRedirectFetchOptions<'a, H, L> {
    SafeRedirectFetchOptions {
        fetch_impl,
        url,
        user_agent: "Polaris/0.1".to_string(),
        headers: None,
        exempt_fake_ip: false,
        max_redirects: None,
        timeout_ms: None,
        max_body_bytes: None,
        lookup,
    }
}

#[tokio::test]
async fn no_redirect_returns_terminal() {
    let fetch = MockFetch::new();
    fetch.set("https://example.com/sub", vec![(200, None)]);
    let lk = MockLookup {
        private: HashMap::new(),
    };
    let r = safe_redirect_fetch(opts(&fetch, &lk, "https://example.com/sub")).await;
    assert!(r.is_ok());
    assert_eq!(r.unwrap().status, 200);
}

#[tokio::test]
async fn follows_safe_redirect_chain() {
    let fetch = MockFetch::new();
    fetch.set(
        "https://example.com/a",
        vec![(302, Some("https://cdn.example.com/b".to_string()))],
    );
    fetch.set("https://cdn.example.com/b", vec![(200, None)]);
    let lk = MockLookup {
        private: HashMap::new(),
    };
    let r = safe_redirect_fetch(opts(&fetch, &lk, "https://example.com/a")).await;
    assert!(r.is_ok());
    assert_eq!(r.unwrap().status, 200);
}

#[tokio::test]
async fn relative_location_resolved() {
    let fetch = MockFetch::new();
    fetch.set(
        "https://example.com/start",
        vec![(302, Some("/next".to_string()))],
    );
    fetch.set("https://example.com/next", vec![(200, None)]);
    let lk = MockLookup {
        private: HashMap::new(),
    };
    let r = safe_redirect_fetch(opts(&fetch, &lk, "https://example.com/start")).await;
    assert!(r.is_ok());
}

#[tokio::test]
async fn redirect_to_private_ssrf_blocked() {
    let fetch = MockFetch::new();
    fetch.set(
        "https://evil.example.com/redir",
        vec![(
            302,
            Some("https://meta.evil.example.com/secret".to_string()),
        )],
    );
    let lk = MockLookup {
        private: HashMap::from([(
            "meta.evil.example.com".to_string(),
            vec!["169.254.169.254".to_string()],
        )]),
    };
    let r = safe_redirect_fetch(opts(&fetch, &lk, "https://evil.example.com/redir")).await;
    assert!(r.is_err());
    assert_eq!(r.unwrap_err().reason, SafeFetchRejectReason::Ssrf);
}

#[tokio::test]
async fn redirect_to_non_http_protocol_blocked() {
    let fetch = MockFetch::new();
    fetch.set(
        "https://example.com/f",
        vec![(302, Some("file:///etc/passwd".to_string()))],
    );
    let lk = MockLookup {
        private: HashMap::new(),
    };
    let r = safe_redirect_fetch(opts(&fetch, &lk, "https://example.com/f")).await;
    assert!(r.is_err());
    assert_eq!(
        r.unwrap_err().reason,
        SafeFetchRejectReason::RedirectProtocol
    );
}

#[tokio::test]
async fn too_many_redirects_blocked() {
    let fetch = MockFetch::new();
    // 循环重定向：a→b→a→b...（无终态）。max_redirects=3 ⇒ hop 0..3 续跳、hop=3 时触发 too-many。
    // MockFetch 每请求弹一个脚本条目，故每 URL 提供足够长度的链（4 跳：a 用 2 次、b 用 2 次）。
    let a_target = "https://loop.example.com/b".to_string();
    let b_target = "https://loop.example.com/a".to_string();
    fetch.set(
        "https://loop.example.com/a",
        vec![(302, Some(a_target.clone())), (302, Some(a_target))],
    );
    fetch.set(
        "https://loop.example.com/b",
        vec![(302, Some(b_target.clone())), (302, Some(b_target))],
    );
    let lk = MockLookup {
        private: HashMap::new(),
    };
    let mut o = opts(&fetch, &lk, "https://loop.example.com/a");
    o.max_redirects = Some(3);
    let r = safe_redirect_fetch(o).await;
    assert!(r.is_err());
    assert_eq!(
        r.unwrap_err().reason,
        SafeFetchRejectReason::TooManyRedirects
    );
}

#[tokio::test]
async fn first_hop_ssrf_blocked() {
    // 首跳 URL 本身解析到内网 → guard 首跳即拒
    let fetch = MockFetch::new();
    let lk = MockLookup {
        private: HashMap::from([(
            "internal.example.com".to_string(),
            vec!["10.0.0.5".to_string()],
        )]),
    };
    let r = safe_redirect_fetch(opts(&fetch, &lk, "https://internal.example.com/x")).await;
    assert!(r.is_err());
    assert_eq!(r.unwrap_err().reason, SafeFetchRejectReason::Ssrf);
}

#[tokio::test]
async fn max_redirects_zero_allows_one_fetch() {
    // max_redirects=0：允许首跳 fetch，但若首跳即 30x → too-many（hop>=max_redirects=0）
    let fetch = MockFetch::new();
    fetch.set("https://example.com/ok", vec![(200, None)]);
    let lk = MockLookup {
        private: HashMap::new(),
    };
    let mut o = opts(&fetch, &lk, "https://example.com/ok");
    o.max_redirects = Some(0);
    let r = safe_redirect_fetch(o).await;
    assert!(r.is_ok());
}

#[tokio::test]
async fn max_redirects_zero_blocks_redirect() {
    let fetch = MockFetch::new();
    fetch.set(
        "https://example.com/r",
        vec![(302, Some("https://cdn.example.com/x".to_string()))],
    );
    let lk = MockLookup {
        private: HashMap::new(),
    };
    let mut o = opts(&fetch, &lk, "https://example.com/r");
    o.max_redirects = Some(0);
    let r = safe_redirect_fetch(o).await;
    assert!(r.is_err());
    assert_eq!(
        r.unwrap_err().reason,
        SafeFetchRejectReason::TooManyRedirects
    );
}
