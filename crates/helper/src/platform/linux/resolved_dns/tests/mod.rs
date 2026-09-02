use super::*;
use std::collections::VecDeque;
use std::sync::Mutex;

struct MockRunner {
    link_exists: bool,
    calls: Mutex<Vec<Vec<String>>>,
    replies: Mutex<VecDeque<Result<String, String>>>,
}

impl MockRunner {
    fn healthy() -> Self {
        Self {
            link_exists: true,
            calls: Mutex::new(Vec::new()),
            replies: Mutex::new(VecDeque::from([
                Ok(String::new()),
                Ok(String::new()),
                Ok(String::new()),
                Ok(String::new()),
                Ok(String::new()),
                Ok(format!(
                    "Link 7 ({TUN_INTERFACE_NAME}): {CONTROLLED_DNS_IP}"
                )),
                Ok(format!("Link 7 ({TUN_INTERFACE_NAME}): {ROUTE_ALL_DOMAIN}")),
                Ok(format!("Link 7 ({TUN_INTERFACE_NAME}): yes")),
            ])),
        }
    }
}

impl ResolvectlRunner for MockRunner {
    fn link_exists(&self, _interface_name: &str) -> bool {
        self.link_exists
    }

    fn run(&self, args: &[&str]) -> Result<String, String> {
        self.calls
            .lock()
            .unwrap()
            .push(args.iter().map(|arg| (*arg).to_owned()).collect());
        self.replies
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Ok(String::new()))
    }
}

#[test]
fn takeover_sets_and_attests_the_managed_link() {
    let runner = MockRunner::healthy();
    takeover_with(&runner, TUN_INTERFACE_NAME, CONTROLLED_DNS_IP).unwrap();
    let calls = runner.calls.lock().unwrap();
    assert_eq!(calls[0], ["dnssec", TUN_INTERFACE_NAME, "no"]);
    assert_eq!(calls[1], ["dnsovertls", TUN_INTERFACE_NAME, "no"]);
    assert_eq!(calls[2], ["dns", TUN_INTERFACE_NAME, CONTROLLED_DNS_IP]);
    assert_eq!(calls[3], ["domain", TUN_INTERFACE_NAME, ROUTE_ALL_DOMAIN]);
    assert_eq!(calls[4], ["default-route", TUN_INTERFACE_NAME, "yes"]);
    assert_eq!(calls[5], ["dns", TUN_INTERFACE_NAME]);
    assert_eq!(calls[6], ["domain", TUN_INTERFACE_NAME]);
    assert_eq!(calls[7], ["default-route", TUN_INTERFACE_NAME]);
}

#[test]
fn resolvectl_poll_interval_backs_off_to_the_existing_ceiling() {
    let mut interval = INITIAL_POLL_INTERVAL;
    let mut observed = vec![interval];
    for _ in 0..6 {
        interval = next_poll_interval(interval);
        observed.push(interval);
    }
    assert_eq!(
        observed,
        [1, 2, 4, 8, 16, 20, 20].map(Duration::from_millis).to_vec()
    );
}

#[test]
fn invalid_request_is_rejected_without_commands() {
    let runner = MockRunner::healthy();
    assert!(takeover_with(&runner, "eth0", "1.1.1.1").is_err());
    assert!(runner.calls.lock().unwrap().is_empty());
}

#[test]
fn partial_failure_reverts_the_link() {
    let runner = MockRunner {
        link_exists: true,
        calls: Mutex::new(Vec::new()),
        replies: Mutex::new(VecDeque::from([
            Ok(String::new()),
            Err("dnsovertls failed".to_owned()),
            Ok(String::new()),
        ])),
    };
    let error = takeover_with(&runner, TUN_INTERFACE_NAME, CONTROLLED_DNS_IP).unwrap_err();
    assert!(error.contains("partial resolved state reverted"));
    assert_eq!(
        runner.calls.lock().unwrap().last().unwrap(),
        &["revert", TUN_INTERFACE_NAME]
    );
}

#[test]
fn missing_link_is_already_reverted_but_cannot_be_taken_over() {
    let runner = MockRunner {
        link_exists: false,
        calls: Mutex::new(Vec::new()),
        replies: Mutex::new(VecDeque::new()),
    };
    assert!(takeover_with(&runner, TUN_INTERFACE_NAME, CONTROLLED_DNS_IP).is_err());
    revert_with(&runner, TUN_INTERFACE_NAME).unwrap();
    assert!(runner.calls.lock().unwrap().is_empty());
}

#[test]
fn failed_attestation_reverts_the_link() {
    let runner = MockRunner {
        link_exists: true,
        calls: Mutex::new(Vec::new()),
        replies: Mutex::new(VecDeque::from([
            Ok(String::new()),
            Ok(String::new()),
            Ok(String::new()),
            Ok(String::new()),
            Ok(String::new()),
            Ok("Link 7: 1.1.1.1".to_owned()),
            Ok(String::new()),
        ])),
    };
    let error = takeover_with(&runner, TUN_INTERFACE_NAME, CONTROLLED_DNS_IP).unwrap_err();
    assert!(error.contains("read-back missing DNS"));
    assert_eq!(
        runner.calls.lock().unwrap().last().unwrap(),
        &["revert", TUN_INTERFACE_NAME]
    );
}
