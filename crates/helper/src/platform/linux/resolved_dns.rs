//! Linux `systemd-resolved` per-link DNS 接管。
//!
//! 该模块运行在 root helper 内，但能力被收敛到一个固定 TUN 接口与一个受控 DNS 哨兵；app 不能借此
//! 修改任意网卡或任意 DNS。写入是事务性的：任一步或读回自证失败都会 `revert` 已写状态。

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(test)]
use polaris_helper_proto::linux_dns::CONTROLLED_DNS_IP;
use polaris_helper_proto::linux_dns::{
    takeover_request_allowed, ROUTE_ALL_DOMAIN, TUN_INTERFACE_NAME,
};

const RESOLVECTL_BIN: &str = "/usr/bin/resolvectl";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
// `resolvectl` 是启动主链上的短命令（一次接管含 8 次调用）。固定 20ms 轮询会给每次调用附加一格
// 尾延迟；指数退避让短命令 1ms 起被发现，而挂起命令最终仍回到原 20ms 上限，不改变 5s 硬超时。
const INITIAL_POLL_INTERVAL: Duration = Duration::from_millis(1);
const MAX_POLL_INTERVAL: Duration = Duration::from_millis(20);

fn next_poll_interval(current: Duration) -> Duration {
    current.saturating_mul(2).min(MAX_POLL_INTERVAL)
}

/// handler 依赖的最小能力面。
pub trait ResolvedDnsOps: Send + Sync {
    /// 接管并读回自证。
    fn takeover(&self, interface_name: &str, server_ip: &str) -> Result<(), String>;
    /// 撤销链路配置；接口已经消失视为无残留。
    fn revert(&self, interface_name: &str) -> Result<(), String>;
}

trait ResolvectlRunner: Send + Sync {
    fn link_exists(&self, interface_name: &str) -> bool;
    fn run(&self, args: &[&str]) -> Result<String, String>;
}

#[derive(Debug, Default)]
struct SystemResolvectlRunner;

impl ResolvectlRunner for SystemResolvectlRunner {
    fn link_exists(&self, interface_name: &str) -> bool {
        Path::new("/sys/class/net").join(interface_name).exists()
    }

    fn run(&self, args: &[&str]) -> Result<String, String> {
        let mut child = Command::new(RESOLVECTL_BIN)
            .args(args)
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn resolvectl {}: {e}", args.join(" ")))?;
        let started = Instant::now();
        let mut poll_interval = INITIAL_POLL_INTERVAL;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let mut stdout = String::new();
                    let mut stderr = String::new();
                    if let Some(mut pipe) = child.stdout.take() {
                        let _ = pipe.read_to_string(&mut stdout);
                    }
                    if let Some(mut pipe) = child.stderr.take() {
                        let _ = pipe.read_to_string(&mut stderr);
                    }
                    if status.success() {
                        return Ok(stdout.trim().to_owned());
                    }
                    let detail = if stderr.trim().is_empty() {
                        stdout.trim()
                    } else {
                        stderr.trim()
                    };
                    return Err(format!(
                        "resolvectl {} exited {status}: {detail}",
                        args.join(" ")
                    ));
                }
                Ok(None) if started.elapsed() < COMMAND_TIMEOUT => {
                    thread::sleep(poll_interval);
                    poll_interval = next_poll_interval(poll_interval);
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "resolvectl {} timed out after {}s",
                        args.join(" "),
                        COMMAND_TIMEOUT.as_secs()
                    ));
                }
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("wait resolvectl {}: {e}", args.join(" ")));
                }
            }
        }
    }
}

/// 生产实现。
#[derive(Debug, Default)]
pub struct ResolvectlDnsOps {
    runner: SystemResolvectlRunner,
}

impl ResolvectlDnsOps {
    /// 构造生产实现。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl ResolvedDnsOps for ResolvectlDnsOps {
    fn takeover(&self, interface_name: &str, server_ip: &str) -> Result<(), String> {
        takeover_with(&self.runner, interface_name, server_ip)
    }

    fn revert(&self, interface_name: &str) -> Result<(), String> {
        revert_with(&self.runner, interface_name)
    }
}

fn takeover_with(
    runner: &dyn ResolvectlRunner,
    interface_name: &str,
    server_ip: &str,
) -> Result<(), String> {
    if !takeover_request_allowed(interface_name, server_ip) {
        return Err("request denied by Polaris resolved whitelist".to_owned());
    }
    if !runner.link_exists(interface_name) {
        return Err(format!("managed TUN interface {interface_name} is missing"));
    }

    let mutations: [&[&str]; 5] = [
        &["dnssec", interface_name, "no"],
        &["dnsovertls", interface_name, "no"],
        &["dns", interface_name, server_ip],
        &["domain", interface_name, ROUTE_ALL_DOMAIN],
        &["default-route", interface_name, "yes"],
    ];
    for args in mutations {
        if let Err(error) = runner.run(args) {
            return Err(rollback_error(runner, interface_name, error));
        }
    }

    let attestation = attest(runner, interface_name, server_ip);
    if let Err(error) = attestation {
        return Err(rollback_error(runner, interface_name, error));
    }
    Ok(())
}

fn attest(
    runner: &dyn ResolvectlRunner,
    interface_name: &str,
    server_ip: &str,
) -> Result<(), String> {
    let dns = runner.run(&["dns", interface_name])?;
    if !dns.split_whitespace().any(|token| token == server_ip) {
        return Err(format!("resolved read-back missing DNS {server_ip}: {dns}"));
    }
    let domains = runner.run(&["domain", interface_name])?;
    if !domains
        .split_whitespace()
        .any(|token| token == ROUTE_ALL_DOMAIN)
    {
        return Err(format!(
            "resolved read-back missing route-only domain {ROUTE_ALL_DOMAIN}: {domains}"
        ));
    }
    let default_route = runner.run(&["default-route", interface_name])?;
    if !default_route
        .split_whitespace()
        .any(|token| token.eq_ignore_ascii_case("yes"))
    {
        return Err(format!(
            "resolved read-back did not confirm default-route=yes: {default_route}"
        ));
    }
    Ok(())
}

fn rollback_error(runner: &dyn ResolvectlRunner, interface_name: &str, cause: String) -> String {
    match runner.run(&["revert", interface_name]) {
        Ok(_) => format!("{cause}; partial resolved state reverted"),
        Err(rollback) => format!("{cause}; rollback failed: {rollback}"),
    }
}

fn revert_with(runner: &dyn ResolvectlRunner, interface_name: &str) -> Result<(), String> {
    if interface_name != TUN_INTERFACE_NAME {
        return Err("request denied by Polaris resolved whitelist".to_owned());
    }
    if !runner.link_exists(interface_name) {
        return Ok(());
    }
    runner.run(&["revert", interface_name]).map(|_| ())
}

#[cfg(test)]
mod tests;
