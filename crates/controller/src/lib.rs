#![deny(warnings)]

//! Simple nftables-based network controller for Ubuntu 24.04
//!
//! This version intentionally removes ALL tc shaping complexity.
//!
//! Features:
//! - Process blocking
//! - Thread blocking
//! - User blocking
//! - Simple nftables rate limiting
//!
//! Rate limiting is implemented using nftables limit expressions.
//!
//! IMPORTANT:
//! nftables "limit rate" is NOT true bandwidth shaping.
//! It limits packet rate, not exact kbps throughput.
//!
//! This implementation approximates bandwidth control by limiting
//! packet rate based on an assumed average packet size.
//!
//! Ubuntu 24.04 compatible.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};

use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const NFT_TABLE_NAME: &str = "filter";
const NFT_FAMILY: &str = "inet";
const NFT_OUTPUT_CHAIN: &str = "output";

const RULE_COMMENT_PREFIX: &str = "netmon-";

const PROC_NET_HEADER_INDEX: usize = 0;
const PROC_NET_PORT_COLUMN_COUNT: usize = 10;

// Approximation:
// 1 packet ~= 1500 bytes
const APPROX_PACKET_SIZE_BYTES: u32 = 1500;

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ControllerError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("nft error: {0}")]
    Nft(String),

    #[error("parse error: {0}")]
    Parse(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// Rule Tracking
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct RuleRef {
    handle: u64,
}

static RULES_BY_SCOPE: OnceLock<Mutex<HashMap<String, Vec<RuleRef>>>> =
    OnceLock::new();

fn rules_map() -> &'static Mutex<HashMap<String, Vec<RuleRef>>> {
    RULES_BY_SCOPE.get_or_init(|| Mutex::new(HashMap::new()))
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn scope_key(kind: &str, id: impl AsRef<str>) -> String {
    format!("{kind}:{}", id.as_ref())
}

fn scope_marker(scope_key: &str) -> String {
    format!("{RULE_COMMENT_PREFIX}{scope_key}-")
}

fn scoped_comment(scope_key: &str, label: &str) -> String {
    format!(
        "{RULE_COMMENT_PREFIX}{scope_key}-{}",
        label.replace('"', "_")
    )
}

fn join_ports(ports: &BTreeSet<u16>) -> String {
    ports
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn kbps_to_packets_per_second(rate_kbps: u32) -> u32 {
    let bytes_per_sec = (rate_kbps * 1000) / 8;

    let pps = bytes_per_sec / APPROX_PACKET_SIZE_BYTES;

    pps.max(1)
}

// ─────────────────────────────────────────────────────────────────────────────
// nft setup
// ─────────────────────────────────────────────────────────────────────────────

pub fn setup_nftables() -> Result<(), String> {
    run_nft_command(
        &["add", "table", NFT_FAMILY, NFT_TABLE_NAME],
        true,
    )?;

    let script = format!(
        r#"
add chain {NFT_FAMILY} {NFT_TABLE_NAME} {NFT_OUTPUT_CHAIN} {{
    type filter hook output priority 0;
    policy accept;
}}
"#
    );

    if let Err(e) = run_nft_script(&script) {
        if !e.contains("File exists")
            && !e.contains("exists")
            && !e.contains("already exists")
        {
            return Err(e);
        }
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Blocking API
// ─────────────────────────────────────────────────────────────────────────────

pub fn block_process(
    pid: u32,
    process_name: &str,
) -> Result<(), String> {
    let _ = setup_nftables();

    let key = scope_key("proc", pid.to_string());

    remove_rules_for_scope(&key)?;

    let tcp_ports = collect_pid_ports(pid, &["tcp", "tcp6"])?;
    let udp_ports = collect_pid_ports(pid, &["udp", "udp6"])?;

    let comment = scoped_comment(&key, process_name);

    let rules = if tcp_ports.is_empty() && udp_ports.is_empty() {
        if let Some(uid) = read_uid_for_pid(pid) {
            format!(
                r#"add rule {NFT_FAMILY} {NFT_TABLE_NAME} {NFT_OUTPUT_CHAIN} meta skuid {uid} drop comment "{comment}""#
            )
        } else {
            return Err(format!(
                "Could not determine ports or UID for PID {pid}"
            ));
        }
    } else {
        build_block_ruleset(&tcp_ports, &udp_ports, &comment)
    };

    run_nft_script(&rules)?;

    let handles = find_rule_handles_by_marker(&scope_marker(&key))?;

    register_rule_handles(&key, handles)
}

pub fn unblock_process(pid: u32) -> Result<(), String> {
    remove_rules_for_scope(&scope_key("proc", pid.to_string()))
}

pub fn block_thread(
    pid: u32,
    tid: u32,
    thread_name: &str,
) -> Result<(), String> {
    let _ = setup_nftables();

    let key = scope_key("thread", format!("{pid}:{tid}"));

    remove_rules_for_scope(&key)?;

    let tcp_ports = collect_thread_ports(pid, tid, &["tcp", "tcp6"])?;
    let udp_ports = collect_thread_ports(pid, tid, &["udp", "udp6"])?;

    if tcp_ports.is_empty() && udp_ports.is_empty() {
        return Err(format!(
            "No ports found for PID {pid} TID {tid}"
        ));
    }

    let comment = scoped_comment(&key, thread_name);

    let rules = build_block_ruleset(
        &tcp_ports,
        &udp_ports,
        &comment,
    );

    run_nft_script(&rules)?;

    let handles = find_rule_handles_by_marker(&scope_marker(&key))?;

    register_rule_handles(&key, handles)
}

pub fn unblock_thread(pid: u32, tid: u32) -> Result<(), String> {
    remove_rules_for_scope(&scope_key(
        "thread",
        format!("{pid}:{tid}"),
    ))
}

pub fn block_user(uid: u32, username: &str) -> Result<(), String> {
    let _ = setup_nftables();

    let key = scope_key("user", uid.to_string());

    remove_rules_for_scope(&key)?;

    let comment = scoped_comment(&key, username);

    let script = format!(
        r#"add rule {NFT_FAMILY} {NFT_TABLE_NAME} {NFT_OUTPUT_CHAIN} meta skuid {uid} drop comment "{comment}""#
    );

    run_nft_script(&script)?;

    let handles = find_rule_handles_by_marker(&scope_marker(&key))?;

    register_rule_handles(&key, handles)
}

pub fn unblock_user(uid: u32) -> Result<(), String> {
    remove_rules_for_scope(&scope_key("user", uid.to_string()))
}

// ─────────────────────────────────────────────────────────────────────────────
// nft "Rate Limiting"
// ─────────────────────────────────────────────────────────────────────────────

pub fn rate_limit_process(
    pid: u32,
    rate_kbps: u32,
) -> Result<(), String> {
    let _ = setup_nftables();

    let key = scope_key("rate-proc", pid.to_string());

    remove_rules_for_scope(&key)?;

    let pps = kbps_to_packets_per_second(rate_kbps);

    let comment = scoped_comment(&key, "rate-limit");

    let tcp_ports = collect_pid_ports(pid, &["tcp", "tcp6"])?;
    let udp_ports = collect_pid_ports(pid, &["udp", "udp6"])?;

    let mut rules = String::new();

    if !tcp_ports.is_empty() {
        rules.push_str(&format!(
            r#"add rule {NFT_FAMILY} {NFT_TABLE_NAME} {NFT_OUTPUT_CHAIN} tcp sport {{ {} }} limit rate over {pps}/second drop comment "{comment}"{}"#,
            join_ports(&tcp_ports),
            "\n"
        ));
    }

    if !udp_ports.is_empty() {
        rules.push_str(&format!(
            r#"add rule {NFT_FAMILY} {NFT_TABLE_NAME} {NFT_OUTPUT_CHAIN} udp sport {{ {} }} limit rate over {pps}/second drop comment "{comment}"{}"#,
            join_ports(&udp_ports),
            "\n"
        ));
    }

    if rules.is_empty() {
        if let Some(uid) = read_uid_for_pid(pid) {
            rules.push_str(&format!(
                r#"add rule {NFT_FAMILY} {NFT_TABLE_NAME} {NFT_OUTPUT_CHAIN} meta skuid {uid} limit rate over {pps}/second drop comment "{comment}""#
            ));
        } else {
            return Err(format!(
                "Could not determine ports or UID for PID {pid}"
            ));
        }
    }

    run_nft_script(&rules)?;

    let handles = find_rule_handles_by_marker(&scope_marker(&key))?;

    register_rule_handles(&key, handles)
}

pub fn unlimit_process(pid: u32) -> Result<(), String> {
    remove_rules_for_scope(&scope_key(
        "rate-proc",
        pid.to_string(),
    ))
}

pub fn rate_limit_thread(
    pid: u32,
    tid: u32,
    rate_kbps: u32,
) -> Result<(), String> {
    let _ = setup_nftables();

    let key = scope_key("rate-thread", format!("{pid}:{tid}"));

    remove_rules_for_scope(&key)?;

    let pps = kbps_to_packets_per_second(rate_kbps);

    let comment = scoped_comment(&key, "rate-limit");

    let tcp_ports = collect_thread_ports(pid, tid, &["tcp", "tcp6"])?;
    let udp_ports = collect_thread_ports(pid, tid, &["udp", "udp6"])?;

    let mut rules = String::new();

    if !tcp_ports.is_empty() {
        rules.push_str(&format!(
            r#"add rule {NFT_FAMILY} {NFT_TABLE_NAME} {NFT_OUTPUT_CHAIN} tcp sport {{ {} }} limit rate over {pps}/second drop comment "{comment}"{}"#,
            join_ports(&tcp_ports),
            "\n"
        ));
    }

    if !udp_ports.is_empty() {
        rules.push_str(&format!(
            r#"add rule {NFT_FAMILY} {NFT_TABLE_NAME} {NFT_OUTPUT_CHAIN} udp sport {{ {} }} limit rate over {pps}/second drop comment "{comment}"{}"#,
            join_ports(&udp_ports),
            "\n"
        ));
    }

    run_nft_script(&rules)?;

    let handles = find_rule_handles_by_marker(&scope_marker(&key))?;

    register_rule_handles(&key, handles)
}

pub fn unlimit_thread(pid: u32, tid: u32) -> Result<(), String> {
    remove_rules_for_scope(&scope_key(
        "rate-thread",
        format!("{pid}:{tid}"),
    ))
}

pub fn rate_limit_user(
    uid: u32,
    rate_kbps: u32,
) -> Result<(), String> {
    let _ = setup_nftables();

    let key = scope_key("rate-user", uid.to_string());

    remove_rules_for_scope(&key)?;

    let pps = kbps_to_packets_per_second(rate_kbps);

    let comment = scoped_comment(&key, "rate-limit");

    let script = format!(
        r#"add rule {NFT_FAMILY} {NFT_TABLE_NAME} {NFT_OUTPUT_CHAIN} meta skuid {uid} limit rate over {pps}/second drop comment "{comment}""#
    );

    run_nft_script(&script)?;

    let handles = find_rule_handles_by_marker(&scope_marker(&key))?;

    register_rule_handles(&key, handles)
}

pub fn unlimit_user(uid: u32) -> Result<(), String> {
    remove_rules_for_scope(&scope_key(
        "rate-user",
        uid.to_string(),
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
// Ruleset Builders
// ─────────────────────────────────────────────────────────────────────────────

fn build_block_ruleset(
    tcp_ports: &BTreeSet<u16>,
    udp_ports: &BTreeSet<u16>,
    comment: &str,
) -> String {
    let mut rules = String::new();

    if !tcp_ports.is_empty() {
        rules.push_str(&format!(
            r#"add rule {NFT_FAMILY} {NFT_TABLE_NAME} {NFT_OUTPUT_CHAIN} tcp sport {{ {} }} drop comment "{}"{}"#,
            join_ports(tcp_ports),
            comment,
            "\n"
        ));
    }

    if !udp_ports.is_empty() {
        rules.push_str(&format!(
            r#"add rule {NFT_FAMILY} {NFT_TABLE_NAME} {NFT_OUTPUT_CHAIN} udp sport {{ {} }} drop comment "{}"{}"#,
            join_ports(udp_ports),
            comment,
            "\n"
        ));
    }

    rules
}

// ─────────────────────────────────────────────────────────────────────────────
// Port Collection
// ─────────────────────────────────────────────────────────────────────────────

fn collect_pid_ports(
    pid: u32,
    files: &[&str],
) -> Result<BTreeSet<u16>, String> {
    let fd_path = format!("/proc/{pid}/fd");

    let socket_inodes = collect_socket_inodes(&fd_path);

    collect_net_table_ports(files, Some(&socket_inodes))
}

fn collect_thread_ports(
    pid: u32,
    tid: u32,
    files: &[&str],
) -> Result<BTreeSet<u16>, String> {
    let fd_path = format!("/proc/{pid}/task/{tid}/fd");

    let socket_inodes = collect_socket_inodes(&fd_path);

    collect_net_table_ports(files, Some(&socket_inodes))
}

fn collect_net_table_ports(
    files: &[&str],
    inode_filter: Option<&BTreeSet<u64>>,
) -> Result<BTreeSet<u16>, String> {
    let mut ports = BTreeSet::new();

    for file in files {
        let path = format!("/proc/net/{file}");

        let content = match fs::read_to_string(&path) {
            Ok(v) => v,
            Err(_) => continue,
        };

        for (idx, line) in content.lines().enumerate() {
            if idx == PROC_NET_HEADER_INDEX {
                continue;
            }

            let cols: Vec<&str> =
                line.split_whitespace().collect();

            if cols.len() < PROC_NET_PORT_COLUMN_COUNT {
                continue;
            }

            let inode = match cols[9].parse::<u64>() {
                Ok(v) => v,
                Err(_) => continue,
            };

            if let Some(filter) = inode_filter {
                if !filter.contains(&inode) {
                    continue;
                }
            }

            if let Some(port) =
                parse_port_from_proc_addr(cols[1])
            {
                ports.insert(port);
            }
        }
    }

    Ok(ports)
}

fn collect_socket_inodes(fd_path: &str) -> BTreeSet<u64> {
    let mut inodes = BTreeSet::new();

    let entries = match fs::read_dir(fd_path) {
        Ok(v) => v,
        Err(_) => return inodes,
    };

    for entry in entries.flatten() {
        let target = match fs::read_link(entry.path()) {
            Ok(v) => v,
            Err(_) => continue,
        };

        if let Some(inode) = parse_socket_inode(&target) {
            inodes.insert(inode);
        }
    }

    inodes
}

fn parse_port_from_proc_addr(
    proc_addr: &str,
) -> Option<u16> {
    let mut parts = proc_addr.split(':');

    let _ip = parts.next()?;

    let port_hex = parts.next()?;

    u16::from_str_radix(port_hex, 16).ok()
}

fn parse_socket_inode(target: &Path) -> Option<u64> {
    let text = target.to_string_lossy();

    if !text.starts_with("socket:[") || !text.ends_with(']') {
        return None;
    }

    let inode =
        &text["socket:[".len()..text.len() - 1];

    inode.parse::<u64>().ok()
}

fn read_uid_for_pid(pid: u32) -> Option<u32> {
    let content =
        fs::read_to_string(format!("/proc/{pid}/status"))
            .ok()?;

    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest
                .split_whitespace()
                .nth(1)?
                .parse::<u32>()
                .ok();
        }
    }

    None
}

// ─────────────────────────────────────────────────────────────────────────────
// nft execution
// ─────────────────────────────────────────────────────────────────────────────

fn run_nft_script(script: &str) -> Result<(), String> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(map_nft_spawn_error)?;

    if let Some(stdin) = child.stdin.as_mut() {
        stdin
            .write_all(script.as_bytes())
            .map_err(|e| format!("stdin write failed: {e}"))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("nft wait failed: {e}"))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(
            &output.stderr,
        )
        .to_string());
    }

    Ok(())
}

fn run_nft_command(
    args: &[&str],
    ignore_exists: bool,
) -> Result<(), String> {
    let output = Command::new("nft")
        .args(args)
        .output()
        .map_err(map_nft_spawn_error)?;

    if output.status.success() {
        return Ok(());
    }

    let stderr =
        String::from_utf8_lossy(&output.stderr);

    if ignore_exists
        && (stderr.contains("File exists")
            || stderr.contains("exists"))
    {
        return Ok(());
    }

    Err(stderr.to_string())
}

fn map_nft_spawn_error(err: std::io::Error) -> String {
    if err.kind() == std::io::ErrorKind::NotFound {
        return "nft command not found".into();
    }

    format!("failed to run nft: {err}")
}

// ─────────────────────────────────────────────────────────────────────────────
// Rule Tracking
// ─────────────────────────────────────────────────────────────────────────────

fn register_rule_handles(
    scope_key: &str,
    handles: Vec<u64>,
) -> Result<(), String> {
    let mut guard = rules_map()
        .lock()
        .map_err(|_| "rules map poisoned")?;

    guard.insert(
        scope_key.to_string(),
        handles
            .into_iter()
            .map(|h| RuleRef { handle: h })
            .collect(),
    );

    Ok(())
}

fn remove_rules_for_scope(
    scope_key: &str,
) -> Result<(), String> {
    let mut handles = Vec::new();

    {
        let mut guard = rules_map()
            .lock()
            .map_err(|_| "rules map poisoned")?;

        if let Some(v) = guard.remove(scope_key) {
            handles.extend(v.into_iter().map(|r| r.handle));
        }
    }

    if handles.is_empty() {
        handles =
            find_rule_handles_by_marker(&scope_marker(
                scope_key,
            ))?;
    }

    for handle in handles {
        let handle_s = handle.to_string();

        run_nft_command(
            &[
                "delete",
                "rule",
                NFT_FAMILY,
                NFT_TABLE_NAME,
                NFT_OUTPUT_CHAIN,
                "handle",
                &handle_s,
            ],
            false,
        )?;
    }

    Ok(())
}

fn find_rule_handles_by_marker(
    marker: &str,
) -> Result<Vec<u64>, String> {
    let output = Command::new("nft")
        .args([
            "-a",
            "list",
            "chain",
            NFT_FAMILY,
            NFT_TABLE_NAME,
            NFT_OUTPUT_CHAIN,
        ])
        .output()
        .map_err(|e| format!("nft list failed: {e}"))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(
            &output.stderr,
        )
        .to_string());
    }

    let stdout =
        String::from_utf8_lossy(&output.stdout);

    let mut out = Vec::new();

    for line in stdout.lines() {
        if !line.contains(marker) {
            continue;
        }

        if let Some(idx) = line.rfind("handle ") {
            let tail = line[idx + 7..].trim();

            if let Ok(v) = tail.parse::<u64>() {
                out.push(v);
            }
        }
    }

    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility
// ─────────────────────────────────────────────────────────────────────────────

pub fn unblock_all() -> Result<(), String> {
    run_nft_command(
        &[
            "flush",
            "chain",
            NFT_FAMILY,
            NFT_TABLE_NAME,
            NFT_OUTPUT_CHAIN,
        ],
        false,
    )?;

    rules_map()
        .lock()
        .map_err(|_| "rules map poisoned")?
        .clear();

    Ok(())
}

pub fn list_rules() -> Result<Vec<String>, String> {
    let output = Command::new("nft")
        .args([
            "list",
            "chain",
            NFT_FAMILY,
            NFT_TABLE_NAME,
            NFT_OUTPUT_CHAIN,
        ])
        .output()
        .map_err(|e| format!("failed to run nft: {e}"))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(
            &output.stderr,
        )
        .to_string());
    }

    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_string)
        .collect())
}

pub fn is_root() -> bool {
    match Command::new("id").arg("-u").output() {
        Ok(output) => {
            String::from_utf8_lossy(&output.stdout)
                .trim()
                == "0"
        }
        Err(_) => false,
    }
}
