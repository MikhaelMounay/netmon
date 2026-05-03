#![deny(warnings)]

//! Manages nftables rules for blocking traffic belonging to selected processes.
//!
//! The GUI crate calls this crate when the user blocks or unblocks a process.
//! We enumerate active source ports from `/proc/<pid>/net/*`, convert them into
//! nftables drop rules in `inet filter output`, and track rule handles for
//! clean removal later. Blocking is port-based, not PID-based, because standard
//! nftables matching does not include a direct process-id selector.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};

use thiserror::Error;

/// nft table name used by this project.
const NFT_TABLE_NAME: &str = "filter";

/// nft family used by this project.
const NFT_FAMILY: &str = "inet";

/// nft chain name used for outbound filtering.
const NFT_OUTPUT_CHAIN: &str = "output";

/// Marker prefix used in nft rule comments so we can find handles later.
const RULE_COMMENT_PREFIX: &str = "netmon-";

/// Header rows in `/proc/<pid>/net/*` that must be skipped.
const PROC_NET_HEADER_INDEX: usize = 0;

/// Minimum number of columns expected in `/proc/<pid>/net/*`.
const PROC_NET_PORT_COLUMN_COUNT: usize = 2;

#[derive(Debug, Error)]
pub enum ControllerError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("nft command failed: {0}")]
    Nft(String),
    #[error("parse error: {0}")]
    Parse(String),
}

#[derive(Debug, Clone)]
struct RuleRef {
    handle: u64,
}

static RULES_BY_SCOPE: OnceLock<Mutex<HashMap<String, Vec<RuleRef>>>> = OnceLock::new();

// Returns the singleton in-memory map that tracks inserted rule handles.
fn rules_map() -> &'static Mutex<HashMap<String, Vec<RuleRef>>> {
    RULES_BY_SCOPE.get_or_init(|| Mutex::new(HashMap::new()))
}

// Builds a stable key for in-memory rule tracking.
fn scope_key(kind: &str, id: impl AsRef<str>) -> String {
    format!("{kind}:{}", id.as_ref())
}

// Builds the comment prefix used to discover handles for one scope.
fn scope_marker(scope_key: &str) -> String {
    format!("{RULE_COMMENT_PREFIX}{scope_key}-")
}

// Builds the user-visible comment text for a rule.
fn scoped_comment(scope_key: &str, label: &str) -> String {
    format!("{RULE_COMMENT_PREFIX}{scope_key}-{}", label.replace('"', "_"))
}

// Registers the handles returned by nft for one logical control scope.
fn register_rule_handles(scope_key: &str, handles: Vec<u64>) -> Result<(), String> {
    let mut guard = rules_map()
        .lock()
        .map_err(|_| "failed to lock rules map".to_string())?;
    guard.insert(
        scope_key.to_string(),
        handles
            .into_iter()
            .map(|handle| RuleRef { handle })
            .collect(),
    );
    Ok(())
}

// Removes handles from the in-memory map, falling back to discovery if needed.
fn remove_rules_for_scope(scope_key: &str) -> Result<(), String> {
    let mut handles = Vec::new();
    {
        let mut guard = rules_map()
            .lock()
            .map_err(|_| "failed to lock rules map".to_string())?;
        if let Some(refs) = guard.remove(scope_key) {
            handles.extend(refs.into_iter().map(|rule_ref| rule_ref.handle));
        }
    }

    if handles.is_empty() {
        handles = find_rule_handles_by_marker(&scope_marker(scope_key))?;
    }

    for handle in handles {
        run_nft_command(
            [
                "delete",
                "rule",
                NFT_FAMILY,
                NFT_TABLE_NAME,
                NFT_OUTPUT_CHAIN,
                "handle",
                &handle.to_string(),
            ],
            false,
        )?;
    }

    Ok(())
}

/// Creates the nftables table and output chain used by netmon if missing.
pub fn setup_nftables() -> Result<(), String> {
    run_nft_command(["add", "table", NFT_FAMILY, NFT_TABLE_NAME], true)?;
    run_nft_command(
        [
            "add",
            "chain",
            NFT_FAMILY,
            NFT_TABLE_NAME,
            NFT_OUTPUT_CHAIN,
            "{",
            "type",
            "filter",
            "hook",
            NFT_OUTPUT_CHAIN,
            "priority",
            "0",
            ";",
            "policy",
            "accept",
            ";",
            "}",
        ],
        true,
    )?;
    Ok(())
}

/// Blocks outgoing traffic for a process by inserting nftables drop rules.
pub fn block_process(pid: u32, process_name: &str) -> Result<(), String> {
    let _ = setup_nftables();
    let scope_key = scope_key("proc", pid.to_string());
    remove_rules_for_scope(&scope_key)?;

    let tcp_ports = collect_pid_ports(pid, &["tcp", "tcp6"])?;
    let udp_ports = collect_pid_ports(pid, &["udp", "udp6"])?;
    let uid = read_uid_for_pid(pid);

    let safe_name = process_name.replace('"', "_");
    let comment = scoped_comment(&scope_key, &safe_name);

    let rules = if tcp_ports.is_empty() && udp_ports.is_empty() {
        if let Some(uid) = uid {
            format!(
                "add rule {NFT_FAMILY} {NFT_TABLE_NAME} {NFT_OUTPUT_CHAIN} \
                 meta skuid {uid} drop comment \"{comment}\"\n"
            )
        } else {
            return Err(format!(
                "No TCP/UDP ports and could not read UID for PID {pid}"
            ));
        }
    } else {
        build_block_ruleset(&tcp_ports, &udp_ports, &comment)
    };

    run_nft_script(&rules)?;

    let handles = find_rule_handles_by_marker(&scope_marker(&scope_key))?;
    if handles.is_empty() {
        return Err("Inserted rules but could not find nft handles".to_string());
    }

    register_rule_handles(&scope_key, handles)?;

    Ok(())
}

/// Removes all tracked nftables rules associated with one process ID.
pub fn unblock_process(pid: u32) -> Result<(), String> {
    // Phase I Lesson TC-3: ensure reversible control actions with explicit rollback path.
    remove_rules_for_scope(&scope_key("proc", pid.to_string()))?;
    remove_rules_for_scope(&scope_key("rate-proc", pid.to_string()))
}

/// Blocks outgoing traffic for one thread by inserting nftables drop rules.
pub fn block_thread(pid: u32, tid: u32, thread_name: &str) -> Result<(), String> {
    let _ = setup_nftables();
    let scope_key = scope_key("thread", format!("{pid}:{tid}"));
    remove_rules_for_scope(&scope_key)?;

    let tcp_ports = collect_thread_ports(pid, tid, &["tcp", "tcp6"])?;
    let udp_ports = collect_thread_ports(pid, tid, &["udp", "udp6"])?;

    if tcp_ports.is_empty() && udp_ports.is_empty() {
        return Err(format!("No TCP/UDP ports found for PID {pid} TID {tid}"));
    }

    let safe_name = thread_name.replace('"', "_");
    let comment = scoped_comment(&scope_key, &safe_name);
    let rules = build_block_ruleset(&tcp_ports, &udp_ports, &comment);

    run_nft_script(&rules)?;

    let handles = find_rule_handles_by_marker(&scope_marker(&scope_key))?;
    if handles.is_empty() {
        return Err("Inserted thread block rules but could not find nft handles".to_string());
    }

    register_rule_handles(&scope_key, handles)?;
    Ok(())
}

/// Removes all tracked nftables rules associated with one thread.
pub fn unblock_thread(pid: u32, tid: u32) -> Result<(), String> {
    remove_rules_for_scope(&scope_key("thread", format!("{pid}:{tid}")))?;
    remove_rules_for_scope(&scope_key("rate-thread", format!("{pid}:{tid}")))
}

/// Blocks outgoing traffic for one user by UID.
pub fn block_user(uid: u32, username: &str) -> Result<(), String> {
    let _ = setup_nftables();
    let scope_key = scope_key("user", uid.to_string());
    remove_rules_for_scope(&scope_key)?;

    let safe_name = username.replace('"', "_");
    let comment = scoped_comment(&scope_key, &safe_name);
    let rule = format!(
        "add rule {NFT_FAMILY} {NFT_TABLE_NAME} {NFT_OUTPUT_CHAIN} meta skuid {uid} drop comment \"{comment}\"\n"
    );

    run_nft_script(&rule)?;

    let handles = find_rule_handles_by_marker(&scope_marker(&scope_key))?;
    if handles.is_empty() {
        return Err("Inserted user block rules but could not find nft handles".to_string());
    }

    register_rule_handles(&scope_key, handles)?;
    Ok(())
}

/// Removes all tracked nftables rules associated with one user.
pub fn unblock_user(uid: u32) -> Result<(), String> {
    remove_rules_for_scope(&scope_key("user", uid.to_string()))?;
    remove_rules_for_scope(&scope_key("rate-user", uid.to_string()))
}

/// Flushes the output chain and clears all tracked process-to-rule mappings.
pub fn unblock_all() -> Result<(), String> {
    run_nft_command(["flush", "chain", NFT_FAMILY, NFT_TABLE_NAME, NFT_OUTPUT_CHAIN], false)?;
    let mut guard = rules_map()
        .lock()
        .map_err(|_| "failed to lock rules map".to_string())?;
    guard.clear();
    Ok(())
}

/// Lists lines in the current nft output chain for status display.
pub fn list_rules() -> Result<Vec<String>, String> {
    let output = Command::new("nft")
        .args(["list", "chain", NFT_FAMILY, NFT_TABLE_NAME, NFT_OUTPUT_CHAIN])
        .output()
        .map_err(|e| format!("failed to run nft: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        return Err(format!("nft list failed: {stderr}"));
    }

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    Ok(stdout.lines().map(ToString::to_string).collect())
}

/// Placeholder for future process rate limiting via tc HTB.
pub fn rate_limit_process(pid: u32, rate_kbps: u32) -> Result<(), String> {
    let _ = setup_nftables();

    let scope_key = scope_key("rate-proc", pid.to_string());
    remove_rules_for_scope(&scope_key)?;

    let tcp_ports = collect_pid_ports(pid, &["tcp", "tcp6"])?;
    let udp_ports = collect_pid_ports(pid, &["udp", "udp6"])?;
    let uid = read_uid_for_pid(pid);

    let comment = scoped_comment(&scope_key, "rate-limit");

    let rules = if tcp_ports.is_empty() && udp_ports.is_empty() {
        if let Some(uid) = uid {
            format!(
                "add rule {NFT_FAMILY} {NFT_TABLE_NAME} {NFT_OUTPUT_CHAIN} \
                 meta skuid {uid} quota over {rate_kbps} kbytes/second drop comment \"{comment}\"\n"
            )
        } else {
            return Err(format!(
                "No TCP/UDP ports and could not read UID for PID {pid}"
            ));
        }
    } else {
        build_rate_limit_ruleset(&tcp_ports, &udp_ports, &comment, rate_kbps)
    };

    run_nft_script(&rules)?;

    let handles = find_rule_handles_by_marker(&scope_marker(&scope_key))?;
    if handles.is_empty() {
        return Err("Inserted rate-limit rules but could not find nft handles".to_string());
    }

    register_rule_handles(&scope_key, handles)?;

    Ok(())
}

/// Limits the bandwidth for one thread.
pub fn rate_limit_thread(pid: u32, tid: u32, rate_kbps: u32) -> Result<(), String> {
    let _ = setup_nftables();

    let scope_key = scope_key("rate-thread", format!("{pid}:{tid}"));
    remove_rules_for_scope(&scope_key)?;

    let tcp_ports = collect_thread_ports(pid, tid, &["tcp", "tcp6"])?;
    let udp_ports = collect_thread_ports(pid, tid, &["udp", "udp6"])?;

    if tcp_ports.is_empty() && udp_ports.is_empty() {
        return Err(format!("No TCP/UDP ports found for PID {pid} TID {tid}"));
    }

    let comment = scoped_comment(&scope_key, "rate-limit");
    let rules = build_rate_limit_ruleset(&tcp_ports, &udp_ports, &comment, rate_kbps);

    run_nft_script(&rules)?;

    let handles = find_rule_handles_by_marker(&scope_marker(&scope_key))?;
    if handles.is_empty() {
        return Err("Inserted thread rate-limit rules but could not find nft handles".to_string());
    }

    register_rule_handles(&scope_key, handles)?;
    Ok(())
}

/// Limits the bandwidth for one user by UID.
pub fn rate_limit_user(uid: u32, rate_kbps: u32) -> Result<(), String> {
    let _ = setup_nftables();

    let scope_key = scope_key("rate-user", uid.to_string());
    remove_rules_for_scope(&scope_key)?;

    let comment = scoped_comment(&scope_key, "rate-limit");
    let rule = format!(
        "add rule {NFT_FAMILY} {NFT_TABLE_NAME} {NFT_OUTPUT_CHAIN} meta skuid {uid} quota over {rate_kbps} kbytes/second drop comment \"{comment}\"\n"
    );

    run_nft_script(&rule)?;

    let handles = find_rule_handles_by_marker(&scope_marker(&scope_key))?;
    if handles.is_empty() {
        return Err("Inserted user rate-limit rules but could not find nft handles".to_string());
    }

    register_rule_handles(&scope_key, handles)?;
    Ok(())
}

// Builds an nftables ruleset script with TCP and UDP sport drop rules.
fn build_block_ruleset(tcp_ports: &BTreeSet<u16>, udp_ports: &BTreeSet<u16>, comment: &str) -> String {
    let mut ruleset = String::new();

    if !tcp_ports.is_empty() {
        ruleset.push_str(&format!(
            "add rule {NFT_FAMILY} {NFT_TABLE_NAME} {NFT_OUTPUT_CHAIN} tcp sport {{ {} }} drop comment \"{}\"\n",
            join_ports(tcp_ports),
            comment
        ));
    }
    if !udp_ports.is_empty() {
        ruleset.push_str(&format!(
            "add rule {NFT_FAMILY} {NFT_TABLE_NAME} {NFT_OUTPUT_CHAIN} udp sport {{ {} }} drop comment \"{}\"\n",
            join_ports(udp_ports),
            comment
        ));
    }

    ruleset
}

// Builds an nftables ruleset script that drops packets above the requested rate.
fn build_rate_limit_ruleset(
    tcp_ports: &BTreeSet<u16>,
    udp_ports: &BTreeSet<u16>,
    comment: &str,
    rate_kbps: u32,
) -> String {
    let mut ruleset = String::new();
    let rate_expr = format!("{rate_kbps} kbytes/second");

    if !tcp_ports.is_empty() {
        ruleset.push_str(&format!(
            "add rule {NFT_FAMILY} {NFT_TABLE_NAME} {NFT_OUTPUT_CHAIN} tcp sport {{ {} }} quota over {} drop comment \"{}\"\n",
            join_ports(tcp_ports),
            rate_expr,
            comment
        ));
    }
    if !udp_ports.is_empty() {
        ruleset.push_str(&format!(
            "add rule {NFT_FAMILY} {NFT_TABLE_NAME} {NFT_OUTPUT_CHAIN} udp sport {{ {} }} quota over {} drop comment \"{}\"\n",
            join_ports(udp_ports),
            rate_expr,
            comment
        ));
    }

    ruleset
}

// Reads source ports used by a PID from `/proc/<pid>/net/{tcp,tcp6,udp,udp6}`.
fn collect_pid_ports(_pid: u32, files: &[&str]) -> Result<BTreeSet<u16>, String> {
    collect_net_table_ports(files, None)
}

// Reads source ports used by a single thread by following the thread's socket fds.
fn collect_thread_ports(pid: u32, tid: u32, files: &[&str]) -> Result<BTreeSet<u16>, String> {
    let fd_path = format!("/proc/{pid}/task/{tid}/fd");
    let socket_inodes = collect_socket_inodes(&fd_path);
    collect_net_table_ports(files, Some(&socket_inodes))
}

// Reads source ports from `/proc/net/*`, optionally filtering by socket inode.
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
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < PROC_NET_PORT_COLUMN_COUNT {
                continue;
            }
            let inode = match cols[9].parse::<u64>() {
                Ok(inode) => inode,
                Err(_) => continue,
            };
            if let Some(filter) = inode_filter {
                if !filter.contains(&inode) {
                    continue;
                }
            }

            if let Some(port) = parse_port_from_proc_addr(cols[1]) {
                ports.insert(port);
            }
        }
    }

    Ok(ports)
}

// Collects socket inode numbers from /proc/<pid>/task/<tid>/fd.
fn collect_socket_inodes(fd_path: &str) -> BTreeSet<u64> {
    let mut inodes = BTreeSet::new();

    let entries = match fs::read_dir(fd_path) {
        Ok(entries) => entries,
        Err(_) => return inodes,
    };

    for entry in entries.flatten() {
        let target = match fs::read_link(entry.path()) {
            Ok(target) => target,
            Err(_) => continue,
        };

        if let Some(inode) = parse_socket_inode(&target) {
            inodes.insert(inode);
        }
    }

    inodes
}

// Parses the local endpoint field and returns only the local source port.
fn parse_port_from_proc_addr(proc_addr: &str) -> Option<u16> {
    let mut parts = proc_addr.split(':');
    let _ip = parts.next()?;
    let port_hex = parts.next()?;
    u16::from_str_radix(port_hex, 16).ok()
}

// Parses symlinks like `socket:[12345]` into raw inode numbers.
fn parse_socket_inode(target: &Path) -> Option<u64> {
    let target_text = target.to_string_lossy();
    let prefix = "socket:[";

    if !target_text.starts_with(prefix) || !target_text.ends_with(']') {
        return None;
    }

    let inode_text = &target_text[prefix.len()..target_text.len() - 1];
    inode_text.parse::<u64>().ok()
}

// Reads the effective UID of a process from /proc/<pid>/status.
fn read_uid_for_pid(pid: u32) -> Option<u32> {
    let content = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().nth(1)?.parse().ok();
        }
    }
    None
}

// Joins a sorted set of ports into nft set syntax, e.g. `80, 443`.
fn join_ports(ports: &BTreeSet<u16>) -> String {
    ports
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<String>>()
        .join(", ")
}

// Executes `nft -f -` and sends the provided ruleset through stdin.
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
            .map_err(|e| format!("failed writing nft ruleset to stdin: {e}"))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("failed waiting on nft: {e}"))?;

    if !output.status.success() {
        let out = String::from_utf8_lossy(&output.stdout);
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(format!("nft failed. stdout: {out}. stderr: {err}"));
    }

    Ok(())
}

// Runs one nft command and optionally ignores `File exists` conflicts.
fn run_nft_command<const N: usize>(args: [&str; N], ignore_exists: bool) -> Result<(), String> {
    let output = Command::new("nft")
        .args(args)
        .output()
        .map_err(map_nft_spawn_error)?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if ignore_exists && stderr.contains("File exists") {
        return Ok(());
    }

    Err(format!("nft command error: {stderr}"))
}

// G-10: provide a clear operator message when nftables CLI is missing.
fn map_nft_spawn_error(err: std::io::Error) -> String {
    if err.kind() == std::io::ErrorKind::NotFound {
        return "Blocking failed: nft not found. Install with: sudo apt-get install nftables"
            .to_string();
    }
    format!("failed to run nft: {err}")
}

// Finds nft rule handles by scanning chain lines with this comment marker.
fn find_rule_handles_by_marker(marker: &str) -> Result<Vec<u64>, String> {
    let output = Command::new("nft")
        .args(["-a", "list", "chain", NFT_FAMILY, NFT_TABLE_NAME, NFT_OUTPUT_CHAIN])
        .output()
        .map_err(|e| format!("failed to run nft list -a: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        return Err(format!("nft list -a failed: {stderr}"));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut handles = Vec::new();

    for line in stdout.lines() {
        if !line.contains(&marker) {
            continue;
        }
        if let Some(idx) = line.rfind("handle ") {
            let handle_txt = line[(idx + 7)..].trim();
            if let Ok(handle) = handle_txt.parse::<u64>() {
                handles.push(handle);
            }
        }
    }

    Ok(handles)
}
