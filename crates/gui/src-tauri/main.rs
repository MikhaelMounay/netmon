#![deny(warnings)]

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender, SyncSender};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aggregator::{spawn_aggregator_thread, AggregatorControl, HistoryCsvRow, InterfaceStats, ProcessRow, ThreadKey};
use capture::{spawn_capture_thread, CaptureControl, FlowRecord, Protocol};
use controller as net_controller;
use serde::Serialize;
use tauri::{Manager, State};

const STATUS_POLL_TIMEOUT_MS: u64 = 200;
const SNAPSHOT_DEFAULT_TOP_N: usize = 25;
const SNAPSHOT_DEFAULT_MAX_CONNECTIONS: usize = 50;
const THREAD_JOIN_TIMEOUT_SECS: u64 = 2;
const FLOW_CHANNEL_DEPTH: usize = 1024;

#[derive(Clone)]
struct DeviceInfo {
    name: String,
    ips: Vec<IpAddr>,
}

struct AppState {
    devices: Mutex<Vec<DeviceInfo>>,
    capture_control: Mutex<Option<CaptureControl>>,
    aggregator_control: Mutex<Option<AggregatorControl>>,
    capture_running: Arc<AtomicBool>,
    app_running: Arc<AtomicBool>,
    tx_flow: SyncSender<FlowRecord>,
    rows_snapshot: Arc<RwLock<Vec<ProcessRow>>>,
    interface_snapshot: Arc<RwLock<InterfaceStats>>,
    status_snapshot: Arc<RwLock<String>>,
    blocked_pids: Arc<RwLock<HashSet<u32>>>,
    blocked_threads: Arc<RwLock<HashSet<ThreadKey>>>,
    blocked_users: Arc<RwLock<HashSet<u32>>>,
    rate_limited_pids: Arc<RwLock<HashSet<u32>>>,
    rate_limited_threads: Arc<RwLock<HashSet<ThreadKey>>>,
    rate_limited_users: Arc<RwLock<HashSet<u32>>>,
    active_filter: Arc<RwLock<String>>,
    session_history_snapshot: Arc<RwLock<Vec<HistoryCsvRow>>>,
    pcap_record_path: Mutex<Option<PathBuf>>,
    status_tx: Sender<String>,
}

impl AppState {
    fn new() -> Self {
        let devices = Mutex::new(list_pcap_devices());
        let rows_snapshot = Arc::new(RwLock::new(Vec::new()));
        let interface_snapshot = Arc::new(RwLock::new(InterfaceStats::default()));
        let status_snapshot = Arc::new(RwLock::new("Ready".to_string()));
        let blocked_pids = Arc::new(RwLock::new(HashSet::new()));
        let blocked_threads = Arc::new(RwLock::new(HashSet::new()));
        let blocked_users = Arc::new(RwLock::new(HashSet::new()));
        let rate_limited_pids = Arc::new(RwLock::new(HashSet::new()));
        let rate_limited_threads = Arc::new(RwLock::new(HashSet::new()));
        let rate_limited_users = Arc::new(RwLock::new(HashSet::new()));
        let active_filter = Arc::new(RwLock::new(String::new()));
        let session_history_snapshot = Arc::new(RwLock::new(Vec::new()));
        let pcap_record_path = Mutex::new(None);

        let (tx_flow, rx_flow) = mpsc::sync_channel::<FlowRecord>(FLOW_CHANNEL_DEPTH);
        let (status_tx, status_rx) = mpsc::channel::<String>();
        let app_running = Arc::new(AtomicBool::new(true));
        let capture_running = Arc::new(AtomicBool::new(false));

        let aggregator_control = Some(spawn_aggregator_thread(
            rx_flow,
            app_running.clone(),
            rows_snapshot.clone(),
            interface_snapshot.clone(),
            status_snapshot.clone(),
            blocked_pids.clone(),
            blocked_threads.clone(),
            blocked_users.clone(),
            session_history_snapshot.clone(),
        ));

        spawn_status_listener(status_rx, status_snapshot.clone(), app_running.clone());

        Self {
            devices,
            capture_control: Mutex::new(None),
            aggregator_control: Mutex::new(aggregator_control),
            capture_running,
            app_running,
            tx_flow,
            rows_snapshot,
            interface_snapshot,
            status_snapshot,
            blocked_pids,
            blocked_threads,
            blocked_users,
            rate_limited_pids,
            rate_limited_threads,
            rate_limited_users,
            active_filter,
            session_history_snapshot,
            pcap_record_path,
            status_tx,
        }
    }

    fn shutdown(&self) {
        self.app_running.store(false, Ordering::Relaxed);
        self.capture_running.store(false, Ordering::Relaxed);
        let _ = self.stop_capture_inner();
        self.join_aggregator();
    }

    fn stop_capture_inner(&self) -> Result<(), String> {
        let mut guard = self
            .capture_control
            .lock()
            .map_err(|_| "capture control lock poisoned".to_string())?;
        if let Some(control) = guard.as_mut() {
            let _ = control.stop();
            let _ = control.join_timeout(Duration::from_secs(THREAD_JOIN_TIMEOUT_SECS));
        }
        *guard = None;
        Ok(())
    }

    fn join_aggregator(&self) {
        if let Ok(mut guard) = self.aggregator_control.lock() {
            if let Some(control) = guard.as_mut() {
                let _ = control.join_timeout(Duration::from_secs(THREAD_JOIN_TIMEOUT_SECS));
            }
            *guard = None;
        }
    }
}

fn spawn_status_listener(
    status_rx: mpsc::Receiver<String>,
    status_snapshot: Arc<RwLock<String>>,
    running: Arc<AtomicBool>,
) {
    thread::spawn(move || {
        while running.load(Ordering::Relaxed) {
            match status_rx.recv_timeout(Duration::from_millis(STATUS_POLL_TIMEOUT_MS)) {
                Ok(msg) => {
                    if let Ok(mut guard) = status_snapshot.write() {
                        *guard = msg;
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
    });
}

fn list_pcap_devices() -> Vec<DeviceInfo> {
    pcap::Device::list()
        .map(|list| {
            list.into_iter()
                .map(|device| DeviceInfo {
                    name: device.name,
                    ips: device
                        .addresses
                        .into_iter()
                        .map(|address| address.addr)
                        .collect(),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn generate_pcap_path() -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("netmon_capture_{ts}.pcap"))
}

fn sanitize_csv(value: &str) -> String {
    let escaped = value.replace('"', "\"\"");
    if escaped.contains(',') || escaped.contains('\n') || escaped.contains('"') {
        format!("\"{escaped}\"")
    } else {
        escaped
    }
}

fn write_history_csv(rows: &[HistoryCsvRow], path: &Path) -> Result<(), String> {
    let file = File::create(path).map_err(|err| err.to_string())?;
    let mut writer = BufWriter::new(file);
    writer
        .write_all(
            b"timestamp,pid,tid,process,thread,user,uid,tx_bytes_total,rx_bytes_total,tx_2s_avg,rx_2s_avg,tx_10s_avg,rx_10s_avg\n",
        )
        .map_err(|err| err.to_string())?;

    for row in rows {
        let line = format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
            row.timestamp,
            row.pid,
            row.tid,
            sanitize_csv(&row.process),
            sanitize_csv(&row.thread),
            sanitize_csv(&row.user),
            row.uid,
            row.tx_bytes_total,
            row.rx_bytes_total,
            row.tx_2s_avg,
            row.rx_2s_avg,
            row.tx_10s_avg,
            row.rx_10s_avg,
        );
        writer.write_all(line.as_bytes()).map_err(|err| err.to_string())?;
    }
    writer.flush().map_err(|err| err.to_string())?;
    Ok(())
}

#[derive(Serialize)]
struct DeviceDto {
    name: String,
    ips: Vec<String>,
}

#[derive(Serialize)]
struct InterfaceStatsDto {
    tx_bytes_total: u64,
    rx_bytes_total: u64,
    current_bandwidth_bytes_per_sec: u64,
    peak_bandwidth_bytes_per_sec: u64,
    tx_history: Vec<u64>,
    rx_history: Vec<u64>,
}

#[derive(Serialize)]
struct ProcessDto {
    pid: u32,
    tid: u32,
    process: String,
    thread: String,
    uid: u32,
    user: String,
    tx_bytes: u64,
    rx_bytes: u64,
    tx_rate_bytes_per_sec: u64,
    rx_rate_bytes_per_sec: u64,
    tx_history: Vec<u64>,
    rx_history: Vec<u64>,
    is_blocked: bool,
    is_process_blocked: bool,
    is_thread_blocked: bool,
    is_user_blocked: bool,
    is_process_rate_limited: bool,
    is_thread_rate_limited: bool,
    is_user_rate_limited: bool,
}

#[derive(Serialize)]
struct ConnectionDto {
    local_addr: String,
    remote_addr: String,
    protocol: String,
    state: String,
    pid: u32,
    tid: u32,
    process: String,
    thread: String,
    uid: u32,
    user: String,
    tx_bytes: u64,
    rx_bytes: u64,
}

#[derive(Serialize)]
struct BlockedCountsDto {
    processes: usize,
    threads: usize,
    users: usize,
}

#[derive(Serialize)]
struct SnapshotDto {
    status: String,
    interface: InterfaceStatsDto,
    processes: Vec<ProcessDto>,
    connections: Vec<ConnectionDto>,
    blocked: BlockedCountsDto,
    captured_at_ms: u128,
}

fn protocol_label(protocol: Protocol) -> String {
    match protocol {
        Protocol::Tcp => "TCP".to_string(),
        Protocol::Udp => "UDP".to_string(),
        Protocol::Other(value) => format!("Other({value})"),
    }
}

#[tauri::command]
fn list_devices(state: State<'_, AppState>) -> Vec<DeviceDto> {
    let devices = state
        .devices
        .lock()
        .map(|guard| guard.clone())
        .unwrap_or_default();

    devices
        .into_iter()
        .map(|device| DeviceDto {
            name: device.name,
            ips: device.ips.into_iter().map(|ip| ip.to_string()).collect(),
        })
        .collect()
}

#[tauri::command]
fn refresh_devices(state: State<'_, AppState>) -> Vec<DeviceDto> {
    let devices = list_pcap_devices();
    if let Ok(mut guard) = state.devices.lock() {
        *guard = devices.clone();
    }

    devices
        .into_iter()
        .map(|device| DeviceDto {
            name: device.name,
            ips: device.ips.into_iter().map(|ip| ip.to_string()).collect(),
        })
        .collect()
}

#[tauri::command]
fn start_capture(
    state: State<'_, AppState>,
    interface: String,
    bpf_filter: Option<String>,
    record_path: Option<String>,
) -> Result<(), String> {
    if state.capture_running.swap(true, Ordering::Relaxed) {
        return Err("capture already running".to_string());
    }

    let devices = match state.devices.lock() {
        Ok(guard) => guard,
        Err(_) => {
            state.capture_running.store(false, Ordering::Relaxed);
            return Err("device cache lock poisoned".to_string());
        }
    };
    let selected = match devices.iter().find(|device| device.name == interface).cloned() {
        Some(device) => device,
        None => {
            state.capture_running.store(false, Ordering::Relaxed);
            return Err("interface not found".to_string());
        }
    };

    let recording_path = record_path
        .map(PathBuf::from)
        .or_else(|| Some(generate_pcap_path()));

    let control = match spawn_capture_thread(
        &selected.name,
        selected.ips,
        state.tx_flow.clone(),
        state.capture_running.clone(),
        state.status_tx.clone(),
        recording_path.clone(),
    ) {
        Ok(control) => control,
        Err(err) => {
            state.capture_running.store(false, Ordering::Relaxed);
            return Err(err.to_string());
        }
    };

    if let Some(filter) = bpf_filter.clone() {
        if let Err(err) = control.apply_filter(filter) {
            state.capture_running.store(false, Ordering::Relaxed);
            return Err(err.to_string());
        }
    }

    let mut guard = match state.capture_control.lock() {
        Ok(guard) => guard,
        Err(_) => {
            state.capture_running.store(false, Ordering::Relaxed);
            return Err("capture control lock poisoned".to_string());
        }
    };
    *guard = Some(control);

    if let Ok(mut history) = state.session_history_snapshot.write() {
        history.clear();
    }
    if let Ok(mut record_guard) = state.pcap_record_path.lock() {
        *record_guard = recording_path;
    }
    if let Ok(mut active_filter) = state.active_filter.write() {
        *active_filter = bpf_filter.unwrap_or_default();
    }

    Ok(())
}

#[tauri::command]
fn stop_capture(state: State<'_, AppState>) -> Result<(), String> {
    state.capture_running.store(false, Ordering::Relaxed);
    state.stop_capture_inner()
}

#[tauri::command]
fn apply_filter(state: State<'_, AppState>, bpf_filter: String) -> Result<(), String> {
    let mut guard = state
        .capture_control
        .lock()
        .map_err(|_| "capture control lock poisoned".to_string())?;
    let control = guard
        .as_mut()
        .ok_or_else(|| "capture not running".to_string())?;
    control
        .apply_filter(bpf_filter.clone())
        .map_err(|err| err.to_string())?;
    if let Ok(mut active_filter) = state.active_filter.write() {
        *active_filter = bpf_filter;
    }
    Ok(())
}

#[tauri::command]
fn get_snapshot(
    state: State<'_, AppState>,
    top_n: Option<usize>,
    max_connections: Option<usize>,
) -> SnapshotDto {
    let top_n = top_n.unwrap_or(SNAPSHOT_DEFAULT_TOP_N);
    let max_connections = max_connections.unwrap_or(SNAPSHOT_DEFAULT_MAX_CONNECTIONS);

    let status = state
        .status_snapshot
        .read()
        .map(|guard| guard.clone())
        .unwrap_or_else(|_| "Unknown".to_string());

    let interface = state
        .interface_snapshot
        .read()
        .map(|stats| InterfaceStatsDto {
            tx_bytes_total: stats.tx_bytes_total,
            rx_bytes_total: stats.rx_bytes_total,
            current_bandwidth_bytes_per_sec: stats.current_bandwidth_bytes_per_sec,
            peak_bandwidth_bytes_per_sec: stats.peak_bandwidth_bytes_per_sec,
            tx_history: stats.tx_history.to_vec(),
            rx_history: stats.rx_history.to_vec(),
        })
        .unwrap_or(InterfaceStatsDto {
            tx_bytes_total: 0,
            rx_bytes_total: 0,
            current_bandwidth_bytes_per_sec: 0,
            peak_bandwidth_bytes_per_sec: 0,
            tx_history: Vec::new(),
            rx_history: Vec::new(),
        });

    let mut rows = state
        .rows_snapshot
        .read()
        .map(|guard| guard.clone())
        .unwrap_or_default();

    rows.sort_by(|a, b| {
        let a_total = a.tx_bytes + a.rx_bytes;
        let b_total = b.tx_bytes + b.rx_bytes;
        b_total.cmp(&a_total)
    });
    rows.truncate(top_n);

    let blocked_pids = state
        .blocked_pids
        .read()
        .map(|guard| guard.clone())
        .unwrap_or_default();
    let blocked_threads = state
        .blocked_threads
        .read()
        .map(|guard| guard.clone())
        .unwrap_or_default();
    let blocked_users = state
        .blocked_users
        .read()
        .map(|guard| guard.clone())
        .unwrap_or_default();
    let rate_limited_pids = state
        .rate_limited_pids
        .read()
        .map(|guard| guard.clone())
        .unwrap_or_default();
    let rate_limited_threads = state
        .rate_limited_threads
        .read()
        .map(|guard| guard.clone())
        .unwrap_or_default();
    let rate_limited_users = state
        .rate_limited_users
        .read()
        .map(|guard| guard.clone())
        .unwrap_or_default();

    let processes = rows
        .iter()
        .map(|row| {
            let thread_key = ThreadKey {
                pid: row.info.pid,
                tid: row.info.tid,
            };
            let is_process_blocked = blocked_pids.contains(&row.info.pid);
            let is_thread_blocked = blocked_threads.contains(&thread_key);
            let is_user_blocked = blocked_users.contains(&row.info.uid);
            let is_process_rate_limited = rate_limited_pids.contains(&row.info.pid);
            let is_thread_rate_limited = rate_limited_threads.contains(&thread_key);
            let is_user_rate_limited = rate_limited_users.contains(&row.info.uid);
            ProcessDto {
                pid: row.info.pid,
                tid: row.info.tid,
                process: row.info.name.clone(),
                thread: row.info.thread_name.clone(),
                uid: row.info.uid,
                user: row.info.username.clone(),
                tx_bytes: row.tx_bytes,
                rx_bytes: row.rx_bytes,
                tx_rate_bytes_per_sec: row.tx_history[0],
                rx_rate_bytes_per_sec: row.rx_history[0],
                tx_history: row.tx_history.to_vec(),
                rx_history: row.rx_history.to_vec(),
                is_blocked: row.is_blocked,
                is_process_blocked,
                is_thread_blocked,
                is_user_blocked,
                is_process_rate_limited,
                is_thread_rate_limited,
                is_user_rate_limited,
            }
        })
        .collect::<Vec<_>>();

    let filter_active = state
        .active_filter
        .read()
        .map(|guard| !guard.trim().is_empty())
        .unwrap_or(false);
    let mut connections = Vec::new();
    for row in rows {
        for entry in row.connections {
            if connections.len() >= max_connections {
                break;
            }
            if filter_active && entry.tx_bytes == 0 && entry.rx_bytes == 0 {
                continue;
            }
            connections.push(ConnectionDto {
                local_addr: entry.local_addr.to_string(),
                remote_addr: entry.remote_addr.to_string(),
                protocol: protocol_label(entry.protocol),
                state: entry.state,
                pid: entry.pid,
                tid: entry.tid,
                process: entry.process,
                thread: entry.thread_name,
                uid: entry.uid,
                user: entry.username,
                tx_bytes: entry.tx_bytes,
                rx_bytes: entry.rx_bytes,
            });
        }
        if connections.len() >= max_connections {
            break;
        }
    }

    let blocked = BlockedCountsDto {
        processes: state
            .blocked_pids
            .read()
            .map(|guard| guard.len())
            .unwrap_or(0),
        threads: state
            .blocked_threads
            .read()
            .map(|guard| guard.len())
            .unwrap_or(0),
        users: state
            .blocked_users
            .read()
            .map(|guard| guard.len())
            .unwrap_or(0),
    };

    SnapshotDto {
        status,
        interface,
        processes,
        connections,
        blocked,
        captured_at_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis())
            .unwrap_or(0),
    }
}

#[tauri::command]
fn block_process(state: State<'_, AppState>, pid: u32, name: String) -> Result<(), String> {
    net_controller::block_process(pid, &name)?;
    if let Ok(mut guard) = state.blocked_pids.write() {
        guard.insert(pid);
    }
    Ok(())
}

#[tauri::command]
fn unblock_process(state: State<'_, AppState>, pid: u32) -> Result<(), String> {
    net_controller::unblock_process(pid)?;
    if let Ok(mut guard) = state.blocked_pids.write() {
        guard.remove(&pid);
    }
    Ok(())
}

#[tauri::command]
fn block_thread(
    state: State<'_, AppState>,
    pid: u32,
    tid: u32,
    name: String,
) -> Result<(), String> {
    net_controller::block_thread(pid, tid, &name)?;
    if let Ok(mut guard) = state.blocked_threads.write() {
        guard.insert(ThreadKey { pid, tid });
    }
    Ok(())
}

#[tauri::command]
fn unblock_thread(state: State<'_, AppState>, pid: u32, tid: u32) -> Result<(), String> {
    net_controller::unblock_thread(pid, tid)?;
    if let Ok(mut guard) = state.blocked_threads.write() {
        guard.remove(&ThreadKey { pid, tid });
    }
    Ok(())
}

#[tauri::command]
fn block_user(state: State<'_, AppState>, uid: u32, username: String) -> Result<(), String> {
    net_controller::block_user(uid, &username)?;
    if let Ok(mut guard) = state.blocked_users.write() {
        guard.insert(uid);
    }
    Ok(())
}

#[tauri::command]
fn unblock_user(state: State<'_, AppState>, uid: u32) -> Result<(), String> {
    net_controller::unblock_user(uid)?;
    if let Ok(mut guard) = state.blocked_users.write() {
        guard.remove(&uid);
    }
    Ok(())
}

#[tauri::command]
fn rate_limit_process(state: State<'_, AppState>, pid: u32, rate_kbps: u32) -> Result<(), String> {
    net_controller::rate_limit_process(pid, rate_kbps)?;
    if let Ok(mut guard) = state.rate_limited_pids.write() {
        guard.insert(pid);
    }
    Ok(())
}

#[tauri::command]
fn unlimit_process(state: State<'_, AppState>, pid: u32) -> Result<(), String> {
    net_controller::unlimit_process(pid)?;
    if let Ok(mut guard) = state.rate_limited_pids.write() {
        guard.remove(&pid);
    }
    Ok(())
}

#[tauri::command]
fn rate_limit_thread(
    state: State<'_, AppState>,
    pid: u32,
    tid: u32,
    rate_kbps: u32,
) -> Result<(), String> {
    net_controller::rate_limit_thread(pid, tid, rate_kbps)?;
    if let Ok(mut guard) = state.rate_limited_threads.write() {
        guard.insert(ThreadKey { pid, tid });
    }
    Ok(())
}

#[tauri::command]
fn unlimit_thread(state: State<'_, AppState>, pid: u32, tid: u32) -> Result<(), String> {
    net_controller::unlimit_thread(pid, tid)?;
    if let Ok(mut guard) = state.rate_limited_threads.write() {
        guard.remove(&ThreadKey { pid, tid });
    }
    Ok(())
}

#[tauri::command]
fn rate_limit_user(state: State<'_, AppState>, uid: u32, rate_kbps: u32) -> Result<(), String> {
    net_controller::rate_limit_user(uid, rate_kbps)?;
    if let Ok(mut guard) = state.rate_limited_users.write() {
        guard.insert(uid);
    }
    Ok(())
}

#[tauri::command]
fn unlimit_user(state: State<'_, AppState>, uid: u32) -> Result<(), String> {
    net_controller::unlimit_user(uid)?;
    if let Ok(mut guard) = state.rate_limited_users.write() {
        guard.remove(&uid);
    }
    Ok(())
}

#[tauri::command]
fn export_csv(state: State<'_, AppState>, path: String) -> Result<(), String> {
    let rows = state
        .session_history_snapshot
        .read()
        .map(|guard| guard.clone())
        .unwrap_or_default();
    write_history_csv(&rows, Path::new(&path))
}

#[tauri::command]
fn export_pcap(state: State<'_, AppState>, path: String) -> Result<(), String> {
    if let Ok(guard) = state.capture_control.lock() {
        if let Some(control) = guard.as_ref() {
            let _ = control.flush();
        }
    }

    let source = state
        .pcap_record_path
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
        .ok_or_else(|| "no PCAP recording available".to_string())?;

    if !source.exists() {
        return Err("PCAP recording file missing".to_string());
    }

    fs::copy(&source, &path).map_err(|err| err.to_string())?;
    Ok(())
}

fn main() {
    env_logger::init();
    let state = AppState::new();

    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            list_devices,
            refresh_devices,
            start_capture,
            stop_capture,
            apply_filter,
            get_snapshot,
            block_process,
            unblock_process,
            block_thread,
            unblock_thread,
            block_user,
            unblock_user,
            rate_limit_process,
            unlimit_process,
            rate_limit_thread,
            unlimit_thread,
            rate_limit_user,
            unlimit_user,
            export_csv,
            export_pcap
        ])
        .build(tauri::generate_context!())
        .expect("error while running netmon")
        .run(|app_handle, event| {
            if let tauri::RunEvent::ExitRequested { .. } = event {
                let state = app_handle.state::<AppState>();
                state.shutdown();
            }
        });
}


