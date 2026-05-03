#![deny(warnings)]

//! Renders the netmon desktop interface and coordinates capture, aggregation,
//! and controller actions from user input.
//!
//! This binary crate runs the `eframe` event loop, periodically reads immutable
//! snapshots from the aggregator thread, and shows process and connection data
//! in interactive tables and charts. User actions such as applying a BPF filter
//! or blocking a process call directly into the capture and controller crates.
//! The UI remains immediate-mode: each frame redraws from current shared state.

use std::cmp::Ordering;
use std::collections::HashSet;
use std::net::IpAddr;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aggregator::{spawn_aggregator_thread, AggregatorControl, HistoryCsvRow, InterfaceStats, ProcessRow, ThreadKey};
use anyhow::Result;
use capture::{spawn_capture_thread, CaptureControl};
use eframe::egui::{self, Color32, RichText, ScrollArea};
use eframe::{App, Frame};
use egui_plot::{Line, Plot, PlotPoints};

/// Number of history points shown in traffic charts.
const CHART_HISTORY_SECONDS: usize = 300;

/// Number of samples used for short rolling rates.
const SHORT_RATE_WINDOW_SECONDS: usize = 2;

/// Default number of seconds shown by the live chart.
const DEFAULT_CHART_WINDOW_SECONDS: usize = 60;

/// UI repaint interval in milliseconds.
const UI_REPAINT_INTERVAL_MS: u64 = 16;

/// Join timeout for worker thread shutdown.
const THREAD_JOIN_TIMEOUT_SECS: u64 = 2;

/// Height of the process table scroll area.
const PROCESS_TABLE_HEIGHT: f32 = 320.0;

/// Height of the connection table scroll area.
#[allow(dead_code)]
const CONNECTION_TABLE_HEIGHT: f32 = 250.0;

/// Width at which the process/chart area switches from split to stacked.
const RESPONSIVE_STACK_WIDTH: f32 = 1200.0;

/// New larger chart height for improved visibility and focus.
const CHART_HEIGHT: f32 = 500.0;

/// Width of the left sidebar panel (top processes).
#[allow(dead_code)]
const SIDEBAR_WIDTH: f32 = 280.0;

/// Height of KPI cards section.
#[allow(dead_code)]
const KPI_CARDS_HEIGHT: f32 = 120.0;

/// Maximum number of processes shown in detailed table.
#[allow(dead_code)]
const MAX_PROCESSES_DISPLAYED: usize = 10;

/// Maximum number of connections shown in details.
#[allow(dead_code)]
const MAX_CONNECTIONS_DISPLAYED: usize = 20;

/// Spike detection threshold (bytes per second).
const SPIKE_THRESHOLD_BYTES_PER_SEC: u64 = 500_000_000;

/// Cache update interval (milliseconds).
const CACHE_UPDATE_INTERVAL_MS: u64 = 100;

/// Per-second throughput threshold for orange warning rows.
const HIGH_TRAFFIC_THRESHOLD_BYTES_PER_SEC: u64 = 1024 * 1024;

/// Per-second throughput threshold for red critical rows.
const VERY_HIGH_TRAFFIC_THRESHOLD_BYTES_PER_SEC: u64 = 10 * 1024 * 1024;

/// Red tint used for blocked rows in the connection table.
#[allow(dead_code)]
const BLOCKED_ROW_COLOR: Color32 = Color32::from_rgb(255, 140, 140);

/// G-06: blocked processes must be visually distinct in the process table.
const BLOCKED_PROCESS_ROW_FILL: Color32 = Color32::from_rgb(70, 20, 20);

/// G-06: keep username text readable in a dedicated column.
const USER_COLUMN_MIN_WIDTH: f32 = 110.0;

/// Plot line color for TX bandwidth history.
const TX_LINE_COLOR: Color32 = Color32::from_rgb(80, 120, 240);

/// Plot line color for RX bandwidth history.
const RX_LINE_COLOR: Color32 = Color32::from_rgb(60, 180, 90);

/// KPI Card accent color: TX rate (blue).
const KPI_TX_COLOR: Color32 = Color32::from_rgb(80, 120, 240);

/// KPI Card accent color: RX rate (green).
const KPI_RX_COLOR: Color32 = Color32::from_rgb(60, 180, 90);

/// KPI Card accent color: Peak bandwidth (orange).
const KPI_PEAK_COLOR: Color32 = Color32::from_rgb(255, 165, 0);

/// KPI Card accent color: Connections (purple).
const KPI_CONN_COLOR: Color32 = Color32::from_rgb(200, 100, 200);

/// Rank badge color: 1st place (red).
const RANK_1ST_COLOR: Color32 = Color32::from_rgb(255, 100, 100);

/// Rank badge color: 2nd place (orange).
#[allow(dead_code)]
const RANK_2ND_COLOR: Color32 = Color32::from_rgb(255, 165, 0);

/// Rank badge color: 3rd place (gold).
#[allow(dead_code)]
const RANK_3RD_COLOR: Color32 = Color32::from_rgb(255, 215, 0);

/// Rank badge color: 4th+ place (blue).
#[allow(dead_code)]
const RANK_OTHER_COLOR: Color32 = Color32::from_rgb(100, 150, 255);

/// PROFESSIONAL SPACING SCALE
/// Consistent spacing for professional polish
#[allow(dead_code)]
const SPACING_XXSMALL: f32 = 2.0;
const SPACING_XSMALL: f32 = 4.0;
const SPACING_SMALL: f32 = 8.0;
const SPACING_MEDIUM: f32 = 12.0;
const SPACING_LARGE: f32 = 16.0;
#[allow(dead_code)]
const SPACING_XLARGE: f32 = 24.0;
#[allow(dead_code)]
const SPACING_XXLARGE: f32 = 32.0;

/// PROFESSIONAL COLOR PALETTE
/// Neutral backgrounds and separators
#[allow(dead_code)]
const COLOR_BG_DARK: Color32 = Color32::from_rgb(20, 20, 20);
#[allow(dead_code)]
const COLOR_BG_SURFACE: Color32 = Color32::from_rgb(30, 30, 30);
#[allow(dead_code)]
const COLOR_BORDER: Color32 = Color32::from_rgb(50, 50, 50);
const COLOR_TEXT_MUTED: Color32 = Color32::from_rgb(120, 120, 120);

/// Status colors
const COLOR_STATUS_GOOD: Color32 = Color32::from_rgb(76, 175, 80);
const COLOR_STATUS_WARNING: Color32 = Color32::from_rgb(255, 152, 0);
const COLOR_STATUS_CRITICAL: Color32 = Color32::from_rgb(244, 67, 54);

/// Panel resizing constraints
#[allow(dead_code)]
const CHART_PANEL_MIN_HEIGHT: f32 = 250.0;
#[allow(dead_code)]
const CHART_PANEL_MAX_HEIGHT: f32 = 800.0;
#[allow(dead_code)]
const PROCESS_TABLE_MIN_HEIGHT: f32 = 150.0;
#[allow(dead_code)]
const PROCESS_TABLE_MAX_HEIGHT: f32 = 600.0;
#[allow(dead_code)]
const KPI_SECTION_MIN_HEIGHT: f32 = 180.0;
#[allow(dead_code)]
const KPI_SECTION_MAX_HEIGHT: f32 = 350.0;

/// Millisecond conversion helper for bits-per-second display.
const BITS_PER_BYTE: f64 = 8.0;

/// Binary scale used in byte/bit unit formatting.
const KIBI_BASE: f64 = 1024.0;

/// Process table PID column width.
const PROCESS_PID_WIDTH: f32 = 60.0;

/// Process table TID column width.
const PROCESS_TID_WIDTH: f32 = 60.0;

/// Process table process-name column width.
const PROCESS_NAME_WIDTH: f32 = 180.0;

/// Process table thread-name column width.
const PROCESS_THREAD_WIDTH: f32 = 180.0;

/// Process table bandwidth column width.
const PROCESS_BW_WIDTH: f32 = 88.0;

/// Process table total-byte column width.
const PROCESS_TOTAL_WIDTH: f32 = 96.0;

/// Connection table PID/TID width.
const CONNECTION_PID_WIDTH: f32 = 60.0;

/// Connection table thread-name width.
const CONNECTION_THREAD_WIDTH: f32 = 160.0;

/// Connection table process-name width.
const CONNECTION_PROCESS_WIDTH: f32 = 180.0;

/// Connection table address width.
const CONNECTION_ADDR_WIDTH: f32 = 160.0;

/// Connection table protocol/state width.
const CONNECTION_PROTO_WIDTH: f32 = 72.0;

/// Connection table traffic total width.
const CONNECTION_TOTAL_WIDTH: f32 = 96.0;

/// Single connection row height used for scroll area sizing.
const CONNECTION_ROW_HEIGHT: f32 = 18.0;

/// Path prefix used for session PCAP recordings.
const PCAP_SESSION_PREFIX: &str = "netmon_capture_";

/// Path prefix used for exported PCAP files.
const PCAP_EXPORT_PREFIX: &str = "netmon_export_";

/// Data structure for spike events in network traffic.
#[derive(Clone, Debug)]
struct SpikeEvent {
    bandwidth_bytes_per_sec: u64,
    #[allow(dead_code)]
    timestamp: std::time::Instant,
}

/// Cached insights computed at regular intervals to avoid recomputation.
#[derive(Clone)]
struct DashboardCache {
    /// Top N processes sorted by total bandwidth (TX + RX)
    top_processes: Vec<(ProcessRow, u64)>,
    /// Current detected spike (if any)
    spike_detected: Option<SpikeEvent>,
    /// Top port by bytes transferred
    top_port: Option<(u16, String)>,
    /// Count of blocked processes
    blocked_process_count: usize,
    /// Count of active processes (with network activity)
    active_process_count: usize,
    /// Total active connections
    total_connections: usize,
    /// Protocol counts (TCP, UDP, Other)
    protocol_tcp_count: usize,
    protocol_udp_count: usize,
    protocol_other_count: usize,
    /// Network utilization as percentage of peak (0-100)
    network_utilization_percent: u8,
    /// Last time cache was updated
    last_computed: std::time::Instant,
}

impl Default for DashboardCache {
    fn default() -> Self {
        Self {
            top_processes: Vec::new(),
            spike_detected: None,
            top_port: None,
            blocked_process_count: 0,
            active_process_count: 0,
            total_connections: 0,
            protocol_tcp_count: 0,
            protocol_udp_count: 0,
            protocol_other_count: 0,
            network_utilization_percent: 0,
            last_computed: std::time::Instant::now(),
        }
    }
}

#[derive(Clone)]
struct DeviceInfo {
    name: String,
    ips: Vec<IpAddr>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SortColumn {
    Pid,
    Tid,
    Process,
    Thread,
    User,
    ProtocolMix,
    TxRate,
    RxRate,
    TxTotal,
    RxTotal,
}

struct NetmonApp {
    devices: Vec<DeviceInfo>,
    selected_iface: usize,
    capture_control: Option<CaptureControl>,
    capture_running: Arc<AtomicBool>,
    app_running: Arc<AtomicBool>,

    tx_flow: SyncSender<capture::FlowRecord>,
    aggregator_control: Option<AggregatorControl>,

    rows_snapshot: Arc<RwLock<Vec<ProcessRow>>>,
    interface_snapshot: Arc<RwLock<InterfaceStats>>,
    status_snapshot: Arc<RwLock<String>>,
    blocked_pids: Arc<RwLock<HashSet<u32>>>,
    blocked_threads: Arc<RwLock<HashSet<ThreadKey>>>,
    blocked_users: Arc<RwLock<HashSet<u32>>>,

    status_tx: Sender<String>,
    status_rx: Receiver<String>,

    selected_thread: Option<ThreadKey>,
    sort_column: SortColumn,
    sort_ascending: bool,

    is_capturing: bool,
    bpf_input: String,
    show_bits: bool,
    // G-10: tracks the last successfully applied BPF expression.
    active_filter: String,
    chart_window_seconds: usize,
    rate_limit_kbps_input: String,
    session_history_snapshot: Arc<RwLock<Vec<HistoryCsvRow>>>,
    capture_recording_path: Option<PathBuf>,
    pending_block: Option<(u32, String)>,
    virtualization_warning: bool,

    // New fields for redesigned UI
    dashboard_cache: DashboardCache,
    
    // Panel height tracking for dynamic resizing
    chart_panel_height: f32,
    kpi_panel_height: f32,
    #[allow(dead_code)]
    process_table_height: f32,
}

impl NetmonApp {
    // Builds initial GUI state and starts the aggregator worker thread.
    fn new() -> Self {
        let devices = pcap::Device::list()
            .map(|list| {
                list.into_iter()
                    .map(|d| DeviceInfo {
                        name: d.name,
                        ips: d.addresses.into_iter().map(|address| address.addr).collect(),
                    })
                    .collect::<Vec<DeviceInfo>>()
            })
            .unwrap_or_default();

        let rows_snapshot = Arc::new(RwLock::new(Vec::new()));
        let interface_snapshot = Arc::new(RwLock::new(InterfaceStats::default()));
        let status_snapshot = Arc::new(RwLock::new("Ready".to_string()));
        let blocked_pids = Arc::new(RwLock::new(HashSet::new()));
        let blocked_threads = Arc::new(RwLock::new(HashSet::new()));
        let blocked_users = Arc::new(RwLock::new(HashSet::new()));
        let session_history_snapshot = Arc::new(RwLock::new(Vec::new()));

        // Phase I Lesson WS-2: bounded channel provides backpressure between capture and UI pipeline.
        let (tx_flow, rx_flow) = mpsc::sync_channel::<capture::FlowRecord>(1024);
        let app_running = Arc::new(AtomicBool::new(true));

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

        let (status_tx, status_rx) = mpsc::channel::<String>();

        Self {
            devices,
            selected_iface: 0,
            capture_control: None,
            capture_running: Arc::new(AtomicBool::new(false)),
            app_running,
            tx_flow,
            aggregator_control,
            rows_snapshot,
            interface_snapshot,
            status_snapshot,
            blocked_pids,
            blocked_threads,
            blocked_users,
            status_tx,
            status_rx,
            selected_thread: None,
            sort_column: SortColumn::Pid,
            sort_ascending: true,
            is_capturing: false,
            bpf_input: String::new(),
            show_bits: false,
            active_filter: String::new(),
            chart_window_seconds: DEFAULT_CHART_WINDOW_SECONDS,
            rate_limit_kbps_input: "1024".to_string(),
            session_history_snapshot,
            capture_recording_path: None,
            pending_block: None,
            virtualization_warning: detect_virtualbox(),
            dashboard_cache: DashboardCache::default(),
            chart_panel_height: 450.0,
            kpi_panel_height: 220.0,
            process_table_height: 300.0,
        }
    }

    // Starts packet capture on the currently selected interface.
    fn start_capture(&mut self) {
        if self.is_capturing || self.devices.is_empty() {
            return;
        }

        let iface = match self.devices.get(self.selected_iface) {
            Some(v) => v.name.clone(),
            None => return,
        };

        self.capture_running = Arc::new(AtomicBool::new(true));

        let local_ips = self
            .devices
            .get(self.selected_iface)
            .map(|device| device.ips.clone())
            .unwrap_or_default();

        let home = get_user_home();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let recording_path = PathBuf::from(format!("{home}/{PCAP_SESSION_PREFIX}{ts}.pcap"));

        match spawn_capture_thread(
            &iface,
            local_ips,
            self.tx_flow.clone(),
            self.capture_running.clone(),
            self.status_tx.clone(),
            Some(recording_path.clone()),
        ) {
            Ok(control) => {
                self.capture_control = Some(control);
                self.capture_recording_path = Some(recording_path);
                self.is_capturing = true;
                if let Ok(mut status) = self.status_snapshot.write() {
                    *status = format!("Capturing on {iface}...");
                }
            }
            Err(e) => {
                self.capture_recording_path = None;
                if let Ok(mut status) = self.status_snapshot.write() {
                    *status = format!("Failed to start capture on {iface}: {e}");
                }
            }
        }
    }

    // Stops the active capture thread and updates status text.
    fn stop_capture(&mut self) {
        if !self.is_capturing {
            return;
        }

        self.capture_running.store(false, AtomicOrdering::Relaxed);

        if let Some(control) = self.capture_control.as_ref() {
            let _ = control.stop();
        }

        if let Some(mut control) = self.capture_control.take() {
            let _ = control.join_timeout(Duration::from_secs(THREAD_JOIN_TIMEOUT_SECS));
        }

        self.is_capturing = false;
        if let Ok(mut status) = self.status_snapshot.write() {
            *status = "Capture stopped".to_string();
        }
    }

    // Restarts capture after an interface selection change.
    fn restart_capture_for_interface_change(&mut self) {
        let was_running = self.is_capturing;
        self.stop_capture();
        if was_running {
            self.start_capture();
        }
    }

    // Applies the current BPF expression through the capture control channel.
    fn apply_bpf_filter(&mut self) {
        if let Some(control) = self.capture_control.as_ref() {
            let expr = self.bpf_input.trim().to_string();
            if expr.is_empty() {
                if let Ok(mut status) = self.status_snapshot.write() {
                    *status = "Enter a BPF expression before applying it".to_string();
                }
                return;
            }
            if let Err(e) = control.apply_filter(expr.clone()) {
                if let Ok(mut status) = self.status_snapshot.write() {
                    *status = format!("BPF error: {e}");
                }
            }
        } else if let Ok(mut status) = self.status_snapshot.write() {
            *status = "Cannot apply BPF: capture is not running".to_string();
        }
    }

    // Sorts process rows according to the selected column and direction.
    fn sorted_rows(&self, mut rows: Vec<ProcessRow>) -> Vec<ProcessRow> {
        rows.sort_by(|a, b| {
            let cmp = match self.sort_column {
                SortColumn::Pid => a.info.pid.cmp(&b.info.pid),
                SortColumn::Process => a.info.name.cmp(&b.info.name),
                SortColumn::User => a.info.username.cmp(&b.info.username),
                SortColumn::ProtocolMix => protocol_mix_summary(a).cmp(&protocol_mix_summary(b)),
                SortColumn::TxRate => two_second_avg(&a.tx_history).cmp(&two_second_avg(&b.tx_history)),
                SortColumn::RxRate => two_second_avg(&a.rx_history).cmp(&two_second_avg(&b.rx_history)),
                SortColumn::TxTotal => a.tx_bytes.cmp(&b.tx_bytes),
                SortColumn::RxTotal => a.rx_bytes.cmp(&b.rx_bytes),
                SortColumn::Tid => a.info.tid.cmp(&b.info.tid),
                SortColumn::Thread => a.info.thread_name.cmp(&b.info.thread_name),
            };

            if self.sort_ascending {
                cmp
            } else {
                match cmp {
                    Ordering::Less => Ordering::Greater,
                    Ordering::Equal => Ordering::Equal,
                    Ordering::Greater => Ordering::Less,
                }
            }
        });
        rows
    }

    // Updates sort state when the user clicks a process table header.
    #[allow(dead_code)]
    fn set_sort(&mut self, col: SortColumn) {
        if self.sort_column == col {
            self.sort_ascending = !self.sort_ascending;
        } else {
            self.sort_column = col;
            self.sort_ascending = true;
        }
    }

    // Clones the latest process snapshot from shared state.
    fn process_rows(&self) -> Vec<ProcessRow> {
        self.rows_snapshot
            .read()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    // Drains pending status messages sent from background threads.
    fn update_status_from_channel(&mut self) {
        while let Ok(msg) = self.status_rx.try_recv() {
            // G-10: keep last successful filter when invalid expressions fail.
            if let Some(applied_filter) = msg.strip_prefix("Filter applied: ") {
                self.active_filter = applied_filter.to_string();
            }

            // G-10: transition UI state to stopped when capture thread reports failure.
            if msg.starts_with("Capture stopped:") {
                self.is_capturing = false;
                self.capture_running.store(false, AtomicOrdering::Relaxed);
                if let Some(mut control) = self.capture_control.take() {
                    let _ = control.join_timeout(Duration::from_secs(THREAD_JOIN_TIMEOUT_SECS));
                }
            }

            if let Ok(mut status) = self.status_snapshot.write() {
                *status = msg;
            }
        }
    }

    // Blocks one process through nftables and updates local blocked state.
    fn block_pid(&mut self, pid: u32, name: &str) {
        match controller::block_process(pid, name) {
            Ok(()) => {
                if let Ok(mut blocked) = self.blocked_pids.write() {
                    blocked.insert(pid);
                }
                if let Ok(mut status) = self.status_snapshot.write() {
                    *status = format!("Blocked {name} (PID {pid})");
                }
            }
            Err(e) => {
                if let Ok(mut status) = self.status_snapshot.write() {
                    *status = format!("Block failed for PID {pid}: {e}");
                }
            }
        }
    }

    // Blocks one thread through nftables and updates local blocked state.
    fn block_thread(&mut self, pid: u32, tid: u32, thread_name: &str) {
        match controller::block_thread(pid, tid, thread_name) {
            Ok(()) => {
                if let Ok(mut blocked) = self.blocked_threads.write() {
                    blocked.insert(ThreadKey { pid, tid });
                }
                if let Ok(mut status) = self.status_snapshot.write() {
                    *status = format!("Blocked {thread_name} (PID {pid}, TID {tid})");
                }
            }
            Err(e) => {
                if let Ok(mut status) = self.status_snapshot.write() {
                    *status = format!("Block failed for PID {pid}, TID {tid}: {e}");
                }
            }
        }
    }

    // Unblocks one process through nftables and updates local blocked state.
    fn unblock_pid(&mut self, pid: u32) {
        match controller::unblock_process(pid) {
            Ok(()) => {
                if let Ok(mut blocked) = self.blocked_pids.write() {
                    blocked.remove(&pid);
                }
                if let Ok(mut status) = self.status_snapshot.write() {
                    *status = format!("Unblocked PID {pid}");
                }
            }
            Err(e) => {
                if let Ok(mut status) = self.status_snapshot.write() {
                    *status = format!("Unblock failed for PID {pid}: {e}");
                }
            }
        }
    }

    // Unblocks one thread through nftables and updates local blocked state.
    fn unblock_thread(&mut self, pid: u32, tid: u32) {
        match controller::unblock_thread(pid, tid) {
            Ok(()) => {
                if let Ok(mut blocked) = self.blocked_threads.write() {
                    blocked.remove(&ThreadKey { pid, tid });
                }
                if let Ok(mut status) = self.status_snapshot.write() {
                    *status = format!("Unblocked PID {pid}, TID {tid}");
                }
            }
            Err(e) => {
                if let Ok(mut status) = self.status_snapshot.write() {
                    *status = format!("Unblock failed for PID {pid}, TID {tid}: {e}");
                }
            }
        }
    }

    // Blocks one user through nftables and updates local blocked state.
    fn block_user(&mut self, uid: u32, username: &str) {
        match controller::block_user(uid, username) {
            Ok(()) => {
                if let Ok(mut blocked) = self.blocked_users.write() {
                    blocked.insert(uid);
                }
                if let Ok(mut status) = self.status_snapshot.write() {
                    *status = format!("Blocked user {username} (UID {uid})");
                }
            }
            Err(e) => {
                if let Ok(mut status) = self.status_snapshot.write() {
                    *status = format!("Block failed for UID {uid}: {e}");
                }
            }
        }
    }

    // Unblocks one user through nftables and updates local blocked state.
    fn unblock_user(&mut self, uid: u32, username: &str) {
        match controller::unblock_user(uid) {
            Ok(()) => {
                if let Ok(mut blocked) = self.blocked_users.write() {
                    blocked.remove(&uid);
                }
                if let Ok(mut status) = self.status_snapshot.write() {
                    *status = format!("Unblocked user {username} (UID {uid})");
                }
            }
            Err(e) => {
                if let Ok(mut status) = self.status_snapshot.write() {
                    *status = format!("Unblock failed for UID {uid}: {e}");
                }
            }
        }
    }

    // Limits a selected PID using the controller's rate-limit hook.
    fn limit_process_bandwidth(&mut self, pid: u32, name: &str) {
        let Some(rate_kbps) = self.parse_rate_limit_kbps() else {
            return;
        };

        match controller::rate_limit_process(pid, rate_kbps) {
            Ok(()) => {
                if let Ok(mut status) = self.status_snapshot.write() {
                    *status = format!("Rate-limited {name} (PID {pid}) to {rate_kbps} kbit/s");
                }
            }
            Err(error) => {
                if let Ok(mut status) = self.status_snapshot.write() {
                    *status = format!("Rate limit failed for PID {pid}: {error}");
                }
            }
        }
    }

    // Limits a selected thread using the controller's rate-limit hook.
    fn limit_thread_bandwidth(&mut self, pid: u32, tid: u32, thread_name: &str) {
        let Some(rate_kbps) = self.parse_rate_limit_kbps() else {
            return;
        };

        match controller::rate_limit_thread(pid, tid, rate_kbps) {
            Ok(()) => {
                if let Ok(mut status) = self.status_snapshot.write() {
                    *status = format!(
                        "Rate-limited {thread_name} (PID {pid}, TID {tid}) to {rate_kbps} kbit/s"
                    );
                }
            }
            Err(error) => {
                if let Ok(mut status) = self.status_snapshot.write() {
                    *status = format!("Rate limit failed for PID {pid}, TID {tid}: {error}");
                }
            }
        }
    }

    // Limits a selected user using the controller's rate-limit hook.
    fn limit_user_bandwidth(&mut self, uid: u32, username: &str) {
        let Some(rate_kbps) = self.parse_rate_limit_kbps() else {
            return;
        };

        match controller::rate_limit_user(uid, rate_kbps) {
            Ok(()) => {
                if let Ok(mut status) = self.status_snapshot.write() {
                    *status = format!("Rate-limited user {username} (UID {uid}) to {rate_kbps} kbit/s");
                }
            }
            Err(error) => {
                if let Ok(mut status) = self.status_snapshot.write() {
                    *status = format!("Rate limit failed for UID {uid}: {error}");
                }
            }
        }
    }

    // Parses the rate-limit text box and reports a friendly error if it is empty or invalid.
    fn parse_rate_limit_kbps(&self) -> Option<u32> {
        match self.rate_limit_kbps_input.trim().parse::<u32>() {
            Ok(value) if value > 0 => Some(value),
            _ => {
                if let Ok(mut status) = self.status_snapshot.write() {
                    *status = "Enter a positive kbit/s value before limiting bandwidth".to_string();
                }
                None
            }
        }
    }

    // Exports the current process snapshot to a timestamped CSV file.
    fn export_csv(&self) {
        let rows = self
            .session_history_snapshot
            .read()
            .map(|snapshot| snapshot.clone())
            .unwrap_or_default();

        if rows.is_empty() {
            if let Ok(mut status) = self.status_snapshot.write() {
                *status = "No session history captured yet".to_string();
            }
            return;
        }

        let home = get_user_home();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let path = format!("{home}/{PCAP_EXPORT_PREFIX}{ts}.csv");

        let mut file = match fs::File::create(&path) {
            Ok(f) => f,
            Err(e) => {
                if let Ok(mut status) = self.status_snapshot.write() {
                    *status = format!("CSV export failed: {e}");
                }
                return;
            }
        };

        let header =
            "timestamp,pid,tid,process,thread,user,uid,tx_bytes_total,rx_bytes_total,tx_2s_avg,rx_2s_avg,tx_10s_avg,rx_10s_avg\n";
        if file.write_all(header.as_bytes()).is_err() {
            if let Ok(mut status) = self.status_snapshot.write() {
                *status = "CSV export failed while writing header".to_string();
            }
            return;
        }

        let mut rows = rows;
        rows.sort_by_key(|row| (row.timestamp, row.pid, row.tid));

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
                row.rx_10s_avg
            );

            if file.write_all(line.as_bytes()).is_err() {
                if let Ok(mut status) = self.status_snapshot.write() {
                    *status = "CSV export failed while writing rows".to_string();
                }
                return;
            }
        }

        if let Ok(mut status) = self.status_snapshot.write() {
            *status = format!("Exported CSV to {path}");
        }
    }

    // Exports the current capture session to a timestamped PCAP file.
    fn export_pcap(&self) {
        let Some(source_path) = self.capture_recording_path.as_ref() else {
            if let Ok(mut status) = self.status_snapshot.write() {
                *status = "PCAP export unavailable: start capture first".to_string();
            }
            return;
        };

        if !source_path.exists() {
            if let Ok(mut status) = self.status_snapshot.write() {
                *status = "PCAP export unavailable: no recording file yet".to_string();
            }
            return;
        }

        let home = get_user_home();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let destination_path = format!("{home}/{PCAP_EXPORT_PREFIX}{ts}.pcap");

        if let Err(error) = fs::copy(source_path, &destination_path) {
            if let Ok(mut status) = self.status_snapshot.write() {
                *status = format!("PCAP export failed: {error}");
            }
            return;
        }

        if let Ok(mut status) = self.status_snapshot.write() {
            *status = format!("Exported PCAP to {destination_path}");
        }
    }

    // Updates the dashboard cache with fresh insights computed from current data.
    fn update_dashboard_cache(&mut self) {
        if self.dashboard_cache.last_computed.elapsed()
            < Duration::from_millis(CACHE_UPDATE_INTERVAL_MS)
        {
            return;
        }

        let rows = self.process_rows();
        let interface_stats = self
            .interface_snapshot
            .read()
            .map(|s| s.clone())
            .unwrap_or_default();

        self.dashboard_cache.top_processes = compute_top_processes(&rows, 5);
        self.dashboard_cache.spike_detected = detect_spike(&rows);
        self.dashboard_cache.top_port = find_top_port(&rows);
        
        // Count blocked processes
        let blocked = self.blocked_pids.read().map(|b| b.len()).unwrap_or(0);
        self.dashboard_cache.blocked_process_count = blocked;
        
        // Keep the process count aligned with the table row count.
        self.dashboard_cache.active_process_count = rows.len();
        
        let total_conns: usize = rows.iter().map(|r| r.connections.len()).sum();
        self.dashboard_cache.total_connections = total_conns;
        
        // Count protocols
        let (tcp, udp, other) = count_protocols(&rows);
        self.dashboard_cache.protocol_tcp_count = tcp;
        self.dashboard_cache.protocol_udp_count = udp;
        self.dashboard_cache.protocol_other_count = other;
        
        // Calculate network utilization
        let current_bw = interface_stats.current_bandwidth_bytes_per_sec;
        let peak_bw = interface_stats.peak_bandwidth_bytes_per_sec;
        let utilization = if peak_bw > 0 {
            ((current_bw as f64 / peak_bw as f64) * 100.0).min(100.0) as u8
        } else {
            0
        };
        self.dashboard_cache.network_utilization_percent = utilization;
        
        self.dashboard_cache.last_computed = std::time::Instant::now();
    }

    // Renders the KPI summary cards with key metrics.
    fn render_kpi_cards(&self, ui: &mut egui::Ui) {
        let interface_stats = self
            .interface_snapshot
            .read()
            .map(|s| s.clone())
            .unwrap_or_default();

        // ROW 1: Primary metrics
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = 10.0;

            // TX RATE CARD
            self.render_kpi_card(
                ui,
                "📤 TX RATE",
                &format_bandwidth(interface_stats.tx_history[0]),
                KPI_TX_COLOR,
                "Current transmitted data rate",
            );

            // RX RATE CARD
            self.render_kpi_card(
                ui,
                "📥 RX RATE",
                &format_bandwidth(interface_stats.rx_history[0]),
                KPI_RX_COLOR,
                "Current received data rate",
            );

            // PEAK BANDWIDTH CARD
            self.render_kpi_card(
                ui,
                "⚡ PEAK BW",
                &format_bandwidth(interface_stats.peak_bandwidth_bytes_per_sec),
                KPI_PEAK_COLOR,
                "Peak bandwidth observed",
            );

            // NETWORK UTILIZATION CARD
            self.render_kpi_card(
                ui,
                "📊 UTIL",
                &format!("{}%", self.dashboard_cache.network_utilization_percent),
                Color32::from_rgb(150, 200, 150),
                "Current utilization vs peak",
            );
        });

        ui.add_space(6.0);

        // ROW 2: Secondary metrics
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = 10.0;

            // CONNECTIONS CARD
            self.render_kpi_card(
                ui,
                "🔗 CONNS",
                &self.dashboard_cache.total_connections.to_string(),
                KPI_CONN_COLOR,
                "Total active connections",
            );

            // ACTIVE PROCESSES CARD
            self.render_kpi_card(
                ui,
                "🔷 TOTAL PROCS",
                &self.dashboard_cache.active_process_count.to_string(),
                Color32::from_rgb(100, 180, 255),
                "Total processes shown in the table",
            );

            // BLOCKED CARD
            let blocked_color = if self.dashboard_cache.blocked_process_count > 0 {
                Color32::from_rgb(255, 120, 120)
            } else {
                Color32::GRAY
            };
            self.render_kpi_card(
                ui,
                "🚫 BLOCKED",
                &self.dashboard_cache.blocked_process_count.to_string(),
                blocked_color,
                "Blocked processes/threads/users",
            );

            // PROTOCOL DISTRIBUTION CARD
            let protocol_text = format!(
                "T:{} U:{} O:{}",
                self.dashboard_cache.protocol_tcp_count,
                self.dashboard_cache.protocol_udp_count,
                self.dashboard_cache.protocol_other_count,
            );
            self.render_kpi_card(
                ui,
                "🌐 PROTO",
                &protocol_text,
                Color32::from_rgb(200, 150, 255),
                "TCP:UDP:Other connection count",
            );
        });
    }

    // Renders a single KPI card with title, value, and styling.
    fn render_kpi_card(
        &self,
        ui: &mut egui::Ui,
        title: &str,
        value: &str,
        accent_color: Color32,
        tooltip: &str,
    ) {
        // Professional card styling
        let response = ui.group(|ui| {
            ui.set_min_size(egui::vec2(120.0, 90.0));
            ui.set_max_size(egui::vec2(200.0, 120.0));
            
            ui.vertical_centered(|ui| {
                ui.add_space(SPACING_XSMALL);

                // Title with professional styling
                ui.label(RichText::new(title)
                    .size(10.0)
                    .color(Color32::from_rgb(180, 180, 180)));

                ui.add_space(SPACING_XSMALL);

                // Value with accent color - responsive sizing
                let value_size = if value.len() > 10 { 15.0 } else { 18.0 };
                ui.label(RichText::new(value)
                    .size(value_size)
                    .strong()
                    .color(accent_color));

                ui.add_space(SPACING_XSMALL);

                // Bottom accent bar
                ui.add_space(2.0);
                ui.painter().line_segment(
                    [
                        ui.min_rect().center_bottom() - egui::vec2(50.0, 8.0),
                        ui.min_rect().center_bottom() + egui::vec2(50.0, 8.0) - egui::vec2(0.0, 8.0),
                    ],
                    egui::Stroke::new(2.0, accent_color.gamma_multiply(0.5)),
                );
            });
        }).response;

        response.on_hover_text(tooltip);
    }

    // Renders the left rail process table.
    fn render_top_processes_sidebar(&mut self, ui: &mut egui::Ui) {
        ui.label(RichText::new("PROCESSES TABLE").size(14.0).strong().color(Color32::WHITE));
        ui.separator();

        let sorted_rows = self.sorted_rows(self.process_rows());

        if sorted_rows.is_empty() {
            ui.label("No processes yet...");
            return;
        }

        self.render_simplified_process_table(ui, &sorted_rows);
    }

    // Renders the insights panel with key findings and alerts.
    fn render_insights_panel(&self, ui: &mut egui::Ui) {
        ui.label(RichText::new("💡 INSIGHTS & ALERTS").size(11.0).strong().color(Color32::from_rgb(200, 200, 100)));

        let mut has_insights = false;
        
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = SPACING_MEDIUM;

            // 1. TOP BANDWIDTH CONSUMER
            if let Some((row, total_rate)) = self.dashboard_cache.top_processes.first() {
                has_insights = true;
                ui.vertical(|ui| {
                    ui.label(RichText::new("🔴 Top Consumer").size(9.0).strong().color(RANK_1ST_COLOR));
                    ui.label(RichText::new(&format!("{}\n{}/s", 
                        &row.info.name[..row.info.name.len().min(12)],
                        format_bandwidth(*total_rate)))
                        .size(10.0).strong().color(Color32::WHITE));
                });
                ui.separator();
            }

            // 2. SPIKE DETECTION
            if let Some(spike) = &self.dashboard_cache.spike_detected {
                has_insights = true;
                ui.vertical(|ui| {
                    ui.label(RichText::new("⚡ Spike Alert").size(9.0).strong().color(Color32::YELLOW));
                    ui.label(RichText::new(&format_bandwidth(spike.bandwidth_bytes_per_sec))
                        .size(10.0).strong().color(Color32::YELLOW));
                });
                ui.separator();
            }

            // 3. TOP PORT
            if let Some((port, proto)) = &self.dashboard_cache.top_port {
                has_insights = true;
                ui.vertical(|ui| {
                    ui.label(RichText::new("🌐 Top Port").size(9.0).strong().color(KPI_CONN_COLOR));
                    ui.label(RichText::new(&format!(":{}\n{}", port, proto))
                        .size(10.0).strong().color(Color32::WHITE));
                });
            }
        });

        if !has_insights {
            ui.label(RichText::new("• No significant alerts").size(10.0).color(COLOR_TEXT_MUTED).italics());
        }
    }

    // Renders the top toolbar and interface bandwidth summary.
    fn render_top_panel(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            self.render_virtualbox_warning(ui);
            self.render_toolbar_controls(ui);
            self.render_interface_summary(ui);
        });
    }

    // Renders the status bar with the latest background status message.
    fn render_status_panel(&self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            let text = self
                .status_snapshot
                .read()
                .map(|status_text| status_text.clone())
                .unwrap_or_else(|_| "Status unavailable".to_string());
            ui.label(text);
        });
    }

    // Renders process table, chart, and connection table in the main area.
	fn render_main_panel(&mut self, ctx: &egui::Context) {
	    let sorted_rows = self.sorted_rows(self.process_rows());

        // LEFT SIDEBAR: Process table (resizable)
	    egui::SidePanel::left("top_processes_panel")
	        .min_width(500.0)
	        .max_width(600.0)
	        .resizable(true)
	        .show(ctx, |ui| {
	            ui.spacing_mut().item_spacing.y = SPACING_SMALL;
	            
                ui.add_space(SPACING_MEDIUM);
                self.render_top_processes_sidebar(ui);
                
                ui.add_space(SPACING_MEDIUM);

                // ============== SECTION 3: SELECTED CONTROLS ==============
                if self.selected_thread.is_some() {
                    ui.separator();
                    ui.add_space(SPACING_MEDIUM);
                    ui.label(RichText::new("PROCESS CONTROLS").size(13.0).strong().color(Color32::WHITE));
                    ui.separator();
                    self.render_selected_row_controls(ui, &sorted_rows);
                    ui.add_space(SPACING_LARGE);
                }
	        });

	    // CENTRAL PANEL: Stacked sections with dynamic heights
	    egui::CentralPanel::default().show(ctx, |ui| {
	        ui.spacing_mut().item_spacing.y = SPACING_MEDIUM;

	        // Scroll area for all content
	        ScrollArea::vertical()
	            .auto_shrink([false; 2])
	            .show(ui, |ui| {
	                // ============== SECTION 2: KPI CARDS & INSIGHTS ==============
	                ui.add_space(SPACING_MEDIUM);
	                
	                ui.label(RichText::new("📊 KEY METRICS").size(13.0).strong().color(Color32::WHITE));
	                ui.separator();

                    // KPI Cards with professional styling (centered)
                    ui.vertical_centered(|ui| {
                        ui.group(|ui| {
                            ui.set_min_size(egui::vec2(ui.available_width(), self.kpi_panel_height - SPACING_LARGE));
                            ui.vertical(|ui| {
                                ui.spacing_mut().item_spacing.y = SPACING_SMALL;
                                self.render_kpi_cards(ui);
                                ui.add_space(SPACING_SMALL);
                                self.render_insights_panel(ui);
                            });
                        });
                    });

                    ui.add_space(SPACING_MEDIUM);
                    ui.separator();

                    // ============== SECTION 2: NETWORK ACTIVITY GRAPH ==============
                    ui.add_space(SPACING_MEDIUM);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("📈 NETWORK ACTIVITY").size(14.0).strong().color(Color32::WHITE));
                        ui.separator();
                        ui.label(RichText::new(&format!("Window: {}s", self.chart_window_seconds))
                            .size(11.0).color(COLOR_TEXT_MUTED));
                    });
                    ui.separator();

                    ui.group(|ui| {
                        ui.set_min_size(egui::vec2(ui.available_width(), self.chart_panel_height - SPACING_LARGE));
                        draw_chart(
                            ui,
                            &sorted_rows,
                            self.selected_thread,
                            self.show_bits,
                            self.chart_window_seconds,
                        );
                    });

                    ui.add_space(SPACING_LARGE);

                    ui.add_space(SPACING_MEDIUM);
                    ui.separator();

                    // Connections are collapsed by default.
                    egui::CollapsingHeader::new("🔗 CONNECTIONS TABLE")
                        .default_open(false)
                        .show(ui, |ui| {
                            ui.add_space(SPACING_SMALL);
                            self.render_connection_table(ui, &sorted_rows);
                        });

                    ui.add_space(SPACING_LARGE);
	            });
	    });
	}

	    // Renders the full process table.
    fn render_simplified_process_table(&mut self, ui: &mut egui::Ui, sorted_rows: &[ProcessRow]) {
        let display_rows = sorted_rows.iter().collect::<Vec<_>>();

        ScrollArea::both()
            .auto_shrink([true; 2])
            .show(ui, |ui| {
                egui::Grid::new("process_grid_simple")
                    .striped(true)
                    .spacing([SPACING_MEDIUM, SPACING_SMALL])
                    .show(ui, |ui| {
                        // Professional header row with darker background
                        let header_color = Color32::from_rgb(60, 60, 60);
                        ui.label(RichText::new("PID").strong().size(10.0).color(Color32::WHITE).background_color(header_color));
                        ui.label(RichText::new("PROCESS").strong().size(10.0).color(Color32::WHITE).background_color(header_color));
                        ui.label(RichText::new("USER").strong().size(10.0).color(Color32::WHITE).background_color(header_color));
                        ui.label(RichText::new("TX/s").strong().size(10.0).color(Color32::WHITE).background_color(header_color));
                        ui.label(RichText::new("RX/s").strong().size(10.0).color(Color32::WHITE).background_color(header_color));
                        ui.label(RichText::new("TOTAL TX").strong().size(10.0).color(Color32::WHITE).background_color(header_color));
                        ui.label(RichText::new("TOTAL RX").strong().size(10.0).color(Color32::WHITE).background_color(header_color));
                        ui.label(RichText::new("ACTION").strong().size(10.0).color(Color32::WHITE).background_color(header_color));
                        ui.end_row();

                        // Data rows with professional styling
                        for row in display_rows {
                            let tx_rate = two_second_avg(&row.tx_history);
                            let rx_rate = two_second_avg(&row.rx_history);
                            let total_rate = tx_rate + rx_rate;

                            // Professional color coding for traffic levels
                            let text_color = if total_rate > VERY_HIGH_TRAFFIC_THRESHOLD_BYTES_PER_SEC {
                                COLOR_STATUS_CRITICAL
                            } else if total_rate > HIGH_TRAFFIC_THRESHOLD_BYTES_PER_SEC {
                                COLOR_STATUS_WARNING
                            } else {
                                Color32::from_rgb(200, 200, 200)
                            };

                            // Row values with proper formatting
                            ui.label(RichText::new(row.info.pid.to_string()).size(10.0).color(Color32::from_rgb(150, 150, 255)));
                            ui.label(RichText::new(&row.info.name).size(10.0).strong().color(text_color));
                            ui.label(RichText::new(&row.info.username).size(10.0).color(Color32::from_rgb(150, 200, 150)));
                            ui.label(RichText::new(format_bandwidth(tx_rate)).size(10.0).color(text_color));
                            ui.label(RichText::new(format_bandwidth(rx_rate)).size(10.0).color(text_color));
                            ui.label(RichText::new(format_bytes(row.tx_bytes)).size(10.0).color(Color32::from_rgb(150, 150, 150)));
                            ui.label(RichText::new(format_bytes(row.rx_bytes)).size(10.0).color(Color32::from_rgb(150, 150, 150)));

                            if ui.small_button("📌").on_hover_text("Select this process").clicked() {
                                self.selected_thread = Some(ThreadKey {
                                    pid: row.info.pid,
                                    tid: row.info.tid,
                                });
                            }

                            ui.end_row();
                        }
                    });
            });
    }

    // Renders the VirtualBox warning banner when virtualized capture is detected.
    fn render_virtualbox_warning(&self, ui: &mut egui::Ui) {
        if self.virtualization_warning {
            ui.horizontal(|ui| {
                ui.label("⚠️");
                ui.vertical(|ui| {
                    ui.label(RichText::new("VirtualBox Environment Detected").strong().color(COLOR_STATUS_WARNING));
                    ui.label(RichText::new("Promiscuous mode capture may be limited or unavailable.")
                        .size(10.0).color(COLOR_TEXT_MUTED));
                });
            });
            ui.add_space(SPACING_SMALL);
        }
    }

    // Renders interface selection, capture controls, and toolbar action buttons.
    fn render_toolbar_controls(&mut self, ui: &mut egui::Ui) {
        ui.spacing_mut().item_spacing.x = SPACING_LARGE;
        
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = SPACING_MEDIUM;
            
            // Interface selector
            ui.label(RichText::new("🖧 Interface:").strong().size(10.0));
            let interface_changed = self.render_interface_combo(ui);
            if interface_changed {
                self.restart_capture_for_interface_change();
            }

            // Capture toggle
            self.render_capture_toggle_button(ui);

            // BPF Filter section
            ui.separator();
            ui.label(RichText::new("🔍 BPF Filter:").strong().size(10.0));
            let response = ui.text_edit_singleline(&mut self.bpf_input);
            if response.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter)) {
                self.apply_bpf_filter();
            }
            if ui.button("Apply").on_hover_text("Apply BPF filter").clicked() {
                self.apply_bpf_filter();
            }

            // Display mode
            ui.separator();
            ui.checkbox(&mut self.show_bits, "Show bits/s");

            // Chart window
            ui.label(RichText::new("📊 Window:").strong().size(10.0));
            ui.add(egui::Slider::new(
                &mut self.chart_window_seconds,
                30..=CHART_HISTORY_SECONDS,
            )
            .step_by(10.0)
            .suffix("s"));

            // Export controls
            ui.separator();
            if ui.button("📥 Export CSV").on_hover_text("Export network data to CSV").clicked() {
                self.export_csv();
            }
            if ui.button("📥 Export PCAP").on_hover_text("Export captured packets to PCAP").clicked() {
                self.export_pcap();
            }
        });
    }

    // Renders the interface selection combo box and reports if selection changed.
    fn render_interface_combo(&mut self, ui: &mut egui::Ui) -> bool {
        let mut interface_changed = false;
        egui::ComboBox::from_id_source("iface_combo")
            .selected_text(
                self.devices
                    .get(self.selected_iface)
                    .map(|device| device.name.as_str())
                    .unwrap_or("No interfaces"),
            )
            .show_ui(ui, |ui| {
                for (index, device) in self.devices.iter().enumerate() {
                    if ui
                        .selectable_value(&mut self.selected_iface, index, &device.name)
                        .clicked()
                    {
                        interface_changed = true;
                    }
                }
            });
        interface_changed
    }

    // Renders the start/stop capture button based on current capture state.
    fn render_capture_toggle_button(&mut self, ui: &mut egui::Ui) {
        // G-07: explicit start/stop affordances for capture lifecycle control.
        if self.is_capturing {
            if ui.button("■ Stop").clicked() {
                self.stop_capture();
            }
            return;
        }

        if ui.button("▶ Start").clicked() {
            self.start_capture();
        }
    }

    // Renders aggregate interface TX/RX totals and current/peak bandwidth.
    fn render_interface_summary(&self, ui: &mut egui::Ui) {
        ui.add_space(SPACING_SMALL);
        
        let interface_stats = self
            .interface_snapshot
            .read()
            .map(|snapshot| snapshot.clone())
            .unwrap_or_default();

        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = SPACING_LARGE;
            
            // TX total
            ui.vertical(|ui| {
                ui.label(RichText::new("TX Total").size(9.0).color(COLOR_TEXT_MUTED));
                ui.label(RichText::new(format_bytes_or_bits(interface_stats.tx_bytes_total, self.show_bits))
                    .size(11.0).strong().color(Color32::from_rgb(150, 220, 150)));
            });
            
            // RX total
            ui.vertical(|ui| {
                ui.label(RichText::new("RX Total").size(9.0).color(COLOR_TEXT_MUTED));
                ui.label(RichText::new(format_bytes_or_bits(interface_stats.rx_bytes_total, self.show_bits))
                    .size(11.0).strong().color(Color32::from_rgb(220, 150, 150)));
            });
            
            // Current BW
            ui.vertical(|ui| {
                ui.label(RichText::new("Current BW").size(9.0).color(COLOR_TEXT_MUTED));
                let current_bw = format_bandwidth(interface_stats.current_bandwidth_bytes_per_sec);
                let bw_color = if interface_stats.current_bandwidth_bytes_per_sec > VERY_HIGH_TRAFFIC_THRESHOLD_BYTES_PER_SEC {
                    COLOR_STATUS_CRITICAL
                } else if interface_stats.current_bandwidth_bytes_per_sec > HIGH_TRAFFIC_THRESHOLD_BYTES_PER_SEC {
                    COLOR_STATUS_WARNING
                } else {
                    COLOR_STATUS_GOOD
                };
                ui.label(RichText::new(&format!("{}/s", current_bw))
                    .size(11.0).strong().color(bw_color));
            });
            
            // Peak BW
            ui.vertical(|ui| {
                ui.label(RichText::new("Peak BW").size(9.0).color(COLOR_TEXT_MUTED));
                ui.label(RichText::new(&format!("{}/s", format_bandwidth(interface_stats.peak_bandwidth_bytes_per_sec)))
                    .size(11.0).strong().color(Color32::from_rgb(200, 150, 100)));
            });
            
            // Active filter
            if !self.active_filter.is_empty() {
                ui.separator();
                ui.vertical(|ui| {
                    ui.label(RichText::new("Active Filter").size(9.0).color(COLOR_TEXT_MUTED));
                    ui.label(RichText::new(&self.active_filter)
                        .size(10.0).strong().color(Color32::from_rgb(100, 200, 255)));
                });
            }
        });
    }

    // Renders the process table and chart in either split or stacked form.
    #[allow(dead_code)]
	fn render_process_and_chart_columns(&mut self, ui: &mut egui::Ui, sorted_rows: &[ProcessRow]) {
	    let available_width = ui.available_width();

	    if available_width < RESPONSIVE_STACK_WIDTH {
		ui.vertical(|ui| {
		    ui.heading("Processes");
		    if let Some(column) = draw_process_table(ui, sorted_rows, self.show_bits, &mut self.selected_thread) {
		        self.set_sort(column);
		    }

		    ui.separator();
		    ui.heading(format!("Chart (Last {}s)", self.chart_window_seconds));
		    draw_chart(
		        ui,
		        sorted_rows,
		        self.selected_thread,
		        self.show_bits,
		        self.chart_window_seconds,
		    );
		});
	    } else {
		ui.columns(2, |columns| {
		    columns[0].vertical(|ui| {
		        ui.heading("Processes");
		        if let Some(column) = draw_process_table(ui, sorted_rows, self.show_bits, &mut self.selected_thread) {
		            self.set_sort(column);
		        }
		    });

		    columns[1].vertical(|ui| {
		        ui.heading(format!("Chart (Last {}s)", self.chart_window_seconds));
		        egui::ScrollArea::vertical()
		            .id_source("chart_scroll")
		            .max_height(CHART_HEIGHT + 32.0)
		            .show(ui, |ui| {
		                draw_chart(
		                    ui,
		                    sorted_rows,
		                    self.selected_thread,
		                    self.show_bits,
		                    self.chart_window_seconds,
		                );
		            });
		    });
		});
	    }

	    self.render_selected_row_controls(ui, sorted_rows);
	}

    // Renders quick actions for the currently selected thread row.
    fn render_selected_row_controls(&mut self, ui: &mut egui::Ui, sorted_rows: &[ProcessRow]) {
        let Some(selected_thread) = self.selected_thread else {
            return;
        };

        let Some(selected_row) = sorted_rows
            .iter()
            .find(|row| row.info.pid == selected_thread.pid && row.info.tid == selected_thread.tid) else {
            return;
        };

        ui.add_space(SPACING_MEDIUM);
        
        ui.label(RichText::new(&format!("{} (PID {}, TID {})",
            selected_row.info.name,
            selected_row.info.pid,
            selected_row.info.tid))
            .size(10.0).color(Color32::from_rgb(200, 200, 200)));
        
        ui.label(RichText::new(&format!("User: {}", selected_row.info.username))
            .size(9.0).color(Color32::from_rgb(150, 200, 150)));
        
        ui.add_space(SPACING_SMALL);

        // Block controls row
        ui.horizontal(|ui| {
            ui.label(RichText::new("Block:").size(10.0).strong().color(Color32::from_rgb(180, 180, 180)));
            ui.spacing_mut().item_spacing.x = SPACING_SMALL;
            
            if ui.button("🚫 Process").on_hover_text("Block all traffic for this process").clicked() {
                self.block_pid(selected_row.info.pid, &selected_row.info.name);
            }

            if ui.button("🚫 Thread").on_hover_text("Block this thread only").clicked() {
                self.block_thread(
                    selected_row.info.pid,
                    selected_row.info.tid,
                    &selected_row.info.thread_name,
                );
            }

            if ui.button("🚫 User").on_hover_text(&format!("Block all traffic for user {}", selected_row.info.username)).clicked() {
                self.block_user(selected_row.info.uid, &selected_row.info.username);
            }
        });

        ui.add_space(SPACING_SMALL);

        // Limit controls row
        ui.horizontal(|ui| {
            ui.label(RichText::new("Limit:").size(10.0).strong().color(Color32::from_rgb(180, 180, 180)));
            ui.spacing_mut().item_spacing.x = SPACING_SMALL;
            
            ui.label(RichText::new("kbps:").size(9.0).color(COLOR_TEXT_MUTED));
            ui.add(
                egui::TextEdit::singleline(&mut self.rate_limit_kbps_input)
                    .desired_width(60.0)
                    .hint_text("0"),
            );
            
            if ui.button("📊 Process").on_hover_text("Limit this process bandwidth").clicked() {
                self.limit_process_bandwidth(selected_row.info.pid, &selected_row.info.name);
            }

            if ui.button("📊 Thread").on_hover_text("Limit this thread bandwidth").clicked() {
                self.limit_thread_bandwidth(
                    selected_row.info.pid,
                    selected_row.info.tid,
                    &selected_row.info.thread_name,
                );
            }

            if ui.button("📊 User").on_hover_text(&format!("Limit user {} bandwidth", selected_row.info.username)).clicked() {
                self.limit_user_bandwidth(selected_row.info.uid, &selected_row.info.username);
            }
        });

        ui.add_space(SPACING_SMALL);

        // Unblock controls row
        ui.horizontal(|ui| {
            ui.label(RichText::new("Unblock:").size(10.0).strong().color(Color32::from_rgb(180, 180, 180)));
            ui.spacing_mut().item_spacing.x = SPACING_SMALL;
            
            if ui.button("✅ Process").on_hover_text("Remove block for this process").clicked() {
                self.unblock_pid(selected_row.info.pid);
            }

            if ui.button("✅ Thread").on_hover_text("Remove block for this thread").clicked() {
                self.unblock_thread(selected_row.info.pid, selected_row.info.tid);
            }

            if ui.button("✅ User").on_hover_text(&format!("Remove block for user {}", selected_row.info.username)).clicked() {
                self.unblock_user(selected_row.info.uid, &selected_row.info.username);
            }
        });
    }

    // Renders the connection table and row-level context menu actions.
    fn render_connection_table(&mut self, ui: &mut egui::Ui, sorted_rows: &[ProcessRow]) {
        let visible_connections = self.collect_visible_connections(sorted_rows);

        // Professional header for selected process
        if let Some(selected_thread) = self.selected_thread {
            if let Some(selected_row) = sorted_rows
                .iter()
                .find(|row| row.info.pid == selected_thread.pid && row.info.tid == selected_thread.tid)
            {
                ui.label(RichText::new("🔗 CONNECTIONS").size(11.0).strong().color(Color32::from_rgb(100, 200, 255)));
                ui.label(RichText::new(&format!("{} (PID {}) • User: {}",
                    selected_row.info.name,
                    selected_row.info.pid,
                    selected_row.info.username))
                    .size(10.0).color(Color32::from_rgb(200, 200, 200)));
                ui.add_space(SPACING_SMALL);
            }
        } else {
            ui.label(RichText::new("🔗 ALL CONNECTIONS").size(11.0).strong().color(Color32::from_rgb(100, 200, 255)));
            ui.add_space(SPACING_SMALL);
        }

        ScrollArea::vertical()
            // .auto_shrink([false; 2])
            .min_scrolled_height(CONNECTION_ROW_HEIGHT * 10.0 + 48.0)
            .max_height(std::f32::INFINITY)
            .show(ui, |ui| {
                egui::Grid::new("conn_grid").striped(true).spacing([SPACING_MEDIUM, SPACING_SMALL]).show(ui, |ui| {
                    draw_connection_table_header(ui);
                    for (is_blocked, connection) in &visible_connections {
                        self.draw_connection_row(ui, *is_blocked, connection);
                    }
                });
            });
    }

    // Collects connection rows for either the selected PID or all processes.
    fn collect_visible_connections(
        &self,
        sorted_rows: &[ProcessRow],
    ) -> Vec<(bool, aggregator::ConnectionEntry)> {
        let mut visible_connections = Vec::new();
        // TODO(future): async DNS resolution
        for row in sorted_rows {
            if self
                .selected_thread
                .is_none_or(|selected| selected.pid == row.info.pid && selected.tid == row.info.tid)
            {
                for connection in &row.connections {
                    visible_connections.push((row.is_blocked, connection.clone()));
                }
            }
        }
        visible_connections
    }

    // Draws one connection table row and attaches a context menu to PID cell.
    fn draw_connection_row(
        &mut self,
        ui: &mut egui::Ui,
        is_blocked: bool,
        connection: &aggregator::ConnectionEntry,
    ) {
        let row_color = if is_blocked {
            Color32::from_rgb(200, 100, 100)
        } else {
            Color32::from_rgb(200, 200, 200)
        };

        let pid_response = ui.add_sized(
            [CONNECTION_PID_WIDTH, 18.0],
            egui::Label::new(RichText::new(connection.pid.to_string()).size(9.0).color(row_color)),
        );
        
        ui.add_sized(
            [CONNECTION_PID_WIDTH, 18.0],
            egui::Label::new(RichText::new(connection.tid.to_string()).size(9.0).color(row_color)),
        );
        
        ui.add_sized(
            [CONNECTION_THREAD_WIDTH, 18.0],
            egui::Label::new(RichText::new(&connection.thread_name).size(9.0).color(row_color)),
        );
        
        ui.add_sized(
            [CONNECTION_PROCESS_WIDTH, 18.0],
            egui::Label::new(RichText::new(&connection.process).size(9.0).color(row_color).strong()),
        );
        
        ui.add_sized(
            [USER_COLUMN_MIN_WIDTH, 18.0],
            egui::Label::new(RichText::new(&connection.username).size(9.0).color(Color32::from_rgb(150, 200, 150))),
        );
        
        ui.add_sized(
            [CONNECTION_ADDR_WIDTH, 18.0],
            egui::Label::new(RichText::new(connection.local_addr.to_string()).size(9.0).color(Color32::from_rgb(150, 150, 200))),
        );
        
        ui.add_sized(
            [CONNECTION_ADDR_WIDTH, 18.0],
            egui::Label::new(RichText::new(connection.remote_addr.to_string()).size(9.0).color(Color32::from_rgb(200, 150, 150))),
        );
        
        ui.add_sized(
            [CONNECTION_PROTO_WIDTH, 18.0],
            egui::Label::new(RichText::new(format_protocol(connection.protocol)).size(9.0).color(row_color)),
        );
        
        ui.add_sized(
            [CONNECTION_PROTO_WIDTH, 18.0],
            egui::Label::new(RichText::new(&connection.state).size(9.0).color(Color32::from_rgb(180, 180, 100))),
        );
        
        ui.add_sized(
            [CONNECTION_TOTAL_WIDTH, 18.0],
            egui::Label::new(RichText::new(connection.tx_bytes.to_string()).size(9.0).color(Color32::from_rgb(150, 220, 150))),
        );
        
        ui.add_sized(
            [CONNECTION_TOTAL_WIDTH, 18.0],
            egui::Label::new(RichText::new(connection.rx_bytes.to_string()).size(9.0).color(Color32::from_rgb(220, 150, 150))),
        );
        
        ui.end_row();

        let pid = connection.pid;
        let tid = connection.tid;
        let process_name = connection.process.clone();
        let thread_name = connection.thread_name.clone();
        let user_name = connection.username.clone();
        
        pid_response.context_menu(|ui| {
            ui.label(RichText::new("Process Control").size(10.0).strong().color(Color32::from_rgb(200, 200, 100)));
            ui.separator();
            
            if ui.button("🚫 Block Process").clicked() {
                self.pending_block = Some((pid, process_name.clone()));
                ui.close_menu();
            }
            if ui.button("🚫 Block Thread").clicked() {
                self.block_thread(pid, tid, &thread_name);
                ui.close_menu();
            }
            if ui.button("🚫 Block User").clicked() {
                self.block_user(connection.uid, &user_name);
                ui.close_menu();
            }
            if ui.button("📊 Limit Process").clicked() {
                self.limit_process_bandwidth(pid, &process_name);
                ui.close_menu();
            }
            if ui.button("📊 Limit Thread").clicked() {
                self.limit_thread_bandwidth(pid, tid, &thread_name);
                ui.close_menu();
            }
            if ui.button("📊 Limit User").clicked() {
                self.limit_user_bandwidth(connection.uid, &user_name);
                ui.close_menu();
            }
            if ui.button("✅ Unblock Process").clicked() {
                self.unblock_pid(pid);
                ui.close_menu();
            }
            if ui.button("✅ Unblock Thread").clicked() {
                self.unblock_thread(pid, tid);
                ui.close_menu();
            }
            if ui.button("✅ Unblock User").clicked() {
                self.unblock_user(connection.uid, &user_name);
                ui.close_menu();
            }
        });
    }

    // Renders the confirmation dialog before inserting a block rule.
    fn render_block_confirmation_dialog(&mut self, ctx: &egui::Context) {
        if let Some((pid, process_name)) = self.pending_block.clone() {
            egui::Window::new("Confirm Block")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label(format!(
                        "Block all traffic for {process_name} (PID {pid})? This will insert an nftables rule. Confirm?"
                    ));
                    ui.horizontal(|ui| {
                        if ui.button("Confirm").clicked() {
                            self.block_pid(pid, &process_name);
                            self.pending_block = None;
                        }
                        if ui.button("Cancel").clicked() {
                            self.pending_block = None;
                        }
                    });
                });
        }
    }
}

impl App for NetmonApp {
    // Renders one GUI frame from current shared snapshots and UI state.
    fn update(&mut self, ctx: &egui::Context, _frame: &mut Frame) {
        self.update_status_from_channel();
        self.update_dashboard_cache();

        // G-07: keyboard shortcut for quickly clearing process selection.
        if ctx.input(|input| input.key_pressed(egui::Key::Escape)) {
            self.selected_thread = None;
        }

        self.render_top_panel(ctx);
        self.render_status_panel(ctx);
        self.render_main_panel(ctx);
        self.render_block_confirmation_dialog(ctx);
        // Phase I Lesson IF-4: deterministic repaint cadence keeps UI responsive under load.
        ctx.request_repaint_after(Duration::from_millis(UI_REPAINT_INTERVAL_MS));
    }
}

impl Drop for NetmonApp {
    // Stops worker threads and flushes netmon nft rules during application exit.
    fn drop(&mut self) {
        // G-03: coordinated shutdown sets stop flags, joins workers, then flushes nft rules.
        self.capture_running.store(false, AtomicOrdering::Relaxed);
        self.app_running.store(false, AtomicOrdering::Relaxed);

        if let Some(control) = self.capture_control.as_ref() {
            let _ = control.stop();
        }

        if let Some(mut control) = self.capture_control.take() {
            let _ = control.join_timeout(Duration::from_secs(THREAD_JOIN_TIMEOUT_SECS));
        }

        if let Some(mut control) = self.aggregator_control.take() {
            let _ = control.join_timeout(Duration::from_secs(THREAD_JOIN_TIMEOUT_SECS));
        }

        let _ = controller::unblock_all();
    }
}

// Draws the process table and returns the clicked sort column, if any.
#[allow(dead_code)]
fn draw_process_table(
    ui: &mut egui::Ui,
    rows: &[ProcessRow],
    show_bits: bool,
    selected_thread: &mut Option<ThreadKey>,
 ) -> Option<SortColumn> {
    let mut clicked_sort = None;
    let available_width = ui.available_width();
    let base_total_width = PROCESS_PID_WIDTH
        + PROCESS_NAME_WIDTH
        + USER_COLUMN_MIN_WIDTH
        + (PROCESS_BW_WIDTH * 3.0)
        + (PROCESS_TOTAL_WIDTH * 2.0)
        + PROCESS_TID_WIDTH
        + PROCESS_THREAD_WIDTH;
    let width_scale = (available_width / base_total_width).clamp(0.55, 1.6);
    let pid_width = PROCESS_PID_WIDTH * width_scale;
    let process_width = PROCESS_NAME_WIDTH * width_scale;
    let user_width = USER_COLUMN_MIN_WIDTH * width_scale;
    let bw_width = PROCESS_BW_WIDTH * width_scale;
    let total_width = PROCESS_TOTAL_WIDTH * width_scale;
    let tid_width = PROCESS_TID_WIDTH * width_scale;
    let thread_width = PROCESS_THREAD_WIDTH * width_scale;

    egui::Grid::new("process_header_grid")
        .striped(true)
        .show(ui, |ui| {
            if ui.add_sized([pid_width, 18.0], egui::Button::new("PID")).clicked() {
                clicked_sort = Some(SortColumn::Pid);
            }
            if ui
                .add_sized([process_width, 18.0], egui::Button::new("Process"))
                .clicked()
            {
                clicked_sort = Some(SortColumn::Process);
            }
            if ui
                .add_sized([user_width, 18.0], egui::Button::new("User"))
                .clicked()
            {
                clicked_sort = Some(SortColumn::User);
            }
            if ui.add_sized([bw_width, 18.0], egui::Button::new("Proto Mix")).clicked() {
                clicked_sort = Some(SortColumn::ProtocolMix);
            }
            if ui
                .add_sized([bw_width, 18.0], egui::Button::new("TX/s (2s)"))
                .clicked()
            {
                clicked_sort = Some(SortColumn::TxRate);
            }
            if ui
                .add_sized([bw_width, 18.0], egui::Button::new("RX/s (2s)"))
                .clicked()
            {
                clicked_sort = Some(SortColumn::RxRate);
            }
            if ui
                .add_sized([total_width, 18.0], egui::Button::new("TX Total"))
                .clicked()
            {
                clicked_sort = Some(SortColumn::TxTotal);
            }
            if ui
                .add_sized([total_width, 18.0], egui::Button::new("RX Total"))
                .clicked()
            {
                clicked_sort = Some(SortColumn::RxTotal);
            }
            if ui.add_sized([tid_width, 18.0], egui::Button::new("TID")).clicked() {
                clicked_sort = Some(SortColumn::Tid);
            }
            if ui
                .add_sized([thread_width, 18.0], egui::Button::new("Thread"))
                .clicked()
            {
                clicked_sort = Some(SortColumn::Thread);
            }
            ui.end_row();
        });

    ScrollArea::both().max_height(PROCESS_TABLE_HEIGHT).show(ui, |ui| {
        for row in rows {
            let tx_rate = two_second_avg(&row.tx_history);
            let rx_rate = two_second_avg(&row.rx_history);
            // Phase I Lesson IF-3: highlight heavy senders to improve operator response speed.
            let hot_color = if tx_rate > VERY_HIGH_TRAFFIC_THRESHOLD_BYTES_PER_SEC
                || rx_rate > VERY_HIGH_TRAFFIC_THRESHOLD_BYTES_PER_SEC
            {
                Color32::RED
            } else if tx_rate > HIGH_TRAFFIC_THRESHOLD_BYTES_PER_SEC
                || rx_rate > HIGH_TRAFFIC_THRESHOLD_BYTES_PER_SEC
            {
                Color32::from_rgb(255, 140, 0)
            } else {
                ui.visuals().text_color()
            };

            let row_fill = if row.is_blocked {
                BLOCKED_PROCESS_ROW_FILL
            } else {
                Color32::TRANSPARENT
            };

            egui::Frame::none().fill(row_fill).show(ui, |ui| {
                ui.horizontal(|ui| {
                    let selected = *selected_thread == Some(ThreadKey { pid: row.info.pid, tid: row.info.tid });
                    let pid_response = ui.add_sized(
                        [pid_width, 18.0],
                        egui::Button::new(RichText::new(row.info.pid.to_string()).color(hot_color)).selected(selected),
                    );
                    if pid_response.clicked() {
                        if selected {
                            *selected_thread = None;
                        } else {
                            *selected_thread = Some(ThreadKey { pid: row.info.pid, tid: row.info.tid });
                        }
                    }
                    ui.add_sized(
                        [process_width, 18.0],
                        egui::Label::new(RichText::new(row.info.name.clone()).color(hot_color)),
                    );
                    let user_text = RichText::new(row.info.username.clone()).color(hot_color);
                    ui.add_sized([user_width, 18.0], egui::Label::new(user_text));
                    // Phase I Lesson WS-4: keep protocol split visible in the process table.
                    ui.add_sized(
                        [bw_width, 18.0],
                        egui::Label::new(RichText::new(protocol_mix_summary(row)).color(hot_color)),
                    );
                    // G-05: display throughput in human-readable per-second units.
                    ui.add_sized(
                        [bw_width, 18.0],
                        egui::Label::new(RichText::new(format_bandwidth(tx_rate)).color(hot_color)),
                    );
                    ui.add_sized(
                        [bw_width, 18.0],
                        egui::Label::new(RichText::new(format_bandwidth(rx_rate)).color(hot_color)),
                    );
                    ui.add_sized(
                        [total_width, 18.0],
                        egui::Label::new(RichText::new(format_bytes_or_bits(row.tx_bytes, show_bits)).color(hot_color)),
                    );
                    ui.add_sized(
                        [total_width, 18.0],
                        egui::Label::new(RichText::new(format_bytes_or_bits(row.rx_bytes, show_bits)).color(hot_color)),
                    );
                    ui.add_sized(
                        [tid_width, 18.0],
                        egui::Label::new(RichText::new(row.info.tid.to_string()).color(hot_color)),
                    );
                    ui.add_sized(
                        [thread_width, 18.0],
                        egui::Label::new(RichText::new(row.info.thread_name.clone()).color(hot_color)),
                    );
                });
            });
            ui.separator();
        }
    });

    clicked_sort
}

// Draws TX/RX chart lines for selected process or aggregate traffic.
fn draw_chart(
    ui: &mut egui::Ui,
    rows: &[ProcessRow],
    selected_thread: Option<ThreadKey>,
    _show_bits: bool,
    window_seconds: usize,
) {
    let window = window_seconds.clamp(1, CHART_HISTORY_SECONDS);

    let (tx_hist, rx_hist) = if let Some(selected_thread) = selected_thread {
        if let Some(row) = rows.iter().find(|r| {
            r.info.pid == selected_thread.pid && r.info.tid == selected_thread.tid
        }) {
            (row.tx_history, row.rx_history)
        } else {
            ([0; CHART_HISTORY_SECONDS], [0; CHART_HISTORY_SECONDS])
        }
    } else {
        let mut tx = [0u64; CHART_HISTORY_SECONDS];
        let mut rx = [0u64; CHART_HISTORY_SECONDS];
        for row in rows {
            for idx in 0..CHART_HISTORY_SECONDS {
                tx[idx] = tx[idx].saturating_add(row.tx_history[idx]);
                rx[idx] = rx[idx].saturating_add(row.rx_history[idx]);
            }
        }
        (tx, rx)
    };

    let tx_points = (0..window)
        .map(|i| [-(i as f64), bytes_to_kib_per_sec(tx_hist[i])])
        .collect::<PlotPoints>();
    let rx_points = (0..window)
        .map(|i| [-(i as f64), bytes_to_kib_per_sec(rx_hist[i])])
        .collect::<PlotPoints>();

    let tx_line = Line::new(tx_points).name("TX").color(TX_LINE_COLOR);
    let rx_line = Line::new(rx_points).name("RX").color(RX_LINE_COLOR);

    Plot::new("traffic_plot")
        .height(CHART_HEIGHT)
        // Make the plot non-interactive so it stays centered and doesn't pan/zoom with input.
        .allow_drag(false)
        .allow_boxed_zoom(false)
        .allow_scroll(false)
        .allow_zoom(false)
        // G-05: explicit axis labels for real-time demo clarity.
        .x_axis_label(format!("Last {window} seconds"))
        .y_axis_label("KB/s")
        .show(ui, |plot_ui| {
            plot_ui.line(tx_line);
            plot_ui.line(rx_line);
        });
}

// Draws the connection table header row.
fn draw_connection_table_header(ui: &mut egui::Ui) {
    let header_color = Color32::from_rgb(60, 60, 60);
    ui.label(RichText::new("PID").strong().size(10.0).color(Color32::WHITE).background_color(header_color));
    ui.label(RichText::new("TID").strong().size(10.0).color(Color32::WHITE).background_color(header_color));
    ui.label(RichText::new("THREAD").strong().size(10.0).color(Color32::WHITE).background_color(header_color));
    ui.label(RichText::new("PROCESS").strong().size(10.0).color(Color32::WHITE).background_color(header_color));
    ui.label(RichText::new("USER").strong().size(10.0).color(Color32::WHITE).background_color(header_color));
    ui.label(RichText::new("LOCAL ADDR").strong().size(10.0).color(Color32::WHITE).background_color(header_color));
    ui.label(RichText::new("REMOTE ADDR").strong().size(10.0).color(Color32::WHITE).background_color(header_color));
    ui.label(RichText::new("PROTO").strong().size(10.0).color(Color32::WHITE).background_color(header_color));
    ui.label(RichText::new("STATE").strong().size(10.0).color(Color32::WHITE).background_color(header_color));
    ui.label(RichText::new("TX BYTES").strong().size(10.0).color(Color32::WHITE).background_color(header_color));
    ui.label(RichText::new("RX BYTES").strong().size(10.0).color(Color32::WHITE).background_color(header_color));
    ui.end_row();
}

// Computes a 2-second average from the newest two history samples.
fn two_second_avg(history: &[u64]) -> u64 {
    history[..SHORT_RATE_WINDOW_SECONDS]
        .iter()
        .copied()
        .sum::<u64>()
        / SHORT_RATE_WINDOW_SECONDS as u64
}

// Computes a 10-second average from the newest ten history samples.

// Converts bytes/s to KB/s for chart display.
fn bytes_to_kib_per_sec(bytes_per_sec: u64) -> f64 {
    (bytes_per_sec as f64) / KIBI_BASE
}

// G-05: helper for readable bandwidth rendering in tables and summary bars.
fn format_bandwidth(bytes_per_sec: u64) -> String {
    if bytes_per_sec < 1024 {
        return format!("{} B/s", bytes_per_sec);
    }
    if bytes_per_sec < 1024 * 1024 {
        return format!("{:.1} KB/s", (bytes_per_sec as f64) / KIBI_BASE);
    }
    format!("{:.1} MB/s", (bytes_per_sec as f64) / (KIBI_BASE * KIBI_BASE))
}

// Helper function to format bytes in human-readable form.
fn format_bytes(value: u64) -> String {
    format_bytes_or_bits(value, false)
}

// Formats throughput as either byte or bit units based on UI toggle state.
fn format_bytes_or_bits(value: u64, bits: bool) -> String {
    if bits {
        format_scaled((value as f64) * BITS_PER_BYTE, ["b", "Kb", "Mb", "Gb", "Tb"])
    } else {
        format_scaled(value as f64, ["B", "KB", "MB", "GB", "TB"])
    }
}

// Formats one numeric value into a binary-scaled human-readable unit string.
fn format_scaled(mut value: f64, units: [&str; 5]) -> String {
    let mut idx = 0usize;
    while value >= KIBI_BASE && idx < units.len() - 1 {
        value /= KIBI_BASE;
        idx += 1;
    }
    format!("{value:.2} {}", units[idx])
}

// Maps the protocol enum to a short uppercase string for table rendering.
fn format_protocol(proto: capture::Protocol) -> &'static str {
    match proto {
        capture::Protocol::Tcp => "TCP",
        capture::Protocol::Udp => "UDP",
        capture::Protocol::Other(_) => "OTHER",
    }
}

// Summarizes protocol composition for one process row (TCP/UDP/OTHER counts).
fn protocol_mix_summary(row: &ProcessRow) -> String {
    let mut tcp = 0u32;
    let mut udp = 0u32;
    let mut other = 0u32;

    for conn in &row.connections {
        match conn.protocol {
            capture::Protocol::Tcp => tcp += 1,
            capture::Protocol::Udp => udp += 1,
            capture::Protocol::Other(_) => other += 1,
        }
    }

    format!("T:{tcp} U:{udp} O:{other}")
}

// Escapes problematic CSV characters in process and user names.
fn sanitize_csv(value: &str) -> String {
    value.replace('"', "'").replace(',', " ")
}

// Detects VirtualBox environment strings to show a capture limitation warning.
fn detect_virtualbox() -> bool {
    let host = fs::read_to_string("/proc/sys/kernel/hostname")
        .unwrap_or_default()
        .to_lowercase();
    let product = fs::read_to_string("/sys/class/dmi/id/product_name")
        .unwrap_or_default()
        .to_lowercase();

    host.contains("vbox") || product.contains("virtualbox")
}

// Returns the invoking user's home directory even when running under sudo.
fn get_user_home() -> String {
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
            for line in passwd.lines() {
                let fields: Vec<&str> = line.split(':').collect();
                if fields.len() >= 6 && fields[0] == sudo_user {
                    return fields[5].to_string();
                }
            }
        }
    }
    std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string())
}

// Checks Linux effective capabilities for CAP_NET_ADMIN and CAP_NET_RAW.
fn has_required_capabilities() -> bool {
    let status = match fs::read_to_string("/proc/self/status") {
        Ok(v) => v,
        Err(_) => return false,
    };

    let cap_eff_line = status.lines().find(|line| line.starts_with("CapEff:"));
    let cap_eff_hex = match cap_eff_line.and_then(|line| line.split_whitespace().nth(1)) {
        Some(v) => v,
        None => return false,
    };

    let cap_eff = match u64::from_str_radix(cap_eff_hex, 16) {
        Ok(v) => v,
        Err(_) => return false,
    };

    // Linux capability bit index for CAP_NET_ADMIN.
    let cap_net_admin = 1u64 << 12;
    // Linux capability bit index for CAP_NET_RAW.
    let cap_net_raw = 1u64 << 13;

    (cap_eff & cap_net_admin) != 0 && (cap_eff & cap_net_raw) != 0
}

// Exits with code 1 unless the process is root or has required net capabilities.
fn ensure_privileges_or_exit() {
    // SAFETY: libc::geteuid has no preconditions and does not dereference pointers.
    let is_root = unsafe { libc::geteuid() == 0 };

    if is_root || has_required_capabilities() {
        return;
    }

    eprintln!(
        "Insufficient privileges. Run as root or grant CAP_NET_RAW and CAP_NET_ADMIN to this binary."
    );
    std::process::exit(1);
}

// Returns the color for a rank badge based on position (1st, 2nd, 3rd, or other).
#[allow(dead_code)]
fn rank_color(rank: usize) -> Color32 {
    match rank {
        1 => RANK_1ST_COLOR,
        2 => RANK_2ND_COLOR,
        3 => RANK_3RD_COLOR,
        _ => RANK_OTHER_COLOR,
    }
}

// Computes top processes sorted by total bandwidth (TX + RX).
fn compute_top_processes(rows: &[ProcessRow], limit: usize) -> Vec<(ProcessRow, u64)> {
    let mut ranked: Vec<_> = rows
        .iter()
        .map(|row| {
            let tx_rate = two_second_avg(&row.tx_history);
            let rx_rate = two_second_avg(&row.rx_history);
            (row.clone(), tx_rate + rx_rate)
        })
        .collect();

    ranked.sort_by(|(_, a), (_, b)| b.cmp(a));
    ranked.into_iter().take(limit).collect()
}

// Detects if current bandwidth exceeds spike threshold.
fn detect_spike(rows: &[ProcessRow]) -> Option<SpikeEvent> {
    let total_bandwidth: u64 = rows
        .iter()
        .map(|r| two_second_avg(&r.tx_history) + two_second_avg(&r.rx_history))
        .sum();

    if total_bandwidth > SPIKE_THRESHOLD_BYTES_PER_SEC {
        Some(SpikeEvent {
            bandwidth_bytes_per_sec: total_bandwidth,
            timestamp: std::time::Instant::now(),
        })
    } else {
        None
    }
}

// Finds the top port by bytes transferred across all connections.
fn find_top_port(rows: &[ProcessRow]) -> Option<(u16, String)> {
    let mut port_map: std::collections::HashMap<u16, u64> = std::collections::HashMap::new();
    
    for row in rows {
        for conn in &row.connections {
            let port = conn.remote_addr.port();
            *port_map.entry(port).or_insert(0) += conn.tx_bytes + conn.rx_bytes;
        }
    }

    let top_port = port_map.iter().max_by_key(|(_, bytes)| *bytes)?;
    let port_num = *top_port.0;
    
    let proto = match port_num {
        80 => "HTTP",
        443 => "HTTPS",
        53 => "DNS",
        22 => "SSH",
        21 => "FTP",
        25 => "SMTP",
        3306 => "MySQL",
        5432 => "PostgreSQL",
        6379 => "Redis",
        27017 => "MongoDB",
        _ => "Other",
    };
    
    Some((port_num, proto.to_string()))
}

// Counts the distribution of protocols (TCP, UDP, Other) across all connections.
fn count_protocols(rows: &[ProcessRow]) -> (usize, usize, usize) {
    let mut tcp = 0usize;
    let mut udp = 0usize;
    let mut other = 0usize;

    for row in rows {
        for conn in &row.connections {
            match conn.protocol {
                capture::Protocol::Tcp => tcp += 1,
                capture::Protocol::Udp => udp += 1,
                capture::Protocol::Other(_) => other += 1,
            }
        }
    }

    (tcp, udp, other)
}

/// Starts the native egui application after privilege checks and nft setup.
fn main() -> Result<()> {
    ensure_privileges_or_exit();
    env_logger::init();

    let _ = controller::setup_nftables();

    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "Linux Network Monitor & Controller",
        options,
        Box::new(|_cc| Ok(Box::new(NetmonApp::new()))),
    )
    .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    Ok(())
}
