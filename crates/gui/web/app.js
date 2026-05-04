const invoke = window.__TAURI__?.core?.invoke || window.__TAURI__?.tauri?.invoke;

const ifaceSelect = document.getElementById("ifaceSelect");
const statusText = document.getElementById("statusText");
const currentBandwidth = document.getElementById("currentBandwidth");
const peakBandwidth = document.getElementById("peakBandwidth");
const totalBytes = document.getElementById("totalBytes");
const activeThreads = document.getElementById("activeThreads");
const blockedCounts = document.getElementById("blockedCounts");
const processTable = document.getElementById("processTable");
const connectionTable = document.getElementById("connectionTable");
const trafficGraph = document.getElementById("trafficGraph");
const processGraph = document.getElementById("processGraph");
const filterInput = document.getElementById("filterInput");
const windowSizeRange = document.getElementById("windowSizeRange");
const windowSizeLabel = document.getElementById("windowSizeLabel");

const selectedSummary = document.getElementById("selectedSummary");
const blockProcessBtn = document.getElementById("blockProcessBtn");
const unblockProcessBtn = document.getElementById("unblockProcessBtn");
const blockThreadBtn = document.getElementById("blockThreadBtn");
const unblockThreadBtn = document.getElementById("unblockThreadBtn");
const blockUserBtn = document.getElementById("blockUserBtn");
const unblockUserBtn = document.getElementById("unblockUserBtn");
const limitProcessBtn = document.getElementById("limitProcessBtn");
const clearProcessBtn = document.getElementById("clearProcessBtn");
const limitThreadBtn = document.getElementById("limitThreadBtn");
const clearThreadBtn = document.getElementById("clearThreadBtn");
const limitUserBtn = document.getElementById("limitUserBtn");
const clearUserBtn = document.getElementById("clearUserBtn");
const processRateInput = document.getElementById("processRateInput");
const threadRateInput = document.getElementById("threadRateInput");
const userRateInput = document.getElementById("userRateInput");

const refreshBtn = document.getElementById("refreshBtn");
const startBtn = document.getElementById("startBtn");
const stopBtn = document.getElementById("stopBtn");
const applyFilterBtn = document.getElementById("applyFilterBtn");

const SNAPSHOT_TOP_N = 25;
const SNAPSHOT_MAX_CONNECTIONS = 200;
const SNAPSHOT_INTERVAL_MS = 1000;
const GRAPH_COLOR_TX = "#4cc3ff";
const GRAPH_COLOR_RX = "#f7b267";
const CHART_TICK_COLOR = "#c7d1d8";
const CHART_GRID_COLOR = "rgba(84, 96, 109, 0.35)";

let selectedKey = null;
let lastSnapshot = null;
let trafficChart = null;
let processChart = null;

function formatBytes(bytes) {
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes;
  let idx = -1;
  while (value >= 1024 && idx < units.length - 1) {
    value /= 1024;
    idx += 1;
  }
  return `${value.toFixed(1)} ${units[idx]}`;
}

function formatRate(bytesPerSec) {
  return `${formatBytes(bytesPerSec)}/s`;
}

function setStatus(text) {
  statusText.textContent = text;
}

function parseRateInput(input) {
  const value = Number.parseInt(input.value, 10);
  if (!Number.isFinite(value) || value <= 0) {
    setStatus("Enter a valid KB/s value");
    return null;
  }
  return value;
}

function getWindowSize() {
  const value = Number.parseInt(windowSizeRange.value, 10);
  return Number.isFinite(value) ? value : 120;
}

function updateWindowLabel() {
  windowSizeLabel.textContent = `${getWindowSize()}s`;
}

function buildChart(canvas) {
  if (!canvas || !window.Chart) {
    return null;
  }
  return new window.Chart(canvas.getContext("2d"), {
    type: "line",
    data: {
      labels: [],
      datasets: [
        {
          label: "TX/s",
          data: [],
          borderColor: GRAPH_COLOR_TX,
          backgroundColor: "rgba(76, 195, 255, 0.2)",
          tension: 0.25,
          pointRadius: 0,
        },
        {
          label: "RX/s",
          data: [],
          borderColor: GRAPH_COLOR_RX,
          backgroundColor: "rgba(247, 178, 103, 0.2)",
          tension: 0.25,
          pointRadius: 0,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: {
        mode: "index",
        intersect: false,
      },
      plugins: {
        legend: {
          display: true,
          position: "top",
          labels: {
            boxWidth: 14,
            color: CHART_TICK_COLOR,
          },
        },
        tooltip: {
          callbacks: {
            label: (ctx) => `${ctx.dataset.label}: ${formatRate(ctx.raw)}`,
          },
        },
      },
      scales: {
        x: {
          ticks: {
            maxTicksLimit: 8,
            color: CHART_TICK_COLOR,
          },
          grid: {
            color: CHART_GRID_COLOR,
          },
        },
        y: {
          ticks: {
            callback: (value) => formatBytes(value),
            color: CHART_TICK_COLOR,
          },
          grid: {
            color: CHART_GRID_COLOR,
          },
        },
      },
    },
  });
}

function buildStatusBadges(proc) {
  const badges = [];
  if (proc.is_process_blocked) {
    badges.push({ text: "P Blocked", tone: "warn" });
  }
  if (proc.is_thread_blocked) {
    badges.push({ text: "T Blocked", tone: "warn" });
  }
  if (proc.is_user_blocked) {
    badges.push({ text: "U Blocked", tone: "warn" });
  }
  if (proc.is_process_rate_limited) {
    badges.push({ text: "P Limit", tone: "ok" });
  }
  if (proc.is_thread_rate_limited) {
    badges.push({ text: "T Limit", tone: "ok" });
  }
  if (proc.is_user_rate_limited) {
    badges.push({ text: "U Limit", tone: "ok" });
  }
  return badges;
}

function updateChart(chart, txHistory, rxHistory) {
  if (!chart || !txHistory || !rxHistory) {
    return;
  }
  const windowSize = getWindowSize();
  const count = Math.min(windowSize, txHistory.length, rxHistory.length);
  const tx = txHistory.slice(0, count).reverse();
  const rx = rxHistory.slice(0, count).reverse();
  const labels = Array.from({ length: count }, (_, idx) => `${count - 1 - idx}s`);
  chart.data.labels = labels;
  chart.data.datasets[0].data = tx;
  chart.data.datasets[1].data = rx;
  chart.update("none");
}

async function loadDevices() {
  if (!invoke) {
    setStatus("Tauri API not available");
    return;
  }
  const selected = ifaceSelect.value;
  const devices = await invoke("refresh_devices");
  ifaceSelect.innerHTML = "";
  devices.forEach((device) => {
    const option = document.createElement("option");
    option.value = device.name;
    option.textContent = `${device.name} (${device.ips.join(", ")})`;
    ifaceSelect.appendChild(option);
  });
  if (selected) {
    ifaceSelect.value = selected;
  }
}

async function startCapture() {
  if (!invoke) {
    return;
  }
  const iface = ifaceSelect.value;
  if (!iface) {
    setStatus("Select interface");
    return;
  }
  try {
    await invoke("start_capture", {
      interface: iface,
      bpf_filter: filterInput.value ? filterInput.value : null,
      record_path: null,
    });
    setStatus("Capturing...");
  } catch (err) {
    setStatus(String(err));
  }
}

async function stopCapture() {
  if (!invoke) {
    return;
  }
  try {
    await invoke("stop_capture");
    setStatus("Stopped");
  } catch (err) {
    setStatus(String(err));
  }
}

async function applyFilter() {
  if (!invoke) {
    return;
  }
  const filter = filterInput.value.trim();
  if (!filter) {
    setStatus("Filter empty");
    return;
  }
  try {
    await invoke("apply_filter", { bpf_filter: filter });
    setStatus(`Filter applied: ${filter}`);
  } catch (err) {
    setStatus(String(err));
  }
}

function renderProcesses(processes) {
  processTable.innerHTML = "";
  processes.forEach((proc) => {
    const key = `${proc.pid}:${proc.tid}`;
    const row = document.createElement("tr");
    if (selectedKey === key) {
      row.classList.add("selected");
    }
    const badges = buildStatusBadges(proc);
    row.innerHTML = `
      <td>${proc.pid}/${proc.tid}</td>
      <td>${proc.process}</td>
      <td>${proc.thread}</td>
      <td>${proc.user}</td>
      <td>${formatRate(proc.tx_rate_bytes_per_sec)}</td>
      <td>${formatRate(proc.rx_rate_bytes_per_sec)}</td>
      <td>${formatBytes(proc.tx_bytes)}</td>
      <td>${formatBytes(proc.rx_bytes)}</td>
      <td class="status-cell"></td>
    `;
    const statusCell = row.querySelector(".status-cell");
    if (badges.length === 0) {
      statusCell.textContent = "-";
    } else {
      badges.forEach((badge) => {
        const span = document.createElement("span");
        span.className = `status-badge ${badge.tone}`;
        span.textContent = badge.text;
        statusCell.appendChild(span);
      });
    }
    row.addEventListener("click", () => {
      selectedKey = key;
      renderProcesses(processes);
      if (lastSnapshot) {
        renderDetails(lastSnapshot);
      }
    });
    processTable.appendChild(row);
  });
}

function setControlsEnabled(enabled) {
  [
    blockProcessBtn,
    unblockProcessBtn,
    blockThreadBtn,
    unblockThreadBtn,
    blockUserBtn,
    unblockUserBtn,
    limitProcessBtn,
    clearProcessBtn,
    limitThreadBtn,
    clearThreadBtn,
    limitUserBtn,
    clearUserBtn,
    processRateInput,
    threadRateInput,
    userRateInput,
  ].forEach((el) => {
    if (el) {
      el.disabled = !enabled;
    }
  });
}

function renderConnections(connections) {
  connectionTable.innerHTML = "";
  connections.forEach((conn) => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${conn.local_addr}</td>
      <td>${conn.remote_addr}</td>
      <td>${conn.protocol}</td>
      <td>${conn.state}</td>
      <td>${conn.thread}</td>
      <td>${formatBytes(conn.tx_bytes)}</td>
      <td>${formatBytes(conn.rx_bytes)}</td>
    `;
    connectionTable.appendChild(row);
  });
}

function renderDetails(snapshot) {
  if (!selectedKey) {
    selectedSummary.textContent = "No process selected";
    renderConnections([]);
    updateChart(processChart, [], []);
    setControlsEnabled(false);
    return;
  }

  const selected = snapshot.processes.find(
    (proc) => `${proc.pid}:${proc.tid}` === selectedKey
  );

  if (!selected) {
    selectedSummary.textContent = "No process selected";
    renderConnections([]);
    updateChart(processChart, [], []);
    setControlsEnabled(false);
    return;
  }

  selectedSummary.textContent = `${selected.process} (${selected.thread}) pid ${selected.pid} tid ${selected.tid} user ${selected.user}`;
  const connections = snapshot.connections.filter(
    (conn) => conn.pid === selected.pid && conn.tid === selected.tid
  );
  renderConnections(connections);
  updateChart(processChart, selected.tx_history, selected.rx_history);
  setControlsEnabled(true);

  blockProcessBtn.onclick = () => invoke("block_process", { pid: selected.pid, name: selected.process }).catch((err) => setStatus(String(err)));
  unblockProcessBtn.onclick = () => invoke("unblock_process", { pid: selected.pid }).catch((err) => setStatus(String(err)));
  blockThreadBtn.onclick = () => invoke("block_thread", { pid: selected.pid, tid: selected.tid, name: selected.thread }).catch((err) => setStatus(String(err)));
  unblockThreadBtn.onclick = () => invoke("unblock_thread", { pid: selected.pid, tid: selected.tid }).catch((err) => setStatus(String(err)));
  blockUserBtn.onclick = () => invoke("block_user", { uid: selected.uid, username: selected.user }).catch((err) => setStatus(String(err)));
  unblockUserBtn.onclick = () => invoke("unblock_user", { uid: selected.uid }).catch((err) => setStatus(String(err)));

  limitProcessBtn.onclick = () => {
    const rate = parseRateInput(processRateInput);
    if (!rate) return;
    invoke("rate_limit_process", { pid: selected.pid, rate_kbps: rate }).catch((err) => setStatus(String(err)));
  };
  clearProcessBtn.onclick = () => invoke("unlimit_process", { pid: selected.pid }).catch((err) => setStatus(String(err)));

  limitThreadBtn.onclick = () => {
    const rate = parseRateInput(threadRateInput);
    if (!rate) return;
    invoke("rate_limit_thread", { pid: selected.pid, tid: selected.tid, rate_kbps: rate }).catch((err) => setStatus(String(err)));
  };
  clearThreadBtn.onclick = () => invoke("unlimit_thread", { pid: selected.pid, tid: selected.tid }).catch((err) => setStatus(String(err)));

  limitUserBtn.onclick = () => {
    const rate = parseRateInput(userRateInput);
    if (!rate) return;
    invoke("rate_limit_user", { uid: selected.uid, rate_kbps: rate }).catch((err) => setStatus(String(err)));
  };
  clearUserBtn.onclick = () => invoke("unlimit_user", { uid: selected.uid }).catch((err) => setStatus(String(err)));
}

async function refreshSnapshot() {
  if (!invoke) {
    return;
  }
  try {
    const snapshot = await invoke("get_snapshot", {
      top_n: SNAPSHOT_TOP_N,
      max_connections: SNAPSHOT_MAX_CONNECTIONS,
    });
    lastSnapshot = snapshot;
    setStatus(snapshot.status);
    currentBandwidth.textContent = formatRate(
      snapshot.interface.current_bandwidth_bytes_per_sec
    );
    peakBandwidth.textContent = formatRate(
      snapshot.interface.peak_bandwidth_bytes_per_sec
    );
    totalBytes.textContent = formatBytes(
      snapshot.interface.tx_bytes_total + snapshot.interface.rx_bytes_total
    );
    activeThreads.textContent = `${snapshot.processes.length}`;
    blockedCounts.textContent = `${snapshot.blocked.processes}p / ${snapshot.blocked.threads}t / ${snapshot.blocked.users}u`;
    renderProcesses(snapshot.processes);
    renderDetails(snapshot);
    updateChart(trafficChart, snapshot.interface.tx_history, snapshot.interface.rx_history);
  } catch (err) {
    setStatus(String(err));
  }
}

refreshBtn.addEventListener("click", loadDevices);
startBtn.addEventListener("click", startCapture);
stopBtn.addEventListener("click", stopCapture);
applyFilterBtn.addEventListener("click", applyFilter);
windowSizeRange.addEventListener("input", () => {
  updateWindowLabel();
  if (lastSnapshot) {
    updateChart(trafficChart, lastSnapshot.interface.tx_history, lastSnapshot.interface.rx_history);
    renderDetails(lastSnapshot);
  }
});

updateWindowLabel();
trafficChart = buildChart(trafficGraph);
processChart = buildChart(processGraph);
setControlsEnabled(false);
loadDevices().then(refreshSnapshot);
setInterval(refreshSnapshot, SNAPSHOT_INTERVAL_MS);
window.addEventListener("contextmenu", (event) => event.preventDefault());
