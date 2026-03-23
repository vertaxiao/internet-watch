/* NetWatch frontend app.js */

const API = "";  // same origin

let allDevices = [];
let activeFilter = "all";
let sortField = "status";
let sortAsc = true;
let historyChart = null;
let scanInterval = 60;
let refreshTimer = null;

// ── Init ─────────────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
  initChart();
  refresh();
});

// ── Data fetching ─────────────────────────────────────────────────────────────

async function refresh() {
  try {
    const [stats, devices, history] = await Promise.all([
      fetchJSON("/api/stats"),
      fetchJSON("/api/devices"),
      fetchJSON("/api/history"),
    ]);

    updateStats(stats);
    allDevices = devices;
    renderTable();
    updateChart(history);

    scheduleRefresh(stats.scan_interval || 60);
  } catch (err) {
    showError("Failed to load data: " + err.message);
    scheduleRefresh(15);
  }
}

async function fetchJSON(path) {
  const res = await fetch(API + path);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

async function triggerScan() {
  const btn = document.getElementById("scan-btn");
  btn.disabled = true;
  btn.textContent = "Scanning…";
  try {
    const res = await fetch(API + "/api/scan", { method: "POST" });
    if (res.status === 409) {
      // Already scanning — just wait
    } else if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }
    // Wait a bit, then refresh
    setTimeout(() => refresh(), 3000);
  } catch (err) {
    showError("Scan trigger failed: " + err.message);
  } finally {
    setTimeout(() => {
      btn.disabled = false;
      btn.textContent = "Scan Now";
    }, 5000);
  }
}

function scheduleRefresh(interval) {
  scanInterval = interval;
  document.getElementById("footer-interval").textContent = interval;

  if (refreshTimer) clearTimeout(refreshTimer);
  refreshTimer = setTimeout(refresh, interval * 1000);
}

// ── Stats ─────────────────────────────────────────────────────────────────────

function updateStats(stats) {
  const online = stats.online ?? 0;
  const total = stats.total ?? 0;

  set("online-count", online);
  set("total-count", total);
  set("offline-count", total - online);
  set("scan-interval", (stats.scan_interval ?? 60) + "s");
  set("footer-interval", stats.scan_interval ?? 60);

  const lastScan = stats.last_scan
    ? "Last scan " + timeAgo(stats.last_scan)
    : "No scan yet";
  set("last-scan", lastScan);

  if (stats.scan_error) {
    showError("Scan error: " + stats.scan_error);
  } else {
    hideError();
  }
}

// ── Table ─────────────────────────────────────────────────────────────────────

function filterDevices(filter, btn) {
  activeFilter = filter;
  document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
  btn.classList.add("active");
  renderTable();
}

function sortBy(field) {
  if (sortField === field) {
    sortAsc = !sortAsc;
  } else {
    sortField = field;
    sortAsc = true;
  }
  renderTable();
}

function renderTable() {
  const query = (document.getElementById("search-input")?.value || "").toLowerCase().trim();
  const tbody = document.getElementById("device-tbody");

  let filtered = allDevices.filter(d => {
    if (activeFilter !== "all" && d.status !== activeFilter) return false;
    if (!query) return true;
    return (
      (d.ip || "").toLowerCase().includes(query) ||
      (d.mac || "").toLowerCase().includes(query) ||
      (d.hostname || "").toLowerCase().includes(query)
    );
  });

  filtered.sort((a, b) => {
    let av = (a[sortField] || "").toString().toLowerCase();
    let bv = (b[sortField] || "").toString().toLowerCase();
    // Natural sort for IP addresses
    if (sortField === "ip") {
      av = ipToNum(a.ip);
      bv = ipToNum(b.ip);
      return sortAsc ? av - bv : bv - av;
    }
    if (av < bv) return sortAsc ? -1 : 1;
    if (av > bv) return sortAsc ? 1 : -1;
    return 0;
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="empty-row">No devices found.</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map(d => `
    <tr>
      <td>${statusBadge(d.status)}</td>
      <td class="mono">${esc(d.ip)}</td>
      <td class="mono">${esc(d.mac) || "<span style='color:var(--text-muted)'>—</span>"}</td>
      <td>${esc(d.hostname) || "<span style='color:var(--text-muted)'>—</span>"}</td>
      <td style="color:var(--text-muted)">${fmtDate(d.first_seen)}</td>
      <td style="color:var(--text-muted)">${fmtDate(d.last_seen)}</td>
    </tr>
  `).join("");
}

function statusBadge(status) {
  const isOnline = status === "online";
  return `<span class="badge badge-${status}">
    <span class="badge-dot"></span>${isOnline ? "Online" : "Offline"}
  </span>`;
}

// ── Chart ─────────────────────────────────────────────────────────────────────

function initChart() {
  const ctx = document.getElementById("history-chart").getContext("2d");
  historyChart = new Chart(ctx, {
    type: "line",
    data: {
      labels: [],
      datasets: [{
        label: "Devices Online",
        data: [],
        borderColor: "#58a6ff",
        backgroundColor: "rgba(88,166,255,0.10)",
        borderWidth: 2,
        pointRadius: 3,
        pointBackgroundColor: "#58a6ff",
        fill: true,
        tension: 0.3,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: "#21262d",
          borderColor: "#30363d",
          borderWidth: 1,
          titleColor: "#e6edf3",
          bodyColor: "#7d8590",
          callbacks: {
            title: items => fmtHour(items[0].label),
            label: item => `  ${item.raw} device${item.raw !== 1 ? "s" : ""}`,
          },
        },
      },
      scales: {
        x: {
          grid: { color: "#21262d" },
          ticks: {
            color: "#7d8590",
            maxRotation: 0,
            callback: (_, i, vals) => {
              // Only show every ~4th label to avoid crowding
              if (vals.length <= 8 || i % Math.ceil(vals.length / 8) === 0) {
                return fmtHour(historyChart.data.labels[i]);
              }
              return "";
            },
          },
        },
        y: {
          beginAtZero: true,
          grid: { color: "#21262d" },
          ticks: { color: "#7d8590", precision: 0 },
        },
      },
    },
  });
}

function updateChart(history) {
  if (!historyChart) return;
  if (!history || history.length === 0) {
    document.getElementById("chart-status").textContent = "Not enough data yet";
    return;
  }
  document.getElementById("chart-status").textContent = `${history.length} hour${history.length !== 1 ? "s" : ""} of data`;

  historyChart.data.labels = history.map(h => h.hour);
  historyChart.data.datasets[0].data = history.map(h => Math.round(h.max_count));
  historyChart.update("active");
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function set(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function esc(str) {
  if (!str) return "";
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function timeAgo(isoStr) {
  const diff = Math.floor((Date.now() - new Date(isoStr + "Z").getTime()) / 1000);
  if (diff < 5) return "just now";
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  return `${Math.floor(diff / 3600)}h ago`;
}

function fmtDate(isoStr) {
  if (!isoStr) return "—";
  const d = new Date(isoStr + (isoStr.endsWith("Z") ? "" : "Z"));
  return d.toLocaleString(undefined, {
    month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

function fmtHour(isoStr) {
  if (!isoStr) return "";
  const d = new Date(isoStr + (isoStr.endsWith("Z") ? "" : "Z"));
  return d.toLocaleString(undefined, { hour: "2-digit", minute: "2-digit" });
}

function ipToNum(ip) {
  return (ip || "").split(".").reduce((n, part) => n * 256 + parseInt(part || "0", 10), 0);
}

function showError(msg) {
  const el = document.getElementById("error-banner");
  if (el) {
    el.textContent = msg;
    el.classList.remove("hidden");
  }
}

function hideError() {
  const el = document.getElementById("error-banner");
  if (el) el.classList.add("hidden");
}
