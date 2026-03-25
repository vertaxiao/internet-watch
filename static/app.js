/* NetWatch frontend - Full stack with Cyber News & Email Protection */

const API = "";

// ── Init ─────────────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
  loadCyberNews();
  loadEmailScans();
  loadDailyTrends();
});

// ── Cyber News ───────────────────────────────────────────────────────────────

async function loadCyberNews() {
  try {
    const data = await fetchJSON("/api/cyber_news");
    const grid = document.getElementById("news-grid");
    if (!grid) return;
    
    if (!data.newsItems || data.newsItems.length === 0) {
      grid.innerHTML = `<p style="color:#888;">No cyber news available yet.</p>`;
      return;
    }
    
    grid.innerHTML = data.newsItems.map(item => `
      <div class="news-card severity-${item.severity.toLowerCase()}">
        <div class="news-severity">${item.severity}</div>
        <div class="news-date">${item.date}</div>
        <h3 class="news-headline">${item.headline}</h3>
        <p class="news-summary">${item.summary}</p>
        <div class="news-meta">
          <span class="news-source">${item.source}</span>
          <a href="${item.url}" target="_blank" rel="noopener" class="news-link">Read more →</a>
        </div>
      </div>
    `).join("");
    
    // Update status if present
    if (data.status) {
      const statusEl = document.querySelector(".cybernews-subtitle");
      if (statusEl) statusEl.textContent = data.status;
    }
  } catch (err) {
    console.error("Failed to load cyber news:", err);
    const grid = document.getElementById("news-grid");
    if (grid) grid.innerHTML = `<p style="color:#888;">Failed to load cyber news.</p>`;
  }
}

// ── Email Scans ──────────────────────────────────────────────────────────────

async function loadEmailScans() {
  try {
    const data = await fetchJSON("/api/email_scans");
    if (!data.dashboard) return;
    
    const d = data.dashboard;
    set("email-total", d.totalScanned ?? 0);
    set("email-clean", d.clean ?? 0);
    set("email-junk", d.flagged ?? 0);
    set("email-flagged", (d.byRisk?.HIGH ?? 0) + (d.byRisk?.CRITICAL ?? 0));
    
    // Update inbox status
    const inboxStatus = document.getElementById("inbox-status");
    if (inboxStatus && d.inboxes) {
      const gmailStatus = d.inboxes.gmail?.status ?? "unknown";
      const outlookStatus = d.inboxes.outlook?.status ?? "unknown";
      inboxStatus.innerHTML = `
        <div>Gmail: <span class="status-${gmailStatus}">${gmailStatus.replace("_", " ")}</span></div>
        <div>Outlook: <span class="status-${outlookStatus}">${outlookStatus.replace("_", " ")}</span></div>
      `;
    }
  } catch (err) {
    console.error("Failed to load email scans:", err);
  }
}

// ── Daily Trends ─────────────────────────────────────────────────────────────

async function loadDailyTrends() {
  try {
    const data = await fetchJSON("/api/daily_trends");
    if (!data || !data.trends) return;
    
    // Update trend display if element exists
    const trendEl = document.getElementById("daily-trend-summary");
    if (trendEl) {
      trendEl.innerHTML = `
        <div><strong>Date:</strong> ${data.date ?? "N/A"}</div>
        <div><strong>Total Scanned:</strong> ${data.trends.totalScanned ?? 0}</div>
        <div><strong>Flagged:</strong> ${data.trends.flagged ?? 0} (${data.trends.scamRate ?? "0%"})</div>
        <div><strong>Trend:</strong> ${data.trends.trendVsYesterday ?? "→"}</div>
      `;
    }
  } catch (err) {
    console.error("Failed to load daily trends:", err);
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

async function fetchJSON(path) {
  const res = await fetch(API + path);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

function set(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}
