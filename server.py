#!/usr/bin/env python3
"""
Flask server for network device monitoring dashboard.
Serves the web interface and provides API endpoints.
"""

from flask import Flask, jsonify, send_from_directory, request
from pathlib import Path
import json
from datetime import datetime
import subprocess
import re
import socket
import os
import imaplib
import email
import requests
from functools import wraps
import dns.resolver
import dns.exception

# ── Email Inspector: two-tier pipeline (Tier 1 screener + Mino researcher) ────
import sys as _sys
_sys.path.insert(0, str(Path(__file__).parent))
from email_inspector import inspect as _ei_inspect, verify_identity as _ei_verify   # noqa: E402
from db import init_db, store_live_incident, get_live_incidents                     # noqa: E402

# Ensure DB tables exist (runs at import time so launchd service gets it too)
try:
    init_db()
except Exception as _dbe:
    print(f"[netwatch] DB init warning: {_dbe}")

app = Flask(__name__)

# ── LiteLLM health cache ──────────────────────────────────────────────────────
import threading as _threading
import collections as _collections
import time as _time
_health_cache = {"data": [], "checking": False, "last_checked": None}
_health_lock = _threading.Lock()

# ── Per-model query-rate tracker (tails gateway.log) ─────────────────────────
_GATEWAY_LOG = os.path.expanduser("~/.openclaw/logs/gateway.log")
_RATE_HISTORY_SECS = 120   # keep 2 minutes of history
# model -> deque of float timestamps
_model_req_times: dict = _collections.defaultdict(_collections.deque)
_req_lock = _threading.Lock()
# Burst thresholds: (window_seconds, max_allowed_queries)
_BURST_THRESHOLDS = [
    (5,  20),   # 20 queries in 5s  — primary alert
    (30, 80),   # 80 queries in 30s — sustained burst
    (60, 120),  # 120 queries in 1m — high volume
]

# ── Unusual query pattern tracker ─────────────────────────────────────────────
# Stores (timestamp, model) tuples for 5-minute pattern analysis window
_PATTERN_HISTORY_SECS = 300
_query_log: _collections.deque = _collections.deque()   # (ts: float, model: str)

# ── Threat occurrence counter ──────────────────────────────────────────────────
# Increments once per PASS→FAIL transition so sustained threats count as one event
threat_occurrences: int = 0
_last_theft_was_fail: bool = False
_threat_lock = _threading.Lock()

# Pattern thresholds
_PATTERN_SAME_MODEL_SECS    = 60    # window for single-model repetition
_PATTERN_SAME_MODEL_MAX     = 20    # >20 queries to same model in 60s → extraction probe
_PATTERN_ENUM_SECS          = 60    # window for model enumeration
_PATTERN_ENUM_UNIQUE_MAX    = 5     # >5 unique models in 60s → systematic enumeration
_PATTERN_REGULARITY_MIN_N   = 10    # minimum queries needed for timing analysis
_PATTERN_REGULARITY_COV_MAX = 0.20  # inter-query CoV < 0.20 → bot-like regularity


def _detect_query_patterns(now: float) -> dict:
    """
    Analyse recent query log for unusual patterns that indicate scraping or
    systematic probing, independent of raw volume burst detection.

    Returns a dict with keys:
        flags      — list of triggered pattern names
        details    — list of human-readable explanations for each flag
        suspicious — bool (any flag triggered)
    """
    with _req_lock:
        recent = [(ts, m) for ts, m in _query_log if ts >= now - _PATTERN_HISTORY_SECS]

    flags: list[str] = []
    details: list[str] = []
    impacted_models: list[str] = []   # models involved in triggered flags

    # ── 1. Same-model repetition ─────────────────────────────────────────────
    window_60 = [(ts, m) for ts, m in recent if ts >= now - _PATTERN_SAME_MODEL_SECS]
    model_counts: dict[str, int] = _collections.Counter(m for _, m in window_60)
    top_model, top_count = max(model_counts.items(), key=lambda x: x[1], default=(None, 0))
    if top_count > _PATTERN_SAME_MODEL_MAX:
        flags.append("same_model_repeat")
        details.append(
            f"Single model '{top_model}' queried {top_count}× in {_PATTERN_SAME_MODEL_SECS}s "
            f"(limit {_PATTERN_SAME_MODEL_MAX}) — possible extraction probing."
        )
        if top_model:
            impacted_models.append(top_model)

    # ── 2. Model enumeration (systematic probing across model list) ───────────
    enum_window = [(ts, m) for ts, m in recent if ts >= now - _PATTERN_ENUM_SECS]
    enum_models = sorted(set(m for _, m in enum_window))
    unique_models_in_window = len(enum_models)
    if unique_models_in_window > _PATTERN_ENUM_UNIQUE_MAX:
        flags.append("model_enumeration")
        details.append(
            f"{unique_models_in_window} unique models queried in {_PATTERN_ENUM_SECS}s "
            f"(limit {_PATTERN_ENUM_UNIQUE_MAX}) — possible systematic model enumeration."
        )
        impacted_models.extend(m for m in enum_models if m not in impacted_models)

    # ── 3. Bot-like regularity (very uniform inter-query timing) ─────────────
    ts_60 = sorted(ts for ts, _ in window_60)
    if len(ts_60) >= _PATTERN_REGULARITY_MIN_N:
        gaps = [ts_60[i + 1] - ts_60[i] for i in range(len(ts_60) - 1)]
        mean_gap = sum(gaps) / len(gaps)
        if mean_gap > 0:
            variance = sum((g - mean_gap) ** 2 for g in gaps) / len(gaps)
            cov = (variance ** 0.5) / mean_gap
            if cov < _PATTERN_REGULARITY_COV_MAX:
                flags.append("uniform_timing")
                details.append(
                    f"Inter-query timing is unusually uniform (CoV={cov:.2f}, "
                    f"threshold {_PATTERN_REGULARITY_COV_MAX}) across {len(ts_60)} queries — "
                    "bot-like automated scraping pattern."
                )
                timing_models = [m for _, m in window_60]
                for m in sorted(set(timing_models)):
                    if m not in impacted_models:
                        impacted_models.append(m)

    return {
        "flags":            flags,
        "details":          details,
        "impacted_models":  impacted_models,
        "suspicious":       len(flags) > 0,
        "window_secs":      _PATTERN_HISTORY_SECS,
        "queries_analysed": len(recent),
    }
_GATEWAY_MODEL_RE = re.compile(r'^\S+ \[gateway\] agent model: (.+)$')

# ── Auto-kill state ──────────────────────────────────────────────────────────
_autokill_enabled = False   # armed/disarmed
_autokill_triggered = None  # None or {triggered_at, window_seconds, count, threshold}
_autokill_lock = _threading.Lock()
_LITELLM_PLIST = os.path.expanduser("~/Library/LaunchAgents/com.openclaw.litellm.plist")
_OPENCLAW_NOTIFY = "http://localhost:18789/__openclaw__/internal/notify"
_DISCORD_MONITOR_CHANNEL = "1473791675997622364"  # #monitor


def _send_autokill_discord(msg):
    try:
        import json as _json
        import urllib.request as _urlreq
        payload = _json.dumps({
            "channel": "discord",
            "channelId": _DISCORD_MONITOR_CHANNEL,
            "message": msg,
        }).encode()
        req = _urlreq.Request(
            _OPENCLAW_NOTIFY, data=payload,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        _urlreq.urlopen(req, timeout=5)
    except Exception:
        pass


def _do_autokill(burst_info):
    """Unload LiteLLM via launchctl and record the event."""
    global _autokill_triggered
    with _autokill_lock:
        if _autokill_triggered is not None:
            return  # already triggered — don't fire again
        _autokill_triggered = {
            "triggered_at": _time.time(),
            "window_seconds": burst_info["window_seconds"],
            "count": burst_info["count"],
            "threshold": burst_info["threshold"],
        }
    try:
        subprocess.run(
            ["launchctl", "unload", _LITELLM_PLIST],
            capture_output=True, timeout=10,
        )
    except Exception:
        pass
    ts_str = datetime.fromtimestamp(_autokill_triggered["triggered_at"]).strftime("%H:%M:%S")
    _send_autokill_discord(
        f"🔴 **LiteLLM AUTO-KILLED** ({ts_str})\n"
        f"Burst detected: **{burst_info['count']} queries in {burst_info['window_seconds']}s** "
        f"(threshold: {burst_info['threshold']})\n"
        f"LiteLLM proxy has been shut down. Use NetWatch to restore."
    )


def _parse_gateway_ts(ts_str):
    try:
        from datetime import datetime
        return datetime.fromisoformat(ts_str).timestamp()
    except Exception:
        return None

def _tail_gateway_log():
    """Background thread: tail gateway.log and record per-model query timestamps."""
    while True:
        try:
            with open(_GATEWAY_LOG, "r", errors="replace") as f:
                f.seek(0, 2)  # jump to end — only track live queries
                while True:
                    line = f.readline()
                    if not line:
                        _time.sleep(0.05)
                        continue
                    m = _GATEWAY_MODEL_RE.match(line.strip())
                    if m:
                        # Use wall-clock time so tailing is always "now"
                        ts = _time.time()
                        model = m.group(1).strip()
                        pending_kill = None
                        with _req_lock:
                            dq = _model_req_times[model]
                            dq.append(ts)
                            cutoff = ts - _RATE_HISTORY_SECS
                            while dq and dq[0] < cutoff:
                                dq.popleft()
                            # Also feed pattern-detection log (5-min window)
                            _query_log.append((ts, model))
                            pattern_cutoff = ts - _PATTERN_HISTORY_SECS
                            while _query_log and _query_log[0][0] < pattern_cutoff:
                                _query_log.popleft()
                            # Check autokill while holding lock for a consistent snapshot
                            if _autokill_enabled and _autokill_triggered is None:
                                all_ts = [t for dq2 in _model_req_times.values() for t in dq2]
                                for w_secs, w_thresh in _BURST_THRESHOLDS:
                                    count = sum(1 for t in all_ts if t >= ts - w_secs)
                                    if count >= w_thresh:
                                        pending_kill = {
                                            "window_seconds": w_secs,
                                            "count": count,
                                            "threshold": w_thresh,
                                        }
                                        break
                        if pending_kill:
                            _threading.Thread(
                                target=_do_autokill, args=(pending_kill,), daemon=True
                            ).start()
        except FileNotFoundError:
            _time.sleep(5)
        except Exception:
            _time.sleep(2)

_tail_thread = _threading.Thread(target=_tail_gateway_log, daemon=True, name="gateway-log-tailer")
_tail_thread.start()

def _refresh_health_cache():
    """Run LiteLLM /health in background and cache result."""
    with _health_lock:
        if _health_cache["checking"]:
            return
        _health_cache["checking"] = True
    try:
        import yaml
        friendly_name = {}
        cfg_path = Path.home() / ".openclaw" / "litellm_config.yaml"
        if cfg_path.exists():
            with open(cfg_path) as f:
                lcfg = yaml.safe_load(f)
            for entry in lcfg.get("model_list", []):
                backend = entry.get("litellm_params", {}).get("model", "")
                name = entry.get("model_name", "")
                if backend and name:
                    friendly_name[backend] = name

        token = os.environ.get("GATEWAY_TOKEN", "")
        r = requests.get(
            "http://localhost:4000/health",
            headers={"Authorization": f"Bearer {token}"},
            timeout=90,
        )
        r.raise_for_status()
        health = r.json()

        def _short_error(err_str):
            if not err_str:
                return "Unknown error"
            for line in str(err_str).splitlines():
                line = line.strip()
                if not line or line.startswith(("stack trace", "Traceback", "File ")):
                    continue
                for prefix in ["litellm.", "GeminiException - ", "OpenAIException - "]:
                    if prefix in line:
                        line = line.split(prefix, 1)[-1].lstrip(": -")
                if '"message"' in line:
                    m = re.search(r'"message"\s*:\s*"([^"]+)"', line)
                    if m:
                        return m.group(1)
                if len(line) > 10:
                    return line[:200]
            return str(err_str)[:200]

        result = []
        for m in health.get("healthy_endpoints", []):
            backend = m.get("model", "")
            result.append({"name": friendly_name.get(backend, backend), "backend": backend, "status": "up", "error": None})
        for m in health.get("unhealthy_endpoints", []):
            backend = m.get("model", "")
            result.append({"name": friendly_name.get(backend, backend), "backend": backend, "status": "down", "error": _short_error(m.get("error"))})

        with _health_lock:
            _health_cache["data"] = result
            _health_cache["last_checked"] = datetime.now().isoformat()
    except Exception as e:
        with _health_lock:
            _health_cache["error"] = str(e)
    finally:
        with _health_lock:
            _health_cache["checking"] = False


def require_local(f):
    """Restrict endpoint to localhost-only requests."""
    @wraps(f)
    def decorated(*args, **kwargs):
        remote = request.remote_addr
        if remote not in ("127.0.0.1", "::1", "localhost"):
            return jsonify({"error": "Access denied: localhost only"}), 403
        return f(*args, **kwargs)
    return decorated

DATA_FILE = Path(__file__).parent / "devices.json"
HISTORY_FILE = Path(__file__).parent / "history.json"
NAMES_FILE = Path(__file__).parent / "device_names.json"

DEVICE_NAMES = {
    "aa:bb:cc:dd:ee:ff": "Bing's iPhone",
    "11:22:33:44:55:66": "Andy's MacBook Pro",
    "77:88:99:aa:bb:cc": "Living Room TV",
}

def load_device_names():
    """Load custom device names from JSON file."""
    if NAMES_FILE.exists():
        with open(NAMES_FILE, "r") as f:
            return json.load(f)
    return DEVICE_NAMES

def get_device_name(mac, custom_names=None):
    """Lookup friendly device name from MAC address."""
    if custom_names is None:
        custom_names = load_device_names()
    mac_normalized = mac.replace("-", ":").upper()
    return custom_names.get(mac_normalized, None)

def parse_arp_output():
    """Parse `arp -a` output to extract device info with background thread to avoid timeout."""
    import threading
    
    result_container = {"output": None, "error": None}
    
    def run_arp():
        try:
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=2)
            result_container["output"] = result.stdout
        except subprocess.TimeoutExpired:
            result_container["error"] = "timeout"
        except Exception as e:
            result_container["error"] = str(e)
    
    thread = threading.Thread(target=run_arp)
    thread.start()
    thread.join(timeout=2.5)
    
    if result_container["error"]:
        print(f"WARNING: arp -a failed ({result_container['error']}), using cached data")
        # Return existing devices as-is (don't mark offline if scan fails)
        existing = load_devices()
        return existing
    
    if not result_container["output"]:
        print("WARNING: arp -a returned no output")
        existing = load_devices()
        return existing
    
    lines = result_container["output"].strip().split("\n")
    
    devices = []
    pattern = r'\(([\d.]+)\) at ([a-f0-9:]+)'
    
    for line in lines:
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            ip = match.group(1)
            mac = match.group(2).replace("-", ":").upper()
            hostname = ""
            if "?" not in line:
                parts = line.split()
                for i, part in enumerate(parts):
                    if part == "at":
                        continue
                    if i > 0 and parts[i-1] == "at":
                        continue
                    if "(" in part and ")" in part and "?" not in part:
                        hostname = part.replace("(", "").replace(")", "")
                        break
            
            # If no hostname found, try reverse DNS lookup
            if not hostname:
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except (socket.herror, socket.gaierror):
                    pass
            
            device_name = get_device_name(mac)
            
            devices.append({
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "deviceName": device_name,
                "first_seen": datetime.now().isoformat(),
                "last_seen": datetime.now().isoformat(),
                "status": "online"
            })
    
    return devices

def load_devices():
    """Load devices from JSON file."""
    if DATA_FILE.exists():
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return []

def save_devices(devices):
    """Save devices to JSON file."""
    with open(DATA_FILE, "w") as f:
        json.dump(devices, f, indent=2)

def load_history():
    """Load historical data from JSON file."""
    if HISTORY_FILE.exists():
        try:
            with open(HISTORY_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            try:
                corrupted = HISTORY_FILE.with_suffix(".corrupted.json")
                HISTORY_FILE.replace(corrupted)
            except OSError:
                pass
            return []
    return []

def save_history(history):
    """Save historical data to JSON file."""
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)

def record_history_entry():
    """Record current device count to history."""
    history = load_history()
    devices = load_devices()
    online_count = sum(1 for d in devices if d["status"] == "online")
    
    entry = {
        "timestamp": datetime.now().isoformat(),
        "total": len(devices),
        "online": online_count,
        "offline": len(devices) - online_count
    }
    history.append(entry)
    
    # Keep only last 24 hours of data (assuming scans every minute)
    if len(history) > 1440:
        history = history[-1440:]
    
    save_history(history)
    return entry

@app.route("/")
def index():
    """Serve the main dashboard page."""
    return send_from_directory(Path(__file__).parent, "index.html")

@app.route("/api/devices")
def get_devices():
    """Return current device list."""
    current = parse_arp_output()
    existing = load_devices()
    
    current_ips = {d["ip"] for d in current}
    
    # Update existing devices
    for device in existing:
        if device["ip"] not in current_ips:
            device["status"] = "offline"
        else:
            device["last_seen"] = datetime.now().isoformat()
            device["status"] = "online"
    
    # Add new devices
    existing_ips = {d["ip"] for d in existing}
    for device in current:
        if device["ip"] not in existing_ips:
            existing.append(device)
    
    save_devices(existing)
    record_history_entry()
    
    return jsonify(existing)

@app.route("/api/history")
def get_history():
    """Return historical data for chart."""
    history = load_history()
    return jsonify(history)

@app.route("/api/scan", methods=["POST"])
def trigger_scan():
    """Trigger a network scan and return results."""
    current = parse_arp_output()
    existing = load_devices()
    
    current_ips = {d["ip"] for d in current}
    for device in existing:
        if device["ip"] not in current_ips:
            device["status"] = "offline"
        else:
            device["last_seen"] = datetime.now().isoformat()
            device["status"] = "online"
    
    existing_ips = {d["ip"] for d in existing}
    for device in current:
        if device["ip"] not in existing_ips:
            existing.append(device)
    
    save_devices(existing)
    record_history_entry()
    
    return jsonify(existing)

EMAIL_SCANS_DIR = Path(__file__).parent / "email_scans"

def get_latest_email_scan():
    """Get the most recent email scan results."""
    if not EMAIL_SCANS_DIR.exists():
        EMAIL_SCANS_DIR.mkdir(exist_ok=True)
        return {
            "scan_time": datetime.now().isoformat(),
            "total_scanned": 0,
            "flagged": 0,
            "results": [],
            "scam_type_counts": {}
        }
    
    scan_files = sorted(EMAIL_SCANS_DIR.glob("scan_*.json"), reverse=True)
    if scan_files:
        with open(scan_files[0]) as f:
            return json.load(f)
    
    return {
        "scan_time": datetime.now().isoformat(),
        "total_scanned": 0,
        "flagged": 0,
        "results": [],
        "scam_type_counts": {}
    }

def get_email_scans_history():
    """Get all email scan results for charting."""
    if not EMAIL_SCANS_DIR.exists():
        return []
    
    scan_files = sorted(EMAIL_SCANS_DIR.glob("scan_*.json"))
    history = []
    
    for scan_file in scan_files:
        try:
            with open(scan_file) as f:
                data = json.load(f)
            
            history.append({
                "timestamp": data.get("scan_time", scan_file.stem.split("_")[1]),
                "total_scanned": data.get("total_scanned", 0),
                "flagged": data.get("flagged_count", 0),
                "accounts": data.get("accounts_scanned", []),
                "flagged_emails": data.get("flagged_emails", []),
                "results": data.get("results", [])
            })
        except Exception as e:
            print(f"Error loading {scan_file}: {e}")
    
    return history

def run_email_scan():
    """Run email scam scanner in sandboxed mode and return results."""
    sandbox_script = Path(__file__).parent / "email_scans_sandbox.sh"
    script_path = Path(__file__).parent / "email_scams.py"
    
    if not sandbox_script.exists():
        return {"error": "sandbox script not found"}
    if not script_path.exists():
        return {"error": "email_scams.py not found"}
    
    try:
        # Run scan in sandboxed environment
        result = subprocess.run(
            ["bash", str(sandbox_script), "all"],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=str(Path(__file__).parent)
        )
        
        # Parse JSON output from stdout
        output = result.stdout
        json_start = output.find("--- JSON Output ---")
        if json_start > 0:
            json_str = output[json_start + len("--- JSON Output ---"):].strip()
            return json.loads(json_str)
        
        # Fallback: load latest scan file
        return get_latest_email_scan()
        
    except subprocess.TimeoutExpired:
        return {"error": "Email scan timed out"}
    except Exception as e:
        return {"error": str(e)}

# ── On-Demand Domain Verification ────────────────────────────────────────────
# Canonical baseline of legitimate business domains — mirrors the list used
# inside email_scams.py::analyze_email() and extends it with additional brands
# so both the automated heartbeat scan and the manual check are consistent.
_LEGIT_DOMAINS = [
    # Big tech / cloud
    "microsoft.com", "office.com", "outlook.com", "live.com", "hotmail.com",
    "google.com", "gmail.com", "youtube.com", "googlemail.com",
    "apple.com", "icloud.com", "me.com",
    "amazon.com", "amazonaws.com", "amazon.co.uk",
    "facebook.com", "fb.com", "instagram.com", "meta.com",
    "twitter.com", "x.com",
    "linkedin.com",
    "netflix.com",
    "adobe.com",
    "dropbox.com",
    "salesforce.com",
    "zoom.us",
    "slack.com",
    # Dev / infra
    "github.com", "gitlab.com", "bitbucket.org",
    "cloudflare.com", "digitalocean.com", "heroku.com",
    # Finance / payments
    "paypal.com", "paypal.me",
    "stripe.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citibank.com",
    "americanexpress.com",
    # Airlines / travel
    "delta.com", "aa.com", "united.com", "southwest.com",
    "jetblue.com", "alaskaair.com", "spirit.com", "frontier.com",
    "airfrance.com", "britishairways.com", "lufthansa.com",
    "booking.com", "expedia.com", "hotels.com", "airbnb.com",
    # Retail / services
    "ebay.com", "etsy.com", "shopify.com",
    "fedex.com", "ups.com", "usps.com", "dhl.com",
    # Comms / social
    "discord.com", "telegram.org", "whatsapp.com", "signal.org",
    # Govt / health
    "irs.gov", "ssa.gov", "medicare.gov",
]

# Free/personal email providers — sending a corporate claim from these is forgery
_FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com",
    "icloud.com", "me.com", "aol.com", "protonmail.com", "proton.me",
    "yandex.com", "mail.com",
}

# Brand keywords that indicate a corporate identity claim
_BRAND_KEYWORDS = [
    "microsoft", "amazon", "paypal", "apple", "google", "netflix",
    "facebook", "instagram", "meta", "linkedin", "twitter", "stripe",
    "chase", "bankofamerica", "wellsfargo", "irs", "security", "support",
    "billing", "account", "verify",
]

# Precomputed: base label → full legitimate domain, for brand-embedding detection.
# Only brands with base label ≥ 6 chars to avoid short false-positive matches.
# Sorted longest-first so "microsoft" is matched before "micro" if both existed.
_BRAND_TO_LEGIT: dict[str, str] = {
    legit.split(".")[0]: legit
    for legit in _LEGIT_DOMAINS
    if len(legit.split(".")[0]) >= 6
}
_PROTECTED_BRANDS: list[str] = sorted(_BRAND_TO_LEGIT, key=len, reverse=True)


def _levenshtein(a: str, b: str) -> int:
    """Full Levenshtein edit distance (handles insertions + deletions, not just substitutions)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(prev[j] + 1, curr[j - 1] + 1,
                            prev[j - 1] + (0 if ca == cb else 1)))
        prev = curr
    return prev[-1]


# ── DNS existence check ───────────────────────────────────────────────────────

def _dns_lookup(domain: str) -> dict:
    """
    Query A and MX records for domain.

    Returns:
      has_a     — True if at least one A record resolves
      has_mx    — True if at least one MX record resolves
      nxdomain  — True if the domain definitively does not exist (NXDOMAIN)
      status    — "LIVE" | "MAIL_ONLY" | "DEAD"
      a_records — list of IP strings (may be empty)
      mx_records— list of MX host strings (may be empty)
    """
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 4   # seconds total per query

    has_a, has_mx, nxdomain = False, False, False
    a_records, mx_records = [], []

    try:
        ans = resolver.resolve(domain, "A")
        has_a = True
        a_records = [r.address for r in ans]
    except dns.resolver.NXDOMAIN:
        nxdomain = True
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers,
            dns.exception.Timeout, Exception):
        pass   # domain may exist but have no A record

    try:
        ans = resolver.resolve(domain, "MX")
        has_mx = True
        mx_records = [str(r.exchange).rstrip(".") for r in ans]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout, Exception):
        pass

    if nxdomain or (not has_a and not has_mx):
        status = "DEAD"
    elif has_a:
        status = "LIVE"
    else:
        status = "MAIL_ONLY"

    return {
        "has_a": has_a, "has_mx": has_mx,
        "nxdomain": nxdomain, "status": status,
        "a_records": a_records, "mx_records": mx_records,
    }


# ── Blacklisted Squatters persistence ────────────────────────────────────────

_SQUATTER_FILE = Path(__file__).parent / "squatters.json"
_SQUATTER_LOCK = __import__("threading").Lock()


def _load_squatters() -> list:
    with _SQUATTER_LOCK:
        if _SQUATTER_FILE.exists():
            try:
                return json.loads(_SQUATTER_FILE.read_text()).get("squatters", [])
            except Exception:
                pass
    return []


def _save_squatters(squatters: list) -> None:
    with _SQUATTER_LOCK:
        _SQUATTER_FILE.write_text(json.dumps({"squatters": squatters}, indent=2))


def _add_squatter(domain: str, matched_legit: str, reason: str,
                  dns_status: str, verdict: str) -> None:
    """Upsert domain into squatter list (no duplicate entries)."""
    squatters = _load_squatters()
    if any(s["domain"] == domain for s in squatters):
        return
    squatters.insert(0, {
        "domain":       domain,
        "matched_legit": matched_legit,
        "reason":       reason,
        "dns_status":   dns_status,
        "verdict":      verdict,
        "first_seen":   datetime.utcnow().isoformat() + "Z",
    })
    _save_squatters(squatters)


# ── Core domain verification ──────────────────────────────────────────────────

def _mino_verify_domain(domain: str) -> dict:
    """
    Mino AI domain intelligence — four independent data signals:

    1. HTTP redirect chain   — follow to final URL; if it lands on a known
                               brand domain, the input is an alias, not a forgery.
    2. Page identity         — extract <title> and meta description from homepage.
    3. DuckDuckGo Instant    — query the domain as a search term; AbstractText
                               and AbstractSource reveal known businesses.
    4. WHOIS registrant      — organisation name from WHOIS record.

    After collecting signals, a best-effort LLM call (glm-4.7-flash via Ollama)
    synthesises them into a final verdict.  If the LLM is unavailable the function
    returns a rule-based verdict from the data signals alone.

    Returns:
        verdict      — "LEGITIMATE" | "SUSPICIOUS" | "UNKNOWN"
        confidence   — float 0.0–1.0
        reason       — human-readable explanation
        signals      — dict of raw collected data
        source       — "llm" | "heuristic"
    """
    signals: dict = {}

    # ── Signal 1: HTTP redirect chain ────────────────────────────────────────
    final_domain = ""
    try:
        resp = requests.get(
            f"https://{domain}",
            timeout=6,
            headers={"User-Agent": "Mozilla/5.0 (compatible; NetWatch/1.0)"},
            allow_redirects=True,
        )
        signals["http_status"] = resp.status_code
        final_url = resp.url
        signals["final_url"] = final_url
        # e.g. "https://www.delta.com/en_US/..." → "delta.com"
        parts = final_url.split("/")
        if len(parts) >= 3:
            host = parts[2].lstrip("www.")
            final_domain = host
            signals["final_domain"] = final_domain

        # Page title & meta description
        html = resp.text[:6000]
        title_m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
        desc_m  = re.search(
            r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)',
            html, re.I,
        )
        signals["page_title"]   = title_m.group(1).strip()[:120] if title_m else ""
        signals["meta_desc"]    = desc_m.group(1).strip()[:200]  if desc_m  else ""
    except (requests.exceptions.SSLError,
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout):
        # Try plain HTTP fallback
        try:
            resp = requests.get(
                f"http://{domain}", timeout=8,
                headers={"User-Agent": "Mozilla/5.0 (compatible; NetWatch/1.0)"},
                allow_redirects=True,
            )
            final_url = resp.url
            signals["final_url"] = final_url
            host = final_url.split("/")[2].lstrip("www.") if len(final_url.split("/")) >= 3 else ""
            final_domain = host
            signals["final_domain"] = final_domain
            html = resp.text[:6000]
            title_m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
            signals["page_title"] = title_m.group(1).strip()[:120] if title_m else ""
        except Exception as e:
            signals["http_error"] = str(e)[:100]
    except Exception as e:
        signals["http_error"] = str(e)[:100]

    # ── Signal 2: DuckDuckGo Instant Answer ──────────────────────────────────
    try:
        ddg = requests.get(
            "https://api.duckduckgo.com/",
            params={"q": domain, "format": "json", "no_html": "1", "skip_disambig": "1"},
            timeout=5,
        ).json()
        signals["ddg_abstract"] = ddg.get("AbstractText", "")[:300]
        signals["ddg_source"]   = ddg.get("AbstractSource", "")
        signals["ddg_type"]     = ddg.get("Type", "")
        # Also try the company name query
        ddg2 = requests.get(
            "https://api.duckduckgo.com/",
            params={"q": domain.split(".")[0] + " company airline bank",
                    "format": "json", "no_html": "1", "skip_disambig": "1"},
            timeout=5,
        ).json()
        if not signals["ddg_abstract"] and ddg2.get("AbstractText"):
            signals["ddg_abstract"] = ddg2.get("AbstractText", "")[:300]
            signals["ddg_source"]   = ddg2.get("AbstractSource", "")
    except Exception as e:
        signals["ddg_error"] = str(e)[:80]

    # ── Signal 3: WHOIS registrant ────────────────────────────────────────────
    try:
        proc = subprocess.run(
            ["whois", domain],
            capture_output=True, text=True, timeout=8,
        )
        whois_text = proc.stdout
        # Extract Registrant Org
        org_m = re.search(
            r"(?:Registrant\s+Org(?:anization)?|org)[:\s]+([^\n\r]+)",
            whois_text, re.I,
        )
        signals["whois_org"] = org_m.group(1).strip()[:120] if org_m else ""
        # Extract Creation Date
        created_m = re.search(
            r"(?:Creation Date|Created(?:\s+On)?)[:\s]+([^\n\r]+)",
            whois_text, re.I,
        )
        signals["whois_created"] = created_m.group(1).strip()[:40] if created_m else ""
    except Exception as e:
        signals["whois_error"] = str(e)[:60]

    # ── Rule-based verdict from signals ───────────────────────────────────────
    def _rule_verdict() -> dict:
        # Redirect to a known-good domain → definitive alias
        if final_domain:
            fd_base = final_domain.split(".")[0]
            if final_domain in _LEGIT_DOMAINS or final_domain.lstrip("www.") in _LEGIT_DOMAINS:
                return {"verdict": "LEGITIMATE", "confidence": 0.97,
                        "reason": f"Domain redirects to verified legitimate domain '{final_domain}'."}
            # Redirect to a domain containing a protected brand label
            for brand in _PROTECTED_BRANDS:
                if brand in fd_base:
                    return {"verdict": "LEGITIMATE", "confidence": 0.90,
                            "reason": f"Domain redirects to '{final_domain}' which carries the '{brand}' brand identity."}

        # DuckDuckGo returned a named business source
        ddg_src = signals.get("ddg_source", "")
        ddg_abs = signals.get("ddg_abstract", "")
        if ddg_src and len(ddg_abs) > 30:
            return {"verdict": "LEGITIMATE", "confidence": 0.85,
                    "reason": f"DuckDuckGo identifies domain as '{ddg_src}': {ddg_abs[:80]}…"}

        # WHOIS registrant is a recognisable corporation (not privacy-shield or comment)
        whois_org = signals.get("whois_org", "").lower()
        privacy_terms = {"privacy", "whoisguard", "domains by proxy", "redacted", "withheld", "%"}
        if whois_org and not any(p in whois_org for p in privacy_terms) and len(whois_org) > 4:
            return {"verdict": "LEGITIMATE", "confidence": 0.75,
                    "reason": f"WHOIS registrant organisation: '{signals['whois_org']}'."}

        # Page title looks like a real business (not parked/placeholder/error page)
        title = signals.get("page_title", "").lower()
        parked = {"parked", "for sale", "coming soon", "under construction",
                  "buy this domain", "domain default page", "404", "not found",
                  "403", "forbidden", "error", "page not found"}
        if title and not any(p in title for p in parked) and len(title) > 5:
            return {"verdict": "LEGITIMATE", "confidence": 0.65,
                    "reason": f"Homepage title suggests active site: '{signals['page_title']}'."}

        return {"verdict": "UNKNOWN", "confidence": 0.4,
                "reason": "Insufficient signals to verify domain legitimacy — treat with caution."}

    rule_result = _rule_verdict()

    # ── Signal 4: LLM synthesis (best-effort, Ollama glm-4.7-flash) ──────────
    llm_verdict = None
    try:
        summary = (
            f"Domain: {domain}\n"
            f"Redirects to: {signals.get('final_url','—')}\n"
            f"Page title: {signals.get('page_title','—')}\n"
            f"Meta description: {signals.get('meta_desc','—')}\n"
            f"DuckDuckGo: {signals.get('ddg_abstract','—')} (source: {signals.get('ddg_source','—')})\n"
            f"WHOIS org: {signals.get('whois_org','—')}\n"
            f"WHOIS created: {signals.get('whois_created','—')}\n"
        )
        prompt = (
            f"You are Mino, a domain security analyst. Based only on the data below, "
            f"determine if '{domain}' is a legitimate business domain.\n\n"
            f"{summary}\n"
            f"Reply ONLY with JSON on one line: "
            f'{{\"verdict\":\"LEGITIMATE\" or \"SUSPICIOUS\",\"confidence\":0.0-1.0,\"reason\":\"one sentence\"}}'
        )
        llm_resp = requests.post(
            "http://localhost:4000/v1/chat/completions",
            json={
                "model": "glm-4.7-flash",
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 120,
                "temperature": 0,
            },
            timeout=25,
        ).json()
        content = llm_resp.get("choices", [{}])[0].get("message", {}).get("content", "")
        if content and content.strip():
            # Extract JSON block from content
            json_m = re.search(r'\{[^{}]+\}', content, re.S)
            if json_m:
                parsed = json.loads(json_m.group())
                if parsed.get("verdict") in ("LEGITIMATE", "SUSPICIOUS"):
                    llm_verdict = {
                        "verdict":    parsed["verdict"],
                        "confidence": float(parsed.get("confidence", 0.7)),
                        "reason":     parsed.get("reason", "")[:200],
                        "source":     "llm",
                    }
    except Exception:
        pass   # LLM unavailable — fall through to rule verdict

    result = llm_verdict if llm_verdict else {**rule_result, "source": "heuristic"}
    result["signals"] = signals
    return result


def _check_domain(domain: str) -> dict:
    """
    Domain verification: typosquatting + quarantine patterns + DNS existence.

    Checks (in order):
      1. Exact match against legitimate baseline → CLEAN (skip DNS, known safe)
      2. DNS lookup (A + MX records)
      3. Typosquatting detection (3 methods)
         - NXDOMAIN + typosquat → CRITICAL: Non-Existent Forgery + squatter list
         - Domain exists + typosquat → FORGERY DETECTED
      4. MAIL_ONLY (MX but no A, not a known brand) → SUSPICIOUS: Mail-Only Shadow Domain
      5. Quarantine pattern match → FORGERY DETECTED
      6. No signals → CLEAN

    Returns dict: verdict, risk_level, matched_legit, detail, checks, dns
    """
    domain = domain.lower().strip()
    checks = []
    typo_hits = []

    # ── 1. Exact match — skip DNS, it's definitively legitimate ──────────────
    if domain in _LEGIT_DOMAINS:
        return {
            "verdict": "CLEAN",
            "risk_level": "LOW",
            "matched_legit": domain,
            "detail": f"{domain} is a verified legitimate domain.",
            "dns": {"status": "LIVE", "has_a": True, "has_mx": None,
                    "nxdomain": False, "a_records": [], "mx_records": []},
            "checks": [{"name": "Exact match", "result": "PASS",
                        "detail": "Found in verified domain baseline"}],
        }

    # ── 2. DNS lookup ─────────────────────────────────────────────────────────
    dns_info = _dns_lookup(domain)
    dns_status = dns_info["status"]   # "LIVE" | "MAIL_ONLY" | "DEAD"

    checks.append({
        "name":   "DNS existence",
        "result": "PASS" if dns_status == "LIVE" else ("WARNING" if dns_status == "MAIL_ONLY" else "FAIL"),
        "detail": (
            f"LIVE — A records: {', '.join(dns_info['a_records']) or '—'}"
            if dns_status == "LIVE" else
            f"MAIL_ONLY — MX: {', '.join(dns_info['mx_records']) or '—'}, no A record"
            if dns_status == "MAIL_ONLY" else
            "DEAD — domain does not resolve (NXDOMAIN or no records)"
        ),
    })

    # ── 3. Typosquatting detection ────────────────────────────────────────────
    domain_base = domain.split(".")[0]
    for legit in _LEGIT_DOMAINS:
        legit_base = legit.split(".")[0]

        # Sub-check A: equal-length char substitution (≤ 2 diffs)
        if domain != legit and len(domain_base) == len(legit_base):
            diff = sum(1 for a, b in zip(domain_base, legit_base) if a != b)
            if 0 < diff <= 2:
                typo_hits.append((legit, f"character substitution ({diff} char(s) changed from '{legit}')"))
                continue

        # Sub-check B: homoglyph / number-for-letter swaps
        normalised = domain_base.replace("0", "o").replace("1", "l").replace("3", "e").replace("@", "a")
        if normalised == legit_base and domain_base != legit_base:
            typo_hits.append((legit, f"homoglyph/number substitution ('{domain}' normalises to '{legit}')"))
            continue

        # Sub-check C: full Levenshtein ≤ 2
        if len(domain_base) > 3 and _levenshtein(domain_base, legit_base) <= 2 and domain_base != legit_base:
            typo_hits.append((legit, f"edit distance {_levenshtein(domain_base, legit_base)} from '{legit}'"))

    # Sub-check D: brand-name embedding — catches prefix/suffix abuse that
    # evades edit-distance checks (e.g. "microsoftcarriers", "amazon-delivery",
    # "paypal-billing-update"). Requires brand ≥ 6 chars to avoid short hits.
    # Strip hyphens from domain_base so "microsoft-carriers" also matches.
    if not typo_hits:
        domain_base_nohyphen = domain_base.replace("-", "").replace("_", "")
        for brand in _PROTECTED_BRANDS:
            if brand in domain_base_nohyphen and brand != domain_base_nohyphen:
                matched_legit = _BRAND_TO_LEGIT[brand]
                position = "prefix" if domain_base_nohyphen.startswith(brand) else \
                           "suffix" if domain_base_nohyphen.endswith(brand) else "embedded"
                typo_hits.append((
                    matched_legit,
                    f"protected brand '{brand}' {position} in '{domain}' — brand-name embedding attack"
                ))
                break   # first (longest) match wins

    if typo_hits:
        best_legit, best_detail = typo_hits[0]

        if dns_status == "DEAD":
            # Non-existent domain impersonating a brand → add to squatter list
            verdict   = "CRITICAL: Non-Existent Forgery"
            risk      = "CRITICAL"
            detail    = (f"Domain '{domain}' does not exist (NXDOMAIN) but is a near-miss of "
                         f"'{best_legit}': {best_detail}. Registered for future phishing.")
            _add_squatter(domain, best_legit, best_detail, dns_status, verdict)
        else:
            verdict = "FORGERY DETECTED"
            risk    = "CRITICAL"
            detail  = f"Domain '{domain}' is a near-miss of '{best_legit}': {best_detail}."

        return {
            "verdict": verdict,
            "risk_level": risk,
            "matched_legit": best_legit,
            "detail": detail,
            "dns": dns_info,
            "checks": checks + [
                {"name": "Typosquatting", "result": "FAIL", "detail": best_detail},
            ],
        }

    checks.append({"name": "Typosquatting", "result": "PASS",
                   "detail": "No near-miss to known legitimate domains"})

    # ── 4. Mail-Only Shadow Domain ────────────────────────────────────────────
    if dns_status == "MAIL_ONLY":
        return {
            "verdict": "SUSPICIOUS: Mail-Only Shadow Domain",
            "risk_level": "HIGH",
            "matched_legit": None,
            "detail": (f"'{domain}' has MX records ({', '.join(dns_info['mx_records'])}) "
                       f"but no website (no A record). Typical of covert mail-relay infrastructure."),
            "dns": dns_info,
            "checks": checks,
        }

    # ── 5. Free-email forgery check ───────────────────────────────────────────
    if domain in _FREE_EMAIL_PROVIDERS:
        checks.append({"name": "Free email provider", "result": "WARNING",
                        "detail": f"{domain} is a personal/free provider — verify sender claims"})
    else:
        checks.append({"name": "Free email provider", "result": "PASS",
                        "detail": "Not a free email provider"})

    # ── 6. Quarantine patterns ────────────────────────────────────────────────
    patterns_path = Path(__file__).parent.parent.parent.parent / \
        ".openclaw" / "scripts" / "verta_quarantine_patterns.json"
    suspicious_pattern_hit = None
    if patterns_path.exists():
        try:
            qp = json.loads(patterns_path.read_text())
            for pat in qp.get("suspicious_domains", []):
                if pat.lower() in domain:
                    suspicious_pattern_hit = pat
                    break
        except Exception:
            pass

    if suspicious_pattern_hit:
        return {
            "verdict": "FORGERY DETECTED",
            "risk_level": "HIGH",
            "matched_legit": None,
            "detail": f"Domain '{domain}' matches quarantine pattern '{suspicious_pattern_hit}'.",
            "dns": dns_info,
            "checks": checks + [{"name": "Quarantine patterns", "result": "FAIL",
                                  "detail": f"Matched suspicious pattern: {suspicious_pattern_hit}"}],
        }

    checks.append({"name": "Quarantine patterns", "result": "PASS",
                   "detail": "No suspicious patterns matched"})

    # ── 7. Mino AI domain intelligence (rule-based + optional LLM) ───────────
    mino = _mino_verify_domain(domain)
    if mino.get("verdict") == "SUSPICIOUS":
        return {
            "verdict": "SUSPICIOUS: Unverified Domain",
            "risk_level": "MEDIUM",
            "matched_legit": None,
            "detail": mino.get("reason", f"Mino could not verify '{domain}' as a legitimate domain."),
            "dns": dns_info,
            "checks": checks + [{"name": "Mino AI verification", "result": "WARN",
                                  "detail": mino.get("reason", "")}],
            "mino": mino,
        }

    return {
        "verdict": "CLEAN",
        "risk_level": "LOW",
        "matched_legit": None,
        "detail": mino.get("reason") or f"No forgery signals detected for '{domain}'.",
        "dns": dns_info,
        "checks": checks + [{"name": "Mino AI verification", "result": "PASS",
                              "detail": mino.get("reason", "Domain verified clean.")}],
        "mino": mino,
    }


@app.route("/api/email_domain_check", methods=["POST"])
def email_domain_check():
    """
    On-demand domain verification — full two-tier pipeline (Tier 1 + Mino Tier 2).
    Accepts { "email": "user@domain.tld" } or { "email": "domain.tld" }.
    Optional: { "tier1_only": true }  for a fast sub-second Tier 1 check only.
    Optional: { "subject": "..." }    for Subject-to-Domain Alignment analysis.
    """
    body = request.get_json(silent=True) or {}
    raw_input = body.get("email", "").strip()
    if not raw_input:
        return jsonify({"error": "missing 'email' field"}), 400

    domain = (raw_input.split("@")[-1].lower().strip() if "@" in raw_input
              else raw_input.lower().strip())
    if not domain or "." not in domain:
        return jsonify({"error": "invalid email or domain"}), 400

    tier1_only = bool(body.get("tier1_only", False))
    subject    = body.get("subject", "").strip()
    cc_bcc     = body.get("cc_bcc", "").strip()
    try:
        result = _ei_inspect(raw_input, realtime=True,
                             run_tier2=not tier1_only, subject=subject, cc_bcc=cc_bcc)
    except Exception as exc:
        # Fallback to legacy _check_domain on unexpected error
        result = _check_domain(domain)
        result["input"]     = raw_input
        result["domain"]    = domain
        result["timestamp"] = datetime.utcnow().isoformat() + "Z"
        result["pipeline_error"] = (str(exc) or f"{type(exc).__name__}")[:120]
    return jsonify(result), 200


@app.route("/api/email_inspect", methods=["POST"])
def email_inspect_deep():
    """
    Deep Research endpoint — always real-time, always runs full Tier 1 + Tier 2.
    Returns the full SecurityVerdict including tier1, tier2 sub-results,
    trust_score, reasoning, and all Mino signals.
    Body: { "domain": "deltaairlines.com" }  or  { "email": "user@domain.com" }
    Optional: { "subject": "..." }  for Subject-to-Domain Alignment analysis.
    """
    body = request.get_json(silent=True) or {}
    raw  = (body.get("domain") or body.get("email") or "").strip()
    if not raw:
        return jsonify({"error": "missing 'domain' or 'email' field"}), 400
    domain = raw.split("@")[-1].lower().strip() if "@" in raw else raw.lower().strip()
    if not domain or "." not in domain:
        return jsonify({"error": "invalid domain"}), 400
    subject = body.get("subject", "").strip()
    cc_bcc  = body.get("cc_bcc", "").strip()
    try:
        result = _ei_inspect(raw, realtime=True, run_tier2=True, subject=subject, cc_bcc=cc_bcc)
        return jsonify(result), 200
    except Exception as exc:
        # str(TimeoutError()) and str(CancelledError()) are '' — always give a message
        msg = str(exc) or f"{type(exc).__name__} (no message)"
        return jsonify({"error": msg, "domain": domain}), 500


@app.route("/api/verify_identity", methods=["POST"])
def verify_identity_endpoint():
    """
    Identity Verification Gate — sequential 5-step decision tree.
    Returns VerifyResult: { status, code, passed, reason, checks, trust_score, domain, verdict, inspect_result }.
    Body: { "email": "user@domain.com" }  or  { "domain": "domain.com" }
    Optional: { "subject": "...", "headers": "..." }
    """
    body    = request.get_json(silent=True) or {}
    raw     = (body.get("email") or body.get("domain") or "").strip()
    if not raw:
        return jsonify({"error": "missing 'email' or 'domain' field"}), 400
    domain = raw.split("@")[-1].lower().strip() if "@" in raw else raw.lower().strip()
    if not domain or "." not in domain:
        return jsonify({"error": "invalid domain"}), 400
    subject = body.get("subject", "").strip()
    headers = body.get("headers") or None
    try:
        result = _ei_verify(raw, subject=subject, headers=headers, realtime=True)
        return jsonify(result), 200
    except Exception as exc:
        msg = str(exc) or f"{type(exc).__name__} (no message)"
        return jsonify({"error": msg, "domain": domain}), 500


# ── Mino verdict classifier ───────────────────────────────────────────────────

def _classify_mino_verdict(result: dict) -> tuple[str, list[str]]:
    """
    Map an inspect() result to one of three Mino verdicts:
      FORGERY    — definitive impersonation / infrastructure attack
      SUSPICIOUS — signals present but not conclusive
      LEGIT      — clean

    Returns (mino_verdict, flags_list).
    """
    verdict = (result.get("verdict") or "").upper()
    score   = result.get("trust_score", 50)
    sa      = result.get("subject_alignment") or {}
    ha      = result.get("header_audit")      or {}
    t2      = result.get("tier2")             or {}
    flags: list[str] = []

    # ── FORGERY criteria ──────────────────────────────────────────────────────
    # 1. Brand Dissonance
    if sa.get("alignment_status") == "BRAND_DISSONANCE":
        brands = ", ".join(
            b.split(".")[0].title()
            for b in (sa.get("extracted_brands") or [])[:2]
        )
        flags.append(f"Brand Dissonance — {brands or 'corporate brand'} claimed via consumer inbox")

    # 2. Header Ghosting
    if ha.get("status") == "SECONDARY_HEADER_SPOOFING":
        addrs = ", ".join((ha.get("flagged_addresses") or [])[:2])
        flags.append(f"Header Ghosting — {addrs}")

    # 3. Infrastructure Failure: domain < 48 hours old
    reg      = (t2.get("ownership") or {}).get("registration") or {}
    age_days = reg.get("age_days")
    if age_days is not None and 0 <= age_days < 2:
        flags.append(f"Infrastructure Failure — domain registered {age_days:.1f} days ago (< 48 h)")

    # 4. Hard verdict keywords
    _forgery_kw = ("CRITICAL", "FORGERY", "GHOST", "BEC",
                   "SPOOFING", "DISSONANCE", "NON-EXISTENT")
    if any(kw in verdict for kw in _forgery_kw):
        if not flags:
            flags.append(result.get("verdict", verdict))
        return "FORGERY", flags

    if flags:
        return "FORGERY", flags

    # ── SUSPICIOUS criteria ───────────────────────────────────────────────────
    sus_flags: list[str] = []
    if score < 50:
        sus_flags.append(f"Low trust score ({score}/100)")
    sa_status = sa.get("alignment_status", "")
    if sa_status == "MISALIGNED":
        sus_flags.append("Subject-domain mismatch")
    elif sa_status == "IDENTITY_THEFT":
        sus_flags.append("Identity theft attempt")
    elif sa_status == "HIGH_RISK_BILLING":
        sus_flags.append("Unverified billing domain")
    if "SUSPICIOUS" in verdict:
        sus_flags.append(result.get("verdict", ""))

    if sus_flags:
        return "SUSPICIOUS", sus_flags

    return "LEGIT", []


# ── Historical backfill from local email scan files ───────────────────────────

def _verdict_from_scan_result(r: dict) -> tuple[str, int, str, list[str]]:
    """
    Convert a scan-file result dict into (mino_verdict, trust_score, detail, flags)
    without re-running the full inspect() pipeline.
    """
    risk_level    = (r.get("risk_level") or "LOW").upper()
    primary_type  = (r.get("primary_type") or "").upper()
    risk_score    = int(r.get("risk_score") or 0)
    classifications = r.get("classifications") or []

    # Map risk_score (0-10 scale) to trust_score (0-100 scale, inverted)
    trust_score = max(0, 100 - risk_score * 10)

    flags: list[str] = []
    for c in classifications:
        ctype   = (c.get("type") or "").upper()
        detail  = c.get("detail") or ""
        conf    = c.get("confidence", 0)
        if ctype and conf > 0.3:
            flags.append(f"{ctype}: {detail}" if detail else ctype)

    if primary_type in ("FORGERY", "PHISHING", "IMPERSONATION", "SPOOFING"):
        mino_verdict = "FORGERY"
        if not flags:
            flags.append(primary_type)
    elif risk_level in ("HIGH", "CRITICAL") or trust_score < 40:
        mino_verdict = "SUSPICIOUS"
        if not flags:
            flags.append(f"Risk level: {risk_level}")
    elif risk_level == "MEDIUM" or trust_score < 60:
        mino_verdict = "SUSPICIOUS"
    else:
        mino_verdict = "LEGIT"

    detail = primary_type or risk_level
    return mino_verdict, trust_score, detail, flags


def _backfill_historical_incidents() -> None:
    """
    Populate netwatch_live_incidents from existing email_scans/*.json files.
    Uses source_ref = "scan:<message_id>" to skip already-imported rows.
    Runs once at startup in a background thread; safe to re-run (idempotent).
    """
    import glob as _glob
    from datetime import timedelta

    scan_dir   = Path(__file__).parent / "email_scans"
    cutoff     = datetime.now() - timedelta(days=92)   # ~3 months
    scan_files = sorted(_glob.glob(str(scan_dir / "scan_*.json")))

    imported = skipped = 0
    for fpath in scan_files:
        # Filename: scan_YYYYMMDD_HHMMSS.json — skip files older than cutoff
        fname = Path(fpath).stem  # e.g. scan_20260318_103052
        try:
            file_date = datetime.strptime(fname, "scan_%Y%m%d_%H%M%S")
        except ValueError:
            continue
        if file_date < cutoff:
            continue

        try:
            with open(fpath) as fh:
                data = json.load(fh)
        except Exception:
            continue

        for r in (data.get("results") or []):
            sender      = (r.get("sender") or "").strip()
            subject     = (r.get("subject") or "").strip()
            message_id  = r.get("message_id") or ""
            file_stem   = Path(fpath).stem
            # Include filename so per-file sequential IDs don't collide across scans
            source_ref  = f"scan:{file_stem}:{message_id}" if message_id else f"scan:{file_stem}:{sender}:{subject[:40]}"

            if not sender:
                continue

            # Extract domain from sender string like "Name <addr@domain.com>"
            m = re.search(r"@([\w.\-]+)", sender)
            domain = m.group(1).lower() if m else sender

            # Use received_date if present, else fall back to timestamp or file date
            received_at = (
                r.get("received_date")
                or r.get("timestamp")
                or file_date.isoformat()
            )

            mino_verdict, trust_score, detail, flags = _verdict_from_scan_result(r)

            row_id = store_live_incident(
                sender       = sender,
                subject      = subject,
                domain       = domain,
                mino_verdict = mino_verdict,
                trust_score  = trust_score,
                verdict_detail = detail,
                flags        = flags,
                raw_result   = {
                    "source": "scan_file",
                    "risk_level":   r.get("risk_level"),
                    "primary_type": r.get("primary_type"),
                    "risk_score":   r.get("risk_score"),
                },
                received_at  = received_at,
                source_ref   = source_ref,
            )
            if row_id:
                imported += 1
            else:
                skipped += 1

    print(f"[netwatch] backfill complete — {imported} imported, {skipped} skipped (duplicates)")


# Kick off backfill in background so it doesn't block server startup
import threading as _threading
_threading.Thread(target=_backfill_historical_incidents, daemon=True, name="backfill").start()


# ── Webhook: incoming email from external source ──────────────────────────────

@app.route("/api/webhook/incoming_email", methods=["POST"])
def webhook_incoming_email():
    """
    Receive an inbound email payload and run the full Mino analysis pipeline.

    Expected JSON body:
      sender  (required) — e.g. "billing@fakepaypal.net"
      subject (optional) — email subject line
      to      (optional) — primary To address(es)
      cc      (optional) — CC addresses
      bcc     (optional) — BCC addresses

    Returns the Mino verdict summary immediately; full result stored in DB.
    """
    body    = request.get_json(silent=True) or {}
    sender  = (body.get("sender") or body.get("from") or "").strip()
    subject = body.get("subject", "").strip()
    to_addr = body.get("to",  "").strip()
    cc      = body.get("cc",  "").strip()
    bcc     = body.get("bcc", "").strip()

    if not sender:
        return jsonify({"error": "missing 'sender' field"}), 400

    # Build combined header string for secondary brand scan
    cc_bcc = ", ".join(filter(None, [to_addr, cc, bcc]))

    # ── Phase 1 + Phase 2: full Mino pipeline ────────────────────────────────
    try:
        result = _ei_inspect(
            sender,
            realtime=True,
            run_tier2=True,
            subject=subject,
            cc_bcc=cc_bcc,
        )
    except Exception as exc:
        return jsonify({"error": str(exc) or type(exc).__name__}), 500

    # ── Classify verdict ─────────────────────────────────────────────────────
    mino_verdict, flags = _classify_mino_verdict(result)

    # ── Persist to DB ────────────────────────────────────────────────────────
    incident_id = store_live_incident(
        sender        = sender,
        subject       = subject,
        domain        = result.get("domain", ""),
        mino_verdict  = mino_verdict,
        trust_score   = result.get("trust_score", 0),
        verdict_detail= result.get("verdict", ""),
        flags         = flags,
        raw_result    = {k: result[k] for k in
                         ("domain", "verdict", "trust_score", "tier1", "subject_alignment",
                          "header_audit", "timestamp") if k in result},
    )

    return jsonify({
        "incident_id":  incident_id,
        "mino_verdict": mino_verdict,
        "trust_score":  result.get("trust_score", 0),
        "verdict":      result.get("verdict", ""),
        "domain":       result.get("domain", ""),
        "flags":        flags,
        "sender":       sender,
        "subject":      subject,
    }), 200


# ── Live Incidents feed ───────────────────────────────────────────────────────

@app.route("/api/live_incidents")
def live_incidents():
    """Return the 100 most recent Mino-analysed incidents, newest first."""
    try:
        rows = get_live_incidents(limit=100)
        return jsonify({"incidents": rows}), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/squatters")
def get_squatters():
    """Return the blacklisted squatter domains list."""
    return jsonify({"squatters": _load_squatters()})


@app.route("/api/squatters/remove", methods=["POST"])
def remove_squatter():
    """Remove a domain from the squatter blacklist. Body: { "domain": "bad.com" }"""
    body   = request.get_json(silent=True) or {}
    domain = body.get("domain", "").strip().lower()
    if not domain:
        return jsonify({"error": "missing 'domain'"}), 400
    squatters = _load_squatters()
    before = len(squatters)
    squatters = [s for s in squatters if s["domain"] != domain]
    _save_squatters(squatters)
    return jsonify({"removed": before - len(squatters), "domain": domain})


@app.route("/api/email_scans")
def get_email_scans():
    """Return latest email scan results with dashboard summary."""
    raw = get_latest_email_scan()
    # Build dashboard summary expected by UI/tests
    results = raw.get("results", [])
    total_scanned = raw.get("total_scanned", len(results))
    flagged = raw.get("flagged", raw.get("flagged_count", 0))
    clean = total_scanned - flagged

    # Build byRisk counts from results
    by_risk = {}
    for r in results:
        risk = r.get("risk", r.get("severity", "LOW")).upper()
        by_risk[risk] = by_risk.get(risk, 0) + 1
    # Ensure MEDIUM key exists for junk mail tracking
    if "MEDIUM" not in by_risk:
        by_risk["MEDIUM"] = raw.get("junk_count", 0)

    dashboard = {
        "totalScanned": total_scanned,
        "flagged": flagged,
        "clean": clean,
        "byRisk": by_risk,
    }
    raw["dashboard"] = dashboard
    return jsonify(raw)

@app.route("/api/email_scan", methods=["POST"])
@require_local
def trigger_email_scan():
    """Trigger a new email scan and return dashboard-enriched results."""
    raw = run_email_scan()
    # Build same dashboard summary as /api/email_scans
    results = raw.get("results", [])
    total_scanned = raw.get("total_scanned", len(results))
    flagged = raw.get("flagged", raw.get("flagged_count", 0))
    clean = total_scanned - flagged
    by_risk = {}
    for r in results:
        risk = r.get("risk", r.get("severity", "LOW")).upper()
        by_risk[risk] = by_risk.get(risk, 0) + 1
    if "MEDIUM" not in by_risk:
        by_risk["MEDIUM"] = raw.get("junk_count", 0)
    raw["dashboard"] = {
        "totalScanned": total_scanned,
        "flagged": flagged,
        "clean": clean,
        "byRisk": by_risk,
    }
    return jsonify(raw)

def load_email_scans_history():
    """Get all email scan results for charting."""
    if not EMAIL_SCANS_DIR.exists():
        return []
    
    scan_files = sorted(EMAIL_SCANS_DIR.glob("scan_*.json"))
    history = []
    
    for scan_file in scan_files:
        try:
            with open(scan_file) as f:
                data = json.load(f)
            
            history.append({
                "timestamp": data.get("scan_time", scan_file.stem.split("_")[1]),
                "total_scanned": data.get("total_scanned", 0),
                "flagged": data.get("flagged_count", 0),
                "accounts": data.get("accounts_scanned", []),
                "flagged_emails": data.get("flagged_emails", []),
                "results": data.get("results", [])
            })
        except Exception as e:
            print(f"Error loading {scan_file}: {e}")
    
    return history

@app.route("/api/email_scans_history")
def get_email_scans_history_api():
    """Return all email scan results for historical charting."""
    return jsonify(load_email_scans_history())

@app.route("/api/email_bulk_action", methods=["POST"])
@require_local
def email_bulk_action():
    """Perform bulk action on flagged emails (report spam, delete)."""
    data = request.get_json()
    action = data.get("action")
    
    if not action:
        return jsonify({"error": "No action specified"}), 400
    
    # Get latest scan results
    latest = get_latest_email_scan()
    flagged = latest.get("flagged_emails", [])
    
    if not flagged:
        return jsonify({"message": "No flagged emails to process"})
    
    # Process each flagged email
    processed = 0
    for email in flagged:
        account = email.get("account")
        message_id = email.get("message_id")
        
        if not account or not message_id:
            continue
        
        try:
            if action == "report_spam":
                # Mark as spam via IMAP or Graph API
                if "gmail" in account.lower():
                    password_file = os.path.expanduser("~/.verta_gmail_app_password")
                    if os.path.exists(password_file):
                        with open(password_file) as f:
                            password = f.read().strip().replace(" ", "")
                        mail = imaplib.IMAP4_SSL("imap.gmail.com")
                        mail.login(account, password)
                        mail.select("[Gmail]/Spam")
                        mail.copy(message_id, "[Gmail]/Spam")
                        mail.store(message_id, '+FLAGS', '\\Deleted')
                        mail.close()
                        mail.logout()
                        processed += 1
                
                elif "outlook" in account.lower():
                    token_file = os.path.expanduser("~/.verta_outlook_token.json")
                    if os.path.exists(token_file):
                        with open(token_file) as f:
                            token_data = json.load(f)
                        access_token = token_data.get("access_token")
                        if access_token:
                            url = f"https://graph.microsoft.com/v1.0/me/messages/{message_id}"
                            headers = {"Authorization": f"Bearer {access_token}"}
                            # Move to junk folder
                            requests.patch(url, headers=headers, json={"isRead": True, "categories": ["Junk"]}, timeout=30)
                            processed += 1
            
            elif action == "delete":
                # Permanently delete
                if "gmail" in account.lower():
                    password_file = os.path.expanduser("~/.verta_gmail_app_password")
                    if os.path.exists(password_file):
                        with open(password_file) as f:
                            password = f.read().strip().replace(" ", "")
                        mail = imaplib.IMAP4_SSL("imap.gmail.com")
                        mail.login(account, password)
                        mail.select("inbox")
                        mail.store(message_id, '+FLAGS', '\\Deleted')
                        mail.expunge()
                        mail.close()
                        mail.logout()
                        processed += 1
                
                elif "outlook" in account.lower():
                    token_file = os.path.expanduser("~/.verta_outlook_token.json")
                    if os.path.exists(token_file):
                        with open(token_file) as f:
                            token_data = json.load(f)
                        access_token = token_data.get("access_token")
                        if access_token:
                            url = f"https://graph.microsoft.com/v1.0/me/messages/{message_id}"
                            headers = {"Authorization": f"Bearer {access_token}"}
                            requests.delete(url, headers=headers, timeout=30)
                            processed += 1
        
        except Exception as e:
            print(f"Error processing {message_id}: {e}")
    
    return jsonify({
        "message": f"Successfully processed {processed}/{len(flagged)} flagged emails",
        "processed": processed,
        "total": len(flagged)
    })

@app.route("/api/email_view")
@require_local
def view_email():
    """View full email content by message ID."""
    account = request.args.get("account")
    message_id = request.args.get("message_id")
    
    if not account or not message_id:
        return jsonify({"error": "Missing account or message_id"}), 400
    
    # Handle Gmail (IMAP)
    if "gmail" in account.lower():
        password_file = os.path.expanduser("~/.verta_gmail_app_password")
        if not os.path.exists(password_file):
            return jsonify({"error": "Gmail password not found"}), 400
        
        with open(password_file) as f:
            password = f.read().strip().replace(" ", "")
        
        try:
            mail = imaplib.IMAP4_SSL("imap.gmail.com")
            mail.login(account, password)
            mail.select("inbox")
            
            status, msg_data = mail.fetch(message_id, "(RFC822)")
            if status != "OK":
                mail.logout()
                return jsonify({"error": "Message not found"}), 404
            
            raw_email = email.message_from_bytes(msg_data[0][1])
            
            # Extract full content
            body = ""
            html_body = ""
            if raw_email.is_multipart():
                for part in raw_email.walk():
                    content_type = part.get_content_type()
                    if content_type == "text/plain":
                        try:
                            body = part.get_payload(decode=True).decode(errors="ignore")
                        except:
                            pass
                        break
                    elif content_type == "text/html":
                        try:
                            html_body = part.get_payload(decode=True).decode(errors="ignore")
                        except:
                            pass
            else:
                try:
                    body = raw_email.get_payload(decode=True).decode(errors="ignore")
                except:
                    pass
            
            mail.logout()
            
            return jsonify({
                "subject": raw_email.get("Subject", ""),
                "from": raw_email.get("From", ""),
                "to": raw_email.get("To", ""),
                "date": raw_email.get("Date", ""),
                "received_date": raw_email.get("Date", ""),
                "body": body if body else html_body,
                "html_body": html_body,
                "headers": dict(raw_email.items())
            })
        
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    # Handle Outlook (Graph API)
    elif "outlook" in account.lower():
        token_file = os.path.expanduser("~/.verta_outlook_token.json")
        if not os.path.exists(token_file):
            return jsonify({"error": "Outlook token not found"}), 400
        
        with open(token_file) as f:
            token_data = json.load(f)
        
        access_token = token_data.get("access_token")
        if not access_token:
            return jsonify({"error": "No access token"}), 400
        
        headers = {"Authorization": f"Bearer {access_token}"}
        
        try:
            # Fetch message details
            msg_url = f"https://graph.microsoft.com/v1.0/me/messages/{message_id}"
            params = {"$select": "subject,from,toRecipients,body,receivedDateTime,internetMessageHeaders"}
            response = requests.get(msg_url, headers=headers, params=params, timeout=30)
            
            if response.status_code != 200:
                return jsonify({"error": "Message not found"}), 404
            
            msg_data = response.json()
            
            # Extract body
            body_content = msg_data.get("body", {})
            body = body_content.get("content", "") if body_content.get("contentType") == "text" else ""
            html_body = body_content.get("content", "") if body_content.get("contentType") == "html" else ""
            
            # Extract headers
            headers_dict = {}
            for h in msg_data.get("internetMessageHeaders", []):
                headers_dict[h.get("name", "")] = h.get("value", "")
            
            return jsonify({
                "subject": msg_data.get("subject", ""),
                "from": msg_data.get("from", {}).get("emailAddress", {}).get("address", ""),
                "to": msg_data.get("toRecipients", [{}])[0].get("emailAddress", {}).get("address", ""),
                "date": headers_dict.get("Date", ""),
                "received_date": msg_data.get("receivedDateTime", ""),
                "body": body if body else html_body,
                "html_body": html_body,
                "headers": headers_dict
            })
        
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    return jsonify({"error": "Unknown account type"}), 400

MINO_NETWATCH_PATH = Path.home() / ".openclaw" / "workspace-mino" / "NetWatch"


@app.route("/api/cyber_news")
def api_cyber_news():
    news_path = MINO_NETWATCH_PATH / "cyber_news.json"
    try:
        with open(news_path) as f:
            return jsonify(json.load(f))
    except FileNotFoundError:
        return jsonify({"newsItems": [], "status": "No cyber news data available"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/cyber_news_7day")
def api_cyber_news_7day():
    """Return cyber news items from the rolling last 7 days, newest first."""
    from datetime import datetime, timedelta
    news_path = MINO_NETWATCH_PATH / "cyber_news.json"
    try:
        with open(news_path) as f:
            data = json.load(f)
        items = data.get("newsItems", [])
        cutoff = (datetime.utcnow() - timedelta(days=7)).strftime("%Y-%m-%d")
        filtered = sorted(
            [item for item in items if item.get("date", "") >= cutoff],
            key=lambda x: x.get("date", ""),
            reverse=True,
        )
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for item in filtered:
            sev = item.get("severity", "LOW").upper()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        return jsonify({
            "newsItems": filtered,
            "total": len(filtered),
            "severityCounts": severity_counts,
            "cutoffDate": cutoff,
            "lastUpdated": data.get("lastUpdated", ""),
            "status": data.get("status", ""),
        })
    except FileNotFoundError:
        return jsonify({"newsItems": [], "total": 0, "status": "No cyber news data available"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/cyber_news_window")
def api_cyber_news_window():
    """Return cyber news for a rolling window. Query param: days=1|7|30 (default 7)."""
    from datetime import datetime, timedelta
    try:
        days = int(request.args.get("days", 7))
        if days not in (1, 7, 30):
            days = 7
    except (ValueError, TypeError):
        days = 7

    news_path = MINO_NETWATCH_PATH / "cyber_news.json"
    try:
        with open(news_path) as f:
            data = json.load(f)
        items = data.get("newsItems", [])
        cutoff = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")
        filtered = sorted(
            [item for item in items if item.get("date", "") >= cutoff],
            key=lambda x: x.get("date", ""),
            reverse=True,
        )
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for item in filtered:
            sev = item.get("severity", "LOW").upper()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        return jsonify({
            "newsItems": filtered,
            "total": len(filtered),
            "severityCounts": severity_counts,
            "cutoffDate": cutoff,
            "days": days,
            "lastUpdated": data.get("lastUpdated", ""),
            "status": data.get("status", ""),
        })
    except FileNotFoundError:
        return jsonify({"newsItems": [], "total": 0, "status": "No cyber news data available"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/daily_trends")
def api_daily_trends():
    import glob
    pattern = str(MINO_NETWATCH_PATH / "daily-trend-*.json")
    files = sorted(glob.glob(pattern), reverse=True)
    if files:
        try:
            with open(files[0]) as f:
                return jsonify(json.load(f))
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    return jsonify({"error": "No daily trend data found"}), 404


@app.route("/api/ai_threats")
def api_ai_threats():
    """Return AI threat events from the Mino threat guard dashboard."""
    dashboard_path = MINO_NETWATCH_PATH / "dashboard.json"
    try:
        with open(dashboard_path) as f:
            data = json.load(f)
    except FileNotFoundError:
        return jsonify({"total": 0, "blocked": 0, "threats": []})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    threats = data.get("aiThreats", [])
    total   = data.get("aiThreatCount", len(threats))
    blocked = data.get("aiThreatBlocked", sum(1 for t in threats if t.get("status") in ("CRITICAL", "TAMPERED")))
    return jsonify({"total": total, "blocked": blocked, "threats": threats})


@app.route("/api/new_devices")
def api_new_devices():
    from datetime import datetime, timedelta
    cutoff = (datetime.utcnow() - timedelta(days=7)).isoformat()
    devices = load_devices()
    new = [d for d in devices if d.get("first_seen", "") >= cutoff]
    return jsonify(new)


@app.route("/api/device_counts")
def api_device_counts():
    from datetime import datetime, timedelta
    devices = load_devices()
    counts = {}
    for d in devices:
        day = (d.get("last_seen") or "")[:10]
        if day:
            counts[day] = counts.get(day, 0) + 1
    # Last 7 days
    result = []
    for i in range(6, -1, -1):
        day = (datetime.utcnow() - timedelta(days=i)).strftime("%Y-%m-%d")
        result.append({"day": day, "device_count": counts.get(day, 0)})
    return jsonify(result)


@app.route("/api/network_firewall")
def api_network_firewall():
    """Monitor network-level firewall activity: external connections, suspicious ports, gateway info."""
    SUSPICIOUS_PORTS = {
        23: "Telnet", 21: "FTP", 25: "SMTP", 110: "POP3", 143: "IMAP",
        1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5900: "VNC",
        6667: "IRC", 6881: "BitTorrent", 4444: "Metasploit",
        1080: "SOCKS Proxy", 8080: "HTTP Alt", 8443: "HTTPS Alt",
    }
    KNOWN_GOOD_SUFFIXES = ["apple.com", "icloud.com", "amazonaws.com", "google.com",
                           "googleapis.com", "cloudflare.com", "discord.com", "discordapp.com",
                           "microsoft.com", "akamai.net", "fastly.net"]

    def parse_host_and_port(endpoint):
        endpoint = endpoint.strip()
        if endpoint.startswith("[") and "]" in endpoint:
            host, _, rest = endpoint[1:].partition("]")
            port = rest.lstrip(".:") or "0"
            return host, port
        if endpoint.count(".") >= 1:
            host, _, port = endpoint.rpartition(".")
            if port.isdigit():
                return host, port
        if ":" in endpoint:
            host, _, port = endpoint.rpartition(":")
            return host, port if port.isdigit() else "0"
        return endpoint, "0"

    result = {
        "gateway": "Unknown",
        "external_connections": [],
        "external_count": 0,
        "flagged_count": 0,
        "open_ports": [],
        "open_port_count": 0,
        "connection_count": 0,
    }

    # ── Gateway IP ────────────────────────────────────────────────────────
    try:
        gw = subprocess.run(
            ["/sbin/route", "-n", "get", "default"],
            capture_output=True,
            text=True,
            timeout=2,
        )
        for line in gw.stdout.splitlines():
            if "gateway:" in line:
                result["gateway"] = line.split("gateway:", 1)[-1].strip() or "Unknown"
                break
    except Exception as e:
        result["gateway_error"] = str(e)

    # Run netstat once and reuse it so the endpoint remains fast/reliable.
    try:
        ns = subprocess.run(
            ["/usr/sbin/netstat", "-an", "-p", "tcp"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        lines = ns.stdout.splitlines()[2:]
        local_prefixes = ("127.", "192.168.", "10.", "172.", "::1", "fe80:", "*", "localhost")

        ext_conns = []
        seen = set()
        open_ports = []

        for line in lines:
            parts = line.split()
            if len(parts) < 6:
                continue

            proto, local, foreign, state = parts[0], parts[3], parts[4], parts[5]
            foreign_ip, foreign_port = parse_host_and_port(foreign)

            if state == "ESTABLISHED":
                if any(foreign_ip.startswith(p) for p in local_prefixes):
                    continue
                key = (foreign_ip, foreign_port)
                if key not in seen:
                    seen.add(key)
                    port_int = int(foreign_port) if foreign_port.isdigit() else 0
                    suspicious = port_int in SUSPICIOUS_PORTS
                    hostname = ""
                    known_good = any(s in hostname for s in KNOWN_GOOD_SUFFIXES)
                    ext_conns.append({
                        "proto": proto,
                        "local": local,
                        "foreign_ip": foreign_ip,
                        "foreign_port": foreign_port,
                        "hostname": hostname,
                        "state": state,
                        "suspicious_port": suspicious,
                        "suspicious_port_name": SUSPICIOUS_PORTS.get(port_int, ""),
                        "known_good": known_good,
                        "flag": suspicious and not known_good,
                    })

            if state == "LISTEN":
                _, port_str = parse_host_and_port(local)
                port_int = int(port_str) if port_str.isdigit() else 0
                suspicious = port_int in SUSPICIOUS_PORTS
                open_ports.append({
                    "address": local,
                    "port": port_int,
                    "suspicious": suspicious,
                    "service": SUSPICIOUS_PORTS.get(port_int, ""),
                })

        ext_conns.sort(key=lambda c: (not c["flag"], not c["suspicious_port"]))
        open_ports.sort(key=lambda p: (not p["suspicious"], p["port"]))

        result["external_connections"] = ext_conns[:60]
        result["external_count"] = len(ext_conns)
        result["flagged_count"] = sum(1 for c in ext_conns if c["flag"])
        result["open_ports"] = open_ports[:40]
        result["open_port_count"] = len(open_ports)
        result["connection_count"] = len(result["external_connections"])
    except Exception as e:
        result["ext_error"] = str(e)

    return jsonify(result)


@app.route("/api/firewall")
def api_firewall():
    """Return macOS firewall status, active connections, and recent log entries."""
    result = {}

    # ── 1. Firewall on/off state ──────────────────────────────────────────
    try:
        fw = subprocess.run(
            ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
            capture_output=True, text=True, timeout=5
        )
        state_line = fw.stdout.strip()
        result["firewall_enabled"] = "enabled" in state_line.lower()
        result["firewall_state_raw"] = state_line
    except Exception as e:
        result["firewall_enabled"] = None
        result["firewall_state_raw"] = str(e)

    # ── 2. Stealth mode ───────────────────────────────────────────────────
    try:
        sm = subprocess.run(
            ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode"],
            capture_output=True, text=True, timeout=5
        )
        result["stealth_mode"] = "enabled" in sm.stdout.lower()
        result["stealth_mode_raw"] = sm.stdout.strip()
    except Exception as e:
        result["stealth_mode"] = None
        result["stealth_mode_raw"] = str(e)

    # ── 3. Block all incoming ─────────────────────────────────────────────
    try:
        ba = subprocess.run(
            ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getblockall"],
            capture_output=True, text=True, timeout=5
        )
        result["block_all"] = "enabled" in ba.stdout.lower()
        result["block_all_raw"] = ba.stdout.strip()
    except Exception as e:
        result["block_all"] = None
        result["block_all_raw"] = str(e)

    # ── 4. Active TCP connections (netstat) ───────────────────────────────
    try:
        ns = subprocess.run(
            ["/usr/sbin/netstat", "-an", "-p", "tcp"],
            capture_output=True, text=True, timeout=10
        )
        lines = ns.stdout.strip().splitlines()
        connections = []
        for line in lines[2:]:
            parts = line.split()
            if len(parts) >= 5:
                state = parts[5] if len(parts) > 5 else "-"
                connections.append({
                    "proto": parts[0],
                    "local": parts[3],
                    "foreign": parts[4],
                    "state": state
                })
        filtered = [c for c in connections if c["state"] in ("ESTABLISHED", "LISTEN")][:50]
        result["connections"] = filtered
        result["connection_count"] = len(filtered)
    except Exception as e:
        result["connections"] = []
        result["connection_count"] = 0
        result["connections_error"] = str(e)

    # ── 5. Recent firewall log entries ─────────────────────────────────────
    try:
        log_path = "/var/log/appfirewall.log"
        log_proc = subprocess.run(
            ["tail", "-n", "100", log_path],
            capture_output=True, text=True, timeout=5
        )
        raw_lines = log_proc.stdout.strip().splitlines()
        log_entries = []
        for raw in raw_lines[-50:]:
            m = re.match(r"(\w+ +\d+ \d+:\d+:\d+) \S+ \S+\[\d+\]: (.+)", raw)
            if m:
                log_entries.append({"time": m.group(1), "message": m.group(2)})
            else:
                log_entries.append({"time": "", "message": raw})
        result["log_entries"] = list(reversed(log_entries))
    except Exception as e:
        result["log_entries"] = []
        result["log_error"] = str(e)

    return jsonify(result)


@app.route("/api/ai_usage")
def api_ai_usage():
    try:
        result = subprocess.run(
            ["openclaw", "sessions", "--all-agents", "--json"],
            capture_output=True, text=True, timeout=30
        )
        data = json.loads(result.stdout)
        sessions_raw = data.get("sessions", [])

        # De-duplicate: skip :run: sub-keys, keep sessions with token data
        seen = set()
        sessions = []
        for s in sessions_raw:
            key = s.get("key", "")
            if ":run:" in key:
                continue
            sid = s.get("sessionId") or key
            if sid in seen:
                continue
            seen.add(sid)
            if s.get("totalTokens") is not None:
                sessions.append({
                    "key": key,
                    "agentId": s.get("agentId", "unknown"),
                    "model": s.get("model", ""),
                    "modelProvider": s.get("modelProvider", ""),
                    "totalTokens": s.get("totalTokens"),
                    "inputTokens": s.get("inputTokens"),
                    "outputTokens": s.get("outputTokens"),
                    "contextTokens": s.get("contextTokens"),
                    "updatedAt": s.get("updatedAt"),
                })

        return jsonify({"sessions": sessions, "count": len(sessions)})
    except Exception as e:
        return jsonify({"error": str(e), "sessions": []}), 500


@app.route("/api/llm")
def api_llm():
    """Return LiteLLM proxy, Ollama status, and per-agent model/token data."""
    from datetime import date, timedelta

    result = {
        "litellm": {"status": "offline", "models": []},
        "ollama": {"status": "offline", "models": [], "running": []},
        "agents": [],
        "next_reset": None,
    }

    # ── LiteLLM proxy ─────────────────────────────────────────────────────
    gateway_token = os.environ.get("GATEWAY_TOKEN", "")

    try:
        r = requests.get(
            "http://localhost:4000/v1/models",
            headers={"Authorization": f"Bearer {gateway_token}"},
            timeout=5,
        )
        r.raise_for_status()
        result["litellm"]["status"] = "online"
        result["litellm"]["models"] = [m["id"] for m in r.json().get("data", [])]
    except Exception as e:
        result["litellm"]["error"] = str(e)

    # ── Model health status (served from cache; triggers background refresh) ──
    with _health_lock:
        cached = list(_health_cache["data"])
        checking = _health_cache["checking"]
        last_checked = _health_cache["last_checked"]

    # Trigger a background refresh if cache is empty or stale (>5 min)
    stale = True
    if last_checked:
        from datetime import timedelta
        age = datetime.now() - datetime.fromisoformat(last_checked)
        stale = age > timedelta(minutes=5)

    if (not cached or stale) and not checking and result["litellm"]["status"] == "online":
        t = _threading.Thread(target=_refresh_health_cache, daemon=True)
        t.start()

    result["model_status"] = cached
    result["model_status_checking"] = checking or (not cached and result["litellm"]["status"] == "online")
    result["model_status_last_checked"] = last_checked

    # ── Ollama ────────────────────────────────────────────────────────────
    try:
        r = requests.get("http://localhost:11434/api/tags", timeout=5)
        r.raise_for_status()
        result["ollama"]["status"] = "online"
        result["ollama"]["models"] = [
            {"name": m.get("name", ""), "size": m.get("size", 0), "modified_at": m.get("modified_at", "")}
            for m in r.json().get("models", [])
        ]
    except Exception as e:
        result["ollama"]["error"] = str(e)

    if result["ollama"]["status"] == "online":
        try:
            r = requests.get("http://localhost:11434/api/ps", timeout=5)
            r.raise_for_status()
            result["ollama"]["running"] = [
                {"name": m.get("name", ""), "size": m.get("size", 0), "size_vram": m.get("size_vram", 0), "until": m.get("expires_at", "")}
                for m in r.json().get("models", [])
            ]
        except Exception:
            pass

    # ── Agent token data ──────────────────────────────────────────────────
    try:
        config_path = Path.home() / ".openclaw" / "openclaw.json"
        agent_names = {}
        if config_path.exists():
            with open(config_path) as f:
                config = json.load(f)
            for a in config.get("agents", {}).get("list", []):
                agent_names[a["id"]] = a.get("name") or a["id"]

        proc = subprocess.run(
            ["openclaw", "sessions", "--all-agents", "--json"],
            capture_output=True, text=True, timeout=30
        )
        sessions_raw = json.loads(proc.stdout).get("sessions", [])

        # Per agent: pick most recently updated session with token data
        by_agent = {}
        for s in sessions_raw:
            if ":run:" in s.get("key", ""):
                continue
            if s.get("totalTokens") is None:
                continue
            aid = s.get("agentId", "unknown")
            if aid not in by_agent or (s.get("updatedAt") or "") > (by_agent[aid].get("updatedAt") or ""):
                by_agent[aid] = s

        # All known agent IDs: union of config list + agents directory
        all_agent_ids = set(agent_names.keys())
        agents_dir = Path.home() / ".openclaw" / "agents"
        if agents_dir.exists():
            all_agent_ids.update(p.name for p in agents_dir.iterdir() if p.is_dir() and not p.name.startswith('.'))

        default_model = config.get("agents", {}).get("defaults", {}).get("model", {}).get("primary", "") if config_path.exists() else ""

        for aid in sorted(all_agent_ids):
            s = by_agent.get(aid)
            ctx = s.get("contextTokens") or 0 if s else 0
            used = s.get("totalTokens") or 0 if s else 0
            result["agents"].append({
                "id": aid,
                "name": agent_names.get(aid, aid),
                "model": s.get("model", "") if s else default_model,
                "provider": s.get("modelProvider", "") if s else "",
                "contextTokens": ctx,
                "totalTokens": used,
                "tokensRemaining": max(0, ctx - used) if ctx else None,
            })

        # Next billing reset (default: 1st of month)
        billing_path = Path(__file__).parent / "billing_config.json"
        reset_day = 1
        if billing_path.exists():
            with open(billing_path) as f:
                reset_day = json.load(f).get("reset_day", 1)
        today = date.today()
        try:
            candidate = today.replace(day=reset_day)
        except ValueError:
            candidate = (today.replace(day=1) + timedelta(days=32)).replace(day=1) - timedelta(days=1)
        if candidate <= today:
            nm = (candidate.replace(day=1) + timedelta(days=32)).replace(day=1)
            try:
                candidate = nm.replace(day=reset_day)
            except ValueError:
                candidate = nm - timedelta(days=1)
        result["next_reset"] = candidate.isoformat()

        # ── Billing ───────────────────────────────────────────────────────
        # Cost per token lookup from openclaw.json
        cost_lookup = {}
        if config_path.exists():
            for provider_id, provider in config.get("models", {}).get("providers", {}).items():
                for m in provider.get("models", []):
                    c = m.get("cost", {})
                    cost_lookup[f"{provider_id}/{m['id']}"] = {
                        "input": c.get("input", 0),
                        "output": c.get("output", 0),
                    }

        # Fallback pricing per token for known models
        FALLBACK_COSTS = {
            "litellm/claude-opus-4-6":   {"input": 0.000015,    "output": 0.000075},
            "litellm/claude-sonnet-4-6": {"input": 0.000003,    "output": 0.000015},
            "litellm/claude-haiku-4-5":  {"input": 0.0000008,   "output": 0.000004},
            "litellm/gemini-2.5-pro":    {"input": 0.00000125,  "output": 0.00001},
            "litellm/gemini-2.0-flash":  {"input": 0.0000001,   "output": 0.0000004},
            "anthropic/claude-opus-4-6":   {"input": 0.000015,  "output": 0.000075},
            "anthropic/claude-sonnet-4-6": {"input": 0.000003,  "output": 0.000015},
            "anthropic/claude-haiku-4-5":  {"input": 0.0000008, "output": 0.000004},
        }

        # Aggregate tokens per provider/model across all sessions
        by_model = {}
        for s in sessions_raw:
            if ":run:" in s.get("key", ""):
                continue
            if s.get("totalTokens") is None:
                continue
            provider = s.get("modelProvider", "")
            model = s.get("model", "")
            key = f"{provider}/{model}" if provider else model
            inp = s.get("inputTokens") or 0
            out = s.get("outputTokens") or 0
            if key not in by_model:
                by_model[key] = {"inputTokens": 0, "outputTokens": 0}
            by_model[key]["inputTokens"] += inp
            by_model[key]["outputTokens"] += out

        billing = []
        for key, tokens in sorted(by_model.items()):
            inp = tokens["inputTokens"]
            out = tokens["outputTokens"]
            costs = cost_lookup.get(key) or FALLBACK_COSTS.get(key) or {"input": 0, "output": 0}
            cost = inp * costs["input"] + out * costs["output"]
            billing.append({
                "model": key,
                "inputTokens": inp,
                "outputTokens": out,
                "costPerInputToken": costs["input"],
                "costPerOutputToken": costs["output"],
                "cost": cost,
                "isFree": costs["input"] == 0 and costs["output"] == 0,
            })

        billing.sort(key=lambda x: x["cost"], reverse=True)
        result["billing"] = billing
        result["billing_total"] = sum(b["cost"] for b in billing)

        # ── Fallback suggestions ───────────────────────────────────────────
        # Ordered fallback preferences per model (model_name as in litellm config)
        FALLBACK_MAP = {
            # Frontier tier
            "claude-opus-4-6":     ["claude-sonnet-4-6", "gemini-2.5-pro", "qwen3.5:397b-cloud", "kimi-k2.5:cloud"],
            "qwen3.5:397b-cloud":  ["claude-opus-4-6", "gemini-2.5-pro", "kimi-k2.5:cloud", "claude-sonnet-4-6"],
            # Mid tier
            "claude-sonnet-4-6":   ["gemini-2.5-pro", "kimi-k2.5:cloud", "qwen3.5:397b-cloud", "claude-haiku-4-5"],
            "gemini-2.5-pro":      ["claude-sonnet-4-6", "qwen3.5:397b-cloud", "kimi-k2.5:cloud", "claude-opus-4-6"],
            "kimi-k2.5:cloud":     ["qwen3.5:397b-cloud", "claude-sonnet-4-6", "glm-5:cloud", "minimax-m2.1:cloud"],
            "glm-5:cloud":         ["qwen3.5:397b-cloud", "kimi-k2.5:cloud", "claude-sonnet-4-6", "minimax-m2.1:cloud"],
            "minimax-m2.1:cloud":  ["kimi-k2.5:cloud", "qwen3.5:397b-cloud", "claude-sonnet-4-6", "glm-5:cloud"],
            # Fast/light tier
            "claude-haiku-4-5":    ["gemini-2.0-flash", "qwen2.5:3b", "glm-4.7-flash", "kimi-k2.5:cloud"],
            "gemini-2.0-flash":    ["claude-haiku-4-5", "qwen2.5:3b", "glm-4.7-flash", "kimi-k2.5:cloud"],
            "glm-4.7:cloud":       ["glm-5:cloud", "kimi-k2.5:cloud", "qwen3.5:397b-cloud", "claude-sonnet-4-6"],
            "glm-4.7-flash":       ["qwen2.5:3b", "kimi-k2.5:cloud", "claude-haiku-4-5", "glm-4.7:cloud"],
            "qwen2.5:3b":          ["claude-haiku-4-5", "glm-4.7-flash", "kimi-k2.5:cloud", "gemini-2.0-flash"],
            # Vision
            "llava":               ["claude-sonnet-4-6", "gemini-2.5-pro"],
            # External (not in LiteLLM — agent uses a different provider)
            "gpt-5.4":             ["claude-sonnet-4-6", "gemini-2.5-pro", "kimi-k2.5:cloud", "qwen3.5:397b-cloud"],
            "gpt-4o":              ["claude-sonnet-4-6", "gemini-2.5-pro", "kimi-k2.5:cloud"],
            "gpt-4o-mini":         ["claude-haiku-4-5", "gemini-2.0-flash", "qwen2.5:3b", "kimi-k2.5:cloud"],
        }

        # Build set of UP model names from cached health status
        up_models = {m["name"] for m in cached if m["status"] == "up"}
        down_models = {m["name"]: m.get("error", "") for m in cached if m["status"] == "down"}
        status_known = bool(cached)

        # Collect all models to evaluate: LiteLLM models + models used by agents
        agent_models = {a["model"].split("/")[-1] for a in result["agents"] if a.get("model")}
        litellm_model_names = set(result["litellm"]["models"])
        all_models = litellm_model_names | agent_models

        # Build agent lookup: model_name → list of agent names using it
        model_to_agents = {}
        for a in result["agents"]:
            m = a.get("model", "").split("/")[-1]
            if m:
                model_to_agents.setdefault(m, []).append(a.get("name") or a.get("id"))

        fallback_suggestions = []
        for model in sorted(all_models):
            if model not in FALLBACK_MAP:
                continue
            status = "down" if model in down_models else ("up" if model in up_models else ("unknown" if status_known else "unknown"))
            error = down_models.get(model, "")
            candidates = FALLBACK_MAP[model]
            suggestions = []
            for fb in candidates:
                if fb == model:
                    continue
                fb_status = "up" if fb in up_models else ("down" if fb in down_models else "unknown")
                # Only suggest if UP or if status not yet known
                if fb_status == "up" or not status_known:
                    suggestions.append({"name": fb, "status": fb_status})
                if len(suggestions) >= 3:
                    break
            fallback_suggestions.append({
                "model": model,
                "status": status,
                "error": error,
                "affectedAgents": model_to_agents.get(model, []),
                "suggestions": suggestions,
            })

        # Sort: down first, then unknown, then up
        order = {"down": 0, "unknown": 1, "up": 2}
        fallback_suggestions.sort(key=lambda x: order.get(x["status"], 1))
        result["fallback_suggestions"] = fallback_suggestions

    except Exception as e:
        result["agents_error"] = str(e)

    return jsonify(result)


@app.route("/api/llm/theft")
def api_llm_theft():
    """Return LiteLLM model theft protection status and current spend."""
    import yaml

    LITELLM_CONFIG = os.path.expanduser("~/.openclaw/litellm_config.yaml")
    LITELLM_BASE = "http://127.0.0.1:4000"
    gateway_token = os.environ.get("GATEWAY_TOKEN", "")

    result = {
        "protections": {
            "ip_restriction": {"enabled": False, "allowed_ips": []},
            "budget_cap":     {"enabled": False, "amount": None, "duration": None},
            "rate_limit":     {"enabled": False, "rpm": None},
            "auth_required":  {"enabled": bool(gateway_token)},
        },
        "spend": {"current": None, "budget": None, "pct": None, "error": None},
    }

    # ── Read litellm_config.yaml for configured protections ──────────────────
    try:
        with open(LITELLM_CONFIG) as f:
            cfg = yaml.safe_load(f)
        gs = cfg.get("general_settings", {})

        ips = gs.get("allowed_ips", [])
        result["protections"]["ip_restriction"] = {
            "enabled": bool(ips),
            "allowed_ips": ips,
        }

        budget = gs.get("max_budget")
        duration = gs.get("budget_duration")
        result["protections"]["budget_cap"] = {
            "enabled": budget is not None,
            "amount": budget,
            "duration": duration,
        }

        rpm = gs.get("rpm_limit")
        result["protections"]["rate_limit"] = {
            "enabled": rpm is not None,
            "rpm": rpm,
        }

        if gs.get("master_key"):
            result["protections"]["auth_required"]["enabled"] = True

    except Exception as e:
        result["config_error"] = str(e)

    # ── Query current spend from LiteLLM ─────────────────────────────────────
    try:
        r = requests.get(
            f"{LITELLM_BASE}/global/spend",
            headers={"Authorization": f"Bearer {gateway_token}"},
            timeout=5,
        )
        r.raise_for_status()
        body = r.json()
        spend = body.get("spend") or body.get("total_cost") or body.get("total_spend") or 0.0
        budget = result["protections"]["budget_cap"].get("amount") or 100.0
        result["spend"] = {
            "current": round(float(spend), 4),
            "budget": float(budget),
            "pct": round(float(spend) / float(budget), 4) if budget else None,
            "error": None,
        }
    except Exception as e:
        result["spend"]["error"] = str(e)

    # ── Per-model query rate / burst detection ───────────────────────────────
    now = _time.time()
    with _req_lock:
        snapshot = {m: list(dq) for m, dq in _model_req_times.items()}

    def _count_in_times(times, secs):
        cutoff = now - secs
        return sum(1 for t in times if t >= cutoff)

    # Aggregate all models for totals + burst detection
    all_times = [t for ts in snapshot.values() for t in ts]
    total_5s  = _count_in_times(all_times, 5)
    total_30s = _count_in_times(all_times, 30)
    total_60s = _count_in_times(all_times, 60)

    warnings = []
    for window_secs, threshold in _BURST_THRESHOLDS:
        count = _count_in_times(all_times, window_secs)
        if count >= threshold:
            severity = "critical" if count >= threshold * 2 else "high"
            # Which models are contributing to this burst window?
            offenders = sorted(
                [
                    {"model": m, "count": _count_in_times(ts, window_secs)}
                    for m, ts in snapshot.items()
                    if _count_in_times(ts, window_secs) > 0
                ],
                key=lambda x: x["count"],
                reverse=True,
            )
            warnings.append({
                "window_seconds": window_secs,
                "count": count,
                "threshold": threshold,
                "severity": severity,
                "message": f"{count} queries in {window_secs}s (limit: {threshold})",
                "models": offenders,
            })

    # Per-model breakdown sorted by last_60s descending
    by_model = {}
    for model, times in snapshot.items():
        last5  = _count_in_times(times, 5)
        last30 = _count_in_times(times, 30)
        last60 = _count_in_times(times, 60)
        by_model[model] = {
            "last_5s":   last5,
            "last_30s":  last30,
            "last_60s":  last60,
            "last_120s": len(times),
        }
    by_model_sorted = dict(
        sorted(by_model.items(), key=lambda x: x[1]["last_60s"], reverse=True)
    )

    # Total sparkline (all models combined, 24 × 5s buckets, newest last)
    bucket_size = 5
    num_buckets = _RATE_HISTORY_SECS // bucket_size
    buckets = [0] * num_buckets
    for t in all_times:
        age = now - t
        if age < _RATE_HISTORY_SECS:
            idx = min(int(age // bucket_size), num_buckets - 1)
            buckets[num_buckets - 1 - idx] += 1

    result["query_rate"] = {
        "total": {
            "last_5s":   total_5s,
            "last_30s":  total_30s,
            "last_60s":  total_60s,
            "last_120s": len(all_times),
        },
        "by_model":  by_model_sorted,
        "warnings":  warnings,
        "sparkline": buckets,
    }

    # ── Auto-kill state ───────────────────────────────────────────────────────
    ak = {"enabled": _autokill_enabled, "triggered": None}
    if _autokill_triggered:
        t = _autokill_triggered
        ak["triggered"] = {
            "triggered_at": datetime.fromtimestamp(t["triggered_at"]).isoformat(),
            "window_seconds": t["window_seconds"],
            "count": t["count"],
            "threshold": t["threshold"],
        }
    result["autokill"] = ak

    # ── Unusual query pattern detection ──────────────────────────────────────
    pattern = _detect_query_patterns(now)
    result["pattern_detection"] = pattern

    # ── Overall theft status ──────────────────────────────────────────────────
    high_volume   = len(warnings) > 0
    unusual_patterns = pattern["suspicious"]

    if high_volume and unusual_patterns:
        theft_status = "FAIL: HIGH VOLUME + UNUSUAL QUERY PATTERNS"
        theft_reasons = ["High Volume", "Unusual Query Patterns"]
    elif high_volume:
        theft_status = "FAIL: HIGH VOLUME"
        theft_reasons = ["High Volume"]
    elif unusual_patterns:
        theft_status = "FAIL: UNUSUAL QUERY PATTERNS"
        theft_reasons = ["Unusual Query Patterns"]
    else:
        theft_status = "PASS"
        theft_reasons = []

    result["theft_status"] = theft_status
    result["theft_reasons"] = theft_reasons

    # ── Threat description + impacted models ──────────────────────────────────
    desc_parts = []
    all_models: list[str] = []

    if high_volume:
        for w in warnings:
            desc_parts.append(f"High Volume: {w['message']}")
            for m in w.get("models", []):
                name = m.get("model", "")
                if name and name not in all_models:
                    all_models.append(name)

    if unusual_patterns:
        desc_parts.extend(pattern.get("details", []))
        for m in pattern.get("impacted_models", []):
            if m not in all_models:
                all_models.append(m)

    result["threat_description"] = "; ".join(desc_parts) if desc_parts else "None"
    result["threat_models"]      = all_models if all_models else []

    # ── Threat occurrence counter ─────────────────────────────────────────────
    global threat_occurrences, _last_theft_was_fail
    is_fail = theft_status.startswith("FAIL")
    with _threat_lock:
        if is_fail and not _last_theft_was_fail:
            threat_occurrences += 1
        _last_theft_was_fail = is_fail
    result["threat_occurrences"] = threat_occurrences

    return jsonify(result)


@app.route("/api/llm/autokill", methods=["POST"])
def api_llm_autokill():
    """Enable/disable burst-triggered auto-kill, or restore LiteLLM after a kill."""
    global _autokill_enabled, _autokill_triggered
    body = request.get_json(silent=True) or {}
    action = body.get("action")

    if action == "enable":
        _autokill_enabled = True
        return jsonify({"ok": True, "autokill_enabled": True})
    elif action == "disable":
        _autokill_enabled = False
        return jsonify({"ok": True, "autokill_enabled": False})
    elif action == "restore":
        try:
            subprocess.run(
                ["launchctl", "load", _LITELLM_PLIST],
                capture_output=True, timeout=10, check=True,
            )
        except subprocess.CalledProcessError as e:
            err = e.stderr.decode(errors="replace").strip() if e.stderr else "launchctl failed"
            return jsonify({"ok": False, "error": err})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)})
        with _autokill_lock:
            _autokill_triggered = None
        return jsonify({"ok": True, "restored": True})
    else:
        return jsonify({"error": "unknown action — use enable, disable, or restore"}), 400


@app.route("/api/llm/watermark/status")
def api_llm_watermark_status():
    """Return watermark configuration and live-probe status."""
    import yaml

    secret = os.environ.get("WATERMARK_SECRET", "")
    litellm_config_path = os.path.expanduser("~/.openclaw/litellm_config.yaml")

    # Check callback registration in config
    callback_registered = False
    try:
        with open(litellm_config_path) as f:
            cfg = yaml.safe_load(f)
        callbacks = cfg.get("litellm_settings", {}).get("callbacks", [])
        callback_registered = any("watermark" in str(c).lower() for c in callbacks)
    except Exception:
        pass

    # Check LiteLLM is reachable (use /v1/models — faster than /health which pings all backends)
    litellm_up = False
    try:
        r = requests.get(
            "http://127.0.0.1:4000/v1/models",
            headers={"Authorization": f"Bearer {os.environ.get('GATEWAY_TOKEN', '')}"},
            timeout=5,
        )
        litellm_up = r.status_code == 200
    except Exception:
        pass

    # Live probe: make a minimal completion and check for ZWSP markers
    probe = {"tested": False, "whitebox_detected": False, "blackbox_ratio": None, "error": None}
    if litellm_up and secret:
        import sys as _sys
        scripts_dir = os.path.expanduser("~/.openclaw/scripts")
        if scripts_dir not in _sys.path:
            _sys.path.insert(0, scripts_dir)
        try:
            from litellm_watermark import wb_decode, bb_detect
            # Use a tiny Ollama model for the probe (fast, free)
            probe_models = ["qwen2.5:3b", "glm-4.7-flash", "llava"]
            probe_text = None
            for model in probe_models:
                try:
                    r = requests.post(
                        "http://127.0.0.1:4000/v1/chat/completions",
                        headers={
                            "Authorization": f"Bearer {os.environ.get('GATEWAY_TOKEN', '')}",
                            "Content-Type": "application/json",
                        },
                        json={
                            "model": model,
                            "messages": [{"role": "user", "content":
                                "List five different software tools developers use and "
                                "explain how they help. Be concise."}],
                            "max_tokens": 150,
                        },
                        timeout=30,
                    )
                    body = r.json()
                    content = (body.get("choices") or [{}])[0].get("message", {}).get("content") or ""
                    if content:
                        probe_text = content
                        probe["model_used"] = model
                        break
                except Exception:
                    continue

            if probe_text:
                probe["tested"] = True
                wb = wb_decode(probe_text, secret.encode())
                bb = bb_detect(probe_text, secret.encode())
                probe["whitebox_detected"] = wb.get("found") and wb.get("valid")
                probe["whitebox_model"] = wb.get("model_id")
                probe["whitebox_markers"] = wb.get("markers", 0)
                probe["blackbox_ratio"] = bb.get("formal_ratio")
                probe["blackbox_key_verified"] = bb.get("key_verified")
                probe["blackbox_suspected"] = bb.get("watermark_suspected")
        except Exception as e:
            probe["error"] = str(e)

    return jsonify({
        "secret_configured": bool(secret),
        "callback_registered": callback_registered,
        "litellm_up": litellm_up,
        "whitebox_enabled": callback_registered and litellm_up,
        "blackbox_enabled": callback_registered and litellm_up,
        "probe": probe,
    })


@app.route("/api/llm/watermark/verify", methods=["POST"])
def api_llm_watermark_verify():
    """Verify white-box and black-box watermarks in submitted text."""
    import sys as _sys
    scripts_dir = os.path.expanduser("~/.openclaw/scripts")
    if scripts_dir not in _sys.path:
        _sys.path.insert(0, scripts_dir)
    try:
        from litellm_watermark import wb_decode, bb_detect
    except ImportError as e:
        return jsonify({"error": f"watermark module not found: {e}"}), 500

    body = request.get_json(silent=True) or {}
    text = body.get("text", "")
    if not text:
        return jsonify({"error": "text field required"}), 400

    secret_str = os.environ.get("WATERMARK_SECRET", "openclaw-watermark-default")
    secret = secret_str.encode()

    wb = wb_decode(text, secret)
    bb = bb_detect(text, secret)

    return jsonify({"whitebox": wb, "blackbox": bb})


@app.route("/api/wifi_networks")
def api_wifi_networks():
    """Return connected interface info plus all visible networks from a scan."""
    import re
    result = {"connected": None, "all_networks": []}

    try:
        import CoreWLAN, objc

        # ── Get IP of the Wi-Fi interface ─────────────────────────────────
        ifconfig = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=10)
        iface_blocks = re.split(r'(?=^\w)', ifconfig.stdout, flags=re.MULTILINE)
        ip_by_iface = {}
        for block in iface_blocks:
            m = re.match(r'^(\S+):', block)
            if not m:
                continue
            ip_m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', block)
            if ip_m:
                ip_by_iface[m.group(1)] = ip_m.group(1)

        # ── Find Wi-Fi interface name ─────────────────────────────────────
        ns = subprocess.run(["networksetup", "-listallhardwareports"],
                            capture_output=True, text=True, timeout=10)
        wifi_iface = "en1"  # fallback
        for block in re.split(r'\n\n+', ns.stdout.strip()):
            lines = block.strip().splitlines()
            port = next((l for l in lines if l.startswith("Hardware Port:")), "")
            dev  = next((l for l in lines if l.startswith("Device:")), "")
            if "wi-fi" in port.lower() and dev:
                wifi_iface = dev.split(":", 1)[1].strip()
                break

        # ── CoreWLAN: connected SSID + scan ──────────────────────────────
        client  = CoreWLAN.CWWiFiClient.sharedWiFiClient()
        cw      = client.interfaceWithName_(wifi_iface)

        connected_ssid = None
        if cw:
            connected_ssid = cw.ssid()
            if not connected_ssid:
                config = cw.configuration()
                if config:
                    profiles = config.networkProfiles()
                    arr = list(profiles.array()) if hasattr(profiles, 'array') else objc.container_unwrap(profiles)
                    if arr:
                        connected_ssid = arr[0].ssid()

        # ── SSID fallback: ipconfig getsummary (works when CoreWLAN returns nil) ──
        if not connected_ssid:
            try:
                summary = subprocess.run(
                    ["ipconfig", "getsummary", wifi_iface],
                    capture_output=True, text=True, timeout=5
                )
                for line in summary.stdout.splitlines():
                    if "SSID" in line and ":" in line:
                        val = line.split(":", 1)[1].strip()
                        if val:
                            connected_ssid = val
                            break
            except Exception:
                pass

        # ── Connectivity check for the connected network ──────────────────
        ip = ip_by_iface.get(wifi_iface)
        connectivity = "No Connectivity"
        if ip:
            try:
                ping = subprocess.run(
                    ["ping", "-c", "1", "-W", "2", "8.8.8.8"],
                    capture_output=True, text=True, timeout=5
                )
                if ping.returncode == 0:
                    connectivity = "Active"
                else:
                    # Internet unreachable — check if local gateway responds
                    gw_ping = subprocess.run(
                        ["ping", "-c", "1", "-W", "1", "192.168.1.1"],
                        capture_output=True, text=True, timeout=3
                    )
                    connectivity = "Limited" if gw_ping.returncode == 0 else "No Connectivity"
            except Exception:
                connectivity = "Limited"

        # ── Default gateway lookup ────────────────────────────────────────
        gateway = None
        try:
            gw_result = subprocess.run(
                ["netstat", "-rn"],
                capture_output=True, text=True, timeout=5
            )
            for line in gw_result.stdout.splitlines():
                parts = line.split()
                if parts and parts[0] == "default" and len(parts) >= 4 and parts[3] == wifi_iface:
                    gateway = parts[1]
                    break
        except Exception:
            pass

        result["connected"] = {
            "ssid": connected_ssid,
            "ip": ip,
            "interface": wifi_iface,
            "connectivity": connectivity,
            "gateway": gateway,
        }

        # ── Scan all visible networks ─────────────────────────────────────
        def band(ch):
            if ch is None:
                return "?"
            if ch <= 14:
                return "2.4 GHz"
            if ch <= 177:
                return "5 GHz"
            return "6 GHz"

        if cw:
            scan_results, _ = cw.scanForNetworksWithName_error_(None, None)
            seen = set()
            for n in list(scan_results.allObjects()):
                ssid = n.ssid()
                if not ssid or ssid in seen:
                    continue
                seen.add(ssid)
                ch = n.wlanChannel().channelNumber() if n.wlanChannel() else None
                result["all_networks"].append({
                    "ssid": ssid,
                    "rssi": n.rssiValue(),
                    "channel": ch,
                    "band": band(ch),
                    "connected": ssid == connected_ssid,
                })
            result["all_networks"].sort(key=lambda x: x["rssi"], reverse=True)

    except Exception as e:
        return jsonify({"error": str(e), "connected": None, "all_networks": []}), 500

    return jsonify(result)


# ── LLM Output Fingerprinting ─────────────────────────────────────────────────

_FP_THREATS_FILE = Path(__file__).parent / "llm_fingerprint_threats.json"
_FP_ALERTS_FILE  = Path(__file__).parent / "llm_fingerprint_alerts.json"
_FP_LOCK         = _threading.Lock()
_FP_DEVIATION_LIMIT = 0.15

_THREAT_NAMES = [
    "Model Distillation (High Trigram Overlap)",
    "Unauthorized API Re-serving",
    "Automated Content Farming",
    "Paraphrase Obfuscation (Hash Match)",
    "Adversarial Statistical Probing",
]

# Human-readable "what happened" sentence per threat type, used in the
# Description column: "[model], [agent], [what happened]"
_THREAT_WHAT_HAPPENED = {
    "Model Distillation (High Trigram Overlap)":
        "high trigram overlap detected — an external model may be training on our outputs",
    "Unauthorized API Re-serving":
        "full statistical profile match from an unrecognized origin — possible middle-man reseller",
    "Automated Content Farming":
        "low vocabulary richness (TTR) detected — model is being used for high-volume SEO spam",
    "Paraphrase Obfuscation (Hash Match)":
        "perceptual hash match detected despite word-swapping and structural changes",
    "Adversarial Statistical Probing":
        "unusual punctuation and sentence-length patterns detected — possible signature mapping attempt",
}


def _fp_load(path: Path) -> dict:
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return {}


def _fp_save(path: Path, data: dict):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def _classify_threat(breakdown, score, model_id, existing_alerts):
    """Map a fingerprint deviation event to one of the five named threat types."""
    trigrams = breakdown.get("trigrams", 0.0)
    simhash  = breakdown.get("simhash",  0.0)

    # 1. Near-exact reproduction across all dimensions
    if score >= 0.90:
        return "Unauthorized API Re-serving"

    # 2. High word-level pattern overlap → knowledge distillation
    if trigrams >= 0.75:
        return "Model Distillation (High Trigram Overlap)"

    # 3. Structural similarity survives synonym substitution
    if simhash >= 0.65 and trigrams < 0.45:
        return "Paraphrase Obfuscation (Hash Match)"

    # 4. Burst of alerts for the same model in the last hour → content farm
    from datetime import timedelta, timezone as _tz
    cutoff = (datetime.now(_tz.utc) - timedelta(hours=1)).isoformat()
    recent = sum(1 for a in existing_alerts
                 if a.get("model_id") == model_id and a.get("timestamp", "") >= cutoff)
    if recent >= 5:
        return "Automated Content Farming"

    # 5. High inter-dimension variance → probing the statistical signal
    vals = list(breakdown.values())
    if len(vals) >= 2:
        mean_v = sum(vals) / len(vals)
        pstdev = (sum((v - mean_v) ** 2 for v in vals) / len(vals)) ** 0.5
        if pstdev >= 0.30:
            return "Adversarial Statistical Probing"

    return None


@app.route("/api/llm_fingerprint/ingest", methods=["POST"])
def api_fp_ingest():
    """
    Accept a fingerprint payload from litellm_fingerprint_reporter.py,
    compare against the stored baseline, and — if deviation > 15% — classify
    and record the threat type in llm_fingerprint_threats.json.
    """
    body        = request.get_json(silent=True) or {}
    model_id    = body.get("model_id", "unknown")
    fingerprint = body.get("fingerprint")
    if not fingerprint:
        return jsonify({"error": "missing fingerprint"}), 400

    now   = datetime.utcnow().isoformat() + "Z"
    alert = None

    with _FP_LOCK:
        alerts_data = _fp_load(_FP_ALERTS_FILE)
        if not isinstance(alerts_data.get("alerts"), list):
            alerts_data = {"alerts": []}

        breakdown = body.get("comparison_breakdown") or {}
        weights   = {"punctuation": 0.25, "length": 0.20,
                     "lexical": 0.15, "trigrams": 0.20, "simhash": 0.20}
        weighted_score = sum(weights.get(d, 0.0) * breakdown.get(d, 1.0) for d in weights)
        deviation      = round(1.0 - weighted_score, 4)

        # Near-exact fingerprint match from an external source is itself a
        # threat (re-serving), even though deviation is low. Check this first
        # so it is never shadowed by the deviation gate below.
        if weighted_score >= 0.90:
            threat_name = "Unauthorized API Re-serving"
            alert = {
                "id":           f"fp-alert-{now}",
                "timestamp":    now,
                "model_id":     model_id,
                "severity":     "CRITICAL",
                "deviation":    deviation,
                "score":        round(weighted_score, 4),
                "breakdown":    breakdown,
                "source":       body.get("source", "unknown"),
                "acknowledged": False,
            }
            alerts_data["alerts"]       = ([alert] + alerts_data["alerts"])[:200]
            alerts_data["last_critical"] = now
            _fp_save(_FP_ALERTS_FILE, alerts_data)

            threat_data = _fp_load(_FP_THREATS_FILE)
            counts  = threat_data.get("counts",  {})
            details = threat_data.get("details", {})
            counts[threat_name] = counts.get(threat_name, 0) + 1
            details[threat_name] = {
                "last_model":    model_id,
                "last_agents":   body.get("source", "unknown"),
                "what_happened": _THREAT_WHAT_HAPPENED.get(threat_name, "threat event recorded"),
                "last_at":       now,
            }
            threat_data["counts"]       = counts
            threat_data["details"]      = details
            threat_data["last_updated"] = now
            _fp_save(_FP_THREATS_FILE, threat_data)

        elif deviation > _FP_DEVIATION_LIMIT:
            alert = {
                "id":           f"fp-alert-{now}",
                "timestamp":    now,
                "model_id":     model_id,
                "severity":     "CRITICAL",
                "deviation":    deviation,
                "score":        round(weighted_score, 4),
                "breakdown":    breakdown,
                "source":       body.get("source", "unknown"),
                "acknowledged": False,
            }
            alerts_data["alerts"]       = ([alert] + alerts_data["alerts"])[:200]
            alerts_data["last_critical"] = now
            _fp_save(_FP_ALERTS_FILE, alerts_data)

            threat_name = _classify_threat(
                breakdown, weighted_score, model_id, alerts_data["alerts"]
            )
            if threat_name:
                threat_data = _fp_load(_FP_THREATS_FILE)
                counts  = threat_data.get("counts",  {})
                details = threat_data.get("details", {})
                counts[threat_name] = counts.get(threat_name, 0) + 1
                details[threat_name] = {
                    "last_model":    model_id,
                    "last_agents":   body.get("source", "unknown"),
                    "what_happened": _THREAT_WHAT_HAPPENED.get(threat_name, "threat event recorded"),
                    "last_at":       now,
                }
                threat_data["counts"]       = counts
                threat_data["details"]      = details
                threat_data["last_updated"] = now
                _fp_save(_FP_THREATS_FILE, threat_data)

    return jsonify({"status": "ok", "model_id": model_id,
                    "deviation": deviation, "alert": alert}), (201 if alert else 200)


@app.route("/api/llm_fingerprint/threat_status")
def api_fp_threat_status():
    """Return per-threat-type occurrence counts and last-event detail for the
    Output Fingerprinting panel.

    Each threat entry shape:
        {
            "name":        str,
            "count":       int,
            "last_model":  str | null,
            "last_agents": str | null,
            "what_happened": str | null
        }
    """
    with _FP_LOCK:
        data = _fp_load(_FP_THREATS_FILE)
    counts  = data.get("counts",  {})
    details = data.get("details", {})
    threats = []
    for name in _THREAT_NAMES:
        d = details.get(name, {})
        threats.append({
            "name":          name,
            "count":         counts.get(name, 0),
            "last_model":    d.get("last_model"),
            "last_agents":   d.get("last_agents"),
            "what_happened": d.get("what_happened"),
        })
    return jsonify({
        "threats":      threats,
        "total":        sum(counts.get(n, 0) for n in _THREAT_NAMES),
        "last_updated": data.get("last_updated"),
    })


@app.route("/api/llm_fingerprint/mitigate", methods=["POST"])
def api_fp_mitigate():
    """Decrement the occurrence count for a single threat type by 1.

    Clears the description when the count reaches 0.

    Body: { "name": "<threat name>" }
    Returns: { "status": "ok", "name": "...", "previous_count": N, "new_count": M }
    """
    body = request.get_json(silent=True) or {}
    name = body.get("name", "").strip()
    if not name:
        return jsonify({"error": "missing 'name'"}), 400
    if name not in _THREAT_NAMES:
        return jsonify({"error": f"unknown threat '{name}'"}), 404

    with _FP_LOCK:
        data    = _fp_load(_FP_THREATS_FILE)
        counts  = data.get("counts", {})
        details = data.get("details", {})
        prev    = counts.get(name, 0)
        new     = max(0, prev - 1)
        counts[name] = new
        if new == 0 and name in details:
            del details[name]
        data["counts"]       = counts
        data["details"]      = details
        data["last_updated"] = datetime.utcnow().isoformat() + "Z"
        _fp_save(_FP_THREATS_FILE, data)

    return jsonify({"status": "ok", "name": name, "previous_count": prev, "new_count": new})


if __name__ == "__main__":
    # Initialize empty files if they don't exist
    if not DATA_FILE.exists():
        save_devices([])
    if not HISTORY_FILE.exists():
        save_history([])
    
    print("Starting NetWatch dashboard on http://localhost:8081")
    app.run(host="0.0.0.0", port=8081, debug=False)
