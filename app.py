"""NetWatch Flask application."""

import logging
import threading
import time
import os
from pathlib import Path

from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS

import db
import scanner

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

SCAN_INTERVAL = int(os.environ.get("SCAN_INTERVAL", "60"))  # seconds

STATIC_DIR = Path(__file__).parent / "static"
app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path="")
CORS(app)

# ── Background scanner ──────────────────────────────────────────────────────

_scan_lock = threading.Lock()
_last_scan_error: str | None = None


def run_scan():
    global _last_scan_error
    logger.info("Starting network scan")
    try:
        devices = scanner.scan()
        db.upsert_devices(devices)
        _last_scan_error = None
        logger.info("Scan saved: %d devices", len(devices))
    except Exception as e:
        _last_scan_error = str(e)
        logger.error("Scan failed: %s", e)


def scanner_loop():
    # Initial scan immediately on startup
    with _scan_lock:
        run_scan()
    while True:
        time.sleep(SCAN_INTERVAL)
        with _scan_lock:
            run_scan()


# ── API routes ───────────────────────────────────────────────────────────────

@app.route("/api/stats")
def api_stats():
    stats = db.get_stats()
    stats["scan_interval"] = SCAN_INTERVAL
    stats["scan_error"] = _last_scan_error
    return jsonify(stats)


@app.route("/api/devices")
def api_devices():
    devices = db.get_devices()
    return jsonify(devices)


@app.route("/api/history")
def api_history():
    snapshots = db.get_snapshots(hours=24)
    return jsonify(snapshots)


@app.route("/api/scan", methods=["POST"])
def api_trigger_scan():
    """Manually trigger an immediate scan."""
    if _scan_lock.locked():
        return jsonify({"status": "scan already in progress"}), 409
    t = threading.Thread(target=lambda: _scan_lock.acquire() or run_scan() or _scan_lock.release(), daemon=True)
    t.start()
    return jsonify({"status": "scan triggered"})


# ── Email Protection & Cyber News API routes ─────────────────────────────────

MINO_NETWATCH_PATH = Path.home() / ".openclaw" / "workspace-mino" / "NetWatch"


@app.route("/api/cyber_news")
def api_cyber_news():
    """Fetch cyber news from Mino's NetWatch workspace."""
    import json
    news_path = MINO_NETWATCH_PATH / "cyber_news.json"
    try:
        with open(news_path, "r") as f:
            data = json.load(f)
        return jsonify(data)
    except FileNotFoundError:
        return jsonify({"newsItems": [], "status": "No cyber news data available"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/email_scans")
def api_email_scans():
    """Fetch email scan data from Mino's NetWatch workspace."""
    import json
    dashboard_path = MINO_NETWATCH_PATH / "dashboard.json"
    history_path = MINO_NETWATCH_PATH / "history.json"
    try:
        with open(dashboard_path, "r") as f:
            dashboard = json.load(f)
        with open(history_path, "r") as f:
            history = json.load(f)
        return jsonify({"dashboard": dashboard, "history": history})
    except FileNotFoundError:
        return jsonify({"error": "Email scan data not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/daily_trends")
def api_daily_trends():
    """Fetch daily trend data from Mino's NetWatch workspace."""
    import json
    import glob
    pattern = str(MINO_NETWATCH_PATH / "daily-trend-*.json")
    files = sorted(glob.glob(pattern), reverse=True)
    if files:
        try:
            with open(files[0], "r") as f:
                data = json.load(f)
            return jsonify(data)
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    return jsonify({"error": "No daily trend data found"}), 404


@app.route("/api/new_devices")
def api_new_devices():
    """Return new devices discovered in the last 7 days, grouped by day."""
    return jsonify(db.get_new_devices(days=7))


@app.route("/api/device_counts")
def api_device_counts():
    """Return total device count per day for the last 7 days."""
    return jsonify(db.get_device_counts_by_day(days=7))


# ── Frontend ─────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


@app.route("/static/<path:filename>")
def static_files(filename):
    return send_from_directory(STATIC_DIR, filename)


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    db.init_db()
    db.cleanup_fake_devices()  # Remove old fake entries
    logger.info("Cleaned up fake devices from database")

    t = threading.Thread(target=scanner_loop, daemon=True)
    t.start()

    port = int(os.environ.get("PORT", "8081"))
    logger.info("NetWatch running on http://localhost:%d", port)
    app.run(host="0.0.0.0", port=port, debug=False)
