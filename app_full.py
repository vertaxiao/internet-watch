/* NetWatch Flask application - Full stack with Email Protection & Cyber News */

import logging
import threading
import time
import os
import json
import glob
from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder="static", static_url_path="")
CORS(app)

# ── Paths ──────────────────────────────────────────────────────────────────────

MINO_NETWATCH_PATH = os.path.expanduser("~/.openclaw/workspace-mino/NetWatch")

# ── API routes ─────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory("static", "index.html")


@app.route("/api/cyber_news")
def api_cyber_news():
    """Fetch cyber news from Mino's NetWatch workspace."""
    news_path = os.path.join(MINO_NETWATCH_PATH, "cyber_news.json")
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
    dashboard_path = os.path.join(MINO_NETWATCH_PATH, "dashboard.json")
    history_path = os.path.join(MINO_NETWATCH_PATH, "history.json")
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
    pattern = os.path.join(MINO_NETWATCH_PATH, "daily-trend-*.json")
    files = sorted(glob.glob(pattern), reverse=True)
    if files:
        try:
            with open(files[0], "r") as f:
                data = json.load(f)
            return jsonify(data)
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    return jsonify({"error": "No daily trend data found"}), 404


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logger.info("NetWatch running on http://localhost:8080")
    app.run(host="0.0.0.0", port=8080, debug=False)
