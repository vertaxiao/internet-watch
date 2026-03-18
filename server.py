#!/usr/bin/env python3
"""
Flask server for network device monitoring dashboard.
Serves the web interface and provides API endpoints.
"""

from flask import Flask, jsonify, send_from_directory
from pathlib import Path
import json
from datetime import datetime
import subprocess
import re
import socket

app = Flask(__name__)

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
        with open(HISTORY_FILE, "r") as f:
            return json.load(f)
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

@app.route("/api/scan")
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

if __name__ == "__main__":
    # Initialize empty files if they don't exist
    if not DATA_FILE.exists():
        save_devices([])
    if not HISTORY_FILE.exists():
        save_history([])
    
    print("Starting NetWatch dashboard on http://localhost:8081")
    app.run(host="0.0.0.0", port=8081, debug=False)
