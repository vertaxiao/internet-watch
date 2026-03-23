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

@app.route("/api/email_scans")
def get_email_scans():
    """Return latest email scan results."""
    return jsonify(get_latest_email_scan())

@app.route("/api/email_scan")
def trigger_email_scan():
    """Trigger a new email scan and return results."""
    return jsonify(run_email_scan())

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

if __name__ == "__main__":
    # Initialize empty files if they don't exist
    if not DATA_FILE.exists():
        save_devices([])
    if not HISTORY_FILE.exists():
        save_history([])
    
    print("Starting NetWatch dashboard on http://localhost:8081")
    app.run(host="0.0.0.0", port=8081, debug=False)
