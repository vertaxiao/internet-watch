#!/usr/bin/env python3
"""
Network device scanner using ARP table.
Scans the local network and returns device information.
"""

import subprocess
import re
import json
import socket
from datetime import datetime
from pathlib import Path

DATA_FILE = Path(__file__).parent / "devices.json"
NAMES_FILE = Path(__file__).parent / "device_names.json"

DEVICE_NAMES = {
    "aa:bb:cc:dd:ee:ff": "Bing's iPhone",
    "11:22:33:44:55:66": "Andy's MacBook Pro",
    "77:88:99:aa:bb:cc": "Living Room TV",
}

def parse_arp_output():
    """Parse `arp -a` output to extract device info."""
    result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
    lines = result.stdout.strip().split("\n")
    
    devices = []
    pattern = r'\(([\d.]+)\) at ([a-f0-9:]+)'
    
    for line in lines:
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            ip = match.group(1)
            mac = match.group(2).replace("-", ":").upper()
            # Try to extract hostname if present
            hostname = ""
            if "?" not in line:
                parts = line.split()
                for part in parts:
                    if part.startswith("(") and "?" not in part:
                        hostname = part.replace("(", "").replace(")", "")
                        break
            
            # If no hostname found, try reverse DNS lookup
            if not hostname:
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except (socket.herror, socket.gaierror):
                    # Reverse DNS failed, leave hostname empty
                    pass
            
            devices.append({
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "first_seen": datetime.now().isoformat(),
                "last_seen": datetime.now().isoformat(),
                "status": "online"
            })
    
    return devices

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

def load_existing_devices():
    """Load previously seen devices from JSON file."""
    if DATA_FILE.exists():
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return []

def merge_devices(existing, current):
    """Merge current scan with existing devices, updating timestamps."""
    current_ips = {d["ip"] for d in current}
    
    # Mark existing devices as offline if not in current scan
    for device in existing:
        if device["ip"] not in current_ips:
            device["status"] = "offline"
        else:
            device["last_seen"] = datetime.now().isoformat()
            device["status"] = "online"
    
    # Add new devices from current scan
    current_ips_in_existing = {d["ip"] for d in existing}
    for device in current:
        if device["ip"] not in current_ips_in_existing:
            existing.append(device)
    
    return existing

def save_devices(devices):
    """Save devices to JSON file."""
    with open(DATA_FILE, "w") as f:
        json.dump(devices, f, indent=2)

def scan():
    """Run a network scan and return device list."""
    current = parse_arp_output()
    existing = load_existing_devices()
    merged = merge_devices(existing, current)
    save_devices(merged)
    return merged

if __name__ == "__main__":
    devices = scan()
    print(json.dumps(devices, indent=2))
