# NetWatch - Network Device Monitoring Dashboard

A lightweight web dashboard that monitors devices connected to your local network.

## Features

- **Device Count Display** - Shows total, online, and offline device counts
- **Device List Table** - IP, MAC, Hostname, First Seen, Last Seen, Status
- **Real-time Updates** - Auto-refreshes every 60 seconds
- **Historical Chart** - Tracks device count over time using Chart.js

## Tech Stack

- **Frontend:** Plain HTML/JS with Chart.js (no build step required)
- **Backend:** Python Flask
- **Data Storage:** JSON files (devices.json, history.json)
- **Network Scanning:** ARP table reader (`arp -a`)

## Requirements

- Python 3.7+
- Flask

## Installation

1. **Install Flask:**
   ```bash
   pip3 install flask
   ```

2. **Navigate to the project directory:**
   ```bash
   cd /Users/verta/.openclaw/workspace/projects/netwatch
   ```

## Usage

### Start the Server

```bash
python3 server.py
```

The dashboard will be available at: **http://localhost:8080**

### Manual Scan

You can also run a standalone scan:

```bash
python3 scanner.py
```

## How It Works

1. **Network Scanning:** Uses `arp -a` to read the ARP table, which shows all devices that have recently communicated on the local network.

2. **Device Tracking:** 
   - New devices are added when first seen
   - Existing devices are marked "online" if seen in current scan
   - Devices not in current scan are marked "offline"

3. **Data Persistence:** 
   - `devices.json` - Stores all discovered devices with timestamps
   - `history.json` - Stores historical counts for the chart

4. **Auto-refresh:** The web dashboard polls `/api/scan` every 60 seconds to update device status and record history.

## API Endpoints

- `GET /` - Serves the dashboard HTML
- `GET /api/devices` - Returns current device list
- `GET /api/history` - Returns historical data for chart
- `GET /api/scan` - Triggers a new network scan and returns updated devices

## Files

```
netwatch/
├── server.py      # Flask web server
├── scanner.py     # Standalone network scanner
├── index.html     # Dashboard frontend
├── devices.json   # Device database (auto-created)
├── history.json   # Historical data (auto-created)
└── README.md      # This file
```

## Notes

- **ARP-based scanning** is passive and fast, but only shows devices that have recently communicated
- For more active scanning, consider using Nmap: `nmap -sn 192.168.1.0/24`
- The dashboard runs on port 8080 by default (configurable in `server.py`)
- History data is limited to the last 24 hours (1440 entries at 1-minute intervals)

## License

MIT
