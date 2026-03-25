#!/usr/bin/env bash
# NetWatch setup & launch script
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV="$SCRIPT_DIR/.venv"

echo "==> NetWatch Setup"

# Create virtualenv if not present
if [ ! -d "$VENV" ]; then
  echo "--> Creating Python virtual environment..."
  python3 -m venv "$VENV"
fi

echo "--> Installing dependencies..."
"$VENV/bin/pip" install -q --upgrade pip
"$VENV/bin/pip" install -q -r requirements.txt

echo "--> Starting NetWatch on http://localhost:8080"
echo "    Press Ctrl+C to stop."
echo ""

# Optional env vars (can be overridden before calling this script):
#   PORT=8080          — port to listen on
#   SCAN_INTERVAL=60   — seconds between scans
#   USE_NMAP=true      — also run nmap (requires nmap installed)
#   SUBNET=192.168.x.0/24  — subnet for nmap scan

exec "$VENV/bin/python" app.py
