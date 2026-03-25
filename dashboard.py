#!/usr/bin/env python3
"""NetWatch Dashboard Server"""

from flask import Flask, send_from_directory, jsonify

app = Flask(__name__)

@app.route('/')
def index():
    """Serve the main dashboard"""
    return send_from_directory('.', 'index.html')

@app.route('/api/health')
def health():
    """Health check"""
    return jsonify({'status': 'ok'})

@app.route('/api/email_scans')
def email_scans():
    """Latest email scan results"""
    import json
    from pathlib import Path
    scans = sorted(Path('.').glob('email_scans/scan_*.json'), reverse=True)
    if scans:
        with open(scans[0]) as f:
            return json.load(f)
    return jsonify({'total_scanned': 0, 'flagged': 0, 'results': []})

if __name__ == '__main__':
    print('🚀 NetWatch Dashboard Server')
    print('=' * 60)
    print('Starting on http://0.0.0.0:8081')
    print()
    print('Access:')
    print('  Local:   http://localhost:8081')
    print('  Network: http://192.168.1.10:8081')
    print('=' * 60)
    app.run(host='0.0.0.0', port=8081, debug=False, threaded=True)
