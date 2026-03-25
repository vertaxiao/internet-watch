#!/usr/bin/env python3
"""Minimal NetWatch server - guaranteed to work"""

from flask import Flask, send_from_directory, jsonify

app = Flask(__name__)

@app.route('/')
def index():
    """Serve main dashboard"""
    return send_from_directory('.', 'index.html')

@app.route('/api/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'ok', 'message': 'NetWatch server running'})

if __name__ == '__main__':
    print('🚀 Starting NetWatch server on http://0.0.0.0:8081')
    print('   Local:   http://localhost:8081')
    print('   Network: http://192.168.1.10:8081')
    app.run(host='0.0.0.0', port=8081, debug=False, threaded=True)
