#!/bin/bash
# NetWatch Server Startup Script

cd /Users/verta/.openclaw/workspace/projects/netwatch

echo "🚀 Starting NetWatch Server..."
echo ""

# Check if port 8081 is already in use
if lsof -ti:8081 > /dev/null 2>&1; then
    echo "⚠️  Port 8081 is already in use"
    echo "   Killing existing process..."
    lsof -ti:8081 | xargs kill -9 2>/dev/null
    sleep 1
fi

# Start server
python3 server.py &
SERVER_PID=$!

echo "Server PID: $SERVER_PID"
echo "Waiting for server to start..."
sleep 3

# Test if server is running
if curl -s http://localhost:8081 > /dev/null 2>&1; then
    echo ""
    echo "✅ SUCCESS! Server is running"
    echo ""
    echo "🌐 Access NetWatch:"
    echo "   Local:   http://localhost:8081"
    echo "   Network: http://192.168.1.10:8081"
    echo ""
    echo "Server running in background (PID: $SERVER_PID)"
else
    echo ""
    echo "❌ Server failed to start"
    echo "Check server.py for errors"
    exit 1
fi
