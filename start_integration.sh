#!/bin/bash

# Quick Start Script for Burp Suite + mitmproxy + AI Security Tool Integration
# This script sets up the complete proxy chain for penetration testing

set -e  # Exit on any error

echo "🚀 Starting AI Security Tool with Burp Suite Integration"
echo "=========================================================="

# Check if required dependencies are installed
echo "📋 Checking dependencies..."

if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed"
    exit 1
fi

if ! command -v mitmproxy &> /dev/null; then
    echo "❌ mitmproxy is not installed"
    echo "💡 Install with: pip install mitmproxy"
    exit 1
fi

echo "✅ Dependencies check passed"

# Install Python requirements if needed
if [ ! -f "requirements.txt" ]; then
    echo "❌ requirements.txt not found. Make sure you're in the project directory."
    exit 1
fi

echo "📦 Installing Python requirements..."
pip install -r requirements.txt

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p /tmp/mitmproxy

# Function to cleanup processes on exit
cleanup() {
    echo ""
    echo "🧹 Cleaning up processes..."
    if [ ! -z "$FLASK_PID" ]; then
        kill $FLASK_PID 2>/dev/null || true
        echo "   Stopped Flask app"
    fi
    if [ ! -z "$MITMPROXY_PID" ]; then
        kill $MITMPROXY_PID 2>/dev/null || true  
        echo "   Stopped mitmproxy"
    fi
    echo "✅ Cleanup complete"
}

trap cleanup EXIT INT TERM

echo ""
echo "🌟 Starting services..."
echo "----------------------"

# Start Flask app in background
echo "1️⃣  Starting AI Security Tool (Flask)..."
python3 middleware10.py &
FLASK_PID=$!

# Wait a bit for Flask to start
echo "   Waiting for Flask to initialize..."
sleep 8

# Check if Flask is running
if ! curl -s http://localhost:5000/health > /dev/null; then
    echo "❌ Flask app failed to start"
    exit 1
fi

echo "✅ AI Security Tool is running at http://localhost:5000"

# Start mitmproxy in background  
echo "2️⃣  Starting mitmproxy with AI integration..."
mitmproxy -p 8080 -s integrations/mitmproxy_forwarder.py --set confdir=/tmp/mitmproxy --mode regular &
MITMPROXY_PID=$!

# Wait a bit for mitmproxy to start
sleep 3

echo "✅ mitmproxy is running on port 8080"
echo ""

# Display configuration instructions
echo "🔧 SETUP INSTRUCTIONS"
echo "===================="
echo ""
echo "📍 Service Status:"
echo "   • AI Security Tool: http://localhost:5000"
echo "   • mitmproxy: http://localhost:8080 (proxy port)"
echo "   • mitmproxy web UI: http://localhost:8081"
echo ""
echo "🎯 Burp Suite Configuration:"
echo "   1. Open Burp Suite"
echo "   2. Go to Proxy → Options → Upstream Proxy Servers"
echo "   3. Click 'Add' and configure:"
echo "      - Destination host: *"
echo "      - Proxy host: 127.0.0.1"  
echo "      - Proxy port: 8080"
echo "   4. Check 'Override user options'"
echo ""
echo "🎯 OWASP ZAP Configuration:"
echo "   1. Open OWASP ZAP"
echo "   2. Go to Tools → Options → Network → Connection"
echo "   3. Enable 'Use proxy chain'"
echo "   4. Set Address: 127.0.0.1, Port: 8080"
echo ""
echo "📊 Testing:"
echo "   • Browse target apps through Burp/ZAP"
echo "   • View real-time analysis at http://localhost:5000"
echo "   • Monitor mitmproxy console for traffic"
echo ""
echo "🛑 To stop: Press Ctrl+C"
echo ""

# Test the integration
echo "🧪 Running quick integration test..."
echo "-----------------------------------"

# Test the API endpoint
if curl -s -X POST http://localhost:5000/integrations/forward \
   -H "Content-Type: application/json" \
   -d '{"URL": "http://test.com", "request_body": "test", "Method": "GET", "User-Agent": "test", "host": "test.com", "content-type": "text/html"}' > /dev/null; then
    echo "✅ Integration API test passed"
else
    echo "❌ Integration API test failed"
fi

echo ""
echo "🎉 Setup complete! The integration is ready to use."
echo "📚 For detailed instructions, see: integrations/BURP_ZAP_INTEGRATION.md"
echo ""

# Keep the script running
echo "💡 Services are running. Press Ctrl+C to stop all services."
echo "   Flask logs will appear below:"
echo ""

# Wait for Flask process to complete (or Ctrl+C)
wait $FLASK_PID