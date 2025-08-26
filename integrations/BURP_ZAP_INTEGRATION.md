# Burp Suite & OWASP ZAP Integration Guide

This guide explains how to integrate the AI Web Security Tool with popular penetration testing tools like Burp Suite and OWASP ZAP, using mitmproxy as an intermediary proxy for real-time traffic analysis.

## Overview

The integration allows you to:
- **Proxy traffic** from Burp Suite through mitmproxy to the AI security tool
- **Real-time analysis** of HTTP requests for malicious patterns
- **Automated threat detection** during penetration testing
- **Enhanced logging** and reporting of security findings

## Architecture

```
[Target Application] ← → [Burp Suite] → [mitmproxy] → [AI Security Tool (Flask API)]
                                           ↓
                                    [Analysis Results]
```

## Prerequisites

1. **Python 3.8+** installed
2. **Burp Suite** (Community or Professional)
3. **mitmproxy** installed via pip
4. **AI Security Tool** running (this Flask application)

## Installation

### 1. Install Dependencies

```bash
# Install mitmproxy and other requirements
pip install -r requirements.txt
```

### 2. Start the AI Security Tool

```bash
# Terminal 1: Start the Flask API
cd /path/to/appsec-and-ai
python middleware10.py
```

The Flask app will be available at `http://localhost:5000`

### 3. Start mitmproxy with Integration Script

```bash
# Terminal 2: Start mitmproxy with the forwarder script
mitmproxy -p 8080 -s integrations/mitmproxy_forwarder.py --set confdir=/tmp/mitmproxy
```

This starts mitmproxy on port 8080 with the AI integration script.

## Configuration

### Burp Suite Configuration

1. **Open Burp Suite**
2. **Configure Upstream Proxy:**
   - Go to `Proxy > Options > Upstream Proxy Servers`
   - Click `Add`
   - Set:
     - **Destination host**: `*` (asterisk for all hosts)
     - **Proxy host**: `127.0.0.1`
     - **Proxy port**: `8080`
   - Check `Override user options`

3. **Alternative Method - Proxy Listener:**
   - Go to `Proxy > Options > Proxy Listeners`
   - Edit the existing listener or add a new one
   - Set it to redirect to `127.0.0.1:8080`

### OWASP ZAP Configuration

1. **Open OWASP ZAP**
2. **Configure Network Proxy:**
   - Go to `Tools > Options > Network > Connection`
   - Enable `Use proxy chain`
   - Set:
     - **Address/Server name**: `127.0.0.1`
     - **Port**: `8080`

## Usage Examples

### Basic Testing Flow

1. **Start all components** (Flask app, mitmproxy, Burp/ZAP)
2. **Configure proxy settings** as described above
3. **Browse target application** through Burp/ZAP
4. **Monitor mitmproxy console** for real-time analysis results
5. **Check Flask dashboard** at `http://localhost:5000` for detailed logs

### Example Attack Testing

```bash
# Terminal 3: Test with curl through the proxy chain
curl -x http://127.0.0.1:8080 -H "User-Agent: TestAgent" \
     "http://example.com/search?q=<script>alert(1)</script>"
```

### Manual Request Analysis

You can also send requests directly to the API:

```bash
# Direct API call for testing
curl -X POST http://localhost:5000/integrations/forward \
  -H "Content-Type: application/json" \
  -d '{
    "URL": "http://test.com/login?admin=true",
    "request_body": "username=admin&password=admin",
    "Method": "POST",
    "User-Agent": "Burp Suite",
    "host": "test.com",
    "content-type": "application/x-www-form-urlencoded"
  }'
```

## Advanced Configuration

### Custom mitmproxy Settings

You can customize the mitmproxy behavior:

```bash
# Run with specific settings
mitmproxy -p 8080 -s integrations/mitmproxy_forwarder.py \
  --set confdir=/tmp/mitmproxy \
  --set web_host=127.0.0.1 \
  --set web_port=8081 \
  --mode transparent
```

### Environment Variables

Set these in your shell or script:

```bash
# Configure API endpoint (if Flask runs elsewhere)
export AI_API_ENDPOINT="http://localhost:5000/integrations/forward"

# Configure mitmproxy port
export MITMPROXY_PORT=8080
```

### SSL Certificate Setup

For HTTPS traffic analysis:

1. **Start mitmproxy** once to generate certificates
2. **Install mitmproxy CA certificate:**
   - Find cert at: `~/.mitmproxy/mitmproxy-ca-cert.pem`
   - Import into Burp Suite: `Proxy > Options > TLS > CA Certificate`
   - Import into browser/OS certificate store

## Monitoring and Logging

### Real-time Monitoring

- **mitmproxy console**: Shows live traffic and analysis results
- **Flask dashboard**: `http://localhost:5000` - View predictions and logs
- **Flask logs endpoint**: `http://localhost:5000/logs` - JSON format logs

### Log Files

- **blocked_requests.log**: Contains blocked malicious requests
- **prediction_logs.json**: Detailed prediction history
- **mitmproxy logs**: Available in mitmproxy console

## Troubleshooting

### Common Issues

1. **Connection refused to Flask API**
   ```bash
   # Check if Flask is running
   curl http://localhost:5000/health
   ```

2. **mitmproxy certificate errors**
   ```bash
   # Clear mitmproxy config and regenerate certificates
   rm -rf ~/.mitmproxy
   mitmproxy -s integrations/mitmproxy_forwarder.py
   ```

3. **Burp Suite not forwarding traffic**
   - Check upstream proxy configuration
   - Ensure proxy port matches mitmproxy port
   - Verify target scope in Burp

4. **High latency/timeouts**
   ```bash
   # Increase timeout in mitmproxy_forwarder.py
   TIMEOUT = 10  # seconds
   ```

### Debug Mode

Enable debug logging in mitmproxy:

```bash
mitmproxy -p 8080 -s integrations/mitmproxy_forwarder.py -v
```

## Integration Examples

### Automated Scan with ZAP

```python
# zap_integration.py - Example ZAP integration
from zapv2 import ZAPv2

# Configure ZAP to use our proxy chain
zap = ZAPv2(proxies={'http': 'http://127.0.0.1:8080',
                     'https': 'http://127.0.0.1:8080'})

# Run spider through the proxy chain
target = 'http://example.com'
zap.spider.scan(target)

# All traffic will be analyzed by the AI tool
```

### Burp Extension Integration

For advanced Burp integration, you can create a Burp extension that:
1. Intercepts requests in Burp
2. Sends them to the `/integrations/forward` endpoint
3. Colors/flags suspicious requests in Burp

## Performance Considerations

- **Latency**: Each request adds ~100-500ms for AI analysis
- **Throughput**: Handles ~10-50 requests/second depending on hardware
- **Memory**: Monitor Flask app memory usage during long sessions
- **Scaling**: For high-traffic testing, consider running multiple Flask instances

## Security Notes

⚠️ **Important Security Considerations:**

1. **Never use in production** - This setup is for testing only
2. **Sensitive data** - Be careful with authentication tokens and PII
3. **Log storage** - Prediction logs may contain sensitive request data
4. **Network exposure** - Keep the Flask API on localhost or secure networks

## API Reference

### POST /integrations/forward

Forward a request for analysis.

**Request Body:**
```json
{
  "URL": "string",
  "request_body": "string", 
  "Method": "string",
  "User-Agent": "string",
  "host": "string",
  "content-type": "string"
}
```

**Response:**
```json
{
  "prediction": "malicious|benign",
  "attack_type": "string",
  "features": {...}
}
```

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review Flask app logs for errors
3. Check mitmproxy console for connection issues
4. Open an issue in the repository

---

**Ready to enhance your penetration testing with AI-powered security analysis!**