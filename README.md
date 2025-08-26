# AI Web Security Tool (Standalone & Integration Ready)

## Overview
This tool is a modern, standalone web security API for detecting and simulating the blocking of malicious web/API requests. It can be used directly, or integrated with security tools like Burp Suite or OWASP ZAP for real-time analysis.

## Features
- **Simulated Blocking:** Malicious requests are detected and a blocking response (HTTP 403) is simulated (not enforced).
- **Logging:** Blocked requests are logged to `blocked_requests.log`.
- **Modern UI:** Clean, responsive dashboard for monitoring and manual testing.
- **Integration Ready:** Real-time API endpoint for forwarding requests from Burp Suite/ZAP or other tools.
- **No DVWA:** All DVWA references removed for a clean, production-ready experience.

## Quick Start
1. **Install Requirements**
   ```
   pip install -r requirements.txt
   ```
2. **Run the Server**
   ```
   flask run
   ```
   Or use Docker:
   ```
   docker build -t ai-websec .
   docker run -p 5000:5000 ai-websec
   ```
3. **Access the Dashboard**
   - Open [http://localhost:5000](http://localhost:5000) in your browser.

## API Usage
- **/predict**: POST JSON with request details. Returns prediction and simulated block status.
- **/logs**: View recent request logs.
- **/last_predictions**: Get recent predictions for the dashboard.

## Integration with Burp Suite/ZAP
- 🚀 **Quick Start**: Run `./start_integration.sh` to start all services automatically
- 📖 **Full Guide**: See `integrations/BURP_ZAP_INTEGRATION.md` for detailed setup instructions
- 🔗 **Architecture**: Burp Suite → mitmproxy → AI Security Tool
- 📡 **API Endpoint**: Use `/integrations/forward` to POST requests for real-time analysis
- 🧪 **Examples**: Run `python integration_examples.py` for usage demonstrations


## Extended Quick Start

### 1. Train the Model (if needed)
```bash
python training_new.py
```

### 2. Start the Backend
```bash
python middleware10.py
```

### 3. (Optional) Generate Synthetic Data
```bash
python request_generator.py
python generate_noisy_realworld_dataset.py
```

## API Usage Examples

### Predict
```bash
curl -X POST http://localhost:5000/predict -H "Content-Type: application/json" -d '{"URL": "http://test.com/?q=1", "Method": "GET", "User-Agent": "Mozilla", "host": "test.com", "content-type": "application/json", "request_body": ""}'
```

### Simulate Attacks
```bash
curl http://localhost:5000/simulate_attack
```

### Generate Report
```bash
curl http://localhost:5000/generate_report
```

### Send Alert (Email/Slack)
See `utils/alert_utils.py` for required fields.

### Upload Labeled Data
```bash
curl -F "file=@yourdata.csv" http://localhost:5000/upload_labeled_data
```

### Retrain Model
```bash
curl -X POST http://localhost:5000/retrain_model -H "Content-Type: application/json" -d '{"data_path": "uploads/yourdata.csv"}'
```

### Submit Feedback
```bash
curl -X POST http://localhost:5000/feedback -H "Content-Type: application/json" -d '{"request_id": "abc123", "prediction": "malicious", "correct": true}'
```

### Visualize Sessions
```bash
curl http://localhost:5000/session_timeline
```

## Penetration Testing
- See `PEN_TESTING_GUIDE.md` for guidance on using this tool with pen testing tools and for security validation.

## Customization
- The UI and backend are modular. You can add new endpoints, features, or integrations as needed.
- Blocking is simulated by default. For real blocking, connect the logic to your gateway, WAF, or proxy.

## Support
- For issues or feature requests, open an issue in your repository or contact the maintainer.

---
**Ready to use as a standalone security tool or as part of your pen testing workflow!**
