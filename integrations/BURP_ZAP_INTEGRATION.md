# Burp Suite/ZAP Integration Guide

This tool can be used as a standalone security API or integrated with Burp Suite/ZAP for real-time request analysis.

## 1. Standalone Usage
- Send HTTP requests to `/predict` endpoint with the required JSON fields.
- The tool will simulate blocking and return detailed analysis.

## 2. Burp Suite Integration
- Use Burp's "Extension" or "Out-of-Band Collaborator" to forward requests to this API.
- Example: Use Burp's "Logger++" or "Custom Extension" to POST intercepted requests to `/predict`.
- You can write a Burp extension in Python/Jython or use Burp's built-in features to automate this.

## 3. OWASP ZAP Integration
- Use ZAP's "Active Scan Rules" or "Script Console" to forward requests to `/predict`.
- Example: Write a ZAP script to POST each request to the API and log/block based on the response.

## 4. Real-Time Request Forwarding (Sample Python Script)

You can use the following script to forward HTTP requests from Burp/ZAP to this tool:

```python
import requests

def forward_to_predict(request_data):
    url = 'http://localhost:5000/predict'
    response = requests.post(url, json=request_data)
    print(response.status_code, response.json())

# Example usage:
# request_data = { ... }  # Extracted from Burp/ZAP
# forward_to_predict(request_data)
```

## 5. No Real Blocking
- The tool only simulates blocking (returns HTTP 403 for malicious) but does not actually block traffic.
- You can use the response to trigger real blocking in your proxy or gateway if needed.

---
For more advanced integration, see Burp/ZAP scripting documentation.
