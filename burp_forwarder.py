# Burp Suite HTTP request forwarder to Flask ML API
# Save this as burp_forwarder.py and run it externally (not as a Burp extension)
# Requires: requests

import requests
import json

# Example: Replace with your Burp-captured request details
request_data = {
    "URL": "http://example.com/test",
    "request_body": "param1=value1&param2=value2"
}

# Flask API endpoint (adjust if running on a different host/port)
API_URL = "http://localhost:5000/integrations/forward"

# Send the request to the Flask ML API
try:
    response = requests.post(API_URL, json=request_data)
    print("Response from ML API:", response.json())
except Exception as e:
    print("Error forwarding request:", e)

# ---
# To automate: parse Burp logs or use Logger++ to export requests, then loop over them and send as above.
# For real-time integration, a Burp extension is needed, but this script is ideal for quick/manual testing.
