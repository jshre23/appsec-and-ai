# mitmproxy addon for real-time AI prediction
# Save as ai_predictor.py and run with: mitmproxy -s ai_predictor.py --listen-port 8888
# Requires: mitmproxy, requests

import mitmproxy.http
import requests
import json

ML_API_URL = "http://localhost:5000/predict"  # Use main prediction endpoint for instant compatibility

class AIPredictor:
    def request(self, flow: mitmproxy.http.HTTPFlow):
        # Prepare data for ML API
        data = {
            'URL': flow.request.pretty_url,
            'request_body': flow.request.get_text() or '',
            'User-Agent': flow.request.headers.get('User-Agent', 'Unknown'),
            'Method': flow.request.method,
            'host': flow.request.host,
            'content-type': flow.request.headers.get('Content-Type', ''),
            'url_length': len(flow.request.pretty_url),
            'user_agent_length': len(flow.request.headers.get('User-Agent', 'Unknown')),
            'body_length': len(flow.request.get_text() or ''),
            # All other required fields with safe defaults
            'num_params': 0,
            'session_duration': 0,
            'svm_anomaly_flag': 0,
            'body_special_char_count': 0,
            'svm_anomaly_score': 0.0,
            'url_domain': '',
            'param_entropy': 0.0,
            'num_param_names': 0,
            'user_agent_changes': 0,
            'body_has_suspicious': 0,
            'session_duration_z': 0.0,
            'has_suspicious_keywords': 0,
            'has_login': 0,
            'unique_endpoints': 0,
            'behavioral_anomaly_flag': 0,
            'requests_per_session': 0,
            'content_type_length': len(flow.request.headers.get('Content-Type', '')),
            'mean_time_between_reqs': 0,
            'session_duration_outlier': 0,
            'behavior_anomaly_score': 0.0,
        }
        try:
            resp = requests.post(ML_API_URL, json=data, timeout=2)
            if resp.status_code == 200:
                try:
                    result = resp.json()
                except Exception as je:
                    print(f"[AI Proxy Error] Invalid JSON response: {resp.text}")
                    return
                print(f"[AI Prediction] {flow.request.method} {flow.request.pretty_url} => {result.get('prediction')}")
                # Simulate blocking (optional):
                if result.get('prediction', '').lower() == 'malicious':
                    flow.response = mitmproxy.http.HTTPResponse.make(
                        200,
                        b"Simulated blocking: This request would be blocked by the AI Security Proxy (capable of blocking).",
                        {"Content-Type": "text/plain"}
                    )
            else:
                print(f"[AI Proxy Error] Backend returned status {resp.status_code}: {resp.text}")
        except Exception as e:
            print(f"[AI Proxy Error] {e}")

addons = [AIPredictor()]
