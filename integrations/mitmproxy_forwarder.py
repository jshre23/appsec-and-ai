#!/usr/bin/env python3
"""
Mitmproxy script to forward intercepted HTTP requests to the AI Security Tool for analysis.

This script captures HTTP requests from tools like Burp Suite and forwards them 
to the Flask API endpoint (/integrations/forward) for real-time security analysis.

Usage:
    mitmproxy -s integrations/mitmproxy_forwarder.py --set confdir=/tmp/mitmproxy
    
    Or with specific port:
    mitmproxy -p 8080 -s integrations/mitmproxy_forwarder.py --set confdir=/tmp/mitmproxy

Configuration:
    - Flask API runs on http://localhost:5000 by default
    - Modify API_ENDPOINT if your Flask app runs on a different host/port
"""

import requests
import logging
from urllib.parse import urlencode
from mitmproxy import http, ctx
from mitmproxy.script import concurrent

# Configuration
API_ENDPOINT = "http://localhost:5000/integrations/forward"
TIMEOUT = 5  # seconds

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def extract_request_features(flow: http.HTTPFlow) -> dict:
    """
    Extract features from an HTTP request flow for analysis by the AI model.
    
    Args:
        flow: The HTTP flow from mitmproxy
        
    Returns:
        dict: Features extracted from the request
    """
    request = flow.request
    
    # Extract basic request information
    url = request.pretty_url
    method = request.method
    headers = dict(request.headers)
    
    # Extract request body
    request_body = ""
    if request.content:
        try:
            request_body = request.content.decode('utf-8', errors='ignore')
        except Exception:
            request_body = str(request.content)
    
    # Calculate some basic metrics
    user_agent = headers.get('User-Agent', 'Unknown')
    content_type = headers.get('Content-Type', '')
    host = headers.get('Host', request.host)
    
    # Build feature dictionary compatible with the API
    features = {
        'URL': url,
        'request_body': request_body,
        'Method': method,
        'User-Agent': user_agent,
        'content-type': content_type,
        'host': host,
        'url_length': len(url),
        'body_length': len(request_body),
        'user_agent_length': len(user_agent),
        'content_type_length': len(content_type),
        # Add query parameter count
        'num_params': len(request.query) if hasattr(request, 'query') and request.query else 0,
        # Add some default values for features expected by the API
        'session_duration': 0,
        'svm_anomaly_flag': 0,
        'body_special_char_count': sum(1 for c in request_body if not c.isalnum()),
        'svm_anomaly_score': 0.0,
        'url_domain': request.host,
        'param_entropy': 0.0,
        'num_param_names': len(request.query) if hasattr(request, 'query') and request.query else 0,
        'user_agent_changes': 0,
        'body_has_suspicious': 0,
        'session_duration_z': 0.0,
        'has_suspicious_keywords': 0,
        'has_login': 1 if 'login' in url.lower() or 'login' in request_body.lower() else 0,
        'unique_endpoints': 1,
        'behavioral_anomaly_flag': 0,
        'requests_per_session': 1,
        'mean_time_between_reqs': 0,
        'session_duration_outlier': 0,
        'behavior_anomaly_score': 0.0
    }
    
    return features

@concurrent  # This allows the function to run in a separate thread
def request(flow: http.HTTPFlow) -> None:
    """
    Handle incoming HTTP requests by forwarding them to the AI security tool.
    
    Args:
        flow: The HTTP flow from mitmproxy
    """
    try:
        # Extract features from the request
        features = extract_request_features(flow)
        
        logger.info(f"Analyzing request: {flow.request.method} {flow.request.pretty_url}")
        
        # Forward to the AI API for analysis
        response = requests.post(
            API_ENDPOINT,
            json=features,
            timeout=TIMEOUT,
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 200:
            analysis_result = response.json()
            prediction = analysis_result.get('prediction', 'unknown')
            attack_type = analysis_result.get('attack_type', 'none')
            
            # Log the analysis result
            if prediction == 'malicious':
                logger.warning(f"🚨 MALICIOUS REQUEST DETECTED: {flow.request.pretty_url}")
                logger.warning(f"   Attack Type: {attack_type}")
                
                # Add a custom header to the response to indicate malicious content
                if flow.response:
                    flow.response.headers["X-AI-Security-Alert"] = "MALICIOUS"
                    flow.response.headers["X-Attack-Type"] = attack_type
            else:
                logger.info(f"✅ Request classified as: {prediction}")
                
                # Add a custom header to indicate clean content
                if flow.response:
                    flow.response.headers["X-AI-Security-Status"] = "CLEAN"
                    
        else:
            logger.error(f"API request failed with status {response.status_code}: {response.text}")
            
    except requests.exceptions.Timeout:
        logger.error(f"Timeout while analyzing request: {flow.request.pretty_url}")
    except requests.exceptions.ConnectionError:
        logger.error(f"Cannot connect to AI API at {API_ENDPOINT}. Make sure the Flask app is running.")
    except Exception as e:
        logger.error(f"Error analyzing request {flow.request.pretty_url}: {str(e)}")

def response(flow: http.HTTPFlow) -> None:
    """
    Handle responses (optional - for additional processing if needed).
    
    Args:
        flow: The HTTP flow from mitmproxy
    """
    # This function is called when a response is received
    # We can add additional processing here if needed
    pass

def load(loader):
    """
    Called when the script is loaded. Can be used for initialization.
    """
    logger.info("AI Security mitmproxy forwarder loaded")
    logger.info(f"Will forward requests to: {API_ENDPOINT}")
    ctx.log.info("AI Security Tool integration active")

def done():
    """
    Called when mitmproxy is shutting down.
    """
    logger.info("AI Security mitmproxy forwarder shutting down")
    ctx.log.info("AI Security Tool integration disabled")