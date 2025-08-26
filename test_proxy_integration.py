#!/usr/bin/env python3
"""
Test script to validate the mitmproxy integration by sending HTTP requests through the proxy.
"""

import requests
import time

def test_proxy_integration():
    """Test HTTP requests through mitmproxy proxy."""
    
    # Proxy configuration
    proxy_config = {
        'http': 'http://127.0.0.1:8080',
        'https': 'http://127.0.0.1:8080'
    }
    
    # Test requests
    test_requests = [
        {
            "url": "http://localhost:5000/health",
            "name": "Health Check via Proxy"
        },
        {
            "url": "http://localhost:5000/",
            "name": "Dashboard via Proxy"
        }
    ]
    
    print("🚀 Testing mitmproxy integration...")
    print("=" * 50)
    
    for req in test_requests:
        try:
            print(f"📡 {req['name']}: {req['url']}")
            
            response = requests.get(
                req['url'],
                proxies=proxy_config,
                timeout=10,
                verify=False  # For testing with mitmproxy certificates
            )
            
            print(f"   Status: {response.status_code}")
            print(f"   Headers: {dict(response.headers)}")
            
            # Check for AI security headers
            if 'X-AI-Security-Status' in response.headers:
                print(f"   🛡️ AI Security Status: {response.headers['X-AI-Security-Status']}")
            
            if 'X-AI-Security-Alert' in response.headers:
                print(f"   🚨 AI Security Alert: {response.headers['X-AI-Security-Alert']}")
                print(f"   🚨 Attack Type: {response.headers.get('X-Attack-Type', 'unknown')}")
            
            print("   ✅ Success")
            
        except Exception as e:
            print(f"   ❌ Error: {e}")
        
        print()
        time.sleep(1)

if __name__ == "__main__":
    test_proxy_integration()