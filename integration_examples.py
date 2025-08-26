#!/usr/bin/env python3
"""
Example: Using the AI Security Tool integration programmatically

This script demonstrates different ways to integrate with the AI Security Tool:
1. Direct API calls
2. Through mitmproxy 
3. Simulating Burp Suite integration
"""

import requests
import json
import time
from typing import Dict, Any

class AISecurityIntegration:
    """Python client for AI Security Tool integration."""
    
    def __init__(self, api_base: str = "http://localhost:5000"):
        self.api_base = api_base.rstrip('/')
        self.integration_endpoint = f"{self.api_base}/integrations/forward"
    
    def analyze_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send a request to the AI Security Tool for analysis.
        
        Args:
            request_data: Dictionary containing request details
            
        Returns:
            Analysis results from the AI tool
        """
        try:
            response = requests.post(
                self.integration_endpoint,
                json=request_data,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"API returned status {response.status_code}", "details": response.text}
                
        except Exception as e:
            return {"error": str(e)}
    
    def analyze_burp_request(self, url: str, method: str = "GET", 
                           headers: Dict[str, str] = None, 
                           body: str = "") -> Dict[str, Any]:
        """
        Analyze a request in the format that Burp Suite would send.
        
        Args:
            url: Target URL
            method: HTTP method
            headers: HTTP headers dict
            body: Request body
            
        Returns:
            Analysis results
        """
        headers = headers or {}
        
        request_data = {
            "URL": url,
            "request_body": body,
            "Method": method,
            "User-Agent": headers.get("User-Agent", "BurpSuite-Integration"),
            "host": headers.get("Host", "example.com"),
            "content-type": headers.get("Content-Type", "application/x-www-form-urlencoded")
        }
        
        return self.analyze_request(request_data)

def demo_direct_integration():
    """Demonstrate direct API integration."""
    print("🔗 Direct API Integration Demo")
    print("=" * 40)
    
    ai = AISecurityIntegration()
    
    # Test cases
    test_cases = [
        {
            "name": "Clean Login Request",
            "url": "https://example.com/login",
            "method": "POST",
            "headers": {"User-Agent": "Mozilla/5.0", "Content-Type": "application/json"},
            "body": '{"username": "user", "password": "pass123"}'
        },
        {
            "name": "SQL Injection Attempt",
            "url": "https://example.com/search?id=1' OR '1'='1' --",
            "method": "GET",
            "headers": {"User-Agent": "sqlmap/1.6"},
            "body": ""
        },
        {
            "name": "XSS Attempt",
            "url": "https://example.com/comment",
            "method": "POST", 
            "headers": {"User-Agent": "Mozilla/5.0", "Content-Type": "application/x-www-form-urlencoded"},
            "body": "comment=<script>alert('XSS')</script>&user=attacker"
        }
    ]
    
    for test in test_cases:
        print(f"\n📋 {test['name']}")
        print(f"   URL: {test['url']}")
        
        result = ai.analyze_burp_request(
            url=test['url'],
            method=test['method'],
            headers=test['headers'],
            body=test['body']
        )
        
        if "error" in result:
            print(f"   ❌ Error: {result['error']}")
        else:
            prediction = result.get('prediction', 'unknown')
            attack_type = result.get('attack_type', 'none')
            
            if prediction == 'malicious':
                print(f"   🚨 THREAT DETECTED: {prediction}")
                print(f"   🔍 Attack Type: {attack_type}")
            else:
                print(f"   ✅ Clean: {prediction}")

def demo_proxy_integration():
    """Demonstrate integration through proxy."""
    print("\n🔗 Proxy Integration Demo")
    print("=" * 40)
    
    proxy_config = {
        'http': 'http://127.0.0.1:8080',
        'https': 'http://127.0.0.1:8080'
    }
    
    test_urls = [
        "http://httpbin.org/get?clean=test",
        "http://httpbin.org/post"
    ]
    
    print("   📡 Sending requests through mitmproxy...")
    print("   (These will be analyzed by the AI tool automatically)")
    
    for url in test_urls:
        try:
            response = requests.get(url, proxies=proxy_config, timeout=5, verify=False)
            print(f"   📊 {url} → Status: {response.status_code}")
            
            # Check for AI analysis headers
            if 'X-AI-Security-Status' in response.headers:
                print(f"      🛡️ AI Status: {response.headers['X-AI-Security-Status']}")
            if 'X-AI-Security-Alert' in response.headers:
                print(f"      🚨 AI Alert: {response.headers['X-AI-Security-Alert']}")
                
        except Exception as e:
            print(f"   📡 {url} → Processed (connection timeout expected)")

def demo_batch_analysis():
    """Demonstrate batch analysis of multiple requests."""
    print("\n🔗 Batch Analysis Demo")
    print("=" * 40)
    
    ai = AISecurityIntegration()
    
    # Simulate a batch of requests from a penetration test
    requests_batch = [
        {"URL": f"https://target.com/page{i}", "request_body": "param=value", "Method": "GET", "User-Agent": "PenTest", "host": "target.com", "content-type": "text/html"}
        for i in range(1, 6)
    ]
    
    # Add some malicious requests
    requests_batch.extend([
        {"URL": "https://target.com/admin?debug=1&admin=true", "request_body": "", "Method": "GET", "User-Agent": "PenTest", "host": "target.com", "content-type": "text/html"},
        {"URL": "https://target.com/search", "request_body": "q='; DROP TABLE users; --", "Method": "POST", "User-Agent": "PenTest", "host": "target.com", "content-type": "application/x-www-form-urlencoded"}
    ])
    
    print(f"   📊 Analyzing {len(requests_batch)} requests...")
    
    malicious_count = 0
    for i, req in enumerate(requests_batch, 1):
        result = ai.analyze_request(req)
        
        if result.get('prediction') == 'malicious':
            malicious_count += 1
            print(f"   🚨 Request {i}: MALICIOUS - {req['URL']}")
        else:
            print(f"   ✅ Request {i}: Clean")
    
    print(f"\n   📈 Summary: {malicious_count}/{len(requests_batch)} requests flagged as malicious")

if __name__ == "__main__":
    print("🧪 AI Security Tool Integration Examples")
    print("=" * 50)
    
    # Check if services are running
    try:
        response = requests.get("http://localhost:5000/health", timeout=5)
        print("✅ AI Security Tool is running")
    except:
        print("❌ AI Security Tool is not running")
        print("   Please start it first: python middleware10.py")
        print("   Or use the quick start script: ./start_integration.sh")
        exit(1)
    
    # Run demonstrations
    demo_direct_integration()
    demo_proxy_integration() 
    demo_batch_analysis()
    
    print("\n🎉 Integration examples completed!")
    print("📚 For more details, see: integrations/BURP_ZAP_INTEGRATION.md")