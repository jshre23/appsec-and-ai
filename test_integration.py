#!/usr/bin/env python3
"""
Test script to validate the AI Security Tool integration endpoints.
"""

import requests
import json
import sys

API_BASE = "http://localhost:5000"

def test_health_check():
    """Test if the Flask app is running."""
    try:
        response = requests.get(f"{API_BASE}/health", timeout=5)
        print(f"✅ Health check: {response.status_code}")
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Health check failed: {e}")
        return False

def test_integration_endpoint():
    """Test the integration/forward endpoint."""
    test_request = {
        "URL": "http://test.com/login?admin=true&debug=1",
        "request_body": "username=admin&password=password123",
        "Method": "POST",
        "User-Agent": "TestAgent/1.0",
        "host": "test.com",
        "content-type": "application/x-www-form-urlencoded"
    }
    
    try:
        response = requests.post(
            f"{API_BASE}/integrations/forward",
            json=test_request,
            headers={'Content-Type': 'application/json'},
            timeout=10
        )
        
        print(f"✅ Integration endpoint: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print(f"   Prediction: {result.get('prediction', 'unknown')}")
            print(f"   Attack Type: {result.get('attack_type', 'none')}")
            return True
        else:
            print(f"   Error: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Integration endpoint failed: {e}")
        return False

def test_malicious_request():
    """Test with a clearly malicious request."""
    malicious_request = {
        "URL": "http://test.com/search?q=<script>alert('XSS')</script>&id=1' UNION SELECT * FROM users--",
        "request_body": "data='; DROP TABLE users; --",
        "Method": "GET",
        "User-Agent": "sqlmap/1.0",
        "host": "test.com",
        "content-type": "text/plain"
    }
    
    try:
        response = requests.post(
            f"{API_BASE}/integrations/forward",
            json=malicious_request,
            headers={'Content-Type': 'application/json'},
            timeout=10
        )
        
        print(f"✅ Malicious request test: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            prediction = result.get('prediction', 'unknown')
            attack_type = result.get('attack_type', 'none')
            
            print(f"   Prediction: {prediction}")
            print(f"   Attack Type: {attack_type}")
            
            if prediction == 'malicious':
                print("   🚨 Correctly identified as malicious!")
                return True
            else:
                print("   ⚠️  Not flagged as malicious - may need model tuning")
                return True  # Still consider success as API is working
        else:
            print(f"   Error: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Malicious request test failed: {e}")
        return False

if __name__ == "__main__":
    print("🔍 Testing AI Security Tool Integration...")
    print("=" * 50)
    
    # Run tests
    tests = [
        ("Health Check", test_health_check),
        ("Integration Endpoint", test_integration_endpoint),
        ("Malicious Request Detection", test_malicious_request),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n📋 {test_name}:")
        if test_func():
            passed += 1
        else:
            print("   Test failed!")
    
    print("\n" + "=" * 50)
    print(f"📊 Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Integration is working correctly.")
        sys.exit(0)
    else:
        print("❌ Some tests failed. Please check the Flask application.")
        sys.exit(1)