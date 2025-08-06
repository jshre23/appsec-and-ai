import requests
import random
import time
import string

API_URL = 'http://localhost:5001/predict'

# Helper to generate random strings

def randstr(n):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=n))

def make_request(url, payload, user_agent, session_id=None):
    headers = {
        'Content-Type': 'application/json',
        'User-Agent': user_agent
    }
    data = {
        'Method': 'GET',
        'User-Agent': user_agent,
        'host': 'localhost',
        'content-type': 'application/json',
        'URL': url,
        'request_body': payload,
    }
    if session_id:
        data['session_id'] = session_id
    resp = requests.post(API_URL, json=data, headers=headers)
    try:
        return resp.json()
    except Exception:
        return {'error': 'Invalid response', 'raw': resp.text}

def main():
    print("\n--- Behavioral & SVM Anomaly Score Tester ---\n")
    session_id = f"sess_{randstr(6)}"
    user_agent = f"TestAgent/{randstr(4)}"

    # 1. Normal request (should be low anomaly)
    url1 = f"/home.php?user={randstr(5)}"
    payload1 = "Hello world!"
    print("[1] Normal request:")
    res1 = make_request(url1, payload1, user_agent, session_id)
    print(res1)
    time.sleep(1)

    # 2. Many requests in session (should increase behavioral anomaly)
    print("\n[2] Burst of requests in session:")
    for i in range(5):
        url2 = f"/api/data?id={randstr(4)}"
        payload2 = randstr(10)
        res2 = make_request(url2, payload2, user_agent, session_id)
        print(f"  Burst {i+1}:", res2.get('features', {}))
        time.sleep(0.5)

    # 3. Suspicious payload (should increase SVM anomaly)
    print("\n[3] Suspicious payload:")
    url3 = "/search.php?q=<script>alert(1)</script>"
    payload3 = "<script>alert('x')</script>"
    res3 = make_request(url3, payload3, user_agent, session_id)
    print(res3)
    time.sleep(1)

    print("\n[3.1] Suspicious payload:")
    url3 = "/search.php?q=' or 1=1 --"
    payload3 = "' or 1=1 --"
    res3 = make_request(url3, payload3, user_agent, session_id)
    print(res3)
    time.sleep(1)

    # 4. Abnormal session (many endpoints, user agent changes)
    print("\n[4] Abnormal session (many endpoints, user agent changes):")
    for i in range(3):
        url4 = f"/endpoint_{i}?param={randstr(3)}"
        ua = f"TestAgent/{randstr(4)}" if i > 0 else user_agent
        res4 = make_request(url4, randstr(8), ua, session_id)
        print(f"  Endpoint {i+1}:", res4.get('features', {}))
        time.sleep(0.5)

    print("\nDone. Check the UI table for corresponding entries and scores.\n")

if __name__ == "__main__":
    main()
