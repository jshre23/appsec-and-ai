import requests
import random
import time
import json
from faker import Faker

fake = Faker()

BACKEND_URL = 'http://localhost:5001/predict'

methods = ['GET', 'POST', 'PUT', 'DELETE']
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "curl/7.68.0",
    "PostmanRuntime/7.29.2",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
]
hosts = ["example.com", "api.example.com", "secure.example.com", "internal.local"]
content_types = ["application/x-www-form-urlencoded", "application/json", "multipart/form-data"]
benign_paths = ["/api/v1/users", "/dashboard", "/profile", "/settings", "/help", "/support"]

# Example attack payloads
attack_payloads = [
    "<script>alert('XSS')</script>",
    "' OR 1=1--",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<iframe src='http://malicious.com'></iframe>",
    "<script>fetch('http://malicious.com')</script>",
    "<form action='http://malicious.com' method='POST'><input type='text' name='data' value='malicious'></form>",
    "<script>document.cookie='session=malicious'</script>",
    "<form action='https://bank.example.com/transfer' method='POST'><input type='hidden' name='amount' value='5000'></form>",
    "<img src='http://localhost/image.jpg' onerror='alert(1)'>",
    "<script>fetch('http://localhost/api')</script>",
    "<script>document.location='http://malicious.com'</script>",
    "<script>window.location='http://malicious.com'</script>",
    "<script>eval('alert(1)')</script>",
    "http://localhost/admin",
    "http://169.254.169.254/latest/meta-data/",
    "file:///etc/passwd",
    "gopher://example.com",
    "ftp://example.com/resource",
    "SELECT * FROM users WHERE username = 'admin' AND password = 'password'",
    "SELECT * FROM products WHERE price < 100; DROP TABLE products;",
    "SELECT * FROM orders WHERE order_id = '1' OR '1'='1'",
    "SELECT username, password FROM users WHERE '1'='1'", 
    "UNION SELECT username, password FROM users",
    "1' OR '1'='1' --",
    "1' OR '1'='1' /*",
    "1' OR '1'='1",
    "1; DROP TABLE users;",
    "1' AND SLEEP(5) --",
    "1' AND BENCHMARK(1000000, MD5('test')) --",
    "1' OR 'a'='a",     
]

def random_benign_request():
    return {
        "Method": random.choice(methods),
        "User-Agent": random.choice(user_agents),
        "host": random.choice(hosts),
        "content-type": random.choice(content_types),
        "URL": f"http://{random.choice(hosts)}{random.choice(benign_paths)}",
        "request_body": fake.text(max_nb_chars=100)
    }

def random_attack_request():
    payload = random.choice(attack_payloads)
    return {
        "Method": random.choice(methods),
        "User-Agent": random.choice(user_agents),
        "host": random.choice(hosts),
        "content-type": random.choice(content_types),
        "URL": f"http://{random.choice(hosts)}/?input={payload}",
        "request_body": payload
    }

def send_request(data):
    try:
        resp = requests.post(BACKEND_URL, json=data)
        resp_json = None
        try:
            resp_json = resp.json()
        except Exception:
            pass
        label = None
        warning = False
        if resp_json:
            label = resp_json.get('label') or resp_json.get('prediction')
            warning = resp_json.get('warning', False)
        icon = ''
        if warning:
            icon = '\u26A0\ufe0f'  # yellow warning
        elif label == 'malicious':
            icon = '\U0001F6A8'  # red police light
        elif label == 'benign':
            icon = '\U0001F7E2'  # green circle
        else:
            icon = ''
        print(f"Sent: {json.dumps(data)}")
        print(f"Response: {resp.status_code} {icon} {resp.text}\n")
    except Exception as e:
        print(f"Error sending request: {e}")

def main():
    for _ in range(200):
        if random.random() < 0.5:
            req = random_benign_request()
        else:
            req = random_attack_request()
        send_request(req)
        time.sleep(0.00001)  # Wait 1 second between requests

if __name__ == "__main__":
    main()
