import pandas as pd
import random
import string
import json
from faker import Faker
from datetime import datetime, timedelta
import numpy as np

fake = Faker()

# Helper functions

def random_string(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_status_code(is_malicious):
    if is_malicious:
        return random.choices([403, 500, 400, 200], weights=[0.4, 0.3, 0.2, 0.1])[0]
    else:
        return random.choices([200, 201, 204], weights=[0.7, 0.2, 0.1])[0]

def generate_realistic_headers():
    # Add more header noise and variety
    headers = {
        "x-forwarded-for": fake.ipv4(),
        "referrer": fake.uri(),
        "accept-language": random.choice([
            "en-US,en;q=0.9", "en-GB,en;q=0.8", "fr-FR,fr;q=0.7", "de-DE,de;q=0.6", "es-ES,es;q=0.5", "zh-CN,zh;q=0.4"
        ]),
        "accept": random.choice([
            "text/html,application/xhtml+xml,application/*;q=0.8",
            "application/json,text/plain,*/*",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "application/xml,application/json,*/*;q=0.7"
        ]),
        "connection": random.choice(["keep-alive", "close"]),
        "cache-control": random.choice(["no-cache", "max-age=0", "no-store", "private", "public"])
    }
    # Add random extra headers
    if random.random() < 0.2:
        headers["x-custom-header"] = random_string(12)
    if random.random() < 0.1:
        headers["x-session-id"] = random_string(24)
    return headers

def random_benign_body():
    style = random.choice(["urlencoded", "json", "multipart"])
    if style == "urlencoded":
        field_names = [
            'username', 'email', 'password', 'first_name', 'last_name',
            'address', 'phone', 'company', 'message', 'subject', 'city', 'country', 'zip', 'dob'
        ]
        fields = []
        for _ in range(random.randint(2, 8)):
            field = random.choice(field_names)
            if field == 'email':
                value = fake.email()
            elif field == 'username':
                value = fake.user_name()
            elif field == 'password':
                value = fake.password(length=random.randint(8, 16))
            elif field in ['first_name', 'last_name']:
                value = fake.name()
            elif field == 'address':
                value = fake.address().replace('\n', ' ')
            elif field == 'phone':
                value = fake.phone_number()
            elif field == 'company':
                value = fake.company()
            elif field == 'city':
                value = fake.city()
            elif field == 'country':
                value = fake.country()
            elif field == 'zip':
                value = fake.zipcode()
            elif field == 'dob':
                value = fake.date_of_birth().isoformat()
            else:
                value = fake.text(max_nb_chars=50).replace('\n', ' ')
            fields.append(f"{field}={value}")
        return "&".join(fields)
    elif style == "json":
        data = {
            "user_id": random.randint(1, 10000),
            "username": fake.user_name(),
            "email": fake.email(),
            "profile": {
                "bio": fake.text(max_nb_chars=100),
                "location": fake.city(),
                "website": fake.url(),
                "dob": fake.date_of_birth().isoformat(),
                "country": fake.country()
            },
            "preferences": {
                "newsletter": random.choice([True, False]),
                "notifications": random.choice([True, False]),
                "theme": random.choice(["light", "dark"])
            }
        }
        return json.dumps(data)
    else:
        boundary = "----WebKitFormBoundary" + random_string(16)
        parts = []
        fields = ['name', 'email', 'message', 'phone', 'company', 'city', 'country', 'zip', 'dob']
        for field in random.sample(fields, random.randint(2, 6)):
            if field == 'email':
                value = fake.email()
            elif field == 'name':
                value = fake.name()
            elif field == 'phone':
                value = fake.phone_number()
            elif field == 'company':
                value = fake.company()
            elif field == 'city':
                value = fake.city()
            elif field == 'country':
                value = fake.country()
            elif field == 'zip':
                value = fake.zipcode()
            elif field == 'dob':
                value = fake.date_of_birth().isoformat()
            else:
                value = fake.text(max_nb_chars=100)
            parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"\r\n\r\n{value}\r\n")
        if random.random() < 0.3:
            parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{fake.file_name()}\"\r\nContent-Type: application/octet-stream\r\n\r\n[binary data]\r\n")
        return "".join(parts) + f"--{boundary}--"

def random_malicious_body(payload):
    style = random.choice(["urlencoded", "json", "multipart"])
    evasion = random.choice(['url_encoding', 'double_encoding', 'unicode_encoding', 'case_variation', 'comment_insertion'])
    if evasion == 'url_encoding':
        payload = payload.replace('<', '%3C').replace('>', '%3E').replace('"', '%22')
    elif evasion == 'double_encoding':
        payload = payload.replace('<', '%253C').replace('>', '%253E')
    elif evasion == 'unicode_encoding':
        payload = payload.replace('<', '\\u003C').replace('>', '\\u003E')
    elif evasion == 'case_variation':
        payload = payload.replace('script', 'ScRiPt').replace('select', 'SeLeCt')
    elif evasion == 'comment_insertion':
        payload = payload.replace('union', 'uni/**/on')
    if style == "urlencoded":
        fields = [f"input={payload}", f"data={random_string(6)}"]
        if random.random() < 0.5: fields.reverse()
        if random.random() < 0.3: fields.append(f"csrf_token={random_string(32)}")
        if random.random() < 0.2: fields.append(f"callback={payload}")
        return "&".join(fields)
    elif style == "json":
        data = {"input": payload, "user_id": random.randint(1, 1000)}
        if random.random() < 0.3: data["extra"] = random_string(5)
        if random.random() < 0.2: data["nested"] = {"payload": payload, "type": "malicious"}
        if random.random() < 0.15: data["metadata"] = {"source": payload}
        return json.dumps(data)
    else:
        boundary = "----WebKitFormBoundary" + random_string(16)
        parts = [
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"input\"\r\n\r\n{payload}\r\n",
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"username\"\r\n\r\n{fake.user_name()}\r\n"
        ]
        if random.random() < 0.3:
            parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"hidden\"\r\n\r\n{payload}\r\n")
        return "".join(parts) + f"--{boundary}--"

# Behavioral feature generator with noise and ambiguity

def generate_behavioral_features(noise_level=0.18):
    requests_per_session = int(np.clip(np.random.choice([
        np.random.poisson(3),
        np.random.poisson(15),
        np.random.poisson(60)
    ], p=[0.7, 0.2, 0.1]), 1, 100))
    if random.random() < noise_level:
        requests_per_session += random.randint(-2, 3)
        requests_per_session = max(1, requests_per_session)

    session_duration = float(np.clip(np.random.choice([
        np.random.exponential(60),
        np.random.normal(300, 60),
        np.random.normal(1200, 300)
    ], p=[0.8, 0.15, 0.05]), 5, 1800))
    if random.random() < noise_level:
        session_duration += random.uniform(-30, 60)
        session_duration = max(5, session_duration)

    mean_time_between_reqs = float(np.clip(np.random.choice([
        np.random.exponential(5),
        np.random.normal(15, 5),
        np.random.normal(45, 15)
    ], p=[0.7, 0.2, 0.1]), 0.5, 120))
    if random.random() < noise_level:
        mean_time_between_reqs += random.uniform(-2, 5)
        mean_time_between_reqs = max(0.5, mean_time_between_reqs)

    unique_endpoints = int(np.clip(np.random.choice([
        np.random.poisson(2),
        np.random.poisson(7),
        np.random.poisson(15)
    ], p=[0.75, 0.2, 0.05]), 1, 20))
    if random.random() < noise_level:
        unique_endpoints += random.randint(-1, 2)
        unique_endpoints = max(1, unique_endpoints)

    user_agent_changes = int(np.clip(np.random.choice([
        1,
        np.random.poisson(2),
        np.random.poisson(3)
    ], p=[0.85, 0.1, 0.05]), 1, 5))
    if random.random() < noise_level:
        user_agent_changes += random.randint(-1, 2)
        user_agent_changes = max(1, user_agent_changes)

    return {
        'requests_per_session': requests_per_session,
        'session_duration': session_duration,
        'mean_time_between_reqs': mean_time_between_reqs,
        'unique_endpoints': unique_endpoints,
        'user_agent_changes': user_agent_changes
    }

# Payloads and config
sqli_payloads = ["1' OR '1'='1", "admin'--", "' OR 1=1;--", "' OR SLEEP(5)#", "' OR 1=1; DROP TABLE users;--", "' OR 1=1;--"]
xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
csrf_payloads = ["<form action='https://bank.example.com/transfer' method='POST'><input type='hidden' name='amount' value='5000'><input type='hidden' name='to_account' value='987654321'></form>"]
ssrf_payloads = ["http://169.254.169.254/latest/meta-data/", "http://localhost/admin"]
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "curl/7.68.0",
    "PostmanRuntime/7.29.2",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
]
hosts = ["example.com", "api.example.com", "secure.example.com", "internal.local"]
content_types = ["application/x-www-form-urlencoded", "application/json", "multipart/form-data"]
methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
param_names = ["id", "search", "user", "token", "page", "query", "input", "csrf_token", "session", "action"]
benign_paths = ["/api/v1/users", "/dashboard", "/profile", "/settings", "/help", "/support"]

rows = []

# Malicious and ambiguous samples
malicious_total = 12000
malicious_types = [(sqli_payloads, 'sqli'), (xss_payloads, 'xss'), (csrf_payloads, 'csrf'), (ssrf_payloads, 'ssrf')]
malicious_per_type = malicious_total // len(malicious_types)
for payload_list, attack_type in malicious_types:
    for _ in range(malicious_per_type):
        payload = random.choice(payload_list)
        param = random.choice(param_names)
        behavioral = generate_behavioral_features(noise_level=0.22)
        # Add ambiguity: sometimes use benign body, sometimes normal features
        if random.random() < 0.18:
            request_body = random_benign_body()
        else:
            request_body = random_malicious_body(payload)
        # Sometimes use benign-looking behavioral features
        if random.random() < 0.15:
            behavioral = generate_behavioral_features(noise_level=0.35)
        # Label flipping: flip label for some samples
        label = 'malicious'
        if random.random() < 0.07:
            label = 'benign'
        row = {
            'Method': random.choices(methods, weights=[0.3, 0.5, 0.1, 0.05, 0.05])[0],
            'User-Agent': random.choice(user_agents + [fake.user_agent()]),
            'host': random.choice(hosts + [fake.domain_name()]),
            'content-type': random.choice(content_types),
            'URL': f"http://{random.choice(hosts + [fake.domain_name()])}/?{param}={payload}",
            'request_body': request_body,
            'status_code': generate_status_code(label == 'malicious'),
            'classification': label,
            'payload_type': attack_type,
            'is_behavioral_anomaly': random.choices([1, 0], weights=[0.4, 0.6])[0],
            **behavioral,
            **generate_realistic_headers()
        }
        rows.append(row)

benign_total = 38000
for _ in range(benign_total):
    path = random.choice(benign_paths)
    behavioral = generate_behavioral_features(noise_level=0.22)
    # Add ambiguity: sometimes use malicious body, sometimes suspicious payloads
    if random.random() < 0.13:
        payload = random.choice(sqli_payloads + xss_payloads + csrf_payloads + ssrf_payloads)
        param = random.choice(param_names)
        request_body = random_malicious_body(payload)
        url = f"http://{random.choice(hosts + [fake.domain_name()])}/?{param}={payload}"
    else:
        request_body = random_benign_body()
        url = f"http://{random.choice(hosts)}{path}"
    # Sometimes use malicious-looking behavioral features
    if random.random() < 0.15:
        behavioral = generate_behavioral_features(noise_level=0.35)
    # Label flipping: flip label for some samples
    label = 'benign'
    if random.random() < 0.07:
        label = 'malicious'
    row = {
        'Method': random.choices(methods, weights=[0.7, 0.2, 0.05, 0.03, 0.02])[0],
        'User-Agent': random.choice(user_agents + [fake.user_agent()]),
        'host': random.choice(hosts + [fake.domain_name()]),
        'content-type': random.choice(content_types),
        'URL': url,
        'request_body': request_body,
        'status_code': generate_status_code(label == 'malicious'),
        'classification': label,
        'payload_type': 'benign',
        'is_behavioral_anomaly': 0,
        **behavioral,
        **generate_realistic_headers()
    }
    rows.append(row)

# Shuffle and save

df = pd.DataFrame(rows)
df = df.sample(frac=1).reset_index(drop=True)

print(f"✅ Generated {len(df)} total samples")
print(f" - Malicious samples: {len(df[df['classification']=='malicious'])}")
print(f" - Benign samples: {len(df[df['classification']=='benign'])}")

df.to_csv('realworld_noisy_web_traffic.csv', index=False)
print("✅ Dataset saved as: realworld_noisy_web_traffic.csv")
