# --- Behavioral feature engineering ---
from sklearn.ensemble import IsolationForest
import shap
import faker

def compute_behavioral_features(df):
    import pandas as pd
    import numpy as np
    # Ensure 'timestamp' column exists and is in datetime format
    if 'timestamp' not in df.columns:
        # If missing, create a default timestamp column
        df['timestamp'] = pd.Timestamp('2025-01-01')
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    # Fill missing session_id with unique value if not present
    if 'session_id' not in df.columns:
        df['session_id'] = np.arange(len(df))
    # Requests per session
    df['requests_per_session'] = df.groupby('session_id')['URL'].transform('count') if 'URL' in df.columns else 0
    # Session duration
    df['session_duration'] = df.groupby('session_id')['timestamp'].transform(lambda x: (x.max()-x.min()).total_seconds() if x.count() > 1 else 0)
    # Mean time between requests
    df['mean_time_between_reqs'] = df.groupby('session_id')['timestamp'].transform(lambda x: x.diff().mean().total_seconds() if x.count() > 1 else 0)
    # Unique endpoints hit
    df['unique_endpoints'] = df.groupby('session_id')['URL'].transform('nunique') if 'URL' in df.columns else 0
    # User agent changes
    df['user_agent_changes'] = df.groupby('session_id')['User-Agent'].transform(lambda x: x.nunique()) if 'User-Agent' in df.columns else 0
    # z-score of session duration
    df['session_duration_z'] = (df['session_duration'] - df['session_duration'].mean()) / (df['session_duration'].std() + 1e-6)
    # Outlier flag for session duration
    df['session_duration_outlier'] = ((df['session_duration_z'].abs()) > 2).astype(int)
    # IsolationForest anomaly score
    behavioral_cols = ['requests_per_session', 'session_duration', 'mean_time_between_reqs',
                       'unique_endpoints', 'user_agent_changes']
    iso = IsolationForest(contamination=0.05, random_state=42)
    iso.fit(df[behavioral_cols].fillna(0))
    df['behavior_anomaly_score'] = -iso.decision_function(df[behavioral_cols].fillna(0))
    df['behavioral_anomaly_flag'] = (df['behavior_anomaly_score'] > 0.4).astype(int)

    # --- Unsupervised anomaly score using OneClassSVM ---
    from sklearn.svm import OneClassSVM
    svm = OneClassSVM(gamma='scale', nu=0.05)
    try:
        svm.fit(df[behavioral_cols].fillna(0))
        df['svm_anomaly_score'] = -svm.decision_function(df[behavioral_cols].fillna(0))
        df['svm_anomaly_flag'] = (df['svm_anomaly_score'] > 0.0).astype(int)
    except Exception as e:
        df['svm_anomaly_score'] = 0.0
        df['svm_anomaly_flag'] = 0
    return df
import pandas as pd
import numpy as np

# --- Option to include SVM anomaly features ---
use_svm_anomaly = True  # Set to False to exclude SVM anomaly features from the model
import re
from attack_detection import detect_attack_from_strings
from urllib.parse import urlparse, parse_qs
from sklearn.model_selection import train_test_split, StratifiedKFold, RandomizedSearchCV
from sklearn.pipeline import make_pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler, LabelEncoder
from sklearn.impute import SimpleImputer
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix, f1_score
import joblib
from xgboost import XGBClassifier

SUSPICIOUS_KEYWORDS = [
    'select', 'union', 'insert', 'drop', 'script', 'alert', 'sleep',
    'gopher', 'file', 'meta-data', 'passwd', 'iframe', 'svg', 'onerror', 'onload', 'fetch'
]


import random
# --- Augment dataset with more realistic samples ---
def augment_realistic_samples(df, n_benign=500, n_attack=500):
    methods = ['GET', 'POST', 'PUT', 'DELETE']
    content_types = ['application/json', 'application/x-www-form-urlencoded', 'text/html', 'multipart/form-data']
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15',
        'Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36'
    ]
    hosts = ['example.com', 'test.com', 'localhost']
    benign_rows = []
    from faker import Faker
    fake = Faker()
    for i in range(n_benign):
        url = f"https://{random.choice(hosts)}/home?data={fake.word()}"
        session_id = f"sess_benign_{i//10}"
        timestamp = pd.Timestamp('2025-01-01') + pd.Timedelta(seconds=random.randint(0, 86400))
        row = {
            'Method': random.choice(methods),
            'User-Agent': random.choice(user_agents),
            'host': url.split('/')[2],
            'content-type': random.choice(content_types),
            'URL': url,
            'request_body': fake.word(),
            'classification': 'benign',
            'payload_type': 'benign',
            'session_id': session_id,
            'timestamp': timestamp
        }
        benign_rows.append(row)
    # Attack samples
    attack_rows = []
    xss_payloads = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(2)>',
        '<svg/onload=alert(3)>',
        'javascript:alert(4)',
        '<iframe src="javascript:alert(5)"></iframe>'
    ]
    sqli_payloads = [
        "' OR 1=1--", 'admin" --', '1; DROP TABLE users', 'SELECT * FROM users WHERE id=1', 'UNION SELECT password FROM users',
        'OR 1=1', 'AND 1=0', 'SELECT password FROM users WHERE username="admin"', 'DROP TABLE', 'SLEEP(10)'
    ]
    csrf_payloads = [
        '<form method="post"><input name="csrf_token" value="badtoken"></form>',
        'csrf_token=badtoken',
        'cross site request forgery',
        'token=badtoken',
        '<input type="hidden" name="csrf_token" value="badtoken">'
    ]
    ssrf_payloads = [
        'file:///etc/passwd',
        'http://127.0.0.1:8080/admin',
        'gopher://malicious.com',
        'ftp://internal/resource',
        'localhost:8000/private',
        'http://localhost',
        'http://169.254.169.254',
        'http://10.0.0.1',
        'http://172.16.0.1',
        'http://192.168.1.1',
        'http://internal/resource',
        'http://private/resource',
        'http://intranet/resource',
        'http://metadata.google.internal',
        'http://aws.amazon.com/metadata',
        'http://azure.microsoft.com/metadata'
    ]
    attack_types = [
        ('xss', xss_payloads),
        ('sqli', sqli_payloads),
        ('csrf', csrf_payloads),
        ('ssrf', ssrf_payloads)
    ]
    for attack, payloads in attack_types:
        for i in range(n_attack // 4):
            payload = random.choice(payloads)
            url = f"https://{random.choice(hosts)}/vuln?input={payload}"
            session_id = f"sess_attack_{attack}_{i//10}"
            timestamp = pd.Timestamp('2025-01-01') + pd.Timedelta(seconds=random.randint(0, 86400))
            row = {
                'Method': random.choice(methods),
                'User-Agent': random.choice(user_agents),
                'host': url.split('/')[2],
                'content-type': random.choice(content_types),
                'URL': url,
                'request_body': '',
                'classification': 'malicious',
                'payload_type': attack,
                'session_id': session_id,
                'timestamp': timestamp
            }
            attack_rows.append(row)
            url2 = f"https://{random.choice(hosts)}/api/{attack}"
            session_id2 = f"sess_attack_{attack}_{i//10}_b"
            timestamp2 = pd.Timestamp('2025-01-01') + pd.Timedelta(seconds=random.randint(0, 86400))
            row2 = {
                'Method': random.choice(methods),
                'User-Agent': random.choice(user_agents),
                'host': url2.split('/')[2],
                'content-type': random.choice(content_types),
                'URL': url2,
                'request_body': payload,
                'classification': 'malicious',
                'payload_type': attack,
                'session_id': session_id2,
                'timestamp': timestamp2
            }
            attack_rows.append(row2)
    df_aug = pd.DataFrame(benign_rows + attack_rows)
    df = pd.concat([df, df_aug], ignore_index=True)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    return df

# Add extra simple benign samples to reduce false positives
def add_simple_benign(df, n=200):
    simple_payloads = [
        '', 'n', 'hello', 'test', 'foo', 'bar', '123', 'abc', 'none', 'ok', 'ping', 'pong', 'sample', 'benign', 'safe', 'normal', 'data', 'user', 'admin', 'guest', 'simple', 'value', 'input', 'output', 'check', 'plain', 'clean', 'empty', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'
    ]
    hosts = ['example.com', 'test.com', 'localhost']
    methods = ['GET', 'POST']
    user_agents = [
        'Mozilla/5.0', 'curl/7.68.0', 'PostmanRuntime/7.26.8'
    ]
    content_types = [
        'application/x-www-form-urlencoded', 'application/json', 'text/plain', 'text/html'
    ]
    rows = []
    for i in range(n):
        payload = random.choice(simple_payloads)
        url = f"https://{random.choice(hosts)}/simple?data={payload}"
        session_id = f"sess_simple_{i//10}"
        timestamp = pd.Timestamp('2025-01-01') + pd.Timedelta(seconds=random.randint(0, 86400))
        row = {
            'Method': random.choice(methods),
            'User-Agent': random.choice(user_agents),
            'host': url.split('/')[2],
            'content-type': random.choice(content_types),
            'URL': url,
            'request_body': payload,
            'classification': 'benign',
            'payload_type': 'benign',
            'session_id': session_id,
            'timestamp': timestamp
        }
        rows.append(row)
    df_simple = pd.DataFrame(rows)
    df = pd.concat([df, df_simple], ignore_index=True)
    return df


# --- Load or generate the initial DataFrame ---
import os
if os.path.exists('realworld_noisy_web_traffic.csv'):
    df = pd.read_csv('realworld_noisy_web_traffic.csv')
    if 'timestamp' in df.columns:
        df = compute_behavioral_features(df)
    else:
        print("Warning: 'timestamp' column missing, skipping behavioral feature computation.")
        # Add missing behavioral columns with default values to avoid KeyError
        behavioral_defaults = {
            'session_duration_z': 0.0,
            'session_duration_outlier': 0,
            'behavior_anomaly_score': 0.0,
            'behavioral_anomaly_flag': 0,
            'svm_anomaly_score': 0.0,
            'svm_anomaly_flag': 0
        }
        for col, val in behavioral_defaults.items():
            if col not in df.columns:
                df[col] = val
else:
    df = pd.DataFrame()
    df = augment_realistic_samples(df, n_benign=500, n_attack=500)
    df = add_simple_benign(df, n=200)
    df = compute_behavioral_features(df)

# --- Augment dataset with more realistic samples ---
def augment_realistic_samples(df, n_benign=500, n_attack=500):
    methods = ['GET', 'POST', 'PUT', 'DELETE']
    content_types = ['application/json', 'application/x-www-form-urlencoded', 'text/html', 'multipart/form-data']
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15',
        'Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36'
    ]
    hosts = ['example.com', 'test.com', 'localhost']
    benign_rows = []
    from faker import Faker
    fake = Faker()

    # Generate benign samples
    for i in range(n_benign):
        url = f"https://{random.choice(hosts)}/home?data={fake.word()}"
        session_id = f"sess_benign_{i//10}"
        timestamp = pd.Timestamp('2025-01-01') + pd.Timedelta(seconds=random.randint(0, 86400))
        row = {
            'Method': random.choice(methods),
            'User-Agent': random.choice(user_agents),
            'host': url.split('/')[2],
            'content-type': random.choice(content_types),
            'URL': url,
            'request_body': fake.word(),
            'classification': 'benign',
            'payload_type': 'benign',
            'session_id': session_id,
            'timestamp': timestamp
        }
        benign_rows.append(row)

    # Attack samples
    attack_rows = []

    # Clear, non-overlapping, realistic payloads for each attack type
    xss_payloads = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(2)>',
        '<svg/onload=alert(3)>',
        'javascript:alert(4)',
        '<iframe src="javascript:alert(5)"></iframe>'
    ]
    sqli_payloads = [
        "' OR 1=1--", 'admin" --', '1; DROP TABLE users', 'SELECT * FROM users WHERE id=1', 'UNION SELECT password FROM users',
        'OR 1=1', 'AND 1=0', 'SELECT password FROM users WHERE username="admin"', 'DROP TABLE', 'SLEEP(10)'
    ]
    csrf_payloads = [
        '<form method="post"><input name="csrf_token" value="badtoken"></form>',
        'csrf_token=badtoken',
        'cross site request forgery',
        'token=badtoken',
        '<input type="hidden" name="csrf_token" value="badtoken">'
    ]
    ssrf_payloads = [
        'file:///etc/passwd',
        'http://127.0.0.1:8080/admin',
        'gopher://malicious.com',
        'ftp://internal/resource',
        'localhost:8000/private',
        'http://localhost',
        'http://169.254.169.254',
        'http://10.0.0.1',
        'http://172.16.0.1',
        'http://192.168.1.1',
        'http://internal/resource',
        'http://private/resource',
        'http://intranet/resource',
        'http://metadata.google.internal',
        'http://aws.amazon.com/metadata',
        'http://azure.microsoft.com/metadata'
    ]
    attack_types = [
        ('xss', xss_payloads),
        ('sqli', sqli_payloads),
        ('csrf', csrf_payloads),
        ('ssrf', ssrf_payloads)
    ]

    # For each attack type, generate n_attack//4 samples with payload in both URL and request_body
    for attack, payloads in attack_types:
        for i in range(n_attack // 4):
            payload = random.choice(payloads)
            # In URL
            url = f"https://{random.choice(hosts)}/vuln?input={payload}"
            session_id = f"sess_attack_{attack}_{i//10}"
            timestamp = pd.Timestamp('2025-01-01') + pd.Timedelta(seconds=random.randint(0, 86400))
            row = {
                'Method': random.choice(methods),
                'User-Agent': random.choice(user_agents),
                'host': url.split('/')[2],
                'content-type': random.choice(content_types),
                'URL': url,
                'request_body': '',
                'classification': 'malicious',
                'payload_type': attack,
                'session_id': session_id,
                'timestamp': timestamp
            }
            attack_rows.append(row)
            # In request_body
            url2 = f"https://{random.choice(hosts)}/api/{attack}"
            session_id2 = f"sess_attack_{attack}_{i//10}_b"
            timestamp2 = pd.Timestamp('2025-01-01') + pd.Timedelta(seconds=random.randint(0, 86400))
            row2 = {
                'Method': random.choice(methods),
                'User-Agent': random.choice(user_agents),
                'host': url2.split('/')[2],
                'content-type': random.choice(content_types),
                'URL': url2,
                'request_body': payload,
                'classification': 'malicious',
                'payload_type': attack,
                'session_id': session_id2,
                'timestamp': timestamp2
            }
            attack_rows.append(row2)

    # Combine and shuffle
    df_aug = pd.DataFrame(benign_rows + attack_rows)
    df = pd.concat([df, df_aug], ignore_index=True)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    return df


# Add extra simple benign samples to reduce false positives
def add_simple_benign(df, n=200):
    simple_payloads = [
        '', 'n', 'hello', 'test', 'foo', 'bar', '123', 'abc', 'none', 'ok', 'ping', 'pong', 'sample', 'benign', 'safe', 'normal', 'data', 'user', 'admin', 'guest', 'simple', 'value', 'input', 'output', 'check', 'plain', 'clean', 'empty', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'
    ]
    hosts = ['example.com', 'test.com', 'localhost']
    methods = ['GET', 'POST']
    user_agents = [
        'Mozilla/5.0', 'curl/7.68.0', 'PostmanRuntime/7.26.8'
    ]
    content_types = [
        'application/x-www-form-urlencoded', 'application/json', 'text/plain', 'text/html'
    ]
    rows = []
    for i in range(n):
        payload = random.choice(simple_payloads)
        url = f"https://{random.choice(hosts)}/simple?data={payload}"
        session_id = f"sess_simple_{i//10}"
        timestamp = pd.Timestamp('2025-01-01') + pd.Timedelta(seconds=random.randint(0, 86400))
        row = {
            'Method': random.choice(methods),
            'User-Agent': random.choice(user_agents),
            'host': url.split('/')[2],
            'content-type': random.choice(content_types),
            'URL': url,
            'request_body': payload,
            'classification': 'benign',
            'payload_type': 'benign',
            'session_id': session_id,
            'timestamp': timestamp
        }
        rows.append(row)
    df_simple = pd.DataFrame(rows)
    df = pd.concat([df, df_simple], ignore_index=True)
    return df

# --- Robust relabeling for all attack types ---
XSS_PATTERNS = [
    r'<script[\s\S]*?>[\s\S]*?<\/script>',  # full script tag
    r'<script[\s\S]*?>',                     # opening script tag
    r'onerror\s*=\s*(["\']).+?\1',       # onerror with value
    r'onload\s*=\s*(["\']).+?\1',        # onload with value
    r'javascript:[^\s]+',                    # javascript: URI
    r'<img[^>]+src\s*=\s*(["\']).+?\1',  # img src with value
    r'<svg[\s\S]*?>',                       # svg tag
    r'<iframe[\s\S]*?>',                    # iframe tag
    r'document\.cookie',                     # document.cookie access
    r'alert\s*\([\s\S]*?\)',             # alert( ... )
    r'\bon\w+\s*=\s*(["\']).+?\1',    # on* attributes with value
]
CSRF_PATTERNS = [
    r'<form[^>]*method=["\']?post["\']?',
    r'csrf',
    r'cross.?site.?request.?forgery',
    r'\btoken=\b',
]
SSRF_PATTERNS = [
    r'file://',
    r'gopher://',
    r'ftp://',
    r'http://127\.0\.0\.1',
    r'https?://127\.0\.0\.1',
    r'127\.0\.0\.1',
    r'localhost',
    r'internal',
    r'169\.254\.',
    r'10\.\d+\.\d+\.\d+',
    r'172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+',
    r'192\.168\.\d+\.\d+',
    r'localhost:\d+',
    r'\bssrf\b',
]
SQLI_PATTERNS = [
    r'(\bselect\b|\binsert\b|\bupdate\b|\bdelete\b|\bdrop\b|\bunion\b|\bwhere\b|\blike\b)',
    r'\bor\b.+?=.+', r'\band\b.+?=.+', r'--', r';', r'\bcast\b', r'\bsleep\b', r'\bbenchmark\b',
    r'\b1=1\b', r'\b1=0\b', r'\btrue\b', r'\bfalse\b', r'\bsqli\b',
]
def detect_attack(row):
    return detect_attack_from_strings(row['URL'], row['request_body'])
df['classification'] = df['classification'].astype(str)
df['payload_type'] = df['payload_type'].astype(str)

def feature_extraction(df):

    # url_length
    df['url_length'] = df['URL'].apply(lambda x: len(str(x)))

    # num_params
    df['num_params'] = df['URL'].apply(lambda x: str(x).count('?') + str(x).count('&'))

    # has_login
    df['has_login'] = df['URL'].str.contains('login', case=False, na=False).astype(int)

    # user_agent_length
    df['user_agent_length'] = df['User-Agent'].apply(lambda x: len(str(x)))

    # content_type_length
    df['content_type_length'] = df['content-type'].apply(lambda x: len(str(x)))

    # has_suspicious_keywords
    df['has_suspicious_keywords'] = df['URL'].apply(
        lambda url: int(any(kw in str(url).lower() for kw in SUSPICIOUS_KEYWORDS)))

    # body_length
    df['body_length'] = df['request_body'].apply(lambda x: len(str(x)))

    # body_has_suspicious
    df['body_has_suspicious'] = df['request_body'].apply(
        lambda x: int(any(kw in str(x).lower() for kw in SUSPICIOUS_KEYWORDS)))

    # param_entropy
    def param_entropy(url):
        try:
            params = parse_qs(urlparse(url).query)
            if not params:
                return 0
            all_keys = ''.join(params.keys())
            return len(set(all_keys)) / (len(all_keys) + 1e-5)
        except:
            return 0
    df['param_entropy'] = df['URL'].apply(param_entropy)

    # num_param_names
    def num_param_names(url):
        try:
            params = parse_qs(urlparse(url).query)
            return len(params.keys())
        except:
            return 0
    df['num_param_names'] = df['URL'].apply(num_param_names)

    # body_special_char_count
    def special_char_count(text):
        try:
            return sum(1 for c in str(text) if not c.isalnum() and not c.isspace())
        except:
            return 0
    df['body_special_char_count'] = df['request_body'].apply(special_char_count)

    # behavioral features (already computed by compute_behavioral_features)
    # No need to recompute here

    # url_domain
    def extract_domain(url):
        try:
            return urlparse(url).netloc
        except:
            return 'missing'
    df['url_domain'] = df['URL'].apply(extract_domain)

    return df

df = feature_extraction(df)

# Persist the fully processed DataFrame for inspection/reuse
# This will save all computed features and labels for transparency and reproducibility
# You can inspect this file to verify the dataset used for model training

df.to_csv('processed_web_traffic.csv', index=False)

# Remove any old is_behavioral_anomaly column if present
if 'is_behavioral_anomaly' in df.columns:
    df = df.drop(columns=['is_behavioral_anomaly'])

# Dynamically build required_cols based on use_svm_anomaly
required_cols = [
    'Method', 'User-Agent', 'host', 'content-type', 'url_domain',
    'url_length', 'num_params', 'has_login', 'user_agent_length', 'content_type_length',
    'has_suspicious_keywords', 'body_length', 'body_has_suspicious', 'param_entropy',
    'num_param_names', 'body_special_char_count',
    'requests_per_session', 'session_duration', 'mean_time_between_reqs',
    'unique_endpoints', 'user_agent_changes', 'session_duration_z', 'session_duration_outlier',
    'behavior_anomaly_score', 'behavioral_anomaly_flag',
    'classification'
]
if use_svm_anomaly:
    required_cols += ['svm_anomaly_score', 'svm_anomaly_flag']
df.dropna(subset=required_cols, inplace=True)

label_encoder = LabelEncoder()
df['classification_encoded'] = label_encoder.fit_transform(df['classification'])



# Dynamically build features based on use_svm_anomaly
features = [
    'Method', 'User-Agent', 'host', 'content-type', 'url_domain',
    'url_length', 'num_params', 'has_login', 'user_agent_length', 'content_type_length',
    'has_suspicious_keywords', 'body_length', 'body_has_suspicious', 'param_entropy',
    'num_param_names', 'body_special_char_count',
    'requests_per_session', 'session_duration', 'mean_time_between_reqs',
    'unique_endpoints', 'user_agent_changes', 'session_duration_z', 'session_duration_outlier',
    'behavior_anomaly_score', 'behavioral_anomaly_flag'
]
if use_svm_anomaly:
    features += ['svm_anomaly_score', 'svm_anomaly_flag']

X = df[features]
y = df['classification_encoded']

categorical_features = ['Method', 'User-Agent', 'host', 'content-type', 'url_domain']


# Dynamically build numerical_features based on use_svm_anomaly
numerical_features = [
    'url_length', 'num_params', 'has_login', 'user_agent_length', 'content_type_length',
    'has_suspicious_keywords', 'body_length', 'body_has_suspicious', 'param_entropy',
    'num_param_names', 'body_special_char_count',
    'requests_per_session', 'session_duration', 'mean_time_between_reqs',
    'unique_endpoints', 'user_agent_changes', 'session_duration_z', 'session_duration_outlier',
    'behavior_anomaly_score', 'behavioral_anomaly_flag'
]
if use_svm_anomaly:
    numerical_features += ['svm_anomaly_score', 'svm_anomaly_flag']

numeric_transformer = make_pipeline(SimpleImputer(strategy='median'), StandardScaler())
categorical_transformer = make_pipeline(SimpleImputer(strategy='constant', fill_value='missing'), OneHotEncoder(handle_unknown='ignore'))

preprocessor = ColumnTransformer(
    transformers=[
        ('num', numeric_transformer, numerical_features),
        ('cat', categorical_transformer, categorical_features)
    ]
)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, stratify=y, test_size=0.2, random_state=42
)

xgb = XGBClassifier(
    objective='binary:logistic',
    scale_pos_weight=(len(y_train) - sum(y_train)) / sum(y_train),
    use_label_encoder=False,
    eval_metric='logloss',
    random_state=42,
    n_estimators=120,
    max_depth=4,
    learning_rate=0.03,
    subsample=0.7,
    colsample_bytree=0.7
)

print("Training model...")
xgb_pipeline = make_pipeline(preprocessor, xgb)

# Overfitting check: train accuracy
y_train_pred = xgb_pipeline.fit(X_train, y_train).predict(X_train)
train_acc = accuracy_score(y_train, y_train_pred)



print("Evaluating model...")
y_pred = xgb_pipeline.predict(X_test)
test_acc = accuracy_score(y_test, y_pred)
print(f"Train accuracy: {train_acc:.4f}")
print(f"Test accuracy: {test_acc:.4f}")
print(f"Overfitting score (train - test): {train_acc - test_acc:.4f}")
print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))

# --- Cross-validation for more robust evaluation ---
from sklearn.model_selection import cross_val_score, StratifiedKFold
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
cv_scores = cross_val_score(xgb_pipeline, X, y, cv=cv, scoring='accuracy')
print(f"Cross-validation accuracy scores: {cv_scores}")
print(f"Mean CV accuracy: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

# --- Analyze misclassified samples (edge cases) ---
misclassified = X_test[y_pred != y_test].copy()  # Make a copy to avoid SettingWithCopyWarning
misclassified['true_label'] = label_encoder.inverse_transform(y_test[y_pred != y_test])
misclassified['predicted_label'] = label_encoder.inverse_transform(y_pred[y_pred != y_test])



# --- Feature attribution for each misclassified sample using SHAP ---
import numpy as np
# Transform features to numeric using the pipeline's preprocessor
preprocessor = xgb_pipeline.named_steps['columntransformer']
X_train_transformed = preprocessor.transform(X_train)
misclassified_transformed = preprocessor.transform(misclassified[features])
# Convert to dense numpy arrays if sparse
if hasattr(X_train_transformed, 'toarray'):
    X_train_transformed = X_train_transformed.toarray()
if hasattr(misclassified_transformed, 'toarray'):
    misclassified_transformed = misclassified_transformed.toarray()

# Get feature names after transformation
def get_feature_names(preprocessor):
    output_features = []
    for name, trans, cols in preprocessor.transformers_:
        if name == 'num':
            output_features += cols
        elif name == 'cat':
            # OneHotEncoder feature names
            encoder = trans.named_steps['onehotencoder'] if hasattr(trans, 'named_steps') else trans
            try:
                cats = encoder.get_feature_names_out(cols)
            except Exception:
                cats = cols
            output_features += list(cats)
    return output_features

feature_names_transformed = get_feature_names(preprocessor)

explainer = shap.Explainer(xgb_pipeline.named_steps['xgbclassifier'], X_train_transformed, feature_names=feature_names_transformed)
shap_values = explainer(misclassified_transformed)

# For each sample, get the top 3 features contributing to the predicted class
top_features = []
top_values = []
for i in range(len(misclassified)):
    vals = shap_values.values[i]
    # Get indices of top 3 absolute SHAP values
    top_idx = abs(vals).argsort()[-3:][::-1]
    top_feats = [feature_names_transformed[j] for j in top_idx]
    top_vals = [vals[j] for j in top_idx]
    top_features.append(';'.join(top_feats))
    top_values.append(';'.join([f"{v:.3f}" for v in top_vals]))
misclassified['top_features'] = top_features
misclassified['top_feature_values'] = top_values

misclassified.to_csv('misclassified_samples.csv', index=False)
print(f"Saved {len(misclassified)} misclassified samples to misclassified_samples.csv for analysis, with top contributing features.")

# --- Hook for adding more real-world samples ---
# To further improve generalization, add more real-world benign and attack samples to the CSV or augment_realistic_samples/add_simple_benign functions.
# You can also load additional CSVs and concatenate them here for more diversity.

print("Saving model and label encoder...")
joblib.dump(xgb_pipeline, 'xgb_model.pkl')
joblib.dump(label_encoder, 'label_encoder.pkl')

print("Training complete. Model saved.")
