# Serve suggestions.json for the homepage suggestions box
from flask import send_from_directory
from utils.report_generator import ReportGenerator
from utils.attack_simulator import AttackSimulator
from utils.alert_utils import send_email_alert, send_slack_alert
from utils.feedback_utils import save_feedback, load_feedback
from utils.session_visualizer import plot_session_timeline, flag_suspicious_sessions
from utils.retrain_utils import upload_labeled_data, retrain_model
import os
import logging
from flask import Flask, request, jsonify, render_template
from attack_detection import detect_attack_from_strings
import pandas as pd
from urllib.parse import urlparse, parse_qs
import joblib
from datetime import datetime



# Setup logging for blocked requests
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[
        logging.FileHandler('blocked_requests.log'),
        logging.StreamHandler()
    ]
)

app = Flask(__name__, static_folder='frontend', template_folder='frontend')
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
# Only one /detect-attack endpoint definition

# --- REPORT GENERATION ENDPOINT ---
@app.route('/generate_report', methods=['GET'])
def generate_report():
    # Example: Use last_predictions for report data
    f1_score = 0.95  # Replace with actual value
    features = {k: v for k, v in (last_predictions[-1]['features'].items() if last_predictions else {})}
    attacks = sum(1 for r in last_predictions if r['label'] == 'malicious')
    blocked = sum(1 for r in last_predictions if r.get('blocked'))
    performance = 'OK'  # Replace with actual system metrics
    shap_img = '/static/shap_summary.png' if os.path.exists('static/shap_summary.png') else ''
    report = ReportGenerator(shap_values=shap_img, features=features, f1_score=f1_score, attacks=attacks, blocked=blocked, performance=performance)
    html_path = os.path.join('frontend', 'report.html')
    report.generate_html_report(html_path)
    return send_from_directory('frontend', 'report.html')

@app.route('/report.html')
def serve_report_html():
    import os
    html_path = os.path.join('frontend', 'report.html')
    if not os.path.exists(html_path):
        try:
            features = {k: v for k, v in (last_predictions[-1]['features'].items() if last_predictions else {})}
            attacks = sum(1 for r in last_predictions if r['label'] == 'malicious')
            blocked = sum(1 for r in last_predictions if r.get('blocked'))
            f1_score = 0.0
            performance = {}
            shap_img = None
            report = ReportGenerator(shap_values=shap_img, features=features, f1_score=f1_score, attacks=attacks, blocked=blocked, performance=performance)
            report.generate_html_report(html_path)
        except Exception as e:
            return f"Error generating report: {e}", 500
    return send_from_directory('frontend', 'report.html')

# --- ATTACK SIMULATION ENDPOINT ---
@app.route('/simulate_attack', methods=['GET'])
def simulate_attack():
    sqli = AttackSimulator.simulate_sqli()
    xss = AttackSimulator.simulate_xss()
    lfi = AttackSimulator.simulate_lfi()
    rce = AttackSimulator.simulate_rce()
    return jsonify({'SQLi': sqli, 'XSS': xss, 'LFI': lfi, 'RCE': rce})

# --- ALERTING ENDPOINT ---
@app.route('/send_alert', methods=['POST'])
def send_alert():
    data = request.json
    alert_type = data.get('type')
    message = data.get('message')
    if alert_type == 'email':
        ok = send_email_alert(
            subject='Malicious Request Detected',
            body=message,
            to_email=data['to_email'],
            from_email=data['from_email'],
            smtp_server=data['smtp_server'],
            smtp_port=data['smtp_port'],
            smtp_user=data['smtp_user'],
            smtp_pass=data['smtp_pass']
        )
        return jsonify({'success': ok})
    elif alert_type == 'slack':
        ok = send_slack_alert(data['webhook_url'], message)
        return jsonify({'success': ok})
    return jsonify({'error': 'Invalid alert type'}), 400

# --- UPLOAD & RETRAIN ENDPOINT ---
@app.route('/upload_labeled_data', methods=['POST'])
def upload_labeled_data_api():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    file = request.files['file']
    path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(path)
    df = upload_labeled_data(path)
    return jsonify({'rows': len(df)})

@app.route('/retrain_model', methods=['POST'])
def retrain_model_api():
    data = request.json
    data_path = data.get('data_path')
    if not data_path or not os.path.exists(data_path):
        return jsonify({'error': 'Invalid data path'}), 400
    f1 = retrain_model(data_path)
    return jsonify({'f1_score': f1})

# --- USER FEEDBACK ENDPOINT ---
@app.route('/feedback', methods=['POST'])
def feedback():
    data = request.json
    save_feedback(data['request_id'], data['prediction'], data['correct'])
    return jsonify({'success': True})

@app.route('/feedback', methods=['GET'])
def get_feedback():
    feedback = load_feedback()
    return jsonify(feedback)

# --- DOWNLOAD FEEDBACK ENDPOINT ---
@app.route('/download_feedback', methods=['GET'])
def download_feedback():
    feedback = load_feedback()
    import csv
    from flask import Response
    # Convert feedback to CSV
    if not feedback:
        return Response('No feedback available.', mimetype='text/plain')
    keys = feedback[0].keys() if isinstance(feedback, list) and feedback else []
    output = []
    output.append(','.join(keys))
    for row in feedback:
        output.append(','.join(str(row[k]) for k in keys))
    csv_data = '\n'.join(output)
    return Response(csv_data, mimetype='text/csv', headers={"Content-disposition": "attachment; filename=feedback.csv"})

# --- SESSION VISUALIZATION ENDPOINT ---
@app.route('/session_timeline', methods=['GET'])
def session_timeline():
    # Example: Use session_store for session data
    session_data = []
    for sid, sess in session_store.items():
        for req in sess['requests']:
            session_data.append({'session_id': sid, 'timestamp': req['timestamp'], 'activity': req['url']})
    img_path = plot_session_timeline(session_data)
    suspicious = flag_suspicious_sessions(session_data)
    return jsonify({'timeline_image': img_path, 'suspicious_sessions': suspicious})

import uuid



# In-memory session store for behavioral analytics
session_store = {}
SESSION_WINDOW = 300  # seconds (5 min window for session activity)

# --- Burp/ZAP Integration Endpoint Registration ---
try:
    from integrations.forward_api import integrations_api
    app.register_blueprint(integrations_api, url_prefix='/integrations')
except Exception as e:
    print(f"Burp/ZAP integration import failed: {e}")

# --- Persistent anomaly models trained on synthetic normal data ---
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
import numpy as np
import pandas as pd

# Use typical normal values from training for synthetic fit
normal_sample = pd.DataFrame({
    'requests_per_session': np.random.randint(1, 10, 100),
    'session_duration': np.random.uniform(0, 120, 100),
    'mean_time_between_reqs': np.random.uniform(0, 20, 100),
    'unique_endpoints': np.random.randint(1, 10, 100),
    'user_agent_changes': np.random.randint(1, 4, 100)
})
iso_model = IsolationForest(contamination=0.05, random_state=42)
iso_model.fit(normal_sample)
svm_model = OneClassSVM(gamma='scale', nu=0.05)
svm_model.fit(normal_sample)

# Only one /detect-attack endpoint definition
@app.route('/detect-attack', methods=['POST'])
def detect_attack_api():
    data = request.get_json(force=True)
    url = data.get('URL', '')
    payload = data.get('request_body', '')
    label, attack_type = detect_attack_from_strings(url, payload)
    return jsonify({'label': label, 'attack_type': attack_type}), 200

model = joblib.load('xgb_model.pkl')
label_encoder = joblib.load('label_encoder.pkl')
MAX_LOG_SIZE = 50
last_predictions = []

def extract_features_from_request(req_json):
    required_fields = ['Method', 'User-Agent', 'host', 'content-type', 'URL', 'request_body']
    missing_fields = [key for key in required_fields if key not in req_json]
    if missing_fields:
        raise ValueError(f"Missing required JSON fields: {missing_fields}")

    import numpy as np
    from datetime import datetime
    from sklearn.ensemble import IsolationForest
    df = pd.DataFrame([req_json])
    # ...existing code for basic features...
    df['url_length'] = df['URL'].apply(lambda x: len(str(x)))
    df['num_params'] = df['URL'].apply(lambda x: str(x).count('?') + str(x).count('&'))
    df['has_login'] = df['URL'].str.contains('login', case=False, na=False).astype(int)
    df['user_agent_length'] = df['User-Agent'].apply(lambda x: len(str(x)))
    df['content_type_length'] = df['content-type'].apply(lambda x: len(str(x)))
    SUSPICIOUS_KEYWORDS = [
        'select', 'union', 'insert', 'drop', 'script', 'alert', 'sleep',
        'gopher', 'file', 'meta-data', 'passwd', 'iframe', 'svg', 'onerror', 'onload', 'fetch'
    ]
    df['has_suspicious_keywords'] = df['URL'].apply(
        lambda url: int(any(kw in str(url).lower() for kw in SUSPICIOUS_KEYWORDS)))
    df['body_length'] = df['request_body'].apply(lambda x: len(str(x)))
    df['body_has_suspicious'] = df['request_body'].apply(
        lambda x: int(any(kw in str(x).lower() for kw in SUSPICIOUS_KEYWORDS)))
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
    def num_param_names(url):
        try:
            params = parse_qs(urlparse(url).query)
            return len(params.keys())
        except:
            return 0
    df['num_param_names'] = df['URL'].apply(num_param_names)
    def body_special_char_count(body):
        special_chars = ['"', '\'', ';', '{', '}', '[', ']', '(', ')', '/', '\\', '@', '$', '%', '^', '&', '*', '=', '+', '|', '`', '~', ':']
        return sum(str(body).count(c) for c in special_chars)
    df['body_special_char_count'] = df['request_body'].apply(body_special_char_count)
    def extract_domain(url):
        try:
            return urlparse(url).netloc
        except:
            return 'missing'
    df['url_domain'] = df['URL'].apply(extract_domain)

    # --- Behavioral features: session tracking ---
    # Use session_id if provided, else generate one per user-agent+host
    now = datetime.utcnow()
    session_id = req_json.get('session_id')
    if not session_id:
        # Use a hash of user-agent+host as pseudo-session
        session_id = f"sess_{hash(req_json.get('User-Agent', '')) % 10000}_{hash(req_json.get('host', '')) % 10000}"
    # Clean up old sessions
    expired = [sid for sid, sess in session_store.items() if (now - sess['last_seen']).total_seconds() > SESSION_WINDOW]
    for sid in expired:
        del session_store[sid]
    # Update session store
    sess = session_store.get(session_id, {'requests': [], 'user_agents': set(), 'endpoints': set(), 'first_seen': now, 'last_seen': now})
    sess['requests'].append({'timestamp': now, 'url': req_json.get('URL', ''), 'user_agent': req_json.get('User-Agent', '')})
    sess['user_agents'].add(req_json.get('User-Agent', ''))
    try:
        parsed_url = urlparse(req_json.get('URL', ''))
        endpoint = parsed_url.path
    except Exception:
        endpoint = req_json.get('URL', '')
    sess['endpoints'].add(endpoint)
    sess['last_seen'] = now
    session_store[session_id] = sess
    # Compute behavioral features over session window
    reqs = [r for r in sess['requests'] if (now - r['timestamp']).total_seconds() <= SESSION_WINDOW]
    timestamps = [r['timestamp'] for r in reqs]
    endpoints = [r['url'] for r in reqs]
    user_agents = [r['user_agent'] for r in reqs]
    df['requests_per_session'] = len(reqs)
    if len(timestamps) > 1:
        df['session_duration'] = (max(timestamps) - min(timestamps)).total_seconds()
        df['mean_time_between_reqs'] = np.mean([ (t2-t1).total_seconds() for t1, t2 in zip(sorted(timestamps)[:-1], sorted(timestamps)[1:]) ])
    else:
        df['session_duration'] = 0
        df['mean_time_between_reqs'] = 0
    df['unique_endpoints'] = len(set(endpoints))
    df['user_agent_changes'] = len(set(user_agents))
    # For z-score and outlier, use typical values from training
    mean_sess = 10
    std_sess = 10
    df['session_duration_z'] = (df['session_duration'] - mean_sess) / (std_sess + 1e-6)
    df['session_duration_outlier'] = (abs(df['session_duration_z']) > 2).astype(int)
    behavioral_cols = ['requests_per_session', 'session_duration', 'mean_time_between_reqs', 'unique_endpoints', 'user_agent_changes']
    try:
        df['behavior_anomaly_score'] = -iso_model.decision_function(df[behavioral_cols].fillna(0))
        df['behavioral_anomaly_flag'] = (df['behavior_anomaly_score'] > 0.4).astype(int)
    except Exception:
        df['behavior_anomaly_score'] = 0.0
        df['behavioral_anomaly_flag'] = 0
    # --- SVM anomaly features (persistent model) ---
    if 'svm_anomaly_score' not in df.columns or 'svm_anomaly_flag' not in df.columns:
        try:
            df['svm_anomaly_score'] = -svm_model.decision_function(df[behavioral_cols].fillna(0))
            df['svm_anomaly_flag'] = (df['svm_anomaly_score'] > 0.0).astype(int)
        except Exception:
            df['svm_anomaly_score'] = 0.0
            df['svm_anomaly_flag'] = 0
    features = [
        'Method', 'User-Agent', 'host', 'content-type', 'url_domain',
        'url_length', 'num_params', 'has_login', 'user_agent_length', 'content_type_length',
        'has_suspicious_keywords', 'body_length', 'body_has_suspicious', 'param_entropy',
        'num_param_names', 'body_special_char_count',
        'requests_per_session', 'session_duration', 'mean_time_between_reqs',
        'unique_endpoints', 'user_agent_changes', 'session_duration_z', 'session_duration_outlier',
        'behavior_anomaly_score', 'behavioral_anomaly_flag',
        'svm_anomaly_score', 'svm_anomaly_flag'
    ]
    return df[features]

@app.route('/suggestions.json')
def serve_suggestions():
    return send_from_directory('frontend', 'suggestions.json')

@app.route('/predict', methods=['POST', 'GET'])
def predict():
    if request.method == 'GET':
        return "Predict endpoint is working. Use POST to send data.", 200
    try:
        if request.is_json:
            req_json = request.get_json(force=True)
            if not req_json:
                return jsonify({'error': 'Invalid or missing JSON in request'}), 400

            features_df = extract_features_from_request(req_json)
            pred_encoded = model.predict(features_df)[0]
            pred_label = label_encoder.inverse_transform([pred_encoded])[0]

            # Use shared attack detection logic for attack type
            url = req_json.get('URL', '')
            payload = req_json.get('request_body', '')
            _, attack_type = detect_attack_from_strings(url, payload)

            features_dict = features_df.iloc[0].to_dict()

            # Compose a meaningful reason and warning state
            top_features = []
            warning = False
            if features_dict.get('has_suspicious_keywords', 0):
                top_features.append('suspicious keywords')
            if features_dict.get('body_has_suspicious', 0):
                top_features.append('suspicious payload')
            if features_dict.get('body_special_char_count', 0) > 5:
                top_features.append('many special characters')
            if features_dict.get('num_params', 0) > 2:
                top_features.append('many URL parameters')
            if features_dict.get('behavioral_anomaly_flag', 0):
                top_features.append('behavioral anomaly')

            # Warning: suspicious payload but no behavioral anomaly
            if (features_dict.get('has_suspicious_keywords', 0) or features_dict.get('body_has_suspicious', 0)) \
                and not features_dict.get('behavioral_anomaly_flag', 0):
                warning = True

            reason = ', '.join(top_features) if top_features else 'No suspicious features detected.'

            # Save prediction for logs and reporting
            pred_record = {
                'url': url,
                'request_body': payload,
                'label': pred_label,
                'reason': reason,
                'attack_type': attack_type,
                'features': features_dict,
                'warning': warning,
                'behavioral_anomaly_flag': features_dict.get('behavioral_anomaly_flag', 0)
            }
            last_predictions.append(pred_record)
            if len(last_predictions) > MAX_LOG_SIZE:
                last_predictions.pop(0)

            return jsonify({
                'prediction': pred_label,
                'reason': reason,
                'attack_type': attack_type,
                'features': features_dict,
                'warning': warning
            }), 200
        else:
            return jsonify({'error': 'Request must be JSON'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/stats', methods=['GET'])
def stats():
    total = len(last_predictions)
    benign = sum(1 for p in last_predictions if p['label'] == 'benign')
    malicious = sum(1 for p in last_predictions if p['label'] == 'malicious')
    # Return keys as expected by frontend: total, benign, malicious
    return jsonify({
        'total': total,
        'benign': benign,
        'malicious': malicious
    }), 200

@app.route('/logs', methods=['GET'])
def logs():
    recent_logs = last_predictions[-10:][::-1]
    return jsonify({'success': True, 'logs': recent_logs}), 200


@app.route('/last_predictions', methods=['GET'])
def last_predictions_api():
    # Return the last 10 predictions with all relevant fields for the home page table
    # Reverse order: most recent first
    rows = []
    for pred in last_predictions:
        # User-friendly explanations
        beh_flag = pred.get('behavioral_anomaly_flag', 0)
        beh_score = pred.get('behavior_anomaly_score', 0)
        svm_flag = pred.get('svm_anomaly_flag', 0)
        svm_score = pred.get('svm_anomaly_score', 0)
        beh_expl = "This request's behavior is {} compared to normal user activity.".format(
            "UNUSUAL" if beh_flag else "normal"
        )
        svm_expl = "This request is {} based on a general anomaly check (SVM).".format(
            "UNUSUAL" if svm_flag else "normal"
        )
        row = {
            'url': pred.get('url', ''),
            'request_body': pred.get('request_body', ''),
            'label': pred.get('label', ''),
            'reason': pred.get('reason', ''),
            'behavioral_anomaly_flag': beh_flag,
            'behavior_anomaly_score': beh_score,
            'svm_anomaly_flag': svm_flag,
            'svm_anomaly_score': svm_score,
            'behavioral_anomaly_explanation': beh_expl,
            'svm_anomaly_explanation': svm_expl,
            'warning': pred.get('warning', False),
            'features': pred.get('features', {})
        }
        rows.append(row)
    return jsonify(rows), 200

# Serve main pages using render_template
@app.route('/')
def root():
    return render_template('home.html')

@app.route('/simulate')
def serve_simulate():
    return render_template('simulate.html')

@app.route('/manual')
def serve_manual():
    return render_template('manual.html')

# Dynamic result page
@app.route('/result', methods=['GET'])
def serve_result():
    # Example: get prediction, reason, features from query params or session
    prediction = request.args.get('prediction', 'benign')
    reason = request.args.get('reason', 'No specific reason detected.')
    attack_type = request.args.get('attack_type', 'benign')
    # For demo, parse features from query string as comma-separated key:value
    features_raw = request.args.get('features', '')
    features = {}
    try:
        if features_raw:
            for item in features_raw.split(','):
                if ':' in item:
                    k, v = item.split(':', 1)
                    features[k.strip()] = v.strip()
        if not features:
            features = {'User-Agent': 'Chrome', 'IP': '192.168.1.1'}
    except Exception as e:
        features = {'Error': 'Could not parse features'}
    return render_template('result.html', prediction=prediction, reason=reason, features=features, attack_type=attack_type)

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'OK'}), 200

if __name__ == '__main__':
    try:
        from flask_cors import CORS
        CORS(app)
    except ImportError:
        print("flask_cors not installed, skipping CORS setup.")
    logging.basicConfig(level=logging.INFO)
    app.run(host='0.0.0.0', port=5000, debug=True)
