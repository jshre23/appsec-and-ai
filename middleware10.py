# Serve suggestions.json for the homepage suggestions box
from flask import send_from_directory
import logging
from flask import Flask, request, jsonify, render_template
from attack_detection import detect_attack_from_strings
import pandas as pd
from urllib.parse import urlparse, parse_qs
import joblib
from datetime import datetime


app = Flask(__name__, static_folder='frontend', template_folder='frontend')

import uuid


# In-memory session store for behavioral analytics
session_store = {}
SESSION_WINDOW = 300  # seconds (5 min window for session activity)

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

@app.route('/predict', methods=['POST'])
def predict():
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

            if pred_label == 'malicious':
                if top_features:
                    reason = f"Malicious: {', '.join(top_features)} detected."
                else:
                    reason = "Malicious: suspicious pattern detected."
            elif warning:
                reason = f"Warning: suspicious payload detected but no behavioral anomaly."
            else:
                if not top_features:
                    reason = "Benign: no suspicious features detected."
                else:
                    reason = f"Benign: {', '.join(top_features)} present but not enough for attack."

            record = {
                'url': req_json.get('URL', ''),
                'request_body': req_json.get('request_body', ''),
                'label': pred_label,
                'reason': reason,
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'behavioral_anomaly_flag': features_dict.get('behavioral_anomaly_flag', 0),
                'behavior_anomaly_score': features_dict.get('behavior_anomaly_score', 0),
                'svm_anomaly_flag': features_dict.get('svm_anomaly_flag', 0),
                'svm_anomaly_score': features_dict.get('svm_anomaly_score', 0),
                'warning': warning,
                'features': features_dict
            }
            last_predictions.append(record)
            if len(last_predictions) > MAX_LOG_SIZE:
                last_predictions.pop(0)

            return jsonify({
                'success': True,
                'prediction': pred_label,
                'attack_type': attack_type,
                'reason': reason,
                'features': features_dict
            }), 200
        else:
            # Handle form POSTs (non-AJAX): fallback to redirect
            req_json = request.form.to_dict()
            features_df = extract_features_from_request(req_json)
            pred_encoded = model.predict(features_df)[0]
            pred_label = label_encoder.inverse_transform([pred_encoded])[0]

            url = req_json.get('URL', '')
            payload = req_json.get('request_body', '')
            _, attack_type = detect_attack_from_strings(url, payload)


            record = {
                'url': req_json.get('URL', ''),
                'request_body': req_json.get('request_body', ''),
                'label': pred_label,
                'reason': reason,
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'behavioral_anomaly_flag': features_dict.get('behavioral_anomaly_flag', 0),
                'behavior_anomaly_score': features_dict.get('behavior_anomaly_score', 0),
                'svm_anomaly_flag': features_dict.get('svm_anomaly_flag', 0),
                'svm_anomaly_score': features_dict.get('svm_anomaly_score', 0),
                'warning': False,
                'features': features_dict
            }
            last_predictions.append(record)
            if len(last_predictions) > MAX_LOG_SIZE:
                last_predictions.pop(0)

            features_dict = features_df.iloc[0].to_dict()
            top_features = []
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
            if pred_label == 'malicious':
                if top_features:
                    reason = f"Malicious: {', '.join(top_features)} detected."
                else:
                    reason = "Malicious: suspicious pattern detected."
            else:
                if not top_features:
                    reason = "Benign: no suspicious features detected."
                else:
                    reason = f"Benign: {', '.join(top_features)} present but not enough for attack."
            from flask import redirect, url_for
            features_str = ','.join([f"{k}:{v}" for k, v in features_dict.items()])
            return redirect(url_for('serve_result', prediction=pred_label, reason=reason, features=features_str, attack_type=attack_type))
    except ValueError as ve:
        logging.warning(f"Validation error in /predict: {ve}")
        return jsonify({'error': str(ve)}), 400
    except Exception as e:
        logging.error(f"Unexpected error in /predict: {e}")
        return jsonify({'error': 'Internal server error'}), 500

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
    logging.basicConfig(level=logging.INFO)
    app.run(host='0.0.0.0', port=5001, debug=True)
