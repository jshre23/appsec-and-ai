import signal
import sys
# Graceful shutdown handler
def graceful_shutdown(signum, frame):
    print("\n[INFO] Shutting down gracefully...")
    # Add any cleanup logic here (e.g., save logs, close files)
    sys.exit(0)

signal.signal(signal.SIGINT, graceful_shutdown)
signal.signal(signal.SIGTERM, graceful_shutdown)
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
from integrations.shared_context import (
    extract_features_from_request, model, label_encoder, detect_attack_from_strings, last_predictions, MAX_LOG_SIZE
)
import pandas as pd
from urllib.parse import urlparse, parse_qs
import joblib
from datetime import datetime




# Persistent prediction log file
PREDICTION_LOG_FILE = 'prediction_logs.json'

# Load logs on startup
import json
if os.path.exists(PREDICTION_LOG_FILE):
    try:
        with open(PREDICTION_LOG_FILE, 'r') as f:
            last_predictions.extend(json.load(f))
    except Exception as e:
        print(f"Error loading prediction logs: {e}")

# Save logs after each new prediction
def save_prediction_log():
    try:
        with open(PREDICTION_LOG_FILE, 'w') as f:
            json.dump(last_predictions, f, indent=2)
    except Exception as e:
        print(f"Error saving prediction logs: {e}")

app = Flask(__name__, static_folder='frontend', template_folder='frontend')
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
# Only one /detect-attack endpoint definition

# --- REPORT GENERATION ENDPOINT ---
@app.route('/generate_report', methods=['GET', 'POST'])
def generate_report():
    if request.method == 'GET':
        return jsonify({'info': 'Report generation endpoint. Use POST to regenerate.'})
    try:
        f1_score = 0.95  # Replace with actual value
        features = {k: v for k, v in (last_predictions[-1]['features'].items() if last_predictions else {})}
        attacks = sum(1 for r in last_predictions if r['label'] == 'malicious')
        blocked = sum(1 for r in last_predictions if r.get('blocked'))
        performance = 'OK'  # Replace with actual system metrics
        shap_img = '/static/shap_summary.png' if os.path.exists('static/shap_summary.png') else ''
        report = ReportGenerator(shap_values=shap_img, features=features, f1_score=f1_score, attacks=attacks, blocked=blocked, performance=performance)
        html_path = os.path.join('frontend', 'report.html')
        report.generate_html_report(html_path)
        return jsonify({'success': True, 'message': 'Report generated successfully.'}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': f'Error generating report: {e}'}), 500

@app.route('/report.html', methods=['GET'])
def serve_report_html():
    import os
    html_path = os.path.join('frontend', 'report.html')
    if not os.path.exists(html_path):
        return jsonify({'success': False, 'error': 'Report file not found. Please generate the report first.'}), 404
    return send_from_directory('frontend', 'report.html')

# --- ATTACK SIMULATION ENDPOINT ---
@app.route('/simulate_attack', methods=['GET', 'POST'])
def simulate_attack():
    if request.method == 'GET':
        return jsonify({'info': 'Simulate attack endpoint. Use POST to trigger simulation.'})
    sqli = AttackSimulator.simulate_sqli()
    xss = AttackSimulator.simulate_xss()
    lfi = AttackSimulator.simulate_lfi()
    rce = AttackSimulator.simulate_rce()
    return jsonify({'SQLi': sqli, 'XSS': xss, 'LFI': lfi, 'RCE': rce})

# --- ALERTING ENDPOINT ---
@app.route('/send_alert', methods=['POST', 'GET'])
def send_alert():
    if request.method == 'GET':
        return jsonify({'info': 'Send a POST request with alert details to trigger an alert.'})
    try:
        data = request.json
        alert_type = data.get('type')
        message = data.get('message')
        if alert_type == 'email':
            ok = send_email_alert(
                subject='Malicious Request Detected',
                body=message,
                to_email=data.get('to_email'),
                from_email=data.get('from_email'),
                smtp_server=data.get('smtp_server'),
                smtp_port=data.get('smtp_port'),
                smtp_user=data.get('smtp_user'),
                smtp_pass=data.get('smtp_pass')
            )
            return jsonify({'success': ok, 'message': 'Email alert sent.' if ok else 'Email alert failed.'})
        elif alert_type == 'slack':
            ok = send_slack_alert(data.get('webhook_url'), message)
            return jsonify({'success': ok, 'message': 'Slack alert sent.' if ok else 'Slack alert failed.'})
        return jsonify({'success': False, 'error': 'Invalid alert type'}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
@app.route('/alert_settings.html')
def alert_settings_page():
    return send_from_directory('frontend', 'alert_settings.html')

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
@app.route('/feedback', methods=['POST', 'GET'])
def feedback():
    if request.method == 'GET':
        feedback = load_feedback()
        return jsonify({'success': True, 'feedback': feedback})
    data = request.json
    request_id = data.get('request_id')
    prediction = data.get('prediction')
    correct = data.get('correct')
    feedback_type = data.get('feedback')
    text_feedback = data.get('text_feedback')
    feedback_record = {
        'request_id': request_id,
        'prediction': prediction,
        'correct': correct,
        'feedback': feedback_type,
        'text_feedback': text_feedback
    }
    save_feedback(**feedback_record)
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
        output.append(','.join(str(row.get(k, '')) for k in keys))
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
import traceback
try:
    from integrations.forward_api import integrations_api
    app.register_blueprint(integrations_api, url_prefix='/integrations')
    print("[INFO] /integrations/forward endpoint registered successfully.")
except Exception as e:
    print(f"[ERROR] Burp/ZAP integration import failed: {e}")
    traceback.print_exc()

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

MAX_LOG_SIZE = 50
last_predictions = []

@app.route('/suggestions.json')
def serve_suggestions():
    return send_from_directory('frontend', 'suggestions.json')

@app.route('/predict', methods=['POST', 'GET'])
def predict():
    if request.method == 'GET':
        return jsonify({'info': 'Prediction endpoint. Use POST to send data.'})
    try:
        if request.is_json:
            req_json = request.get_json(force=True)
            if not req_json:
                return jsonify({'error': 'Invalid or missing JSON in request'}), 400
            features_df = extract_features_from_request(req_json)
            pred_encoded = model.predict(features_df)[0]
            pred_label = label_encoder.inverse_transform([pred_encoded])[0]
            url = req_json.get('URL', '')
            payload = req_json.get('request_body', '')
            _, attack_type = detect_attack_from_strings(url, payload)
            # Consistency logic: if model says malicious but attack_type is benign, set attack_type to 'unknown' and add explanation
            explanation = ''
            if pred_label == 'malicious' and attack_type == 'benign':
                attack_type = 'unknown'
                explanation = 'Model flagged this as malicious based on features, but no known attack pattern was detected.'
            elif pred_label == 'benign' and attack_type != 'benign':
                explanation = 'Known attack pattern detected, but model did not flag as malicious.'
            features_dict = features_df.iloc[0].to_dict()
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
            if (features_dict.get('has_suspicious_keywords', 0) or features_dict.get('body_has_suspicious', 0)) \
                and not features_dict.get('behavioral_anomaly_flag', 0):
                warning = True
            reason = ', '.join(top_features) if top_features else 'No suspicious features detected.'
            pred_record = {
                'url': url,
                'request_body': payload,
                'label': pred_label,
                'reason': reason,
                'attack_type': attack_type,
                'features': features_dict,
                'warning': warning,
                'behavioral_anomaly_flag': features_dict.get('behavioral_anomaly_flag', 0),
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
            last_predictions.append(pred_record)
            save_prediction_log()
            if len(last_predictions) > MAX_LOG_SIZE:
                last_predictions.pop(0)
                save_prediction_log()
            return jsonify({
                'prediction': pred_label,
                'reason': reason,
                'attack_type': attack_type,
                'features': features_dict,
                'warning': warning,
                'explanation': explanation,
                'flagged_features': top_features if pred_label == 'malicious' else []
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
    # Try to load F1 score and feature importance from model training (if available)
    import logging
    error_messages = []
    try:
        import os
        import joblib
        from utils.train_model import train_model
        import pandas as pd
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import seaborn as sns
        import shap
        df = pd.read_csv('processed_web_traffic.csv')
        # Automatic cleaning: remove columns with lists/dicts, convert numeric columns
        for col in df.columns:
            if df[col].apply(lambda x: isinstance(x, (list, dict))).any():
                df.drop(columns=[col], inplace=True)
        # Try to convert object columns to float if possible
        for col in df.select_dtypes(include='object').columns:
            try:
                df[col] = df[col].astype(float)
            except:
                pass
        model, f1, shap_values, feature_importance = train_model(df)
        f1_score_val = round(f1, 3)
        # Feature importance
        sorted_features = sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)
        feature_importance_list = [f[0] for f in sorted_features[:5]]

    except Exception as e:
        msg = f'/stats error: {e}'
        logging.error(msg)
        error_messages.append(msg)
        f1_score_val = 'N/A'
        feature_importance_list = []
    # System performance: basic check (can be expanded)
    system_status = 'OK' if f1_score_val != 'N/A' and total > 0 else 'Needs Attention'
    return jsonify({
        'total': total,
        'benign': benign,
        'malicious': malicious,
        'status': system_status,
        'f1_score': f1_score_val,
        'feature_importance': feature_importance_list
    }), 200


# Serve logs.html page
@app.route('/logs', methods=['GET'])
def serve_logs():
    from flask import request
    if request.args.get('json') == '1':
        # Return all logs as JSON for the logs page
        return jsonify({'success': True, 'logs': last_predictions[::-1]}), 200
    return render_template('logs.html')


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
