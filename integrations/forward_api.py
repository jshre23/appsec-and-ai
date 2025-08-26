# API Endpoint for Real-Time Request Forwarding
# This endpoint allows Burp Suite/ZAP or any external tool to forward HTTP requests for analysis.

from flask import request, jsonify
from integrations.shared_context import extract_features_from_request, model, label_encoder, detect_attack_from_strings, last_predictions, MAX_LOG_SIZE
from datetime import datetime

from flask import Blueprint
integrations_api = Blueprint('integrations_api', __name__)

@integrations_api.route('/forward', methods=['POST'])
def forward_request():
    req_json = request.get_json(force=True)
    # Fill missing fields with safe defaults
    required_fields = [
        'URL', 'request_body', 'User-Agent', 'Method', 'num_params', 'session_duration', 'user_agent_length',
        'url_length', 'svm_anomaly_flag', 'body_special_char_count', 'svm_anomaly_score', 'url_domain',
        'param_entropy', 'num_param_names', 'user_agent_changes', 'body_has_suspicious', 'session_duration_z',
        'has_suspicious_keywords', 'has_login', 'unique_endpoints', 'behavioral_anomaly_flag', 'requests_per_session',
        'content_type_length', 'mean_time_between_reqs', 'body_length', 'session_duration_outlier', 'behavior_anomaly_score',
        'content-type', 'host'
    ]
    defaults = {
        'User-Agent': 'Unknown', 'Method': 'GET', 'num_params': 0, 'session_duration': 0, 'user_agent_length': 0,
        'url_length': 0, 'svm_anomaly_flag': 0, 'body_special_char_count': 0, 'svm_anomaly_score': 0.0, 'url_domain': '',
        'param_entropy': 0.0, 'num_param_names': 0, 'user_agent_changes': 0, 'body_has_suspicious': 0, 'session_duration_z': 0.0,
        'has_suspicious_keywords': 0, 'has_login': 0, 'unique_endpoints': 0, 'behavioral_anomaly_flag': 0, 'requests_per_session': 0,
        'content_type_length': 0, 'mean_time_between_reqs': 0, 'body_length': 0, 'session_duration_outlier': 0, 'behavior_anomaly_score': 0.0,
        'content-type': '', 'host': ''
    }
    for field in required_fields:
        if field not in req_json:
            req_json[field] = defaults.get(field, '')
    features_df = extract_features_from_request(req_json)
    pred_encoded = model.predict(features_df)[0]
    pred_label = label_encoder.inverse_transform([pred_encoded])[0]
    url = req_json.get('URL', '')
    payload = req_json.get('request_body', '')
    _, attack_type = detect_attack_from_strings(url, payload)
    features_dict = features_df.iloc[0].to_dict()
    record = {
        'url': url,
        'request_body': payload,
        'label': pred_label,
        'reason': 'Forwarded from Burp/ZAP',
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'features': features_dict,
        'integration': True
    }
    last_predictions.append(record)
    try:
        from middleware10 import save_prediction_log
        save_prediction_log()
    except Exception:
        pass
    if len(last_predictions) > MAX_LOG_SIZE:
        last_predictions.pop(0)
        try:
            from middleware10 import save_prediction_log
            save_prediction_log()
        except Exception:
            pass
    return jsonify({
        'prediction': pred_label,
        'attack_type': attack_type,
        'features': features_dict
    }), 200
