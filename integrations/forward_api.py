# API Endpoint for Real-Time Request Forwarding
# This endpoint allows Burp Suite/ZAP or any external tool to forward HTTP requests for analysis.

from flask import request, jsonify
from integrations.shared_context import extract_features_from_request, model, label_encoder, detect_attack_from_strings, last_predictions, MAX_LOG_SIZE
from datetime import datetime

from flask import Blueprint
integrations_api = Blueprint('integrations_api', __name__)

@integrations_api.route('/integrations/forward', methods=['POST'])
def forward_request():
    req_json = request.get_json(force=True)
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
    if len(last_predictions) > MAX_LOG_SIZE:
        last_predictions.pop(0)
    return jsonify({
        'prediction': pred_label,
        'attack_type': attack_type,
        'features': features_dict
    }), 200
