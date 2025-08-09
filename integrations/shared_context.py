# Shared context for models, feature extraction, and prediction logic
import joblib
import os
import pandas as pd
from utils.report_generator import ReportGenerator
from utils.feedback_utils import save_feedback, load_feedback
from utils.session_visualizer import plot_session_timeline, flag_suspicious_sessions
from utils.alert_utils import send_email_alert, send_slack_alert
from utils.attack_simulator import AttackSimulator
from utils.retrain_utils import retrain_model, upload_labeled_data
from utils.train_model import train_model

# Model and encoder
model = joblib.load('xgb_model.pkl')
label_encoder = joblib.load('label_encoder.pkl')
MAX_LOG_SIZE = 50
last_predictions = []

def extract_features_from_request(req_json):
    required_fields = ['Method', 'User-Agent', 'host', 'content-type', 'URL', 'request_body']
    # Dummy implementation, replace with actual feature extraction
    df = pd.DataFrame([req_json])
    return df

def detect_attack_from_strings(url, payload):
    # Dummy implementation, replace with actual detection logic
    if 'select' in payload.lower() or 'union' in payload.lower():
        return 'malicious', 'SQLi'
    if '<script>' in payload.lower():
        return 'malicious', 'XSS'
    return 'benign', 'benign'
