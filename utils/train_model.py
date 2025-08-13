"""
Train model utility for retraining and report generation.
"""
import pandas as pd
import joblib
from training_new import compute_behavioral_features
from sklearn.metrics import f1_score
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler, LabelEncoder
from sklearn.impute import SimpleImputer
import shap

def train_model(df):
    df = compute_behavioral_features(df)
    label_encoder = LabelEncoder()
    df['classification_encoded'] = label_encoder.fit_transform(df['classification'])
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
    X = df[features]
    y = df['classification_encoded']
    categorical_features = ['Method', 'User-Agent', 'host', 'content-type', 'url_domain']
    numerical_features = [
        'url_length', 'num_params', 'has_login', 'user_agent_length', 'content_type_length',
        'has_suspicious_keywords', 'body_length', 'body_has_suspicious', 'param_entropy',
        'num_param_names', 'body_special_char_count',
        'requests_per_session', 'session_duration', 'mean_time_between_reqs',
        'unique_endpoints', 'user_agent_changes', 'session_duration_z', 'session_duration_outlier',
        'behavior_anomaly_score', 'behavioral_anomaly_flag',
        'svm_anomaly_score', 'svm_anomaly_flag'
    ]
    numeric_transformer = make_pipeline(SimpleImputer(strategy='median'), StandardScaler())
    categorical_transformer = make_pipeline(SimpleImputer(strategy='constant', fill_value='missing'), OneHotEncoder(handle_unknown='ignore'))
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', numeric_transformer, numerical_features),
            ('cat', categorical_transformer, categorical_features)
        ]
    )
    X_train, X_test, y_train, y_test = train_test_split(X, y, stratify=y, test_size=0.2, random_state=42)
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
    xgb_pipeline = make_pipeline(preprocessor, xgb)
    xgb_pipeline.fit(X_train, y_train)
    y_pred = xgb_pipeline.predict(X_test)
    f1 = f1_score(y_test, y_pred)
    # SHAP summary
    explainer = shap.Explainer(
        xgb_pipeline.named_steps['xgbclassifier'],
        preprocessor.transform(X_train).toarray()  # Convert sparse to dense
    )
    X_test_dense = preprocessor.transform(X_test)
    if hasattr(X_test_dense, 'toarray'):
        X_test_dense = X_test_dense.toarray()
    X_test_dense = X_test_dense.astype(float)
    shap_values = explainer(X_test_dense)
    feature_importance = dict(zip(features, xgb_pipeline.named_steps['xgbclassifier'].feature_importances_))
    return xgb_pipeline, f1, shap_values, feature_importance
