"""
Utilities for uploading new labeled data and retraining the model.
"""
import pandas as pd
import joblib
from training_new import train_model

def upload_labeled_data(file_path):
    # Assume CSV format
    df = pd.read_csv(file_path)
    return df

def retrain_model(data_path, model_path='xgb_model.pkl'):
    df = pd.read_csv(data_path)
    model, f1 = train_model(df)
    joblib.dump(model, model_path)
    return f1
