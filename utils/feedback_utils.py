"""
User feedback utilities for marking predictions as correct/incorrect.
"""
import csv
import os

FEEDBACK_FILE = 'user_feedback.csv'

def save_feedback(request_id, prediction, correct):
    exists = os.path.isfile(FEEDBACK_FILE)
    with open(FEEDBACK_FILE, 'a', newline='') as csvfile:
        writer = csv.writer(csvfile)
        if not exists:
            writer.writerow(['request_id', 'prediction', 'correct'])
        writer.writerow([request_id, prediction, correct])

def load_feedback():
    if not os.path.isfile(FEEDBACK_FILE):
        return []
    with open(FEEDBACK_FILE, 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        return list(reader)
