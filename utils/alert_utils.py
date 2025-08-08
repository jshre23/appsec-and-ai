"""
Alert utilities for sending notifications via email and Slack.
"""
import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_email_alert(subject, body, to_email, from_email, smtp_server, smtp_port, smtp_user, smtp_pass):
    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))
    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.sendmail(from_email, to_email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"Email alert failed: {e}")
        return False

def send_slack_alert(webhook_url, message):
    payload = {"text": message}
    try:
        response = requests.post(webhook_url, json=payload)
        return response.status_code == 200
    except Exception as e:
        print(f"Slack alert failed: {e}")
        return False
