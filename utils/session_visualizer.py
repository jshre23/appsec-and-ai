"""
Visualize user sessions, flag suspicious patterns, and show session timelines.
"""
import matplotlib.pyplot as plt
import pandas as pd
import os

def plot_session_timeline(session_data, output_path='session_timeline.png'):
    df = pd.DataFrame(session_data)
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df = df.sort_values('timestamp')
    plt.figure(figsize=(10, 4))
    for session_id, group in df.groupby('session_id'):
        plt.plot(group['timestamp'], group['activity'], label=f'Session {session_id}')
    plt.xlabel('Time')
    plt.ylabel('Activity')
    plt.title('User Session Timelines')
    plt.legend()
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()
    return output_path

def flag_suspicious_sessions(session_data, threshold=10):
    df = pd.DataFrame(session_data)
    suspicious = df.groupby('session_id').filter(lambda x: len(x) > threshold)
    return suspicious['session_id'].unique().tolist()
