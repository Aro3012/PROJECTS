import pandas as pd
import numpy as np
import time
import psycopg2
import threading
import requests
from flask import Flask, jsonify
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from scapy.all import sniff, IP, TCP, UDP
from transformers import pipeline

# Initialize LLM model for anomaly detection
llm = pipeline("text-classification", model="distilbert-base-uncased-finetuned-sst-2-english")

# Database connection
DB_CONFIG = "dbname=network user=postgres password=yourpassword host=localhost"

def log_to_db(df):
    conn = psycopg2.connect(DB_CONFIG)
    cursor = conn.cursor()
    for _, row in df.iterrows():
        cursor.execute("""
            INSERT INTO network_logs (src_ip, dst_ip, protocol, port, anomaly, llm_anomaly)
            VALUES (%s, %s, %s, %s, %s, %s);
        """, (row['src_ip'], row['dst_ip'], row['protocol'], row['port'], row['anomaly'], row['llm_anomaly']))
    conn.commit()
    conn.close()

def send_discord_alert(anomaly_df):
    DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/YOUR_WEBHOOK"
    message = f"🚨 Network Anomaly Detected:\n{anomaly_df.to_string()}"
    requests.post(DISCORD_WEBHOOK_URL, json={"content": message})

def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        protocol, port = ("TCP", packet[TCP].dport) if TCP in packet else ("UDP", packet[UDP].dport) if UDP in packet else ("Other", None)
        return [src_ip, dst_ip, protocol, port, proto]
    return None

def capture_network_logs(packet_count=100):
    logs = []
    sniff(prn=lambda pkt: logs.append(process_packet(pkt)), count=packet_count, store=0)
    return [log for log in logs if log]

def monitor_network():
    df = pd.DataFrame(columns=["src_ip", "dst_ip", "protocol", "port", "proto"])
    while True:
        new_logs = capture_network_logs(packet_count=50)
        new_df = pd.DataFrame(new_logs, columns=["src_ip", "dst_ip", "protocol", "port", "proto"])
        if not new_df.empty:
            df = pd.concat([df, new_df], ignore_index=True)

        df['timestamp'] = pd.to_datetime("now")
        df['weekday'] = df['timestamp'].dt.weekday
        df['hour'] = df['timestamp'].dt.hour
        df['is_weekend'] = ((df['weekday'] == 5) | (df['weekday'] == 6)).astype(int)
        df.dropna(inplace=True)

        features = ['weekday', 'hour', 'is_weekend', 'proto']
        X = df[features]
        X_scaled = StandardScaler().fit_transform(X)
        pca = PCA(n_components=2)
        X_pca = pca.fit_transform(X_scaled) if np.any(np.var(X_scaled, axis=0) != 0) else X_scaled

        model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
        model.fit(X_pca)
        df['anomaly'] = model.predict(X_pca)
        df['anomaly'] = df['anomaly'].apply(lambda x: 'Anomaly' if x == -1 else 'Normal')

        texts = df.apply(lambda row: f"Source: {row['src_ip']}, Dest: {row['dst_ip']}, Protocol: {row['protocol']}, Port: {row['port']}, Time: {row['hour']}", axis=1).tolist()
        df['llm_anomaly'] = [result['label'] for result in llm(texts)]

        anomalies = df[df['anomaly'] == 'Anomaly']
        if not anomalies.empty:
            log_to_db(anomalies)
            send_discord_alert(anomalies)

        time.sleep(10)

def fetch_logs():
    conn = psycopg2.connect(DB_CONFIG)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM network_logs ORDER BY timestamp DESC LIMIT 100")
    logs = cursor.fetchall()
    conn.close()
    return logs

app = Flask(__name__)

@app.route('/logs', methods=['GET'])
def get_logs():
    logs = fetch_logs()
    return jsonify(logs)

if __name__ == "__main__":
    threading.Thread(target=monitor_network, daemon=True).start()
    app.run(host='0.0.0.0', port=5000)