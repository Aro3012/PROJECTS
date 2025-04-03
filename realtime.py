import pandas as pd
import numpy as np
import re
import time
import seaborn as sns
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
import matplotlib.pyplot as plt
from scapy.all import sniff, IP, TCP, UDP
from transformers import pipeline

# Initialize LLM model for anomaly detection
llm = pipeline("text-classification", model="distilbert-base-uncased-finetuned-sst-2-english")

# Function to process network packets
def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        
        if TCP in packet:
            protocol = "TCP"
            port = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            port = packet[UDP].dport
        else:
            protocol = "Other"
            port = None
        
        return [src_ip, dst_ip, protocol, port, proto]
    return None

# Capture network logs
def capture_network_logs(packet_count=100):
    logs = []
    sniff(prn=lambda pkt: logs.append(process_packet(pkt)), count=packet_count, store=0)
    return [log for log in logs if log]

# Monitor network logs in real-time
def monitor_network():
    df = pd.DataFrame(columns=["src_ip", "dst_ip", "protocol", "port", "proto"])
    
    while True:
        new_logs = capture_network_logs(packet_count=50)
        new_df = pd.DataFrame(new_logs, columns=["src_ip", "dst_ip", "protocol", "port", "proto"])
        if not new_df.empty:
            df = pd.concat([df, new_df], ignore_index=True)

        
        # Feature Engineering
        df['timestamp'] = pd.to_datetime("now")
        df['weekday'] = df['timestamp'].dt.weekday
        df['hour'] = df['timestamp'].dt.hour
        df['is_weekend'] = ((df['weekday'] == 5) | (df['weekday'] == 6)).astype(int)
        df.dropna(inplace=True)
        
        # Selecting relevant features
        features = ['weekday', 'hour', 'is_weekend', 'proto']
        X = df[features]
        
        # Standardizing data
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        # Applying PCA for dimensionality reduction
        if np.any(np.var(X_scaled, axis=0) == 0):
            print("Warning: PCA input has zero variance. Skipping PCA.")
            X_pca = X_scaled  # Skip PCA if variance is zero
        else:
            pca = PCA(n_components=2)
            X_pca = pca.fit_transform(X_scaled)

        
        # Train Isolation Forest model
        model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
        model.fit(X_pca)
        df['anomaly_score'] = model.decision_function(X_pca)
        df['anomaly'] = model.predict(X_pca)
        
        df['anomaly'] = df['anomaly'].apply(lambda x: 'Anomaly' if x == -1 else 'Normal')
        
        # Using LLM for additional anomaly detection
        texts = df.apply(lambda row: f"Source: {row['src_ip']}, Dest: {row['dst_ip']}, Protocol: {row['protocol']}, Port: {row['port']}, Time: {row['hour']}", axis=1).tolist()
        df['llm_anomaly'] = [result['label'] for result in llm(texts)]

        
        # Print anomalies in real-time
        anomalies = df[df['anomaly'] == 'Anomaly']
        if not anomalies.empty:
            print("Detected Anomalies:")
            print(anomalies[['src_ip', 'dst_ip', 'protocol', 'port', 'anomaly', 'llm_anomaly']])
        
        time.sleep(1)  # Monitor logs every 10 seconds
    

# Monitor network logs in real-time
def monitor_network():
    df = pd.DataFrame(columns=["src_ip", "dst_ip", "protocol", "port", "proto"])
    
    while True:
        new_logs = capture_network_logs(packet_count=50)
        new_df = pd.DataFrame(new_logs, columns=["src_ip", "dst_ip", "protocol", "port", "proto"])
        if not new_df.empty:
            df = pd.concat([df, new_df], ignore_index=True)

        # Feature Engineering
        df['timestamp'] = pd.to_datetime("now")
        df['weekday'] = df['timestamp'].dt.weekday
        df['hour'] = df['timestamp'].dt.hour
        df['is_weekend'] = ((df['weekday'] == 5) | (df['weekday'] == 6)).astype(int)
        df.dropna(inplace=True)
        
        # Selecting relevant features
        features = ['weekday', 'hour', 'is_weekend', 'proto']
        X = df[features]
        
        # Standardizing data
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        # Applying PCA for dimensionality reduction
        if np.any(np.var(X_scaled, axis=0) == 0):
            print("Warning: PCA input has zero variance. Skipping PCA.")
            X_pca = X_scaled  # Skip PCA if variance is zero
        else:
            pca = PCA(n_components=2)
            X_pca = pca.fit_transform(X_scaled)

        # Train Isolation Forest model
        model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
        model.fit(X_pca)
        df['anomaly_score'] = model.decision_function(X_pca)
        df['anomaly'] = model.predict(X_pca)
        df['anomaly'] = df['anomaly'].apply(lambda x: 'Anomaly' if x == -1 else 'Normal')

        # Using LLM for additional anomaly detection
        texts = df.apply(lambda row: f"Source: {row['src_ip']}, Dest: {row['dst_ip']}, Protocol: {row['protocol']}, Port: {row['port']}, Time: {row['hour']}", axis=1).tolist()
        df['llm_anomaly'] = [result['label'] for result in llm(texts)]

        # Print anomalies in real-time
        anomalies = df[df['anomaly'] == 'Anomaly']
        if not anomalies.empty:
            print("Detected Anomalies:")
            print(anomalies[['src_ip', 'dst_ip', 'protocol', 'port', 'anomaly', 'llm_anomaly']])

        #Graph the Anomalies
        plt.figure(figsize=(8, 6))
        sns.scatterplot(x=X_pca[:, 0], y=X_pca[:, 1], hue=df['anomaly'], palette={'Normal': 'blue', 'Anomaly': 'red'})
        plt.title("Anomaly Detection using Isolation Forest & PCA")
        plt.xlabel("PCA Component 1")
        plt.ylabel("PCA Component 2")
        plt.legend()
        plt.show()

        time.sleep(1)  # Monitor logs every 10 seconds

if __name__ == "__main__":
    monitor_network()
