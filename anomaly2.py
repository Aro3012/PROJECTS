import pandas as pd
import numpy as np
import re
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
import matplotlib.pyplot as plt

# Load dataset
df = pd.read_csv("logs_dataset.csv")

# Clean timestamp column
def clean_date(date_str):
    return re.sub(r'(\d+)(st|nd|rd|th)', r'\1', date_str)

df['@timestamp'] = df['@timestamp'].apply(lambda x: clean_date(str(x)))
df['@timestamp'] = pd.to_datetime(df['@timestamp'], errors='coerce')

df.sort_values(['ip_address', '@timestamp'], inplace=True)

df['shift_time'] = df.groupby(['ip_address'])['@timestamp'].shift(1)
df['time_diff'] = (df['@timestamp'] - df['shift_time']).dt.seconds // 60
df['date'] = df['@timestamp'].dt.date
df['weekday'] = df['@timestamp'].dt.weekday
df['hour'] = df['@timestamp'].dt.hour
df['is_weekend'] = ((df['weekday'] == 5) | (df['weekday'] == 6)).astype(int)
df['hour_bucket'] = df['hour'] // 4

# Drop NaN values after feature engineering
df.dropna(inplace=True)

# Selecting relevant features for anomaly detection
features = ['time_diff', 'weekday', 'hour', 'is_weekend', 'hour_bucket']
X = df[features]

# Standardizing data
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Applying PCA for dimensionality reduction
pca = PCA(n_components=2)
X_pca = pca.fit_transform(X_scaled)

# Train Isolation Forest model
model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
model.fit(X_pca)
df['anomaly_score'] = model.decision_function(X_pca)
df['anomaly'] = model.predict(X_pca)

df['anomaly'] = df['anomaly'].apply(lambda x: 'Anomaly' if x == -1 else 'Normal')

# Visualizing results
plt.scatter(X_pca[:, 0], X_pca[:, 1], c=df['anomaly'].map({'Normal': 0, 'Anomaly': 1}), cmap='coolwarm')
plt.xlabel('PCA Component 1')
plt.ylabel('PCA Component 2')
plt.title('Anomaly Detection using Isolation Forest')
plt.colorbar(label='Anomaly Score')
plt.show()

# Save processed dataset with anomaly labels
df.to_csv("logs_dataset_with_anomalies.csv", index=False)