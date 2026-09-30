import os
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix

def train_ids_model(dataset_path="data/network_traffic.csv", model_output_path="models/random_forest_ids.pkl"):
    if not os.path.exists(dataset_path):
        print(f"[!] Dataset not found at {dataset_path}. Generate dataset first.")
        return

    df = pd.read_csv(dataset_path)
    
    # Feature engineering for training
    df['bytes_per_second'] = df['byte_count'] / df['duration_seconds'].replace(0, 0.01)
    df['packets_per_second'] = df['packet_count'] / df['duration_seconds'].replace(0, 0.01)
    df['average_packet_size'] = df['byte_count'] / df['packet_count'].replace(0, 1)
    df['failure_ratio'] = df['failed_connection_count'] / df['connection_count'].replace(0, 1)
    df['syn_ratio'] = df['syn_count'] / df['packet_count'].replace(0, 1)
    df['connection_rate'] = df['connection_count'] / df['duration_seconds'].replace(0, 0.01)

    features = [
        'packet_count', 'byte_count', 'duration_seconds', 
        'bytes_per_second', 'packets_per_second', 'average_packet_size',
        'connection_count', 'failed_connection_count', 'failure_ratio',
        'syn_count', 'rst_count', 'syn_ratio', 'connection_rate'
    ]
    
    X = df[features]
    # Binary classification: 0 for NORMAL, 1 for SUSPICIOUS / POTENTIAL INTRUSION
    y = df['label'].apply(lambda x: 0 if x == "NORMAL" else 1)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42)

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print("--- Model Evaluation Metrics ---")
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))
    print("\nClassification Report:\n", classification_report(y_test, y_pred))

    os.makedirs(os.path.dirname(model_output_path), exist_ok=True)
    joblib.dump(model, model_output_path)
    print(f"[+] Model successfully trained and saved to {model_output_path}")

if __name__ == "__main__":
    train_ids_model()
