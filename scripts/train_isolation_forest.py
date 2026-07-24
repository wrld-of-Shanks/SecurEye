import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'services', 'network'))

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

def load_normal_data(csv_path):
    df = pd.read_csv(csv_path)
    
    categorical_cols = ['protocol_type', 'service', 'flag']
    for col in categorical_cols:
        if col in df.columns:
            df[col] = pd.Categorical(df[col]).codes
    
    normal_mask = df['label'] == 'normal'
    X_normal = df[normal_mask].drop(['label', 'difficulty'], axis=1, errors='ignore')
    
    return X_normal.values, df

def train_isolation_forest():
    print("=" * 60)
    print("TRAINING ISOLATION FOREST")
    print("=" * 60)
    
    csv_path = '/Users/shanks/Desktop/SentinelAI/data/network/KDDTrain+.csv'
    X_normal, df = load_normal_data(csv_path)
    
    print(f"Normal traffic samples: {X_normal.shape[0]}")
    print(f"Total samples in dataset: {df.shape[0]}")
    print(f"Normal traffic percentage: {X_normal.shape[0]/df.shape[0]*100:.1f}%")
    
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_normal)
    
    print(f"\nTraining Isolation Forest...")
    print(f"  contamination: 0.1")
    print(f"  n_estimators: 100")
    
    model = IsolationForest(
        contamination=0.1,
        n_estimators=100,
        max_samples='auto',
        random_state=42,
        n_jobs=-1
    )
    
    model.fit(X_scaled)
    
    scores_normal = model.score_samples(X_scaled)
    predictions = model.predict(X_scaled)
    
    n_anomalies = (predictions == -1).sum()
    n_normal_detected = (predictions == 1).sum()
    
    print(f"\n{'='*60}")
    print("ISOLATION FOREST EVALUATION RESULTS")
    print(f"{'='*60}")
    print(f"\nNormal traffic correctly identified: {n_normal_detected}/{len(X_normal)} ({n_normal_detected/len(X_normal)*100:.1f}%)")
    print(f"False positives (normal flagged as anomaly): {n_anomalies}/{len(X_normal)} ({n_anomalies/len(X_normal)*100:.1f}%)")
    print(f"Average anomaly score (normal): {-scores_normal.mean():.4f}")
    print(f"Score range: {-scores_normal.min():.4f} to {-scores_normal.max():.4f}")
    
    save_path = '/Users/shanks/Desktop/SentinelAI/services/network/models/weights/isolation_forest.pkl'
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    joblib.dump({
        'model': model,
        'scaler': scaler
    }, save_path)
    print(f"\nModel saved to: {save_path}")
    
    return model, scaler

if __name__ == '__main__':
    model, scaler = train_isolation_forest()
