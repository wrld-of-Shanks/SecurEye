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
    print("TRAINING ISOLATION FOREST (percentile normalization)")
    print("=" * 60)
    
    csv_path = '/Users/shanks/Desktop/Specula/data/network/KDDTrain+.csv'
    X_normal, df = load_normal_data(csv_path)
    
    print(f"Normal traffic samples: {X_normal.shape[0]}")
    print(f"Total samples in dataset: {df.shape[0]}")
    print(f"Normal traffic percentage: {X_normal.shape[0]/df.shape[0]*100:.1f}%")
    
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_normal)
    
    print(f"\nTraining Isolation Forest (n_estimators=200)...")
    
    model = IsolationForest(
        contamination=0.1,
        n_estimators=200,
        max_samples='auto',
        random_state=42,
        n_jobs=-1
    )
    
    model.fit(X_scaled)
    
    normal_scores = -model.score_samples(X_scaled)
    
    score_percentiles = {
        'p50': float(np.percentile(normal_scores, 50)),
        'p75': float(np.percentile(normal_scores, 75)),
        'p90': float(np.percentile(normal_scores, 90)),
        'p95': float(np.percentile(normal_scores, 95)),
        'p99': float(np.percentile(normal_scores, 99)),
        'mean': float(normal_scores.mean()),
        'std': float(normal_scores.std()),
    }
    
    predictions = model.predict(X_scaled)
    n_anomalies = (predictions == -1).sum()
    n_normal_detected = (predictions == 1).sum()
    
    print(f"\n{'='*60}")
    print("ISOLATION FOREST EVALUATION RESULTS")
    print(f"{'='*60}")
    print(f"\nNormal traffic correctly identified: {n_normal_detected}/{len(X_normal)} ({n_normal_detected/len(X_normal)*100:.1f}%)")
    print(f"False positives (normal flagged as anomaly): {n_anomalies}/{len(X_normal)} ({n_anomalies/len(X_normal)*100:.1f}%)")
    print(f"Average anomaly score (normal): {normal_scores.mean():.4f}")
    print(f"Score range: {normal_scores.min():.4f} to {normal_scores.max():.4f}")
    
    print(f"\nScore percentiles:")
    for k, v in score_percentiles.items():
        print(f"  {k}: {v:.4f}")
    
    save_path = '/Users/shanks/Desktop/Specula/backend/services/network/models/weights/isolation_forest.pkl'
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    joblib.dump({
        'model': model,
        'scaler': scaler,
        'score_percentiles': score_percentiles
    }, save_path)
    print(f"\nModel saved to: {save_path}")
    
    print(f"\n--- Normalized score range (percentile-based) ---")
    norm_scores = []
    for raw in normal_scores[:20]:
        p50 = score_percentiles['p50']
        p95 = score_percentiles['p95']
        p99 = score_percentiles['p99']
        if raw <= p50:
            ns = 0.0
        elif raw <= p95:
            ns = 0.3 + 0.4 * (raw - p50) / (p95 - p50)
        elif raw <= p99:
            ns = 0.7 + 0.2 * (raw - p95) / (p99 - p95)
        else:
            ns = min(0.9 + 0.1 * (raw - p99) / (p99 * 0.5 + 1e-10), 1.0)
        norm_scores.append(ns)
    print(f"  First 20 normal samples normalized: {[f'{s:.3f}' for s in norm_scores]}")
    
    return model, scaler, score_percentiles

if __name__ == '__main__':
    model, scaler, percentiles = train_isolation_forest()
