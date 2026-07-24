import os
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

class IsolationForestDetector:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.is_trained = False
        
    def is_loaded(self):
        return self.is_trained
    
    def prepare_normal_data(self, data_path):
        df = pd.read_csv(data_path)
        
        categorical_cols = ['protocol_type', 'service', 'flag']
        for col in categorical_cols:
            if col in df.columns:
                df[col] = pd.Categorical(df[col]).codes
        
        normal_mask = df['label'] == 'normal'
        X_normal = df[normal_mask].drop(['label', 'difficulty'], axis=1, errors='ignore')
        
        return X_normal.values
    
    def train(self, data_path, contamination=0.1):
        X_normal = self.prepare_normal_data(data_path)
        
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X_normal)
        
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=100,
            max_samples='auto',
            random_state=42,
            n_jobs=-1
        )
        
        self.model.fit(X_scaled)
        
        self.is_trained = True
        self.save_model()
        
        return {'status': 'trained', 'samples': len(X_normal)}
    
    def predict(self, features):
        if not self.is_trained:
            raise ValueError("Model not trained yet")
        
        features_array = np.array(features).reshape(1, -1)
        features_scaled = self.scaler.transform(features_array)
        
        prediction = self.model.predict(features_scaled)[0]
        anomaly_score = -self.model.score_samples(features_scaled)[0]
        
        normalized_score = self._normalize_score(anomaly_score)
        
        return {
            'is_anomaly': prediction == -1,
            'anomaly_score': float(normalized_score),
            'raw_score': float(anomaly_score)
        }
    
    def _normalize_score(self, score):
        return 1 / (1 + np.exp(-score))
    
    def get_threshold_for_confidence(self, confidence):
        return -np.log(1 / confidence - 1)
    
    def save_model(self, path=None):
        if path is None:
            path = os.path.join(os.path.dirname(__file__), 'weights', 'isolation_forest.pkl')
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump({
            'model': self.model,
            'scaler': self.scaler
        }, path)
    
    def load_model(self, path=None):
        if path is None:
            path = os.path.join(os.path.dirname(__file__), 'weights', 'isolation_forest.pkl')
        if os.path.exists(path):
            data = joblib.load(path)
            self.model = data['model']
            self.scaler = data['scaler']
            self.is_trained = True
            return True
        return False
