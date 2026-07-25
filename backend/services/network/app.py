import os
import numpy as np
import pandas as pd
from flask import Flask, request, jsonify
from flask_cors import CORS
from models.xgboost_model import XGBoostClassifier
from models.isolation_forest import IsolationForestDetector
from utils.feature_engineering import preprocess_flow

app = Flask(__name__)
CORS(app)

MODELS_DIR = os.path.join(os.path.dirname(__file__), 'models', 'weights')

xgboost_model = XGBoostClassifier()
isolation_forest = IsolationForestDetector()

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'models': {
            'xgboost': xgboost_model.is_loaded(),
            'isolation_forest': isolation_forest.is_loaded()
        }
    })

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        features = preprocess_flow(data)
        
        supervised_result = xgboost_model.predict(features)
        unsupervised_result = isolation_forest.predict(features)
        
        confidence = calculate_confidence(
            supervised_result['confidence'],
            unsupervised_result['anomaly_score']
        )
        
        prediction = supervised_result['class']
        if unsupervised_result['is_anomaly'] and unsupervised_result['anomaly_score'] > 0.7:
            prediction = 'novel_attack'
        
        return jsonify({
            'prediction': prediction,
            'confidence': confidence,
            'anomaly_score': unsupervised_result['anomaly_score'],
            'supervised': supervised_result,
            'unsupervised': unsupervised_result,
            'explanation': generate_explanation(prediction, confidence, unsupervised_result)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/train', methods=['POST'])
def train():
    try:
        data_path = request.json.get('data_path', 'data/nsl-kdd.csv')
        
        xgboost_model.train(data_path)
        isolation_forest.train(data_path)
        
        return jsonify({'status': 'training_complete'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def calculate_confidence(supervised_conf, anomaly_score):
    if anomaly_score > 0.9:
        return max(supervised_conf, 0.85)
    elif anomaly_score > 0.7:
        return max(supervised_conf, 0.7)
    elif anomaly_score > 0.5:
        return supervised_conf * 0.9
    return supervised_conf

def generate_explanation(prediction, confidence, unsupervised_result):
    is_novel = unsupervised_result['is_anomaly'] and unsupervised_result['anomaly_score'] > 0.7
    return {
        'prediction': prediction,
        'confidence': confidence,
        'is_novel': is_novel,
        'anomaly_score': unsupervised_result['anomaly_score'],
        'override_reason': 'unsupervised_anomaly' if is_novel else None
    }

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
