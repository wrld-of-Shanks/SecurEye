import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'services', 'network'))

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
import xgboost as xgb
import joblib

def load_and_prepare_data(csv_path):
    df = pd.read_csv(csv_path)
    
    categorical_cols = ['protocol_type', 'service', 'flag']
    for col in categorical_cols:
        if col in df.columns:
            df[col] = pd.Categorical(df[col]).codes
    
    X = df.drop(['label', 'difficulty'], axis=1, errors='ignore')
    y = df['label']
    
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)
    
    return X.values, y_encoded, le, df

def train_xgboost():
    print("=" * 60)
    print("TRAINING XGBOOST CLASSIFIER")
    print("=" * 60)
    
    csv_path = '/Users/shanks/Desktop/SentinelAI/data/network/KDDTrain+.csv'
    X, y, label_encoder, df = load_and_prepare_data(csv_path)
    
    print(f"Dataset shape: {X.shape}")
    print(f"Number of classes: {len(label_encoder.classes_)}")
    print(f"Class distribution:")
    unique, counts = np.unique(y, return_counts=True)
    for cls, count in zip(label_encoder.classes_, counts):
        print(f"  {cls}: {count}")
    
    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    n_classes = len(np.unique(y))
    class_counts = np.bincount(y_train)
    total = len(y_train)
    scale_pos_weight = total / (n_classes * class_counts)
    
    print(f"\nTraining XGBoost...")
    print(f"  max_depth: 5")
    print(f"  learning_rate: 0.1")
    print(f"  n_estimators: 200")
    print(f"  early_stopping_rounds: 20")
    
    model = xgb.XGBClassifier(
        objective='multi:softprob',
        num_class=n_classes,
        max_depth=5,
        learning_rate=0.1,
        n_estimators=200,
        scale_pos_weight=scale_pos_weight.tolist(),
        eval_metric='mlogloss',
        early_stopping_rounds=20,
        random_state=42,
        use_label_encoder=False
    )
    
    model.fit(
        X_train, y_train,
        eval_set=[(X_val, y_val)],
        verbose=False
    )
    
    y_pred = model.predict(X_val)
    y_pred_proba = model.predict_proba(X_val)
    
    from sklearn.metrics import log_loss
    all_classes = list(range(n_classes))
    ll = log_loss(y_val, y_pred_proba, labels=all_classes)
    
    print(f"\n{'='*60}")
    print("XGBOOST EVALUATION RESULTS")
    print(f"{'='*60}")
    print(f"\nLog Loss: {ll:.4f}")
    print(f"\nClassification Report:")
    unique_labels = sorted(set(y_val) | set(y_pred))
    target_names = [label_encoder.classes_[i] for i in unique_labels if i < len(label_encoder.classes_)]
    print(classification_report(
        y_val, y_pred, 
        labels=unique_labels,
        target_names=target_names,
        zero_division=0
    ))
    
    save_path = '/Users/shanks/Desktop/SentinelAI/services/network/models/weights/xgboost_model.pkl'
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    joblib.dump({
        'model': model,
        'label_encoder': label_encoder
    }, save_path)
    print(f"\nModel saved to: {save_path}")
    
    return model, label_encoder

if __name__ == '__main__':
    model, le = train_xgboost()
