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
    print("TRAINING XGBOOST CLASSIFIER (tuned)")
    print("=" * 60)
    
    csv_path = '/Users/shanks/Desktop/Specula/data/network/KDDTrain+.csv'
    X, y, label_encoder, df = load_and_prepare_data(csv_path)
    
    print(f"Dataset shape: {X.shape}")
    print(f"Number of classes: {len(label_encoder.classes_)}")
    print(f"Class distribution:")
    unique, counts = np.unique(y, return_counts=True)
    for cls_idx, count in zip(unique, counts):
        cls_name = label_encoder.classes_[cls_idx]
        print(f"  {cls_name}: {count} ({count/len(y)*100:.1f}%)")
    
    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    n_classes = len(np.unique(y))
    class_counts = np.bincount(y_train)
    total = len(y_train)
    scale_pos_weight = total / (n_classes * class_counts)
    
    print(f"\nTraining XGBoost (tuned hyperparameters)...")
    print(f"  max_depth: 6")
    print(f"  learning_rate: 0.05")
    print(f"  n_estimators: 400")
    print(f"  min_child_weight: 3")
    print(f"  subsample: 0.8")
    print(f"  colsample_bytree: 0.8")
    
    model = xgb.XGBClassifier(
        objective='multi:softprob',
        num_class=n_classes,
        max_depth=6,
        learning_rate=0.05,
        n_estimators=400,
        min_child_weight=3,
        subsample=0.8,
        colsample_bytree=0.8,
        gamma=0.1,
        scale_pos_weight=scale_pos_weight.tolist(),
        eval_metric='mlogloss',
        early_stopping_rounds=30,
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
    
    from sklearn.metrics import log_loss, f1_score
    all_classes = list(range(n_classes))
    ll = log_loss(y_val, y_pred_proba, labels=all_classes)
    macro_f1 = f1_score(y_val, y_pred, average='macro')
    weighted_f1 = f1_score(y_val, y_pred, average='weighted')
    
    print(f"\n{'='*60}")
    print("XGBOOST EVALUATION RESULTS (tuned)")
    print(f"{'='*60}")
    print(f"\nLog Loss: {ll:.4f}")
    print(f"Macro F1: {macro_f1:.4f}")
    print(f"Weighted F1: {weighted_f1:.4f}")
    print(f"\nClassification Report:")
    unique_labels = sorted(set(y_val) | set(y_pred))
    target_names = [label_encoder.classes_[i] for i in unique_labels if i < len(label_encoder.classes_)]
    print(classification_report(
        y_val, y_pred, 
        labels=unique_labels,
        target_names=target_names,
        zero_division=0
    ))
    
    print("Confusion Matrix:")
    cm = confusion_matrix(y_val, y_pred)
    print(cm)
    
    save_path = '/Users/shanks/Desktop/Specula/backend/services/network/models/weights/xgboost_model.pkl'
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    joblib.dump({
        'model': model,
        'label_encoder': label_encoder
    }, save_path)
    print(f"\nModel saved to: {save_path}")
    
    return model, label_encoder

if __name__ == '__main__':
    model, le = train_xgboost()
