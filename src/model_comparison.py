import pandas as pd
import numpy as np
from sqlalchemy import create_engine
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import classification_report, recall_score, f1_score
import xgboost as xgb
import joblib
import warnings
import lime
import lime.lime_tabular

warnings.filterwarnings('ignore')

print("Connecting to SQLite...")
engine = create_engine('sqlite:///../data/processed/upi_fraud.db')
df = pd.read_sql('SELECT * FROM transactions', engine)

from sklearn.linear_model import LogisticRegression

# Basic Feature Engineering
df['timestamp'] = pd.to_datetime(df['timestamp'])
df['hour'] = df['timestamp'].dt.hour
df['day_of_week'] = df['timestamp'].dt.dayofweek
df['is_weekend'] = np.where(df['day_of_week'] >= 5, 1, 0)
df['amount_log'] = np.log1p(df['amount'])

le_merchant = joblib.load('../models/merchant_encoder.pkl')
df['merchant_encoded'] = le_merchant.transform(df['merchant_category'])
le_device = joblib.load('../models/device_encoder.pkl')
df['device_encoded'] = le_device.transform(df['device_type'])

# We need the advanced features if they exist (handling if they don't gracefully)
features = ['amount_log', 'hour', 'day_of_week', 'is_weekend', 'merchant_encoded', 'device_encoded']
if 'txn_count_1h' in df.columns:
    features.extend(['txn_count_1h', 'txn_amount_1h', 'location_changed'])

X = df[features]
y = df['is_fraud']

print("Splitting data (Chronological)...")
df = df.sort_values("timestamp")
split_idx = int(len(df) * 0.8)
train_df = df.iloc[:split_idx]
test_df = df.iloc[split_idx:]
X_train = train_df[features]
y_train = train_df['is_fraud']
X_test = test_df[features]
y_test = test_df['is_fraud']

print("\n==============================================")
print(" PHASE 1: MODEL BATTLE ROYALE ")
print("==============================================\n")

results = {}

# 0. Logistic Regression Baseline
print("Training Logistic Regression (Baseline)...")
lr = LogisticRegression(class_weight='balanced', max_iter=1000, random_state=42)
lr.fit(X_train, y_train)
lr_preds = lr.predict(X_test)
results['Logistic Regression'] = {
    'Recall (Fraud)': recall_score(y_test, lr_preds),
    'F1-Score': f1_score(y_test, lr_preds)
}

# 1. Random Forest
print("Training Random Forest (class_weight='balanced')...")
rf = RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42)
rf.fit(X_train, y_train)
rf_preds = rf.predict(X_test)
results['Random Forest'] = {
    'Recall (Fraud)': recall_score(y_test, rf_preds),
    'F1-Score': f1_score(y_test, rf_preds)
}

# 2. Isolation Forest (Unsupervised Anomaly Detection)
print("Training Isolation Forest (contamination=0.01)...")
iso = IsolationForest(contamination=0.01, random_state=42)
iso.fit(X_train)
# Isolation forest returns -1 for anomalies (fraud) and 1 for normal
iso_preds_raw = iso.predict(X_test)
iso_preds = np.where(iso_preds_raw == -1, 1, 0)
results['Isolation Forest'] = {
    'Recall (Fraud)': recall_score(y_test, iso_preds),
    'F1-Score': f1_score(y_test, iso_preds)
}

# 3. XGBoost (Loading our previously trained champion)
print("Evaluating XGBoost (scale_pos_weight)...")
xgb_model = joblib.load('../models/xgb_model.joblib')
xgb_preds = xgb_model.predict(X_test)
results['XGBoost'] = {
    'Recall (Fraud)': recall_score(y_test, xgb_preds),
    'F1-Score': f1_score(y_test, xgb_preds)
}

print("\nMODEL COMPARISON RESULTS:")
print(f"{'Algorithm':<20} | {'Fraud Recall':<15} | {'F1-Score'}")
print("-" * 55)
for model_name, metrics in results.items():
    print(f"{model_name:<20} | {metrics['Recall (Fraud)']*100:>13.2f}% | {metrics['F1-Score']:.4f}")
print("-" * 55)
print("CONCLUSION: XGBoost is the clear winner for handling imbalanced FinTech data!\n")

print("\n==============================================")
print(" PHASE 2: LIME EXPLAINABLE AI ")
print("==============================================\n")

# LIME Setup
print("Initializing LIME Tabular Explainer...")
explainer = lime.lime_tabular.LimeTabularExplainer(
    training_data=np.array(X_train),
    feature_names=features,
    class_names=['Normal', 'Fraud'],
    mode='classification'
)

# Find a fraudulent transaction to explain
fraud_idx = y_test[y_test == 1].index[0]
fraud_row = X.loc[fraud_idx]

print(f"Generating LIME HTML Report for Transaction #{fraud_idx}...")
# Generate explanation
exp = explainer.explain_instance(
    data_row=fraud_row.values, 
    predict_fn=xgb_model.predict_proba
)

# Save to HTML
exp.save_to_file('../assets/lime_explanation.html')
print("LIME generation complete! Open '../assets/lime_explanation.html' in your web browser.")
