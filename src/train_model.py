import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder
from sqlalchemy import create_engine
import joblib
import warnings
import shap
import matplotlib.pyplot as plt

warnings.filterwarnings('ignore')

print("Connecting to SQLite to fetch data...")
engine = create_engine('sqlite:///../data/processed/upi_fraud.db')
df = pd.read_sql("SELECT * FROM transactions", engine)

print("Feature Engineering...")
df['timestamp'] = pd.to_datetime(df['timestamp'])
df['hour'] = df['timestamp'].dt.hour
df['day_of_week'] = df['timestamp'].dt.dayofweek
df['is_weekend'] = np.where(df['day_of_week'] >= 5, 1, 0)
df['amount_log'] = np.log1p(df['amount'])

print("Encoding categories...")
le_merchant = LabelEncoder()
df['merchant_encoded'] = le_merchant.fit_transform(df['merchant_category'])

le_device = LabelEncoder()
df['device_encoded'] = le_device.fit_transform(df['device_type'])

# Save encoders
joblib.dump(le_merchant, '../models/merchant_encoder.pkl')
joblib.dump(le_device, '../models/device_encoder.pkl')

features = ['amount_log', 'hour', 'day_of_week', 'is_weekend', 'merchant_encoded', 'device_encoded', 'txn_count_1h', 'txn_amount_1h', 'location_changed']
X = df[features]
y = df['is_fraud']

print("Splitting data (CHRONOLOGICAL TIME SPLIT - NO LEAKAGE)...")
df = df.sort_values("timestamp")
split_idx = int(len(df) * 0.8)
train_df = df.iloc[:split_idx]
test_df = df.iloc[split_idx:]

X_train = train_df[features]
y_train = train_df['is_fraud']
X_test = test_df[features]
y_test = test_df['is_fraud']

from imblearn.over_sampling import SMOTE

print("Applying SMOTE (Synthetic Minority Oversampling) to Training Data ONLY...")
smote = SMOTE(random_state=42)
X_train_res, y_train_res = smote.fit_resample(X_train, y_train)

print(f"Original Training Fraud Cases: {y_train.value_counts()[1]}")
print(f"SMOTE Training Fraud Cases: {y_train_res.value_counts()[1]}")

print("Training XGBoost Model on SMOTE-balanced data...")
model = xgb.XGBClassifier(n_estimators=100, max_depth=5, learning_rate=0.1, random_state=42)
model.fit(X_train_res, y_train_res)

joblib.dump(model, '../models/xgb_model.joblib')
print("Model saved!")

# ==========================================
# EXPLAINABLE AI (XAI) WITH SHAP
# ==========================================
print("\n--- Generating SHAP Explainability (XAI) ---")
print("Calculating SHAP values (This is mathematically intensive)...")

explainer = shap.TreeExplainer(model)
# We calculate SHAP on a small subset of test data so it doesn't take 10 hours
X_test_sample = X_test.sample(200, random_state=42)
shap_values = explainer.shap_values(X_test_sample)

print("Generating Global Feature Importance Plot...")
plt.figure()
shap.summary_plot(shap_values, X_test_sample, show=False)
plt.savefig("../assets/shap_summary_plot.png", bbox_inches='tight')
plt.close()

# Generate a local waterfall plot for ONE fraudulent transaction to prove WHY it was blocked
fraud_indices = y_test[y_test == 1].index
if len(fraud_indices) > 0:
    print("Generating Local Waterfall Plot for a blocked transaction...")
    fraud_idx = fraud_indices[0]
    fraud_transaction = X.loc[[fraud_idx]]
    
    # Calculate SHAP specifically for this single transaction
    explainer_waterfall = shap.Explainer(model)
    shap_values_single = explainer_waterfall(fraud_transaction)
    
    plt.figure()
    shap.waterfall_plot(shap_values_single[0], show=False)
    plt.savefig("../assets/shap_waterfall_fraud_case.png", bbox_inches='tight')
    plt.close()
    
print("SHAP explainability complete! Look at the .png images in your folder.")
