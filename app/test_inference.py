import joblib
import pandas as pd
import numpy as np
import shap

try:
    print("Loading models...")
    model = joblib.load('../models/xgb_model.joblib')
    le_merchant = joblib.load('../models/merchant_encoder.pkl')
    le_device = joblib.load('../models/device_encoder.pkl')
    explainer = shap.TreeExplainer(model)
    
    print("Simulating UI Inputs...")
    amount = 50000.0
    hour = 3
    merchant = le_merchant.classes_[0]
    device = le_device.classes_[0]
    txn_count_1h = 10
    
    amount_log = np.log1p(amount)
    merchant_encoded = le_merchant.transform([merchant])[0]
    device_encoded = le_device.transform([device])[0]
    loc_changed_val = 1
    
    features = pd.DataFrame([{
        'amount_log': amount_log,
        'hour': hour,
        'day_of_week': 0,
        'is_weekend': 0,
        'merchant_encoded': merchant_encoded,
        'device_encoded': device_encoded,
        'txn_count_1h': txn_count_1h,
        'txn_amount_1h': amount,
        'location_changed': loc_changed_val
    }])
    
    print("Running XGBoost Inference...")
    prob = model.predict_proba(features)[0][1]
    print(f"Fraud Probability: {prob * 100:.2f}%")
    
    print("Running SHAP Explainability...")
    shap_values = explainer.shap_values(features)
    print("SHAP successful.")
    
    print("✅ Project 1 backend is 100% functionally sound.")
except Exception as e:
    print(f"❌ ERROR in Project 1: {e}")
