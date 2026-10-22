from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Response, status
from pydantic import BaseModel
import pandas as pd
import numpy as np
import joblib
import shap
import os
import time
import asyncio
import json
import random
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

app = FastAPI(title="NPCI UPI Fraud Defense API", description="Production Microservice with Prometheus Observability & WebSockets")

# Load models safely on startup (Server Side)
base_dir = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(base_dir, '../models/xgb_model.joblib')
merchant_path = os.path.join(base_dir, '../models/merchant_encoder.pkl')
device_path = os.path.join(base_dir, '../models/device_encoder.pkl')

model = joblib.load(model_path)
le_merchant = joblib.load(merchant_path)
le_device = joblib.load(device_path)
explainer = shap.TreeExplainer(model)

# --- PROMETHEUS PRODUCTION METRICS ---
REQUESTS_TOTAL = Counter("upi_requests_total", "Total HTTP requests received", ["endpoint", "status"])
PREDICTIONS_TOTAL = Counter("upi_predictions_total", "Total predictions by decision", ["decision"])
LATENCY_HISTOGRAM = Histogram("upi_inference_latency_seconds", "Inference latency in seconds", buckets=[0.005, 0.01, 0.02, 0.035, 0.05, 0.1])

class Transaction(BaseModel):
    amount: float
    hour: int
    merchant: str
    device: str
    txn_count_1h: int
    location_changed: str

@app.get("/health")
def health_check():
    return {"status": "HEALTHY", "engine": "XGBoost Production Core", "latency_sla": "<50ms", "models_loaded": True}

@app.get("/metrics")
def get_metrics():
    """Prometheus telemetry scrape endpoint for SRE & Grafana dashboards."""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

@app.post("/predict")
def predict_fraud(txn: Transaction):
    t_start = time.perf_counter()
    try:
        # Feature Engineering inside the Microservice
        amount_log = np.log1p(txn.amount)
        merchant_encoded = int(le_merchant.transform([txn.merchant])[0]) if txn.merchant in le_merchant.classes_ else 0
        device_encoded = int(le_device.transform([txn.device])[0]) if txn.device in le_device.classes_ else 0
        loc_changed_val = 1 if txn.location_changed.lower() in ["yes", "1", "true"] else 0
        
        features = pd.DataFrame([{
            'amount_log': amount_log,
            'hour': txn.hour,
            'day_of_week': 0,
            'is_weekend': 0,
            'merchant_encoded': merchant_encoded,
            'device_encoded': device_encoded,
            'txn_count_1h': txn.txn_count_1h,
            'txn_amount_1h': txn.amount,
            'location_changed': loc_changed_val
        }])
        
        # ML Inference
        prob = float(model.predict_proba(features)[0][1])
        
        # SHAP Generation
        shap_values = explainer.shap_values(features)
        feature_names = features.columns.tolist()
        
        def get_reason_code(shap_row, feature_names, top_n=3):
            positive_pairs = [(name, val) for name, val in zip(feature_names, shap_row) if val > 0]
            if not positive_pairs: return "Normal behavior detected."
            positive_pairs.sort(key=lambda p: p[1], reverse=True)
            parts = [f"{name}" for name, val in positive_pairs[:top_n]]
            return "Anomalies detected in: " + " | ".join(parts).upper()
            
        reason = get_reason_code(shap_values[0], feature_names)
        
        try:
            expected = float(explainer.expected_value[1]) if isinstance(explainer.expected_value, np.ndarray) else float(explainer.expected_value)
        except (IndexError, TypeError, ValueError):
            expected = float(explainer.expected_value)
            
        decision_label = "BLOCKED" if prob > 0.40 else "APPROVED"
        
        # Record Prometheus Telemetry
        REQUESTS_TOTAL.labels(endpoint="/predict", status="200").inc()
        PREDICTIONS_TOTAL.labels(decision=decision_label).inc()
        LATENCY_HISTOGRAM.observe(time.perf_counter() - t_start)
        
        return {
            "fraud_probability": prob,
            "is_fraud": prob > 0.40,
            "decision": decision_label,
            "shap_reason": reason,
            "shap_values": shap_values[0].tolist(),
            "expected_value": expected,
            "feature_values": features.iloc[0].tolist(),
            "feature_names": feature_names,
            "latency_ms": round((time.perf_counter() - t_start) * 1000, 2)
        }
    except Exception as e:
        REQUESTS_TOTAL.labels(endpoint="/predict", status="500").inc()
        raise e

# --- WEBSOCKET EVENT-DRIVEN STREAMING ROUTE ---
@app.websocket("/ws/traffic")
async def websocket_traffic_stream(websocket: WebSocket):
    """Event-driven live transaction feed pushed to frontends via WebSockets."""
    await websocket.accept()
    merchants = list(le_merchant.classes_)
    devices = list(le_device.classes_)
    
    try:
        while True:
            # Generate realistic synthetic UPI packet
            amt = round(random.uniform(50.0, 3500.0), 2)
            hr = random.randint(8, 22)
            merch = random.choice(merchants)
            dev = random.choice(devices)
            count = random.randint(1, 2)
            loc = "No"
            
            # Anomaly injection (8%)
            if random.random() < 0.08:
                amt = round(random.uniform(45000.0, 95000.0), 2)
                hr = random.choice([2, 3, 4])
                merch = "Crypto"
                count = random.randint(8, 15)
                loc = "Yes"
                
            amount_log = np.log1p(amt)
            m_enc = int(le_merchant.transform([merch])[0])
            d_enc = int(le_device.transform([dev])[0])
            l_enc = 1 if loc == "Yes" else 0
            
            feats = pd.DataFrame([{
                'amount_log': amount_log, 'hour': hr, 'day_of_week': 0, 'is_weekend': 0,
                'merchant_encoded': m_enc, 'device_encoded': d_enc,
                'txn_count_1h': count, 'txn_amount_1h': amt, 'location_changed': l_enc
            }])
            prob = float(model.predict_proba(feats)[0][1])
            is_anomaly = prob > 0.40
            
            packet = {
                "timestamp": time.time(),
                "rrn": f"4291{random.randint(10000000, 99999999)}",
                "payer_vpa": f"user_{random.randint(100, 999)}@okaxis",
                "payee_vpa": f"store_{random.randint(10, 99)}@ybl",
                "amount": amt,
                "hour": hr,
                "merchant": merch,
                "device": dev,
                "fraud_probability": round(prob, 4),
                "is_threat": is_anomaly,
                "status": "THREAT_BLOCKED" if is_anomaly else "APPROVED"
            }
            
            await websocket.send_text(json.dumps(packet))
            await asyncio.sleep(0.5)
    except WebSocketDisconnect:
        pass
