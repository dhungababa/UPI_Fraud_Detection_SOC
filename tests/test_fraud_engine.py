import pytest
import numpy as np
import requests

BASE_URL = "http://localhost:9001"

def test_health_endpoint():
    """Verify microservice reports HEALTHY status."""
    res = requests.get(f"{BASE_URL}/health", timeout=3)
    assert res.status_code == 200
    data = res.json()
    assert data.get("status") == "HEALTHY"
    assert data.get("models_loaded") is True

def test_prometheus_metrics_scrape():
    """Verify Prometheus scrape endpoint exposes production counters."""
    res = requests.get(f"{BASE_URL}/metrics", timeout=3)
    assert res.status_code == 200
    text = res.text
    assert "upi_requests_total" in text
    assert "upi_inference_latency_seconds" in text

def test_legitimate_transaction_predict():
    """Verify legitimate daytime transaction yields low fraud probability."""
    payload = {
        "amount": 250.0,
        "hour": 14,
        "merchant": "Groceries",
        "device": "Android",
        "txn_count_1h": 1,
        "location_changed": "No"
    }
    res = requests.post(f"{BASE_URL}/predict", json=payload, timeout=3)
    assert res.status_code == 200
    data = res.json()
    assert "fraud_probability" in data
    assert data["fraud_probability"] < 0.50
    assert data["decision"] == "APPROVED"
    assert len(data["shap_values"]) == len(data["feature_names"])

def test_high_risk_fraud_transaction_predict():
    """Verify 3 AM high-amount foreign transaction is intercepted."""
    payload = {
        "amount": 88000.0,
        "hour": 3,
        "merchant": "Crypto",
        "device": "Android",
        "txn_count_1h": 12,
        "location_changed": "Yes"
    }
    res = requests.post(f"{BASE_URL}/predict", json=payload, timeout=3)
    assert res.status_code == 200
    data = res.json()
    assert "fraud_probability" in data
    assert data["fraud_probability"] > 0.40
    assert data["decision"] == "BLOCKED"

def test_cost_sensitive_optimal_threshold_math():
    """Verify optimal threshold formula tau* scales inversely with transaction value."""
    def calc_tau(amt):
        cost_fp = 50.0
        cost_fn = max(amt * 0.95, 100.0)
        return float(np.clip(cost_fp / (cost_fp + cost_fn), 0.05, 0.85))
    
    # Small transaction: threshold is high (prioritize minimizing customer friction)
    tau_small = calc_tau(100.0)
    # Massive transaction: threshold is low (prioritize blocking fraud)
    tau_large = calc_tau(95000.0)
    
    assert tau_small > tau_large
    assert tau_large <= 0.051
