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

def test_7agent_defense_swarm_threat_evaluation():
    """Verify that the 7-Agent Defense Swarm catches critical SIM-swap and blacklisted VPA threats."""
    from src.defense_swarm import UPISOCDefenseSwarm, build_rbi_sar_pdf
    
    swarm = UPISOCDefenseSwarm()
    tx_threat = {
        "tx_id": "NPCI-TEST-999",
        "amount": 48500.0,
        "receiver_vpa": "binance-p2p@upi",
        "sim_swap_days": 1,
        "is_rooted": True,
        "vpn_detected": True,
        "geo_drift_km": 420.0,
        "keystroke_speed_ms": 210,
        "time_to_entry_s": 4.2,
        "receiver_age_days": 5,
        "inflow_velocity_1h": 7,
        "is_verified_merchant": False
    }
    res = swarm.evaluate_transaction(tx_threat, base_ml_prob=0.88)
    
    assert len(res["verdicts"]) == 7
    assert res["final_action"] == "HARD BLOCK & QUARANTINE"
    assert res["threat_count"] >= 2
    assert res["composite_risk_score"] > 60.0
    assert "LEVEL 3" in res["quarantine_level"]
    assert "SAR" in res["sar_status"]
    
    # Test RBI SAR PDF generation
    pdf_bytes = build_rbi_sar_pdf(res)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 500
    assert pdf_bytes.startswith(b"%PDF")

def test_7agent_defense_swarm_clean_channel_evaluation():
    """Verify that standard retail payment clears with zero threat flags."""
    from src.defense_swarm import UPISOCDefenseSwarm
    
    swarm = UPISOCDefenseSwarm()
    tx_clean = {
        "tx_id": "NPCI-TEST-100",
        "amount": 450.0,
        "receiver_vpa": "swiggy.orders@icici",
        "sim_swap_days": 180,
        "is_rooted": False,
        "vpn_detected": False,
        "geo_drift_km": 1.5,
        "keystroke_speed_ms": 175,
        "time_to_entry_s": 3.1,
        "receiver_age_days": 450,
        "inflow_velocity_1h": 1,
        "is_verified_merchant": True
    }
    res = swarm.evaluate_transaction(tx_clean, base_ml_prob=0.02)
    
    assert len(res["verdicts"]) == 7
    assert res["final_action"] == "AUTHORIZED (SWITCH PASS)"
    assert res["threat_count"] == 0
    assert "LEVEL 0" in res["quarantine_level"]

