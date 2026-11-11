import pytest
import numpy as np
import sys
import os
from fastapi.testclient import TestClient

# Add project root to sys.path for direct ASGI in-memory testing
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
upi_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if upi_root not in sys.path:
    sys.path.insert(0, upi_root)
for mod in list(sys.modules.keys()):
    if mod == "api" or mod.startswith("api."):
        del sys.modules[mod]
import api.main
app = api.main.app

client = TestClient(app)

def test_health_endpoint():
    """Verify microservice reports HEALTHY status in-memory without network dependency."""
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data.get("status") == "HEALTHY"
    assert data.get("models_loaded") is True

def test_prometheus_metrics_scrape():
    """Verify Prometheus scrape endpoint exposes production counters."""
    res = client.get("/metrics")
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
    res = client.post("/predict", json=payload)
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
    res = client.post("/predict", json=payload)
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


def test_ip_geolocation_and_haversine_drift():
    """Verify real IP resolution and Haversine distance calculation."""
    from src.geo_resolver import resolve_ip, haversine_distance_km, detect_impossible_travel
    
    # Internal switch IP resolution
    local_info = resolve_ip("127.0.0.1")
    assert local_info["status"] == "success"
    assert local_info["city"] == "Mumbai"
    
    # Haversine distance between Mumbai (19.0760, 72.8777) and Delhi (28.6139, 77.2090) ~ 1150 km
    dist = haversine_distance_km(19.0760, 72.8777, 28.6139, 77.2090)
    assert 1100.0 < dist < 1250.0

def test_stateful_feature_store_and_impossible_travel():
    """Verify sliding-window accumulation and impossible travel velocity flag."""
    from src.feature_store import StatefulFeatureStore
    
    store = StatefulFeatureStore()
    vpa = "victim_rahul@okaxis"
    
    # Txn 1: Delhi IP
    t1 = store.enrich_and_record(vpa, 500.0, client_ip="49.36.128.5")
    assert t1["txn_count_1h"] == 1
    assert t1["txn_amount_1h"] == 500.0
    assert t1["is_impossible_travel"] is False
    
    # Txn 2: 10 seconds later, IP from US (Ashburn) -> 12,000 km jump
    t2 = store.enrich_and_record(vpa, 75000.0, client_ip="8.8.8.8")
    assert t2["txn_count_1h"] == 2
    assert t2["txn_amount_1h"] == 75500.0
    assert t2["geo_drift_km"] > 5000.0
    assert t2["is_impossible_travel"] is True


def test_soar_playbook_all_actions():
    """Verify all automated SOAR playbook actions execute within sub-50ms SLA and return correct ISO/API structures."""
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app")))
    from soar_playbook import execute_soar_playbook

    txn_sample = {
        "rrn": "984210984120",
        "amt": 85000.0,
        "payer_vpa": "victim@okhdfcbank",
        "payee_vpa": "crypto_mule@ybl",
        "ip": "45.142.212.60",
        "dev": "Android-Pixel8",
        "fraud_prob": 0.942,
        "reason": "Nighttime velocity anomaly + Geo drift"
    }

    # 1. switch_freeze
    res_freeze = execute_soar_playbook(txn_sample["rrn"], "switch_freeze", txn_sample)
    assert res_freeze["action_type"] == "switch_freeze"
    assert res_freeze["status"] == "EXECUTED_SUCCESS"
    assert res_freeze["latency_ms"] < 50.0
    assert "PASS" in res_freeze["sla_status"]
    assert res_freeze["telemetry_packet"]["MTI"] == "0420"
    assert res_freeze["telemetry_packet"]["DE-002 (PAN / Virtual Account)"] == f"VPA:{txn_sample['payee_vpa']}"

    # 2. biometric_step_up
    res_bio = execute_soar_playbook(txn_sample["rrn"], "biometric_step_up", txn_sample)
    assert res_bio["action_type"] == "biometric_step_up"
    assert res_bio["status"] == "DISPATCHED_PENDING_USER"
    assert res_bio["latency_ms"] < 50.0
    assert res_bio["target"] == txn_sample["payer_vpa"]
    assert "FIDO2" in res_bio["protocol"]

    # 3. cert_in_dispatch
    res_cert = execute_soar_playbook(txn_sample["rrn"], "cert_in_dispatch", txn_sample)
    assert res_cert["action_type"] == "cert_in_dispatch"
    assert res_cert["status"] == "DISPATCHED_CONFIRMED"
    assert res_cert["latency_ms"] < 50.0
    assert "NCRP" in res_cert["telemetry_packet"]["incident_ticket_ref"]
    assert res_cert["telemetry_packet"]["beneficiary_mule_vpa"] == txn_sample["payee_vpa"]

    # 4. firewall_quarantine
    res_waf = execute_soar_playbook(txn_sample["rrn"], "firewall_quarantine", txn_sample)
    assert res_waf["action_type"] == "firewall_quarantine"
    assert res_waf["status"] == "APPLIED_EDGE_ACTIVE"
    assert res_waf["latency_ms"] < 50.0
    assert res_waf["target"] == f"{txn_sample['ip']}/32"
    assert res_waf["telemetry_packet"]["action"] == "DROP_IMMEDIATE (TCP RST / HTTP 403 Forbidden)"


def test_threat_intel_feed_generation():
    """Verify live cyber threat intel feed indicators, categories, and severity levels."""
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app")))
    from threat_intel_feed import get_live_threat_feed

    feed = get_live_threat_feed()
    assert isinstance(feed, list)
    assert len(feed) >= 10

    types = {x["threat_type"] for x in feed}
    assert "Android UPI Malware" in types
    assert "Rogue UPI VPA Clusters" in types
    assert "Compromised Tor / VPN IPs" in types
    assert "Impossible Travel Telemetry" in types

    severities = {x["threat_level"] for x in feed}
    assert "CRITICAL" in severities
    assert "HIGH" in severities
    assert "MEDIUM" in severities

    for item in feed:
        assert item["ioc_id"].startswith("IOC-")
        assert len(item["indicator"]) > 0
        assert len(item["source"]) > 0
        assert len(item["description"]) > 0
        assert len(item["action_recommended"]) > 0
