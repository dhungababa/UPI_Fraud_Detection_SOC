# UPI Fraud Detection & Defense SOC Engine

## Overview
Real-time UPI payment fraud scoring microservice and Security Operations Center (SOC) dashboard combining imbalanced ML classification (**XGBoost + SMOTE**), cost-sensitive expected-loss thresholding ($\tau^*$), stateful velocity & impossible-travel enrichment, and **SHAP** local feature attribution.

## Data & Honest Scope
- **Dataset:** 500,000 synthetic DPDP-compliant UPI transactions (`1.00%` fraud / `99:1` imbalance generated via `src/generate_data.py` with overlapping feature distributions). Real banking switch transaction logs are not publicly available for privacy reasons.
- **Measured Chronological Test Metrics (80/20 time split, default 0.50 cutoff):**
  - Fraud Recall: **76.43%**
  - Precision: **23.79%**
  - F1-Score: **0.3628**
  - In production mode, dynamic cost-sensitive thresholding ($\tau^* = C_{FP} / (C_{FP} + C_{FN})$) adjusts the decision boundary based on transaction rupee exposure vs. customer friction cost (`INR 50`).

## Architecture
1. **Inference API (`api/main.py` — FastAPI):**
   - `POST /predict`: Stateful feature enrichment (`StatefulFeatureStore`), Haversine velocity anomaly detection (`src/geo_resolver.py`), XGBoost fraud scoring, and SHAP `TreeExplainer` reason codes.
   - `WS /ws/traffic`: AsyncIO WebSocket real-time streaming route.
   - `GET /metrics` & `GET /health`: Prometheus telemetry counters and inference latency histograms.
2. **Feature Engineering & Explainability (`src/`):**
   - Rolling 10-minute / 1-hour payer velocity windows, spherical Haversine geo-drift (`>800 km/h` impossible travel trigger), SMOTE training pipeline, and SHAP summary/waterfall plots.
3. **Interactive Dashboard & Sandbox Playbooks (`app/`):**
   - Multi-tab Streamlit SOC interface with dynamic UPI QR simulation, NetworkX fraud-ring graph analysis on SQLite records, and **sandbox-simulated** SOAR response payloads (ISO 8583 MTI 0420 freeze schema, FIDO2 challenge, I4C NCRP dossier).

## Running & Testing
```bash
pip install -r requirements.txt
pytest tests/ -v
uvicorn api.main:app --host 127.0.0.1 --port 9001
streamlit run app/app.py
```

## Tech Stack
`Python`, `FastAPI`, `XGBoost`, `scikit-learn`, `imbalanced-learn`, `SHAP`, `LIME`, `Pandas`, `NumPy`, `NetworkX`, `SQLite`, `Prometheus`, `Docker`, `Streamlit`, `Pytest`
