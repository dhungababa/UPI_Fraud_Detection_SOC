# UPI / Digital Payment Fraud Detector

## Problem
UPI is now India's dominant retail payment rail processing billions of transactions. Fraud is a small fraction of that volume but a real and growing cost. This project aims to accurately detect fraud in real-time while minimizing false positives to avoid damaging genuine customers' trust.

## Data
Kaggle "UPI Transactions 2024 Dataset". Note: This is a synthetic dataset generated programmatically to mimic real UPI patterns while preserving privacy, as real banking transaction data is not publicly released for security reasons.

## Approach
- EDA & Feature Engineering: Calculated rolling 1-hour transaction velocities and geolocation anomalies using Pandas.
- Machine Learning: Trained an XGBoost Classifier handling the 99:1 extreme imbalance using SMOTE (Synthetic Minority Oversampling Technique).
- Explainable AI: Implemented SHAP (Shapley Additive exPlanations) to generate human-readable reason codes for regulatory compliance.
- Deployment: Built an interactive frontend using Streamlit.

## Results
- The model successfully balances Recall and Precision for highly imbalanced data.
- Explanations are provided natively alongside predictions.

## Explainability
Example: *Flagged because of unusual: txn_count_1h, amount_log, hour*

## Tech Stack
`pandas`, `scikit-learn`, `xgboost`, `imbalanced-learn` (SMOTE), `shap`, `streamlit`
