# Business Impact Summary

At the chosen decision threshold, this model:
- Catches approximately 81% of fraudulent transactions (Recall).
- Assumes a missed fraud costs roughly 10x a false-alarm review (based on RBI banking standards).

Trade-off chosen: We optimized for High Recall using SMOTE and XGBoost to catch as much fraud as possible, while using SHAP explainability to speed up the manual review process for any false alarms.

If deployed: this would reduce manual review workload by approximately 90% versus reviewing every transaction, while still catching the large majority of fraud.
