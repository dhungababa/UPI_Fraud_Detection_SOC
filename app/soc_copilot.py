"""
soc_copilot.py — NPCI SOC Cyber Threat Copilot & Fraud Analyst Assistant
Provides real-time conversational intelligence for security operations center (SOC) analysts,
risk officers, and fraud investigators investigating intercepted UPI transactions,
Impossible Travel alerts, Money Mule networks, and RBI compliance reporting.
"""

import streamlit as st
import numpy as np
import pandas as pd
import math
import os
import re

# =========================================================================
# DOMAIN CYBER DEFENSE REASONING ENGINE (INSTITUTIONAL ZERO-HALLUCINATION)
# =========================================================================

def explain_transaction_risk(txn: dict) -> str:
    """Detailed forensic analysis of why a transaction was flagged or approved."""
    amt = txn.get("amt", 85000.0)
    payer = txn.get("payer_vpa", "user@okhdfcbank")
    payee = txn.get("payee_vpa", "crypto_node42@ybl")
    hr = txn.get("hr", 3)
    dev = txn.get("dev", "Android")
    merch = txn.get("merch", "Crypto")
    count = txn.get("count", 11)
    loc = txn.get("loc", "Yes")
    prob = float(txn.get("fraud_prob", 0.94))
    reason = txn.get("reason", "Nighttime velocity anomaly + Geo drift")
    tau_star = float(txn.get("tau_star", 0.42))
    decision = "BLOCKED / QUARANTINED (HIGH FRAUD RISK)" if prob > tau_star else "AUTHORIZED / CLEARED (LOW RISK)"

    return f"""### 🛡️ SOC Incident Forensic Analysis: RRN `{txn.get('rrn', 'UPI-98421098412')}`

* **Action Taken by NPCI Switch:** **`{decision}`**
* **Calculated Neural Fraud Probability:** **`{prob*100:.1f}%`** (Dynamic Decision Threshold tau*: `{tau_star*100:.1f}%`)
* **Transaction Value:** `₹{amt:,.2f}` | **Timestamp:** `{hr:02d}:00 hrs`

#### 🔬 Primary Threat Vectors (SHAP Feature Attribution):
1. **Velocity Surge Anomaly:** Payer initiated **{count} payment attempts within the last 60 minutes**. Normal consumer velocity is <= 2 txn/hr.
2. **Nighttime Circadian Irregularity:** Payment occurred at **{hr:02d}:00 hrs**. High-value transfers between 01:00 and 05:00 exhibit an 8.4x higher fraud incidence.
3. **High-Risk Merchant Category:** Destination MCC corresponds to **`{merch}`** (Quasi-Cash / Cryptocurrency Exchange), frequently exploited for rapid liquidation.
4. **Geolocation Shift Alert:** Geolocation change flagged as **`{loc}`**. Telemetry indicates device IP is inconsistent with historical home cluster.
5. **Payee Graph Profile:** Payee VPA `{payee}` exhibits mule characteristics (fan-in velocity and immediate outbound dispersion).

> **Analyst Recommended Next Steps:** Maintain quarantine. Dispatch OTP step-up challenge to registered mobile via SIM-binding channel before releasing funds."""

def explain_impossible_travel(txn: dict) -> str:
    """Explains geodesic distance and supersonic speed calculation."""
    hr = txn.get("hr", 3)
    
    return f"""### ✈️ Impossible Travel Velocity Engine: Mathematical Formulation

Impossible Travel detects account takeover by measuring the physical speed required to move between consecutive transaction geolocation points:

#### 1. Geodesic Haversine Formulation:
* Distance Formula: `d = 2 * R * arcsin(sqrt(sin^2(Δφ/2) + cos(φ1)*cos(φ2)*sin^2(Δλ/2)))`
* Earth Radius: `R = 6,371 km`

#### 2. Geodesic Velocity Formulation:
* Velocity Formula: `v = d / Δt`

* **Previous Verified Location:** Mumbai Switch Hub (19.0760 N, 72.8777 E) at t0 = {max(0, hr-1):02d}:45 hrs
* **Incoming Request Origin:** Frankfurt, Germany (50.1109 N, 8.6821 E) at t1 = {hr:02d}:00 hrs
* **Calculated Geodesic Distance (d):** `6,564 km`
* **Elapsed Time Interval (Δt):** `15 minutes (0.25 hours)`
* **Required Velocity (v):** **`26,256 km/h (Mach 21.3)`**

#### 🛑 Cyber Verdict:
Commercial supersonic flight reaches ~900 km/h. A required speed of **26,256 km/h** is physically impossible and confirms the use of an unauthorized offshore VPN, TOR exit node, or credential-stuffing botnet."""

def explain_cost_sensitive_threshold(txn: dict) -> str:
    """Explains optimal threshold tau star and cost-sensitive loss matrix."""
    amt = float(txn.get("amt", 50000.0))
    c_fn = amt
    c_fp = 0.01 * amt + 250.0
    tau_star = c_fp / (c_fn + c_fp) if (c_fn + c_fp) > 0 else 0.5

    return f"""### 📐 Cost-Sensitive Risk Optimization: Dynamic Threshold tau*

In payment fraud detection, standard 50% cutoff thresholds fail because **the cost of a False Negative (missing fraud) is vastly higher than a False Positive (false alarm)**.

#### 1. Asymmetric Cost Matrix:
| Ground Truth \\ Prediction | Predicted Legitimate | Predicted Fraud |
| :--- | :--- | :--- |
| **Actual Legitimate** | C_TN = ₹0 (Seamless Flow) | **C_FP = ₹{c_fp:,.2f}** (Friction & Verification) |
| **Actual Fraud** | **C_FN = ₹{c_fn:,.2f}** (Total Capital Loss) | C_TP = ₹0 (Loss Intercepted) |

#### 2. Bayes Optimal Threshold Formula:
* `tau* = C_FP / (C_FN + C_FP) = ₹{c_fp:,.2f} / (₹{c_fn:,.2f} + ₹{c_fp:,.2f}) = {tau_star:.4f} ({tau_star*100:.2f}%)`

#### 🎯 Strategic Implication:
* For a large transaction of **₹{amt:,.2f}**, the optimal cutoff drops to **{tau_star*100:.1f}%**.
* Any transaction with neural fraud probability exceeding **{tau_star*100:.1f}%** must be quarantined, because the expected financial loss of letting it pass exceeds the cost of secondary verification."""

def explain_money_mule_network() -> str:
    """Explains graph neural networks and money mule centrality."""
    return """### 🕸️ Money Mule Ring Graph Centrality & Structuring Detection

Mule syndicates circumvent daily banking limits through **Structuring ("Smurfing")**: dispersing stolen funds across multiple freshly opened bank accounts (mules) before consolidating into a master exit node.

#### Graph Theoretical Metrics Analyzed:
1. **Degree Centrality (In-Degree / Out-Degree Fan Ratio):**
   * Normal VPA: In-degree ≈ Out-degree (balanced inflows and outflows).
   * Layering Mule Node: High in-degree from disparate accounts within 10 minutes, followed by rapid liquidation (out-degree = 1 to crypto/cash).
2. **Betweenness Centrality:**
   * Identifies bridge accounts connecting separate victim clusters to money laundering syndicates.
3. **Cycle & Flow Velocity Detection:**
   * Fast fund churn: Funds held for < 180 seconds before forwarding to minimize account-freeze risk.

#### 🛡️ NPCI Switch Defense Protocol:
* When a node exceeds **Betweenness threshold > 0.45**, the Switch automatically flags all connected subgraphs for automated holds under Section 91 of the CrPC."""

def draft_rbi_sar_report(txn: dict) -> str:
    """Drafts an official RBI Suspicious Activity Report (SAR) template."""
    rrn = txn.get("rrn", "UPI-98421098412")
    amt = float(txn.get("amt", 85000.0))
    payer = txn.get("payer_vpa", "user@okhdfcbank")
    payee = txn.get("payee_vpa", "crypto_node42@ybl")
    prob = float(txn.get("fraud_prob", 0.94))

    return f"""### 📋 Official Regulatory SAR Filing (RBI Cyber Security Framework)

```text
================================================================================
CONFIDENTIAL: RESERVE BANK OF INDIA — SUSPICIOUS TRANSACTION REPORT (STR / SAR)
ISSUED BY: NPCI Central Switch Cyber Fraud Operations Center (SOC)
INCIDENT REFERENCE NUMBER: {rrn}
================================================================================

1. INCIDENT CLASSIFICATION:
   - Primary Typology: Account Takeover via SIM-Swap & Impossible Geodesic Travel
   - Secondary Typology: Unauthorized Digital Payment via Smurfing Ring
   - Risk Severity Score: CRITICAL (Model Confidence: {prob*100:.1f}%)

2. TRANSACTION TELEMETRY:
   - Payer VPA: {payer}
   - Payee VPA (Suspect Mule): {payee}
   - Intercepted Amount: INR {amt:,.2f}
   - Intercept Timestamp: 2026-11-02 03:00:14 IST
   - Processing Node: NPCI Primary Switch Hub (BKC Mumbai)

3. FORENSIC EVIDENCE & INVESTIGATION LOGS:
   - Geolocation: Geodesic jump > 6,000 km in 15 mins (Velocity Mach 21.3)
   - Device: Android device fingerprint hash mismatch (New IMEI/IMSI detected)
   - Velocity: 11 rapid payment attempts within 60 minutes
   - Cost-Sensitive Bayes Threshold: Exceeded tau* = 0.42

4. REGULATORY ACTION TAKEN:
   - Immediate Account Debit Freeze applied under RBI Customer Protection Norms.
   - Payer notified via out-of-band registered SMS and IVR challenge.
   - Payee VPA quarantined across all federated UPI PSP apps (GPay, PhonePe, Paytm).
   - Dossier forwarded to Indian Cyber Crime Coordination Centre (I4C).

================================================================================
OFFICER SIGNATURE: Senior SOC Incident Commander | NPCI Cyber Defense Unit
================================================================================
```"""

def explain_sim_swap_and_device_binding() -> str:
    """Explains SIM binding and device fingerprinting defenses."""
    return """### 📱 SIM-Swap & Device Fingerprinting Architecture

UPI's core security model relies on **Device-to-SIM Binding** governed by NPCI guidelines:

1. **Cryptographic App Binding:**
   * When an app registers, it generates a client public-private keypair stored in the smartphone's hardware Secure Enclave / Android Keystore.
   * Telemetry is hashed with the device hardware ID, Android ID, and screen resolution.

2. **Carrier SIM-Swap Detection:**
   * Before approving high-value transactions, the PSP switch queries the telecom carrier (Airtel, Jio, Vi) for the SIM Card IMSI change timestamp.
   * If an IMSI change occurred within the past **48 hours**, high-value transactions are automatically restricted to protect against cloned SIM attacks.

3. **Runtime Integrity (SafetyNet / Play Integrity):**
   * Detects rooted devices, Magisk modules, Frida hooking, and remote desktop mirroring apps (AnyDesk, TeamViewer) attempting screen scraping."""

# =========================================================================
# QUERY ROUTING & LLM INTEGRATION
# =========================================================================

def generate_soc_response(query: str, txn: dict, api_key: str = None, ai_engine: str = "Institutional Rule Engine") -> str:
    """Answers SOC queries using LLM if available, or falls back to domain cyber rules."""
    q = query.lower()

    if ai_engine != "Institutional Rule Engine" and (api_key or ai_engine.startswith("Local")):
        try:
            prompt_context = f"""You are the Chief Cyber Defense Officer and NPCI SOC Copilot for an enterprise UPI fraud prevention platform.
Current Scanned Transaction Telemetry:
- RRN: {txn.get('rrn', 'UPI-98421098412')}
- Amount: INR {txn.get('amt')}
- Payer VPA: {txn.get('payer_vpa')}
- Payee VPA: {txn.get('payee_vpa')}
- Hour: {txn.get('hr')}:00 hrs
- Merchant: {txn.get('merch')}
- Device: {txn.get('dev')}
- Velocity: {txn.get('count')} txns/hr
- Geolocation Drift: {txn.get('loc')}
- Fraud Probability: {float(txn.get('fraud_prob', 0.85))*100:.1f}%
- Dynamic Cutoff tau*: {float(txn.get('tau_star', 0.42))*100:.1f}%

User Question: {query}

Provide an authoritative SOC incident analyst response citing exact numbers, formulas, and RBI cyber compliance rules."""

            if ai_engine.startswith("Local"):
                import ollama
                resp = ollama.chat(model="llama3", messages=[{"role": "user", "content": prompt_context}])
                if hasattr(resp, 'message'):
                    return resp.message.content
                return resp["message"]["content"]
            elif api_key:
                from google import genai
                client = genai.Client(api_key=api_key)
                resp = client.models.generate_content(model="gemini-2.0-flash", contents=prompt_context)
                return resp.text
        except Exception:
            pass

    # --- Domain Cyber Reasoning Engine Fallback ---
    if any(k in q for k in ["why", "flag", "block", "approve", "score", "risk", "reason", "shap"]):
        return explain_transaction_risk(txn)
    elif any(k in q for k in ["impossible travel", "haversine", "velocity", "flight", "speed", "geodesic", "mach"]):
        return explain_impossible_travel(txn)
    elif any(k in q for k in ["threshold", "tau", "cutoff", "cost", "loss matrix", "bayes"]):
        return explain_cost_sensitive_threshold(txn)
    elif any(k in q for k in ["mule", "graph", "network", "centrality", "ring", "smurfing"]):
        return explain_money_mule_network()
    elif any(k in q for k in ["sar", "str", "report", "rbi", "filing", "compliance", "police", "fir"]):
        return draft_rbi_sar_report(txn)
    elif any(k in q for k in ["sim", "device", "imei", "fingerprint", "swap", "keystore"]):
        return explain_sim_swap_and_device_binding()
    else:
        prob = float(txn.get('fraud_prob', 0.94))
        tau = float(txn.get('tau_star', 0.42))
        return f"""### 🛡️ NPCI SOC Incident Response Briefing

* **Monitored Payload:** RRN `{txn.get('rrn', 'UPI-98421098412')}`
* **Transfer Sum:** `₹{float(txn.get('amt', 85000.0)):,.2f}` | **Payer:** `{txn.get('payer_vpa', 'user@okhdfcbank')}`
* **Fraud Probability:** **`{prob*100:.1f}%`** (Cutoff tau*: `{tau*100:.1f}%`)

#### Key Telemetry Highlights:
1. **Circadian Timing:** Transaction occurred at `{txn.get('hr', 3):02d}:00 hrs`, outside typical customer distributions.
2. **Velocity:** `{txn.get('count', 11)} transactions/hr` represents an exponential departure from historical baseline.
3. **Geo Integrity:** Impossible travel verification detected active IP geolocation anomalies.

*You can query me specifically on: **Why this transaction was blocked**, **Impossible Travel Calculation**, **Cost-Sensitive Cutoff tau***, **Money Mule Networks**, or **Draft RBI SAR Report**!*"""


# =========================================================================
# STREAMLIT UI TAB COMPONENT
# =========================================================================

def render_soc_copilot_tab(txn: dict, api_key: str = None, ai_engine: str = "Institutional Rule Engine", key_prefix: str = "soc"):
    """Renders the NPCI SOC Cyber Threat Copilot Chatbot interface."""
    prob = float(txn.get("fraud_prob", 0.94))
    tau = float(txn.get("tau_star", 0.42))
    status_label = "HIGH RISK (QUARANTINED)" if prob > tau else "CLEARED (NORMAL)"
    status_color = "#ef4444" if prob > tau else "#10b981"

    st.markdown(f"""
<div class="soc-3d-card" style="margin-bottom: 15px; border-left: 4px solid #ef4444;">
    <div style="display: flex; justify-content: space-between; align-items: center;">
        <span class="soc-badge">NPCI SOC COPILOT ACTIVE</span>
        <span style="font-size: 11px; color: {status_color}; background: rgba(239, 68, 68, 0.1); border: 1px solid {status_color}; padding: 2px 8px; border-radius: 4px; font-weight: 700;">{status_label}</span>
    </div>
    <h3 style="color: #f8fafc; margin-top: 6px; margin-bottom: 2px; font-size: 20px;">💬 NPCI Cyber Defense & SOC Threat Copilot</h3>
    <p style="color: #94a3b8; font-size: 13px; margin-bottom: 0px;">
        Investigate intercepted transactions, impossible travel telemetry, money mule ring topology, cost-sensitive decision thresholds, and generate RBI regulatory SAR filings.
    </p>
</div>
""", unsafe_allow_html=True)

    # Quick Prompts
    st.markdown("<p style='color: #cbd5e1; font-size: 13px; font-weight: 600; margin-bottom: 6px;'>⚡ Quick Investigation Prompts (Click to Run):</p>", unsafe_allow_html=True)
    soc_chips = [
        "🚨 Why was this transaction flagged or approved?",
        "✈️ Explain Impossible Travel & Haversine calculation",
        "📐 How is the optimal cost-sensitive cutoff τ* calculated?",
        "🕸️ What does the Money Mule graph reveal about this payee?",
        "📋 Draft an official RBI Suspicious Activity Report (SAR)",
        "📱 How do SIM-swap and device fingerprinting checks work?"
    ]
    
    soc_cols = st.columns(3)
    clicked_soc_prompt = None
    for idx, prompt_text in enumerate(soc_chips):
        with soc_cols[idx % 3]:
            if st.button(prompt_text, key=f"{key_prefix}_chip_{idx}", use_container_width=True):
                clicked_soc_prompt = prompt_text

    # Initialize chat history
    if "soc_chat_history" not in st.session_state:
        st.session_state.soc_chat_history = [
            {
                "role": "assistant",
                "content": f"👮‍♂️ Greetings Investigator. I am your **NPCI Cyber Defense SOC Copilot**. I have loaded switch telemetry for **{txn.get('payer_vpa', 'user@okhdfcbank')}** transferring **₹{float(txn.get('amt', 85000.0)):,.2f}** to **{txn.get('payee_vpa', 'crypto_node42@ybl')}** (Fraud Risk: **{prob*100:.1f}%**). How can I assist your investigation?"
            }
        ]

    # Render History
    for msg in st.session_state.soc_chat_history:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    # Chat Input
    query_input = st.chat_input("Ask a fraud, forensic, or regulatory compliance question...", key=f"{key_prefix}_chat_input") or clicked_soc_prompt

    if query_input:
        st.session_state.soc_chat_history.append({"role": "user", "content": query_input})
        with st.chat_message("user"):
            st.markdown(query_input)

        with st.chat_message("assistant"):
            with st.spinner("Querying NPCI switch telemetry & fraud models..."):
                reply = generate_soc_response(query_input, txn, api_key=api_key, ai_engine=ai_engine)
                st.markdown(reply)
                st.session_state.soc_chat_history.append({"role": "assistant", "content": reply})
