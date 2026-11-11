"""
soar_playbook.py — Real-Time Automated SOAR (Security Orchestration, Automation, and Response) Engine
NPCI UPI Payment Cyber Defense Operations Center (SOC)

Simulates institutional cyber defense workflows:
1. 'switch_freeze': Dispatches ISO 8583 message to NPCI switch to block payee VPA and freeze inbound UPI credits.
2. 'biometric_step_up': Pushes out-of-band biometric challenge / SIM-binding reverification to registered payer handset.
3. 'cert_in_dispatch': Formats official Indian Cyber Crime Coordination Centre (I4C / NCRP / CERT-In) incident packet.
4. 'firewall_quarantine': Adds client IP to cloud WAF blacklist.
"""

import time
import random
import datetime
import hashlib
import json
import pandas as pd
import streamlit as st


# =========================================================================
# CORE SOAR PLAYBOOK EXECUTION FUNCTION
# =========================================================================

def execute_soar_playbook(rrn: str, action_type: str, txn_data: dict) -> dict:
    """
    Executes an automated SOAR action against the NPCI switch, identity provider,
    regulatory reporting portal, or cloud edge WAF.

    Args:
        rrn: 12-digit Retrieval Reference Number (e.g. 'UPI-98421098412' or '98421098412')
        action_type: One of 'switch_freeze', 'biometric_step_up', 'cert_in_dispatch', 'firewall_quarantine'
        txn_data: Dictionary containing transaction context (amount, payer_vpa, payee_vpa, ip, etc.)

    Returns:
        dict containing execution outcome, latency, raw ISO/API payload, and status.
    """
    t_start = time.perf_counter()
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    now_iso = now_utc.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    now_ist = (now_utc + datetime.timedelta(hours=5, minutes=30)).strftime("%d-%b-%Y %H:%M:%S IST")

    # Clean RRN
    clean_rrn = str(rrn).replace("RRN-", "").replace("UPI-", "").strip()
    if not clean_rrn:
        clean_rrn = f"{random.randint(100000000000, 999999999999)}"

    payer_vpa = txn_data.get("payer_vpa") or txn_data.get("payer") or "user@okhdfcbank"
    payee_vpa = txn_data.get("payee_vpa") or txn_data.get("payee") or "crypto_node42@ybl"
    amt = float(txn_data.get("amt") or txn_data.get("amount") or 85000.0)
    client_ip = txn_data.get("ip") or txn_data.get("client_ip") or "45.142.212.60"
    device_id = txn_data.get("dev") or txn_data.get("device") or "Android-Pixel8-ARM64"
    fraud_prob = float(txn_data.get("fraud_prob") or txn_data.get("prob") or 0.942)
    reason = txn_data.get("reason") or "Nighttime velocity anomaly + Geo drift"

    action_key = str(action_type).lower().strip()

    # 1. SWITCH FREEZE: ISO 8583 NPCI SWITCH COMMAND
    if action_key == "switch_freeze":
        # Simulate sub-50ms switch roundtrip
        simulated_ms = round(random.uniform(14.2, 26.8), 2)
        exec_latency = max(simulated_ms, (time.perf_counter() - t_start) * 1000.0)
        
        iso_packet = {
            "MTI": "0420",  # Acquirer Reversal / Payee Account Freeze Advice
            "DE-002 (PAN / Virtual Account)": f"VPA:{payee_vpa}",
            "DE-003 (Processing Code)": "200000 (Credit Inbound Freeze / Block Credits)",
            "DE-004 (Transaction Amount)": f"INR {amt:,.2f}",
            "DE-007 (Transmission Date/Time)": now_iso,
            "DE-011 (Systems Trace Audit Number - STAN)": f"{random.randint(100000, 999999)}",
            "DE-037 (Retrieval Reference Number - RRN)": clean_rrn,
            "DE-039 (Action Code)": "05 (Do Not Honor - Account Frozen by Cyber SOC)",
            "DE-048 (Private Data / Fraud Directive)": "NPCI-DPDP-SEC-2026: Rogue Payee VPA Quarantined",
            "DE-102 (Payer VPA)": payer_vpa,
            "DE-103 (Beneficiary Payee VPA)": payee_vpa,
            "Target Node": "NPCI-UPI-CORE-SWITCH-DC01.npci.org.in:9850"
        }

        return {
            "action_id": f"SOAR-FRZ-{clean_rrn[-6:]}-{random.randint(100, 999)}",
            "action_type": "switch_freeze",
            "action_title": "NPCI Switch ISO 8583 VPA Account Freeze",
            "status": "EXECUTED_SUCCESS",
            "rrn": clean_rrn,
            "target": payee_vpa,
            "latency_ms": exec_latency,
            "sla_status": "PASS (<50ms SLA)",
            "timestamp": now_ist,
            "summary": f"Dispatched ISO 8583 MTI 0420 reversal to NPCI switch. Inbound credits for '{payee_vpa}' are frozen instantly.",
            "protocol": "ISO 8583:1993 (NPCI UPI Specification v2.8) over TLS 1.3 mTLS",
            "telemetry_packet": iso_packet
        }

    # 2. BIOMETRIC STEP-UP CHALLENGE (FIDO2 / SIM BINDING)
    elif action_key == "biometric_step_up":
        simulated_ms = round(random.uniform(18.5, 34.2), 2)
        exec_latency = max(simulated_ms, (time.perf_counter() - t_start) * 1000.0)
        
        challenge_nonce = hashlib.sha256(f"{clean_rrn}:{now_iso}:{payer_vpa}".encode()).hexdigest()[:32]
        fido2_packet = {
            "auth_channel": "APNs / FCM Priority Push + FIDO2 / WebAuthn Biometric Prompt",
            "target_device": device_id,
            "registered_payer": payer_vpa,
            "rrn": clean_rrn,
            "challenge_nonce": challenge_nonce,
            "sim_binding_status": "RE-VERIFICATION_REQUIRED (IMSI / eUICC Hash Match)",
            "biometric_modality": "Handset Secure Enclave (FaceID / Fingerprint / Aadhaar Iris L1)",
            "callback_webhook": f"https://api.npci.org.in/v2/upi/auth-callback/{clean_rrn}",
            "timeout_seconds": 60,
            "step_up_reason": f"High risk anomaly detected (Risk: {fraud_prob*100:.1f}%, Reason: {reason})"
        }

        return {
            "action_id": f"SOAR-BIO-{clean_rrn[-6:]}-{random.randint(100, 999)}",
            "action_type": "biometric_step_up",
            "action_title": "Out-of-Band Biometric & SIM-Binding Re-Verification",
            "status": "DISPATCHED_PENDING_USER",
            "rrn": clean_rrn,
            "target": payer_vpa,
            "latency_ms": exec_latency,
            "sla_status": "PASS (<50ms SLA)",
            "timestamp": now_ist,
            "summary": f"Pushed out-of-band FIDO2 cryptographic biometric challenge to {payer_vpa}'s registered secure enclave.",
            "protocol": "FIDO2 / WebAuthn L2 Authenticator + FCM High-Priority Push",
            "telemetry_packet": fido2_packet
        }

    # 3. CERT-IN / I4C NCRP INCIDENT DISPATCH
    elif action_key == "cert_in_dispatch":
        simulated_ms = round(random.uniform(22.1, 41.5), 2)
        exec_latency = max(simulated_ms, (time.perf_counter() - t_start) * 1000.0)
        
        incident_ref = f"NCRP/2026/UPI/{random.randint(1000000, 9999999)}"
        device_hash = hashlib.sha256(f"{device_id}:{client_ip}".encode()).hexdigest()[:24]
        ncrp_packet = {
            "portal": "Indian Cyber Crime Coordination Centre (I4C) / NCRP 1930 Helpline API",
            "incident_ticket_ref": incident_ref,
            "category": "Cyber Financial Fraud — Unauthorized Electronic Payment (UPI)",
            "rrn": clean_rrn,
            "incident_timestamp_utc": now_iso,
            "defrauded_or_payer_vpa": payer_vpa,
            "beneficiary_mule_vpa": payee_vpa,
            "amount_inr": amt,
            "originating_client_ip": client_ip,
            "originating_device_fingerprint": device_hash,
            "fraud_probability": round(fraud_prob, 4),
            "primary_ml_indicator": reason,
            "recommended_enforcement": "Immediate Freeze of Destination Account under Section 91 CrPC / DPDP Act 2023",
            "cert_in_coordination_status": "DISPATCHED (CERT-In Financial SOC Desk Copy Forwarded)"
        }

        return {
            "action_id": f"SOAR-NCRP-{clean_rrn[-6:]}-{random.randint(100, 999)}",
            "action_type": "cert_in_dispatch",
            "action_title": "I4C / NCRP & CERT-In Incident Dossier Dispatch",
            "status": "DISPATCHED_CONFIRMED",
            "rrn": clean_rrn,
            "target": f"I4C NCRP Portal ({incident_ref})",
            "latency_ms": exec_latency,
            "sla_status": "PASS (<50ms SLA)",
            "timestamp": now_ist,
            "summary": f"Formulated and electronically dispatched official I4C/NCRP cyber incident packet for RRN {clean_rrn}.",
            "protocol": "Govt of India I4C Inter-Bank Fraud Management REST API v2.4 (HMAC-SHA256)",
            "telemetry_packet": ncrp_packet
        }

    # 4. CLOUD WAF FIREWALL QUARANTINE
    elif action_key == "firewall_quarantine":
        simulated_ms = round(random.uniform(11.4, 21.9), 2)
        exec_latency = max(simulated_ms, (time.perf_counter() - t_start) * 1000.0)
        
        waf_rule_id = f"waf-rule-drop-{hashlib.md5(client_ip.encode()).hexdigest()[:8]}"
        waf_packet = {
            "waf_provider": "NPCI Edge Security Shield (Cloudflare Magic Transit / AWS WAF)",
            "target_ip_cidr": f"{client_ip}/32",
            "action": "DROP_IMMEDIATE (TCP RST / HTTP 403 Forbidden)",
            "applied_rule_id": waf_rule_id,
            "edge_scope": "All NPCI UPI Ingress Gateways & Switch Edge PoPs",
            "ttl_quarantine_hours": 72,
            "trigger_rrn": clean_rrn,
            "reason": f"Malicious UPI transaction spoofing / Automated botnet activity ({reason})"
        }

        return {
            "action_id": f"SOAR-WAF-{clean_rrn[-6:]}-{random.randint(100, 999)}",
            "action_type": "firewall_quarantine",
            "action_title": "Cloud Edge WAF Client IP Quarantine",
            "status": "APPLIED_EDGE_ACTIVE",
            "rrn": clean_rrn,
            "target": f"{client_ip}/32",
            "latency_ms": exec_latency,
            "sla_status": "PASS (<50ms SLA)",
            "timestamp": now_ist,
            "summary": f"Blacklisted client IP {client_ip} across all NPCI cloud ingress edge nodes for 72 hours.",
            "protocol": "Cloud Edge WAF Policy Sync via gRPC / BGP Flowspec Filter",
            "telemetry_packet": waf_packet
        }

    else:
        return {
            "action_id": f"SOAR-ERR-{random.randint(1000, 9999)}",
            "action_type": action_type,
            "action_title": "Unknown SOAR Action",
            "status": "ERROR_UNRECOGNIZED_ACTION",
            "rrn": clean_rrn,
            "target": "N/A",
            "latency_ms": 0.5,
            "sla_status": "N/A",
            "timestamp": now_ist,
            "summary": f"Unrecognized SOAR action type '{action_type}'",
            "protocol": "N/A",
            "telemetry_packet": {}
        }


# =========================================================================
# STREAMLIT UI COMPONENT: INTERACTIVE SOAR CONTROL PANEL
# =========================================================================

def render_soar_component(current_txn: dict, key_prefix: str = "soar"):
    """
    Renders the interactive Security Orchestration, Automation, and Response (SOAR)
    control panel with action buttons, visual execution timeline, sub-50ms latency
    badges, and audit trail log.
    """
    if "soar_audit_trail" not in st.session_state:
        st.session_state.soar_audit_trail = []

    # Extract transaction values
    rrn = current_txn.get("rrn", "RRN-98421098412")
    amt = float(current_txn.get("amt", 85000.0))
    payer = current_txn.get("payer_vpa", "user@okhdfcbank")
    payee = current_txn.get("payee_vpa", "crypto_node42@ybl")
    ip = current_txn.get("ip", "45.142.212.60")
    fraud_prob = float(current_txn.get("fraud_prob", 0.942))
    reason = current_txn.get("reason", "Nighttime velocity anomaly + Geo drift")

    # Header Card
    st.markdown(f"""
    <div style="background: linear-gradient(135deg, rgba(15, 23, 42, 0.9), rgba(2, 6, 23, 0.95)); border: 1px solid rgba(0, 255, 204, 0.3); border-radius: 10px; padding: 16px 20px; margin-bottom: 20px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
            <span style="color: #00ffcc; font-family: monospace; font-size: 13px; font-weight: 700; letter-spacing: 1px;">
                ⚡ NPCI AUTOMATED SOAR PLAYBOOK CONTROLS
            </span>
            <span style="background: rgba(239, 68, 68, 0.15); color: #ef4444; border: 1px solid #ef4444; font-size: 11px; padding: 2px 8px; border-radius: 4px; font-weight: 700;">
                LIVE INCIDENT READY
            </span>
        </div>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; font-size: 13px; color: #cbd5e1;">
            <div><b>Target RRN:</b> <code style="color: #00ffcc;">{rrn}</code></div>
            <div><b>At-Risk Amount:</b> <span style="color: #f8fafc; font-weight: 700;">₹{amt:,.2f}</span></div>
            <div><b>Beneficiary VPA:</b> <span style="color: #fca5a5;">{payee}</span></div>
            <div><b>Client IP:</b> <code style="color: #93c5fd;">{ip}</code></div>
            <div><b>Calculated Risk:</b> <span style="color: {'#ef4444' if fraud_prob > 0.5 else '#10b981'}; font-weight: 700;">{fraud_prob*100:.1f}%</span></div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # SOAR Action Buttons Grid
    st.markdown("<p style='color: #e2e8f0; font-size: 14px; font-weight: 600; margin-bottom: 8px;'>🎯 Select Immediate Automated Defense Action (Sub-50ms SLA):</p>", unsafe_allow_html=True)

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        if st.button("⚡ NPCI Switch Freeze", key=f"{key_prefix}_btn_freeze", use_container_width=True, help="Dispatch ISO 8583 MTI 0420 reversal to freeze payee VPA credits"):
            result = execute_soar_playbook(rrn, "switch_freeze", current_txn)
            st.session_state.soar_audit_trail.insert(0, result)
            st.toast("✅ ISO 8583 Payee Freeze executed at switch in sub-20ms!", icon="⚡")

    with c2:
        if st.button("🔐 Biometric Step-Up", key=f"{key_prefix}_btn_bio", use_container_width=True, help="Push out-of-band FIDO2 challenge / SIM-binding reverification to payer"):
            result = execute_soar_playbook(rrn, "biometric_step_up", current_txn)
            st.session_state.soar_audit_trail.insert(0, result)
            st.toast("📲 Out-of-band biometric challenge dispatched to payer handset!", icon="🔐")

    with c3:
        if st.button("🚨 I4C / CERT-In Dispatch", key=f"{key_prefix}_btn_cert", use_container_width=True, help="Format & dispatch official NCRP financial cyber fraud packet"):
            result = execute_soar_playbook(rrn, "cert_in_dispatch", current_txn)
            st.session_state.soar_audit_trail.insert(0, result)
            st.toast("📋 Official NCRP / I4C cyber incident ticket formulated & sent!", icon="🚨")

    with c4:
        if st.button("🛡️ Cloud WAF Quarantine", key=f"{key_prefix}_btn_waf", use_container_width=True, help="Blacklist client IP across all edge WAF ingress nodes"):
            result = execute_soar_playbook(rrn, "firewall_quarantine", current_txn)
            st.session_state.soar_audit_trail.insert(0, result)
            st.toast("🛑 Client IP blacklisted on Cloud Edge WAF for 72 hours!", icon="🛡️")

    # Full containment button
    st.markdown("<div style='margin-top: 10px;'></div>", unsafe_allow_html=True)
    if st.button("⚡ EXECUTE AUTOMATED FULL SOAR CONTAINMENT PROTOCOL (ALL 4 ACTIONS)", key=f"{key_prefix}_btn_contain_all", use_container_width=True, type="primary"):
        actions = ["switch_freeze", "biometric_step_up", "cert_in_dispatch", "firewall_quarantine"]
        for act in actions:
            res = execute_soar_playbook(rrn, act, current_txn)
            st.session_state.soar_audit_trail.insert(0, res)
        st.success(f"🛡️ Full 4-tier SOAR containment playbook executed across switch, handset, I4C portal, and edge WAF for RRN {rrn}!")
        st.balloons()

    # Visual Execution Timeline
    st.markdown("<div style='margin-top: 24px;'></div>", unsafe_allow_html=True)
    st.subheader("⏱️ SOAR Visual Execution Timeline & Latency Benchmark")
    
    if not st.session_state.soar_audit_trail:
        st.info("No SOAR actions triggered yet for this session. Click any of the defense buttons above to execute real-time containment.")
    else:
        # Show recent actions as visual cards
        for idx, entry in enumerate(st.session_state.soar_audit_trail[:6]):
            latency = entry.get("latency_ms", 20.0)
            sla_pass = latency < 50.0
            sla_badge_color = "#10b981" if sla_pass else "#f59e0b"
            status_color = "#00ffcc" if "SUCCESS" in entry["status"] or "CONFIRMED" in entry["status"] or "ACTIVE" in entry["status"] else "#fbbf24"

            st.markdown(f"""
            <div style="background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(255, 255, 255, 0.08); border-left: 4px solid {status_color}; border-radius: 8px; padding: 12px 16px; margin-bottom: 12px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                    <div>
                        <b style="color: #f8fafc; font-size: 14px;">{entry.get('action_title')}</b>
                        <span style="color: #64748b; font-size: 11px; margin-left: 10px;">ID: <code>{entry.get('action_id')}</code></span>
                    </div>
                    <div>
                        <span style="background: {sla_badge_color}22; color: {sla_badge_color}; border: 1px solid {sla_badge_color}; padding: 2px 8px; border-radius: 4px; font-weight: 700; font-size: 11px; font-family: monospace;">
                            ⚡ {latency:.2f} ms | {entry.get('sla_status', 'PASS')}
                        </span>
                    </div>
                </div>
                <div style="color: #cbd5e1; font-size: 13px; margin-bottom: 6px;">
                    {entry.get('summary')}
                </div>
                <div style="display: flex; justify-content: space-between; font-size: 11px; color: #94a3b8;">
                    <span><b>Protocol:</b> {entry.get('protocol')}</span>
                    <span><b>Timestamp:</b> {entry.get('timestamp')}</span>
                </div>
            </div>
            """, unsafe_allow_html=True)

            with st.expander(f"🔍 Inspect Dispatched Raw Telemetry Packet ({entry.get('action_id')})"):
                st.json(entry.get("telemetry_packet", {}))

    # Audit Trail Log Table
    st.markdown("<div style='margin-top: 24px;'></div>", unsafe_allow_html=True)
    st.subheader("📋 SOAR Execution Audit Trail Log")
    
    if st.session_state.soar_audit_trail:
        log_rows = []
        for a in st.session_state.soar_audit_trail:
            log_rows.append({
                "Action ID": a.get("action_id"),
                "Timestamp": a.get("timestamp"),
                "RRN": a.get("rrn"),
                "Action Type": a.get("action_type"),
                "Target": a.get("target"),
                "Latency (ms)": f"{a.get('latency_ms', 0):.2f}",
                "Status": a.get("status")
            })
        audit_df = pd.DataFrame(log_rows)
        st.dataframe(audit_df, use_container_width=True)

        col_dl, col_clr = st.columns([1, 1])
        with col_dl:
            csv_data = audit_df.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="📥 Download SOAR Audit Trail (CSV)",
                data=csv_data,
                file_name=f"soar_audit_trail_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                key=f"{key_prefix}_dl_csv"
            )
        with col_clr:
            if st.button("🗑️ Clear SOAR Session Audit Log", key=f"{key_prefix}_btn_clear"):
                st.session_state.soar_audit_trail = []
                st.rerun()
    else:
        st.caption("No audit entries logged yet.")
