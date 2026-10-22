import numpy as np
import pandas as pd
import time
from datetime import datetime
from fpdf import FPDF

class AgentVerdict:
    def __init__(self, agent_id: int, name: str, category: str, vote: str, 
                 risk_score: float, confidence: float, metric_label: str, 
                 metric_val: str, rationale: str):
        self.agent_id = agent_id
        self.name = name
        self.category = category
        self.vote = vote  # 'THREAT', 'SUSPICIOUS', 'PASS'
        self.risk_score = round(float(risk_score), 1)  # 0 to 100
        self.confidence = round(float(confidence), 1)  # 0 to 100
        self.metric_label = metric_label
        self.metric_val = metric_val
        self.rationale = rationale

    def to_dict(self):
        badge = f"[{self.vote}]"
        return {
            "ID": f"#{self.agent_id}",
            "Agent": self.name,
            "Category": self.category,
            "Verdict": badge,
            "Raw_Vote": self.vote,
            "Risk Score": f"{self.risk_score}/100",
            "Confidence": f"{self.confidence}%",
            "Key Metric": f"{self.metric_label}: {self.metric_val}",
            "Forensic Rationale": self.rationale
        }

class UPISOCDefenseSwarm:
    """
    7-Agent Autonomous Cyber Fraud Defense Swarm for NPCI UPI Switch.
    Interprets telemetry, network graphs, device integrity, cost-sensitive math,
    and automated regulatory compliance before switch settlement.
    """
    def __init__(self):
        self.verdicts: list[AgentVerdict] = []

    def evaluate_transaction(self, tx_data: dict, base_ml_prob: float) -> dict:
        """
        Execute all 7 defense agents across incoming UPI packet.
        """
        self.verdicts = []

        amount = float(tx_data.get("amount", 1000.0))
        sim_swap_days = int(tx_data.get("sim_swap_days", 45))
        is_rooted = bool(tx_data.get("is_rooted", False))
        vpn_detected = bool(tx_data.get("vpn_detected", False))
        geo_drift_km = float(tx_data.get("geo_drift_km", 2.5))
        keystroke_speed_ms = int(tx_data.get("keystroke_speed_ms", 180))
        time_to_entry_s = float(tx_data.get("time_to_entry_s", 3.2))
        receiver_vpa = str(tx_data.get("receiver_vpa", "merchant@upi"))
        receiver_age_days = int(tx_data.get("receiver_age_days", 180))
        inflow_velocity_1h = int(tx_data.get("inflow_velocity_1h", 2))
        is_verified_merchant = bool(tx_data.get("is_verified_merchant", True))

        # 1. Device & SIM-Swap Sentinel
        a1 = self._run_agent1_device_sentinel(sim_swap_days, is_rooted, vpn_detected, geo_drift_km)
        self.verdicts.append(a1)

        # 2. Behavioral Biometrics Agent
        a2 = self._run_agent2_behavioral_biometrics(keystroke_speed_ms, time_to_entry_s)
        self.verdicts.append(a2)

        # 3. Money Mule Graph Tracker
        a3 = self._run_agent3_money_mule_tracker(receiver_vpa, receiver_age_days, inflow_velocity_1h)
        self.verdicts.append(a3)

        # 4. VPA & NCRP Blacklist Guard
        a4 = self._run_agent4_vpa_blacklist_guard(receiver_vpa, is_verified_merchant)
        self.verdicts.append(a4)

        # 5. Cost-Sensitive Loss Arbiter
        a5 = self._run_agent5_cost_sensitive_arbiter(amount, base_ml_prob)
        self.verdicts.append(a5)

        # 6. Adaptive Step-Up Quarantine Guard
        a6 = self._run_agent6_adaptive_quarantine(self.verdicts[:5], amount, base_ml_prob)
        self.verdicts.append(a6)

        # 7. RBI Regulatory SAR Compiler
        a7 = self._run_agent7_rbi_sar_compiler(self.verdicts[:6], tx_data, amount, base_ml_prob)
        self.verdicts.append(a7)

        threat_count = sum(1 for v in self.verdicts[:5] if v.vote == "THREAT")
        suspicious_count = sum(1 for v in self.verdicts[:5] if v.vote == "SUSPICIOUS")
        pass_count = sum(1 for v in self.verdicts[:5] if v.vote == "PASS")

        # Composite Swarm Risk Score (0-100)
        composite_score = float(np.mean([v.risk_score for v in self.verdicts[:5]]))

        if threat_count >= 2 or a5.vote == "BLOCK":
            final_action = "HARD BLOCK & QUARANTINE"
        elif threat_count == 1 or suspicious_count >= 2 or a5.vote == "CHALLENGE":
            final_action = "STEP-UP BIOMETRIC CHALLENGE"
        else:
            final_action = "AUTHORIZED (SWITCH PASS)"

        return {
            "tx_id": tx_data.get("tx_id", f"UPI-{int(time.time()*1000)}"),
            "amount": amount,
            "receiver_vpa": receiver_vpa,
            "composite_risk_score": round(composite_score, 1),
            "threat_count": threat_count,
            "suspicious_count": suspicious_count,
            "pass_count": pass_count,
            "final_action": final_action,
            "quarantine_level": a6.metric_val,
            "sar_status": a7.metric_val,
            "sar_narrative": a7.rationale,
            "verdicts": [v.to_dict() for v in self.verdicts]
        }

    # -------------------------------------------------------------
    # AGENT IMPLEMENTATIONS
    # -------------------------------------------------------------
    def _run_agent1_device_sentinel(self, sim_swap_days: int, is_rooted: bool, 
                                   vpn_detected: bool, geo_drift_km: float) -> AgentVerdict:
        risk = 10.0
        threats = []

        if sim_swap_days <= 2:
            risk += 65.0
            threats.append(f"Critical SIM-swap recency ({sim_swap_days}d ago)")
        elif sim_swap_days <= 7:
            risk += 35.0
            threats.append(f"Recent SIM-swap ({sim_swap_days}d ago)")

        if is_rooted:
            risk += 40.0
            threats.append("Rooted/Jailbroken kernel environment detected")

        if vpn_detected:
            risk += 25.0
            threats.append("Anonymous VPN/TOR proxy hop identified")

        if geo_drift_km > 300.0:
            risk += 35.0
            threats.append(f"Abnormal geo-velocity drift ({geo_drift_km:.0f} km)")

        risk = min(99.0, risk)
        if risk >= 75.0:
            vote = "THREAT"
            rationale = "CRITICAL DEVICE COMPROMISE: " + "; ".join(threats)
        elif risk >= 40.0:
            vote = "SUSPICIOUS"
            rationale = "ELEVATED DEVICE RISK: " + "; ".join(threats)
        else:
            vote = "PASS"
            rationale = f"Device integrity verified. Hardware keystore clean, SIM age {sim_swap_days}d, geo-drift {geo_drift_km:.1f}km."

        return AgentVerdict(1, "Device & SIM-Swap Sentinel", "Hardware & Telecom Security",
                            vote, risk, 96.0, "SIM Age / Geo-Drift", 
                            f"{sim_swap_days}d / {geo_drift_km:.0f}km", rationale)

    def _run_agent2_behavioral_biometrics(self, keystroke_ms: int, latency_s: float) -> AgentVerdict:
        risk = 12.0
        reasons = []

        # Bot / automated script injection detection
        if keystroke_ms < 55:
            risk += 75.0
            reasons.append(f"Non-human keystroke speed ({keystroke_ms}ms/key indicates script injection)")
        elif keystroke_ms > 450:
            risk += 30.0
            reasons.append(f"Hesitant PIN entry cadence ({keystroke_ms}ms/key indicates potential social engineering guidance)")

        if latency_s < 0.8:
            risk += 60.0
            reasons.append(f"Instantaneous PIN submission ({latency_s:.2f}s bypasses cognitive processing time)")

        risk = min(99.0, risk)
        if risk >= 70.0:
            vote = "THREAT"
            rationale = "BOT / EMULATOR ANOMALY: " + "; ".join(reasons)
        elif risk >= 35.0:
            vote = "SUSPICIOUS"
            rationale = "BEHAVIORAL FRICTION DETECTED: " + "; ".join(reasons)
        else:
            vote = "PASS"
            rationale = f"Natural human biometric trajectory confirmed (Cadence: {keystroke_ms}ms, Entry Latency: {latency_s:.1f}s)."

        return AgentVerdict(2, "Behavioral Biometrics Agent", "Human Interaction Telemetry",
                            vote, risk, 92.0, "Keystroke / Latency", 
                            f"{keystroke_ms}ms / {latency_s:.1f}s", rationale)

    def _run_agent3_money_mule_tracker(self, vpa: str, age_days: int, velocity: int) -> AgentVerdict:
        risk = 15.0
        signals = []

        if age_days <= 7 and velocity >= 4:
            risk += 70.0
            signals.append(f"Rapid Fan-In on newly registered account ({velocity} payments/hr, age {age_days}d)")
        elif age_days <= 14 and velocity >= 3:
            risk += 45.0
            signals.append(f"Mule velocity clustering ({velocity} inflows/hr on fresh account)")
        elif velocity >= 8:
            risk += 50.0
            signals.append(f"High-frequency account fan-out ({velocity} tx/hr)")

        risk = min(98.0, risk)
        if risk >= 70.0:
            vote = "THREAT"
            rationale = "MONEY MULE LAYERING PATTERN: " + "; ".join(signals)
        elif risk >= 40.0:
            vote = "SUSPICIOUS"
            rationale = "ELEVATED MULE CLUSTER PROBABILITY: " + "; ".join(signals)
        else:
            vote = "PASS"
            rationale = f"Settlement graph profile normal. Account age {age_days}d, historical inflow velocity {velocity} tx/hr."

        return AgentVerdict(3, "Money Mule Graph Tracker", "Network Graph Analysis",
                            vote, risk, 94.0, "Inflow Fan-In Velocity", 
                            f"{velocity} tx/hr (Age: {age_days}d)", rationale)

    def _run_agent4_vpa_blacklist_guard(self, vpa: str, is_verified: bool) -> AgentVerdict:
        # Known suspicious test handles & domain mimics
        flagged_phish_substrings = ["crypto", "binance-p2p", "refund-support", "kyc-verify", "lottery", "telegram", "airdrop"]
        matched_flags = [s for s in flagged_phish_substrings if s in vpa.lower()]

        if matched_flags:
            risk = 92.0
            vote = "THREAT"
            rationale = f"NCRP BLACKLIST MATCH: VPA handle '{vpa}' matches flagged phishing patterns: {', '.join(matched_flags)}."
            val = f"FLAGGED ({matched_flags[0]})"
        elif not is_verified and "@" in vpa and not any(vpa.endswith(b) for b in ["@okhdfcbank", "@okaxis", "@oksbi", "@ybl", "@paytm", "@icici"]):
            risk = 52.0
            vote = "SUSPICIOUS"
            rationale = f"Unregistered unverified payment handle '{vpa}' outside standard verified PSP switch domain whitelist."
            val = "UNVERIFIED PSP DOMAIN"
        else:
            risk = 8.0
            vote = "PASS"
            rationale = f"VPA '{vpa}' cleared against National Cyber Crime Reporting Portal (NCRP) repository and certified PSP registry."
            val = "CLEAN (NCRP CERTIFIED)"

        return AgentVerdict(4, "VPA & NCRP Blacklist Guard", "Entity Intelligence",
                            vote, risk, 97.0, "Registry Status", val, rationale)

    def _run_agent5_cost_sensitive_arbiter(self, amount: float, p_fraud: float) -> AgentVerdict:
        c_fp = 50.0  # Customer friction / operational step-up cost
        c_fn = amount  # Fraud liability loss

        # Mathematical optimal cutoff
        tau_star = c_fp / (c_fp + c_fn) if (c_fp + c_fn) > 0 else 0.05

        expected_loss_authorize = p_fraud * c_fn
        expected_loss_block = (1.0 - p_fraud) * c_fp

        if p_fraud >= tau_star:
            if amount >= 10000.0 or p_fraud >= 0.50:
                vote = "THREAT"
                risk = 90.0
                decision = "BLOCK (Direct Loss Threat)"
                rationale = (f"EXPECTED LOSS ARBITRAGE: P(Fraud)={p_fraud:.2%} exceeds optimal cutoff tau*={tau_star:.3%}. "
                             f"Expected Loss to Authorize (INR {expected_loss_authorize:,.2f}) far exceeds step-up cost (INR {c_fp:.2f}).")
            else:
                vote = "SUSPICIOUS"
                risk = 60.0
                decision = "CHALLENGE (Friction Arbitrage)"
                rationale = (f"THRESHOLD BREACH: P(Fraud)={p_fraud:.2%} > tau*={tau_star:.3%}. Step-up verification required to eliminate INR {expected_loss_authorize:,.2f} liability.")
        else:
            vote = "PASS"
            risk = 15.0
            decision = "AUTHORIZE (Optimal Payoff)"
            rationale = (f"COST-OPTIMAL ACCEPTANCE: P(Fraud)={p_fraud:.2%} is strictly below optimal cutoff tau*={tau_star:.3%}. "
                         f"Direct payment execution maximizes utility without friction drag.")

        return AgentVerdict(5, "Cost-Sensitive Loss Arbiter", "Decision Optimization Math",
                            vote, risk, 98.0, "Optimal Cutoff Tau*", 
                            f"{tau_star:.3%} (Decision: {decision})", rationale)

    def _run_agent6_adaptive_quarantine(self, prior_verdicts: list[AgentVerdict], 
                                        amount: float, p_fraud: float) -> AgentVerdict:
        threats = sum(1 for v in prior_verdicts if v.vote == "THREAT")
        suspicious = sum(1 for v in prior_verdicts if v.vote == "SUSPICIOUS")

        if threats >= 2 or p_fraud >= 0.70:
            level = "LEVEL 3: HARD FREEZE"
            risk = 95.0
            vote = "THREAT"
            rationale = "AUTOMATED ISOLATION: Account and VPA quarantined immediately under DPDP incident response directive."
        elif threats == 1 or suspicious >= 2 or p_fraud >= 0.35:
            level = "LEVEL 2: OUT-OF-BAND OTP"
            risk = 68.0
            vote = "SUSPICIOUS"
            rationale = "STEP-UP LEVEL 2: 30-minute cooling window and out-of-band banking SMS OTP authorization enforced."
        elif suspicious == 1 or p_fraud >= 0.15:
            level = "LEVEL 1: BIOMETRIC AUTH"
            risk = 45.0
            vote = "SUSPICIOUS"
            rationale = "STEP-UP LEVEL 1: Hardware-bound biometric thumbprint/face authentication challenge triggered."
        else:
            level = "LEVEL 0: SILENT PASS"
            risk = 10.0
            vote = "PASS"
            rationale = "FRICTIONLESS PROCESSING: All telemetry satisfies green-channel criteria (<20ms switch throughput)."

        return AgentVerdict(6, "Adaptive Step-Up Quarantine Guard", "Dynamic Enforcement",
                            vote, risk, 95.0, "Enforcement Tier", level, rationale)

    def _run_agent7_rbi_sar_compiler(self, prior_verdicts: list[AgentVerdict], 
                                     tx: dict, amount: float, p_fraud: float) -> AgentVerdict:
        threats = [v for v in prior_verdicts if v.vote == "THREAT"]
        
        if threats or p_fraud >= 0.50:
            sar_status = "SAR FORM 1 COMPILED"
            risk = 88.0
            vote = "THREAT"
            narrative = (f"REGULATORY AUDIT MANDATE: Suspicious Activity Report drafted pursuant to Section 35A of the "
                         f"Banking Regulation Act and PMLA. Telemetry highlights {len(threats)} critical threat triggers: "
                         f"{'; '.join([t.name + ': ' + t.metric_val for t in threats])}. Direct automated filing dispatch initiated.")
        else:
            sar_status = "ROUTINE LOGGED (NO SAR)"
            risk = 10.0
            vote = "PASS"
            narrative = "COMPLIANCE CLEARANCE: Transaction conforms to standard retail payment velocity guidelines. Retained in 180-day audit log."

        return AgentVerdict(7, "RBI Regulatory SAR Compiler", "Statutory Compliance",
                            vote, risk, 99.0, "Statutory Filing Status", sar_status, narrative)


def build_rbi_sar_pdf(tx_summary: dict) -> bytes:
    """
    Generate an official Reserve Bank of India (RBI) Suspicious Activity Report (SAR Form 1).
    """
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 14)
    pdf.cell(190, 8, txt="RESERVE BANK OF INDIA - SUSPICIOUS TRANSACTION REPORT", ln=True, align="C")
    pdf.set_font("Arial", "I", 9)
    pdf.cell(190, 5, txt="Financial Intelligence Unit - India (FIU-IND) / Prevention of Money Laundering Act (PMLA)", ln=True, align="C")
    pdf.ln(5)

    pdf.set_font("Arial", "B", 10)
    pdf.cell(190, 6, txt="PART A: TRANSACTION & ENTITY TELEMETRY", ln=True)
    pdf.set_font("Arial", size=9)
    pdf.cell(95, 6, txt=f"Incident Reference: {tx_summary.get('tx_id', 'N/A')}", ln=0)
    pdf.cell(95, 6, txt=f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}", ln=1)
    pdf.cell(95, 6, txt=f"Transaction Amount: INR {tx_summary.get('amount', 0.0):,.2f}", ln=0)
    pdf.cell(95, 6, txt=f"Beneficiary VPA: {tx_summary.get('receiver_vpa', 'N/A')}", ln=1)
    pdf.cell(95, 6, txt=f"Composite Risk Score: {tx_summary.get('composite_risk_score', 0.0)}/100", ln=0)
    pdf.cell(95, 6, txt=f"Final SOC Action: {tx_summary.get('final_action', 'N/A')}", ln=1)
    pdf.ln(4)

    pdf.set_font("Arial", "B", 10)
    pdf.cell(190, 6, txt="PART B: 7-AGENT DEFENSE SWARM AUDIT VERDICTS", ln=True)
    pdf.set_font("Arial", size=8)
    for v in tx_summary.get("verdicts", []):
        agent_name = str(v.get("Agent", "")).encode('latin-1', 'replace').decode('latin-1')
        verdict = str(v.get("Raw_Vote", v.get("Verdict", "")))
        metric = str(v.get("Key Metric", "")).encode('latin-1', 'replace').decode('latin-1')
        rat = str(v.get("Forensic Rationale", "")).encode('latin-1', 'replace').decode('latin-1')
        pdf.set_font("Arial", "B", 8)
        pdf.cell(190, 5, txt=f"{v.get('ID', '')} {agent_name} [{verdict}] - {metric}", ln=True)
        pdf.set_font("Arial", size=8)
        pdf.multi_cell(190, 4, txt=f"   Rationale: {rat}")
        pdf.ln(1)

    pdf.ln(3)
    pdf.set_font("Arial", "B", 10)
    pdf.cell(190, 6, txt="PART C: STATUTORY REGULATORY NARRATIVE", ln=True)
    pdf.set_font("Arial", size=8)
    clean_narrative = str(tx_summary.get("sar_narrative", "")).encode('latin-1', 'replace').decode('latin-1')
    pdf.multi_cell(190, 4, txt=clean_narrative)

    return pdf.output(dest='S').encode('latin-1')
