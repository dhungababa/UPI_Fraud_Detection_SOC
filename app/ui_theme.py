"""
ui_theme.py — NPCI UPI Fraud Detection SOC Design System
Tier-3 Cyber Defense Operations Center & Threat Intelligence Terminal.
Inspired by Palantir Gotham, Datadog Security, and Cloudflare Radar.
"""
import streamlit as st

SOC_CSS = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

    /* ===== CANVAS & CORE BACKGROUND ===== */
    [data-testid="stAppViewContainer"], .stApp {
        background: #06080D !important;
        background-image: 
            radial-gradient(at 0% 0%, rgba(244, 63, 94, 0.05) 0px, transparent 50%),
            radial-gradient(at 100% 0%, rgba(16, 185, 129, 0.04) 0px, transparent 50%),
            linear-gradient(180deg, #06080D 0%, #0A0E17 100%) !important;
        color: #F1F5F9 !important;
        font-family: 'Inter', -apple-system, sans-serif !important;
    }

    [data-testid="stHeader"] {
        background: rgba(6, 8, 13, 0.90) !important;
        backdrop-filter: blur(16px) !important;
        border-bottom: 1px solid rgba(255, 255, 255, 0.07) !important;
    }

    #MainMenu, footer { visibility: hidden !important; }

    /* ===== TYPOGRAPHY & NUMERICAL MONO ===== */
    h1, h2, h3, h4, h5, h6 {
        font-family: 'Inter', sans-serif !important;
        color: #F8FAFC !important;
        font-weight: 700 !important;
        letter-spacing: -0.015em !important;
    }

    .tabular-mono, code, .stMetricValue, [data-testid="stMetricValue"] {
        font-family: 'JetBrains Mono', monospace !important;
        font-variant-numeric: tabular-nums !important;
    }

    /* ===== STREAMLIT TAB BAR PILLS ===== */
    .stTabs [data-baseweb="tab-list"] {
        background: #0E131F !important;
        border: 1px solid rgba(255, 255, 255, 0.08) !important;
        border-radius: 10px !important;
        padding: 5px !important;
        gap: 6px !important;
    }

    .stTabs [data-baseweb="tab"] {
        background: transparent !important;
        border: none !important;
        border-radius: 7px !important;
        color: #94A3B8 !important;
        font-family: 'Inter', sans-serif !important;
        font-size: 13px !important;
        font-weight: 600 !important;
        padding: 8px 16px !important;
        transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1) !important;
    }

    .stTabs [aria-selected="true"] {
        background: #182033 !important;
        color: #F43F5E !important;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.3), inset 0 0 0 1px rgba(244, 63, 94, 0.3) !important;
    }

    /* ===== SIDEBAR REFINEMENT ===== */
    [data-testid="stSidebar"] {
        background: #080C14 !important;
        border-right: 1px solid rgba(255, 255, 255, 0.08) !important;
    }

    /* ===== INSTITUTIONAL SOC METRIC CARDS ===== */
    .soc-metric-card {
        background: #0E131F;
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 10px;
        padding: 16px 18px;
        transition: transform 0.2s ease, border-color 0.2s ease;
    }

    .soc-metric-card:hover {
        transform: translateY(-2px);
        border-color: rgba(244, 63, 94, 0.4);
    }

    .soc-metric-val {
        font-family: 'JetBrains Mono', monospace;
        font-size: 26px;
        font-weight: 700;
        color: #F43F5E;
        font-variant-numeric: tabular-nums;
        line-height: 1.2;
        margin-top: 4px;
    }

    .soc-metric-lbl {
        font-size: 11px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: #64748B;
    }

    /* ===== STREAMLIT BUTTON OVERRIDES ===== */
    .stButton > button {
        background: #E11D48 !important;
        background: linear-gradient(180deg, #E11D48 0%, #BE123C 100%) !important;
        border: 1px solid rgba(255, 255, 255, 0.15) !important;
        border-radius: 8px !important;
        color: #FFFFFF !important;
        font-weight: 600 !important;
        font-size: 13px !important;
        letter-spacing: 0.02em !important;
        padding: 8px 18px !important;
        transition: all 0.2s ease !important;
        box-shadow: 0 1px 2px rgba(0, 0, 0, 0.2), inset 0 1px 0 rgba(255, 255, 255, 0.15) !important;
    }

    .stButton > button:hover {
        background: linear-gradient(180deg, #BE123C 0%, #9F1239 100%) !important;
        box-shadow: 0 4px 12px rgba(225, 29, 72, 0.3) !important;
        transform: translateY(-1px) !important;
    }

    /* ===== TACTICAL THREAT PULSE ===== */
    .soc-pulse {
        display: inline-block;
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: #F43F5E;
        box-shadow: 0 0 0 rgba(244, 63, 94, 0.4);
        animation: soc-pulse-ring 2s infinite;
        margin-right: 6px;
    }

    @keyframes soc-pulse-ring {
        0% { box-shadow: 0 0 0 0 rgba(244, 63, 94, 0.7); }
        70% { box-shadow: 0 0 0 7px rgba(244, 63, 94, 0); }
        100% { box-shadow: 0 0 0 0 rgba(244, 63, 94, 0); }
    }
</style>
"""

def inject_theme():
    """Inject institutional UPI SOC styling."""
    st.markdown(SOC_CSS, unsafe_allow_html=True)

def render_html(html: str):
    st.markdown(html, unsafe_allow_html=True)

def render_ecosystem_header(active_app: str = "upi"):
    """Institutional top-tier global navigation bar with live SOC telemetry."""
    quant_active = 'background: #0284C7; color: #FFFFFF; border-color: #38BDF8;' if active_app == 'quant' else 'background: #0E131F; color: #94A3B8; border-color: rgba(255,255,255,0.08);'
    sec_active = 'background: #2563EB; color: #FFFFFF; border-color: #60A5FA;' if active_app == 'sec' else 'background: #0E131F; color: #94A3B8; border-color: rgba(255,255,255,0.08);'
    upi_active = 'background: #E11D48; color: #FFFFFF; border-color: #FB7185;' if active_app == 'upi' else 'background: #0E131F; color: #94A3B8; border-color: rgba(255,255,255,0.08);'

    html = f"""
    <div style="background: #080C14; border: 1px solid rgba(255,255,255,0.08); border-radius: 10px; padding: 10px 16px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;">
        <div style="display: flex; align-items: center; gap: 14px;">
            <div style="display: flex; align-items: center;">
                <span class="soc-pulse"></span>
                <span style="font-family: 'JetBrains Mono', monospace; font-size: 11px; font-weight: 700; color: #F43F5E; letter-spacing: 0.05em;">NPCI SOC SENTINEL: ARMED</span>
            </div>
            <div style="height: 14px; width: 1px; background: rgba(255,255,255,0.15);"></div>
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 11px; color: #94A3B8; display: flex; gap: 16px;">
                <span>SWITCH LATENCY: <b style="color: #10B981;">14.2ms</b> (<span style="color: #64748B;">&lt;50ms SLA</span>)</span>
                <span>ATT&CK MATRIX: <b style="color: #F8FAFC;">v14.1 ENFORCED</b></span>
                <span>IoCs MONITORED: <b style="color: #F43F5E;">18 DARK-WEB</b></span>
            </div>
        </div>
        <div style="display: flex; align-items: center; gap: 8px;">
            <a href="http://localhost:8501" target="_blank" style="text-decoration: none; padding: 5px 12px; border-radius: 6px; font-size: 12px; font-weight: 600; border: 1px solid; {quant_active} transition: all 0.15s ease;">📈 Alpha Quant (8501)</a>
            <a href="http://localhost:8502" target="_blank" style="text-decoration: none; padding: 5px 12px; border-radius: 6px; font-size: 12px; font-weight: 600; border: 1px solid; {sec_active} transition: all 0.15s ease;">📜 SEC Filing RAG (8502)</a>
            <a href="http://localhost:8503" target="_blank" style="text-decoration: none; padding: 5px 12px; border-radius: 6px; font-size: 12px; font-weight: 600; border: 1px solid; {upi_active} transition: all 0.15s ease;">🛡️ UPI Cyber SOC (8503)</a>
        </div>
    </div>
    """
    st.markdown(html, unsafe_allow_html=True)

def gradient_header(title: str, subtitle: str = ""):
    sub_html = f"<p style='color: #94A3B8; font-size: 14px; margin-top: 4px; font-weight: 400;'>{subtitle}</p>" if subtitle else ""
    st.markdown(f"""
    <div style="margin-bottom: 22px;">
        <h2 style="font-size: 24px; font-weight: 800; color: #F8FAFC; margin: 0; letter-spacing: -0.015em;">{title}</h2>
        {sub_html}
    </div>
    """, unsafe_allow_html=True)

def glass_metric(value: str, label: str, icon: str = ""):
    st.markdown(f"""
    <div class="soc-metric-card">
        <div class="soc-metric-lbl">{label}</div>
        <div class="soc-metric-val">{value}</div>
    </div>
    """, unsafe_allow_html=True)

def glass_metric_row(metrics: list):
    cols = st.columns(len(metrics))
    for col, item in zip(cols, metrics):
        val = item[0]
        lbl = item[1]
        with col:
            glass_metric(val, lbl)

def glass_panel(title: str):
    st.markdown(f"""
    <div style="border-left: 3px solid #E11D48; background: #0E131F; padding: 8px 14px; border-radius: 0 6px 6px 0; margin-bottom: 14px;">
        <span style="font-family: 'JetBrains Mono', monospace; font-size: 12px; font-weight: 700; color: #FB7185; letter-spacing: 0.05em; text-transform: uppercase;">
            {title}
        </span>
    </div>
    """, unsafe_allow_html=True)

def neon_alert(message: str, alert_type: str = "info"):
    colors = {
        "danger": ("#EF4444", "rgba(239, 68, 68, 0.10)"),
        "success": ("#10B981", "rgba(16, 185, 129, 0.10)"),
        "warning": ("#F59E0B", "rgba(245, 158, 11, 0.10)"),
        "info": ("#FB7185", "rgba(251, 113, 133, 0.10)")
    }
    border, bg = colors.get(alert_type, ("#FB7185", "rgba(251, 113, 133, 0.10)"))
    st.markdown(f"""
    <div style="background: {bg}; border: 1px solid {border}40; border-left: 3px solid {border}; border-radius: 6px; padding: 12px 16px; margin-bottom: 14px; color: #F1F5F9; font-size: 13px; font-weight: 500;">
        {message}
    </div>
    """, unsafe_allow_html=True)

def ai_box(content: str, border_color: str = "#E11D48"):
    st.markdown(f"""
    <div style="background: #0E131F; border: 1px solid rgba(255, 255, 255, 0.08); border-left: 3px solid {border_color}; border-radius: 8px; padding: 18px 20px; margin-bottom: 18px; color: #E2E8F0; font-size: 14px; line-height: 1.6;">
        {content}
    </div>
    """, unsafe_allow_html=True)

def cyber_terminal(content: str, title: str = "SOC INCIDENT TELEMETRY"):
    st.markdown(f"""
    <div style="background: #06080D; border: 1px solid #1E293B; border-radius: 8px; padding: 14px 18px; font-family: 'JetBrains Mono', monospace; font-size: 12px; color: #FB7185; margin-bottom: 16px; line-height: 1.5;">
        <span style="color: #64748B; font-weight: 700;">// {title}</span><br>
        {content}
    </div>
    """, unsafe_allow_html=True)

def section_divider():
    st.markdown("<div style='height: 1px; background: rgba(255, 255, 255, 0.08); margin: 24px 0;'></div>", unsafe_allow_html=True)

PLOTLY_DARK_LAYOUT = dict(
    paper_bgcolor='rgba(0, 0, 0, 0)',
    plot_bgcolor='rgba(14, 19, 31, 0.4)',
    font=dict(family='Inter', color='#94A3B8', size=11),
    xaxis=dict(
        gridcolor='rgba(255, 255, 255, 0.05)',
        zerolinecolor='rgba(255, 255, 255, 0.08)',
        tickfont=dict(family='JetBrains Mono', size=10, color='#64748B')
    ),
    yaxis=dict(
        gridcolor='rgba(255, 255, 255, 0.05)',
        zerolinecolor='rgba(255, 255, 255, 0.08)',
        tickfont=dict(family='JetBrains Mono', size=10, color='#64748B')
    ),
    legend=dict(font=dict(size=11, color='#94A3B8')),
    hoverlabel=dict(
        bgcolor='#0E131F',
        bordercolor='#F43F5E',
        font=dict(family='JetBrains Mono', color='#F8FAFC', size=11)
    ),
    margin=dict(l=30, r=30, t=30, b=30),
)

def apply_plotly_dark(fig):
    fig.update_layout(**PLOTLY_DARK_LAYOUT)
    return fig
