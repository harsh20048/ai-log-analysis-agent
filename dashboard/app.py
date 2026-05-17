import streamlit as st
import sqlite3
import json
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import tempfile
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.log_parser import read_existing_logs, detect_log_type
from agent.analyzer import analyze_logs
from agent.monitor import init_db, store_finding

st.set_page_config(
    page_title="SSOC · AI Log Analysis",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "db", "findings.db")
init_db(DB_PATH)

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────
SEV_HEX = {
    "CRITICAL": "#f87171",
    "HIGH":     "#fb923c",
    "MEDIUM":   "#fbbf24",
    "LOW":      "#4ade80",
    "INFO":     "#60a5fa",
}
SEV_BG = {
    "CRITICAL": "#2d0a0a",
    "HIGH":     "#2d1500",
    "MEDIUM":   "#2d2200",
    "LOW":      "#052d15",
    "INFO":     "#071a2d",
}
SEV_BORDER = {
    "CRITICAL": "#7f1d1d",
    "HIGH":     "#7c2d12",
    "MEDIUM":   "#713f12",
    "LOW":      "#14532d",
    "INFO":     "#1e3a5f",
}
SEV_DOT = {
    "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "🔵",
}
RISK_GRADIENT = [(80,"#f87171"),(60,"#fb923c"),(40,"#fbbf24"),(0,"#4ade80")]

SEV_EXPLAIN = {
    "CRITICAL": ("Immediate Action Required",
                 "An active attack or critical system failure is happening right now. Stop everything else and respond immediately."),
    "HIGH":     ("Urgent — Act Within Minutes",
                 "A serious threat or major error has been detected. Escalate now — delays allow the situation to worsen."),
    "MEDIUM":   ("Investigate Soon",
                 "Suspicious or degraded behaviour detected. Not an emergency, but requires attention before the end of your shift."),
    "LOW":      ("Monitor & Review",
                 "A minor anomaly or threshold warning. Low immediate risk — log it and review during normal working hours."),
    "INFO":     ("No Action Needed",
                 "Normal operational event captured for audit purposes. No response required."),
}
FINDING_EXPLAIN = {
    "CRITICAL_ERROR":  ("System Failure",      "The application or infrastructure has crashed, become unavailable, or is losing data."),
    "SECURITY_THREAT": ("Attack Detected",     "A confirmed or highly suspected attack — brute force, SQL injection, privilege escalation, or suspicious source."),
    "ANOMALY":         ("Unusual Behaviour",   "Behaviour that deviates significantly from the baseline — unexpected timing, volume, location, or access pattern."),
    "WARNING":         ("Threshold Breached",  "A resource or config limit has been exceeded (disk, memory, CPU, cert expiry) but the service is still running."),
    "AUDIT_FLAG":      ("Compliance Review",   "A privileged or administrative action that must be reviewed for policy compliance and accountability."),
}

# ─────────────────────────────────────────────────────────────────────────────
# CSS
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

*, *::before, *::after { box-sizing: border-box; }

html, body, [data-testid="stAppViewContainer"] {
    background: #0d1117 !important;
    color: #e6edf3 !important;
    font-family: 'Inter', sans-serif !important;
}
[data-testid="stHeader"] { display: none !important; }
[data-testid="stSidebar"] {
    background: #010409 !important;
    border-right: 1px solid #21262d !important;
}
[data-testid="stSidebarContent"] { padding: 0 !important; }
.block-container { padding: 1.5rem 2rem !important; max-width: 100% !important; }
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: #0d1117; }
::-webkit-scrollbar-thumb { background: #30363d; border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #484f58; }

/* ── Topbar ── */
.topbar {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 12px;
    padding: 1.1rem 1.75rem;
    margin-bottom: 1.5rem;
    display: flex; align-items: center; justify-content: space-between;
    box-shadow: 0 1px 3px rgba(0,0,0,0.4);
}
.topbar-brand { display: flex; align-items: center; gap: 1rem; }
.topbar-icon {
    width: 44px; height: 44px; border-radius: 10px;
    background: linear-gradient(135deg, #1f6feb, #388bfd);
    display: flex; align-items: center; justify-content: center;
    font-size: 1.3rem;
    box-shadow: 0 0 16px rgba(56,139,253,0.35);
}
.topbar-title { font-size: 1.15rem; font-weight: 700; color: #f0f6fc; }
.topbar-sub   { font-size: 0.68rem; color: #388bfd; letter-spacing: 0.12em; text-transform: uppercase; font-weight: 600; margin-top: 1px; }
.topbar-right { display: flex; align-items: center; gap: 1.5rem; }
.live-badge {
    display: flex; align-items: center; gap: 0.45rem;
    background: rgba(63,185,80,0.1); border: 1px solid rgba(63,185,80,0.4);
    border-radius: 20px; padding: 0.35rem 1rem;
    font-size: 0.72rem; font-weight: 700; color: #3fb950; letter-spacing: 0.06em;
}
.live-dot {
    width: 7px; height: 7px; border-radius: 50%; background: #3fb950;
    animation: pulse 1.6s infinite; box-shadow: 0 0 6px #3fb950;
}
@keyframes pulse { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:.4;transform:scale(.8)} }
.topbar-clock { font-family:'JetBrains Mono',monospace; font-size:0.75rem; color:#484f58; }

/* ── KPI cards ── */
.kpi-grid { display: grid; grid-template-columns: repeat(5,1fr); gap: 1rem; margin-bottom: 1.5rem; }
.kpi {
    background: #161b22; border: 1px solid #30363d;
    border-radius: 12px; padding: 1.25rem 1.5rem;
    position: relative; overflow: hidden;
    transition: border-color .2s, box-shadow .2s, transform .2s;
    border-top: 3px solid var(--c);
}
.kpi:hover {
    border-color: var(--c);
    box-shadow: 0 0 20px color-mix(in srgb, var(--c) 15%, transparent);
    transform: translateY(-3px);
}
.kpi-label { font-size: 0.7rem; font-weight: 600; color: #8b949e; text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 0.5rem; }
.kpi-value { font-family:'JetBrains Mono',monospace; font-size: 2.4rem; font-weight: 700; color: var(--c); line-height: 1; }
.kpi-sub   { font-size: 0.65rem; color: #484f58; margin-top: 0.35rem; font-weight: 600; letter-spacing: 0.08em; text-transform: uppercase; }

/* ── Section header ── */
.sec-hdr {
    font-size: 0.72rem; font-weight: 700; color: #8b949e;
    text-transform: uppercase; letter-spacing: 0.12em;
    display: flex; align-items: center; gap: 0.6rem;
    margin-bottom: 1rem; padding-bottom: 0.65rem;
    border-bottom: 1px solid #21262d;
}
.sec-hdr-dot { width: 4px; height: 16px; background: var(--dc,#388bfd); border-radius: 2px; flex-shrink: 0; }

/* ── Severity badge ── */
.sev-badge {
    display: inline-flex; align-items: center;
    font-size: 0.68rem; font-weight: 700; letter-spacing: 0.08em;
    padding: 3px 10px; border-radius: 5px;
    border: 1px solid var(--bc); background: var(--bg); color: var(--fg);
}

/* ── Severity explanation box ── */
.sev-box {
    background: var(--bg); border: 1px solid var(--bc);
    border-left: 4px solid var(--fg);
    border-radius: 8px; padding: 1rem 1.25rem;
    margin-top: 0.5rem;
}
.sev-box-title { font-size: 0.8rem; font-weight: 700; color: var(--fg); margin-bottom: 0.35rem; }
.sev-box-desc  { font-size: 0.82rem; color: #c9d1d9; line-height: 1.6; }

/* ── Risk bar ── */
.rbar-wrap { display:flex; align-items:center; gap:0.75rem; }
.rbar-track { flex:1; height:8px; background:#21262d; border-radius:4px; overflow:hidden; }
.rbar-fill  { height:100%; border-radius:4px; }
.rbar-label { font-family:'JetBrains Mono',monospace; font-size:0.9rem; font-weight:700; min-width:3rem; text-align:right; }

/* ── Finding card ── */
.fc {
    background: #161b22; border: 1px solid #30363d;
    border-left: 4px solid var(--lc);
    border-radius: 8px; padding: 1.1rem 1.25rem;
    margin-bottom: 0.85rem;
    transition: background .15s, transform .15s;
}
.fc:hover { background: #1c2128; transform: translateX(4px); }
.fc-header { display:flex; align-items:flex-start; gap:0.75rem; flex-wrap:wrap; margin-bottom:0.6rem; }
.fc-type {
    font-size: 0.65rem; font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase;
    padding: 3px 10px; border-radius: 4px;
    background: #21262d; color: #8b949e; border: 1px solid #30363d;
    white-space: nowrap;
}
.fc-type-explain {
    font-size: 0.72rem; color: #8b949e; font-style: italic;
    display: flex; align-items: center; gap: 0.4rem;
}
.fc-type-name { font-weight: 700; color: #c9d1d9; font-style: normal; }
.fc-ts { font-family:'JetBrains Mono',monospace; font-size:0.68rem; color:#484f58; margin-left:auto; }
.fc-desc { font-size: 0.88rem; color: #c9d1d9; line-height: 1.6; margin: 0.5rem 0; }
.fc-log {
    background: #010409; border: 1px solid #21262d; border-radius: 6px;
    padding: 0.6rem 0.9rem; margin: 0.65rem 0;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.74rem; color: #6e7681;
    overflow-x: auto; white-space: pre;
}
.fc-action {
    display: flex; align-items: flex-start; gap: 0.5rem;
    font-size: 0.82rem; color: #3fb950; line-height: 1.5;
    background: rgba(63,185,80,0.07); border: 1px solid rgba(63,185,80,0.2);
    border-radius: 6px; padding: 0.6rem 0.85rem; margin-top: 0.65rem;
}

/* ── Brute force banner ── */
.bf-banner {
    background: #2d0a0a; border: 1px solid #7f1d1d; border-radius: 8px;
    padding: 0.85rem 1.1rem; margin-bottom: 1rem;
    display: flex; align-items: center; gap: 0.75rem;
    font-size: 0.82rem; font-weight: 600; color: #f87171;
    box-shadow: 0 0 20px rgba(248,113,113,0.08);
}
.ip-pill {
    font-family:'JetBrains Mono',monospace; font-size:0.72rem;
    background:#3d0a0a; border:1px solid #7f1d1d;
    border-radius:4px; padding:2px 8px; color:#f87171;
}

/* ── Sidebar ── */
.sb-top { background:#010409; border-bottom:1px solid #21262d; padding:1.75rem 1.25rem 1.5rem; text-align:center; }
.sb-logo { font-size:2.4rem; filter:drop-shadow(0 0 12px rgba(56,139,253,.5)); }
.sb-name { font-size:0.95rem; font-weight:700; color:#f0f6fc; margin-top:0.5rem; }
.sb-sub  { font-size:0.62rem; color:#388bfd; letter-spacing:.15em; text-transform:uppercase; font-weight:600; }
.sb-sect { padding:1.1rem 1.25rem; border-bottom:1px solid #21262d; }
.sb-lbl  { font-size:0.6rem; font-weight:700; color:#30363d; text-transform:uppercase; letter-spacing:.15em; margin-bottom:0.65rem; }
.sb-row  { display:flex; justify-content:space-between; align-items:center; padding:0.4rem 0; border-bottom:1px solid #0d1117; }
.sb-key  { font-size:0.78rem; color:#484f58; }
.sb-val  { font-family:'JetBrains Mono',monospace; font-size:0.84rem; font-weight:700; }
.threat-pill {
    border-radius:8px; padding:0.8rem; text-align:center; margin-bottom:0.85rem;
    border: 1px solid var(--bc); background: var(--bg);
}
.threat-lbl { font-size:0.6rem; color:#484f58; text-transform:uppercase; letter-spacing:.12em; font-weight:600; }
.threat-val { font-size:1rem; font-weight:800; color:var(--fg); margin-top:0.2rem; }

/* ── Tabs ── */
.stTabs [data-baseweb="tab-list"] {
    background: #161b22 !important; border: 1px solid #30363d !important;
    border-radius: 10px !important; padding: 4px !important; gap: 2px !important;
    margin-bottom: 1.25rem !important;
}
.stTabs [data-baseweb="tab"] {
    background: transparent !important; color: #8b949e !important;
    font-size: 0.78rem !important; font-weight: 600 !important;
    border-radius: 7px !important; border: none !important;
    padding: 0.55rem 1.5rem !important; letter-spacing: 0.04em !important;
    transition: all .15s !important;
}
.stTabs [aria-selected="true"] {
    background: #1f6feb !important; color: #ffffff !important;
    box-shadow: 0 2px 8px rgba(31,111,235,.4) !important;
}
.stTabs [data-baseweb="tab-panel"] { padding: 0 !important; }

/* ── Upload zone ── */
.stFileUploader > div {
    background: #161b22 !important; border: 2px dashed #30363d !important;
    border-radius: 10px !important; transition: border-color .2s !important;
}
.stFileUploader > div:hover { border-color: #388bfd !important; }

/* ── Buttons ── */
.stButton > button {
    background: #1f6feb !important; color: #ffffff !important;
    border: none !important; border-radius: 8px !important;
    font-weight: 600 !important; font-size: 0.8rem !important;
    padding: 0.55rem 1.5rem !important;
    box-shadow: 0 2px 8px rgba(31,111,235,.3) !important;
    transition: all .15s !important;
}
.stButton > button:hover {
    background: #388bfd !important;
    box-shadow: 0 4px 14px rgba(31,111,235,.5) !important;
    transform: translateY(-1px) !important;
}

/* ── Expanders ── */
div[data-testid="stExpander"] {
    background: #161b22 !important; border: 1px solid #30363d !important;
    border-radius: 10px !important; margin-bottom: 0.6rem !important; overflow: hidden !important;
    transition: border-color .15s !important;
}
div[data-testid="stExpander"]:hover { border-color: #484f58 !important; }
div[data-testid="stExpander"] > details > summary {
    padding: 0.9rem 1.1rem !important; font-size: 0.84rem !important;
    font-weight: 500 !important; color: #c9d1d9 !important;
}

/* ── Selectbox ── */
.stSelectbox > div > div {
    background: #161b22 !important; border: 1px solid #30363d !important;
    border-radius: 8px !important; color: #c9d1d9 !important;
    font-size: 0.82rem !important;
}

/* ── Dataframe ── */
[data-testid="stDataFrame"] { border: 1px solid #30363d !important; border-radius: 10px !important; overflow: hidden !important; }
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def load_findings():
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql("SELECT * FROM findings ORDER BY id DESC LIMIT 300", conn)
        conn.close()
        return df
    except Exception:
        return pd.DataFrame()

def risk_color(s):
    for t, c in RISK_GRADIENT:
        if s >= t: return c
    return "#4ade80"

def sev_badge_html(sev):
    fg = SEV_HEX.get(sev,"#60a5fa")
    bg = SEV_BG.get(sev,"#071a2d")
    bc = SEV_BORDER.get(sev,"#1e3a5f")
    return f'<span class="sev-badge" style="--fg:{fg};--bg:{bg};--bc:{bc}">{sev}</span>'

def risk_bar_html(score):
    c = risk_color(score)
    return f"""<div class="rbar-wrap">
        <div class="rbar-track"><div class="rbar-fill" style="width:{score}%;background:{c}"></div></div>
        <span class="rbar-label" style="color:{c}">{score}</span>
    </div>"""

def make_risk_chart(df):
    chart_df = df[["timestamp","risk_score","severity"]].copy()
    chart_df["timestamp"] = pd.to_datetime(chart_df["timestamp"])
    chart_df = chart_df.sort_values("timestamp")

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=chart_df["timestamp"], y=chart_df["risk_score"],
        mode="lines+markers",
        line=dict(color="#388bfd", width=2.5),
        marker=dict(
            size=8, color=chart_df["risk_score"],
            colorscale=[[0,"#4ade80"],[0.4,"#fbbf24"],[0.7,"#fb923c"],[1,"#f87171"]],
            cmin=0, cmax=100,
            line=dict(color="#0d1117", width=2)
        ),
        fill="tozeroy",
        fillcolor="rgba(56,139,253,0.07)",
        hovertemplate="<b>Risk: %{y}/100</b><br>%{x}<extra></extra>",
    ))
    fig.update_layout(
        height=240, margin=dict(l=0,r=0,t=10,b=0),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        xaxis=dict(showgrid=False, color="#484f58", tickfont=dict(size=11, family="JetBrains Mono")),
        yaxis=dict(showgrid=True, gridcolor="#21262d", color="#484f58", range=[0,105],
                   tickfont=dict(size=11, family="JetBrains Mono")),
        hovermode="x unified",
        font=dict(family="Inter"),
    )
    return fig

def make_sev_chart(df):
    order  = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
    colors = [SEV_HEX.get(s,"#60a5fa") for s in order]
    counts = [len(df[df["severity"]==s]) for s in order]

    fig = go.Figure(go.Bar(
        x=order, y=counts, marker_color=colors,
        text=counts, textposition="outside",
        textfont=dict(color="#c9d1d9", size=13, family="JetBrains Mono"),
        hovertemplate="<b>%{x}</b>: %{y} findings<extra></extra>",
    ))
    fig.update_layout(
        height=240, margin=dict(l=0,r=0,t=10,b=0),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        xaxis=dict(showgrid=False, color="#484f58", tickfont=dict(size=12, family="Inter", color="#8b949e")),
        yaxis=dict(showgrid=True, gridcolor="#21262d", color="#484f58",
                   tickfont=dict(size=11, family="JetBrains Mono")),
        bargap=0.35, font=dict(family="Inter"),
    )
    return fig

def make_logtype_chart(df):
    lt_counts = df["log_type"].value_counts()
    colors_map = {
        "SECURITY":"#f87171","APPLICATION":"#fb923c",
        "NETWORK":"#fbbf24","SYSTEM":"#4ade80","AUDIT":"#60a5fa",
    }
    colors = [colors_map.get(t,"#8b949e") for t in lt_counts.index]
    fig = go.Figure(go.Pie(
        labels=lt_counts.index, values=lt_counts.values,
        marker=dict(colors=colors, line=dict(color="#0d1117", width=3)),
        hole=0.55,
        textfont=dict(size=12, family="Inter", color="#c9d1d9"),
        hovertemplate="<b>%{label}</b><br>%{value} scans (%{percent})<extra></extra>",
    ))
    fig.update_layout(
        height=240, margin=dict(l=10,r=10,t=10,b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        legend=dict(font=dict(color="#8b949e", size=11), bgcolor="rgba(0,0,0,0)"),
        font=dict(family="Inter"),
    )
    return fig

def run_upload_analysis(filepath, log_type_hint, display_name):
    lines = []
    with open(filepath, errors="ignore") as f:
        lines = [l.strip() for l in f if l.strip()]

    total_chunks = max(1, (len(lines) + 29) // 30)
    progress = st.progress(0.0, text="Initialising…")
    status   = st.empty()
    results  = []

    for i, start in enumerate(range(0, len(lines), 30)):
        chunk = lines[start:start+30]
        det   = detect_log_type(chunk)
        ftype = log_type_hint if log_type_hint != "AUTO-DETECT" else det
        status.markdown(f'<div style="font-size:0.78rem;color:#8b949e">Chunk {i+1} / {total_chunks} &nbsp;·&nbsp; detected: <b style="color:#c9d1d9">{det}</b></div>', unsafe_allow_html=True)
        result = analyze_logs(chunk, realtime=False)
        store_finding(result, ftype, DB_PATH)
        results.append(result)
        progress.progress((i+1)/total_chunks, text=f"Analysing chunk {i+1} of {total_chunks}…")

    progress.empty(); status.empty()

    crits    = sum(1 for r in results if r.get("severity") == "CRITICAL")
    highs    = sum(1 for r in results if r.get("severity") == "HIGH")
    max_risk = max((r.get("overall_risk_score",0) for r in results), default=0)
    bf_det   = any(r.get("brute_force_detected") for r in results)
    all_ips  = list({ip for r in results for ip in r.get("suspicious_ips",[])})

    ca,cb,cc,cd = st.columns(4)
    for col, label, val, c in [
        (ca,"Chunks Analysed", total_chunks, "#60a5fa"),
        (cb,"Critical Found",  crits,        "#f87171"),
        (cc,"High Found",      highs,        "#fb923c"),
        (cd,"Peak Risk Score", f"{max_risk}/100", "#fbbf24"),
    ]:
        col.markdown(f'<div class="kpi" style="--c:{c}"><div class="kpi-label">{label}</div><div class="kpi-value">{val}</div></div>', unsafe_allow_html=True)

    if bf_det:
        pills = "".join(f'<span class="ip-pill">{ip}</span>' for ip in all_ips)
        st.markdown(f'<div class="bf-banner" style="margin-top:0.75rem">🚨 <b>Brute Force Detected</b> &nbsp;·&nbsp; {pills}</div>', unsafe_allow_html=True)

    st.success(f"✅ Analysis complete — {total_chunks} chunks stored. Switch to the **Dashboard** tab to view findings.")

# ─────────────────────────────────────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div class="sb-top">
        <div class="sb-logo">🛡️</div>
        <div class="sb-name">SSOC Agent</div>
        <div class="sb-sub">AI Log Analysis</div>
    </div>
    """, unsafe_allow_html=True)

    df_side = load_findings()
    if not df_side.empty:
        crit = len(df_side[df_side["severity"]=="CRITICAL"])
        high = len(df_side[df_side["severity"]=="HIGH"])
        bf   = int(df_side["brute_force"].sum())
        avg  = df_side["risk_score"].mean()
        act  = int(df_side["requires_action"].sum())

        if crit:   tfg,tbg,tbc,tlvl = "#f87171","#2d0a0a","#7f1d1d","CRITICAL ALERT"
        elif high: tfg,tbg,tbc,tlvl = "#fb923c","#2d1500","#7c2d12","ELEVATED"
        else:      tfg,tbg,tbc,tlvl = "#4ade80","#052d15","#14532d","NORMAL"

        st.markdown(f"""
        <div class="sb-sect">
            <div class="threat-pill" style="--fg:{tfg};--bg:{tbg};--bc:{tbc}">
                <div class="threat-lbl">Threat Level</div>
                <div class="threat-val">{tlvl}</div>
            </div>
        """, unsafe_allow_html=True)
        for lbl, val, col in [
            ("Total Scans",  len(df_side), "#60a5fa"),
            ("Critical",     crit,         "#f87171"),
            ("High",         high,         "#fb923c"),
            ("Brute Force",  bf,           "#f87171"),
            ("Avg Risk",     f"{avg:.0f}/100","#fbbf24"),
            ("Needs Action", act,          "#fb923c"),
        ]:
            st.markdown(f'<div class="sb-row"><span class="sb-key">{lbl}</span><span class="sb-val" style="color:{col}">{val}</span></div>', unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown('<div class="sb-sect"><div class="sb-lbl">Log Sources</div>', unsafe_allow_html=True)
    for src in ["APPLICATION","SECURITY","NETWORK","SYSTEM","AUDIT"]:
        n   = len(df_side[df_side["log_type"]==src]) if not df_side.empty else 0
        dot = "🟢" if n else "⚫"
        st.markdown(f'<div class="sb-row"><span class="sb-key">{dot} {src}</span><span class="sb-val" style="color:#484f58">{n}</span></div>', unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown('<div class="sb-sect">', unsafe_allow_html=True)
    if st.button("⟳  Refresh", use_container_width=True):
        st.rerun()
    st.markdown(f'<div style="text-align:center;margin-top:0.75rem;font-family:JetBrains Mono,monospace;font-size:0.62rem;color:#30363d">{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div></div>', unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
df = load_findings()

st.markdown(f"""
<div class="topbar">
    <div class="topbar-brand">
        <div class="topbar-icon">🛡️</div>
        <div>
            <div class="topbar-title">AI Log Analysis Agent</div>
            <div class="topbar-sub">Security Operations Center</div>
        </div>
    </div>
    <div class="topbar-right">
        <span class="topbar-clock">{datetime.now().strftime('%a %d %b %Y  %H:%M:%S')}</span>
        <div class="live-badge"><div class="live-dot"></div>AGENT ONLINE</div>
    </div>
</div>
""", unsafe_allow_html=True)

tab_dash, tab_upload, tab_raw = st.tabs(["📊  Dashboard", "📤  Upload Logs", "🗄️  Raw Database"])

# ═════════════════════════════════════════════════════
# TAB 1 — DASHBOARD
# ═════════════════════════════════════════════════════
with tab_dash:
    if df.empty:
        st.markdown("""
        <div style="text-align:center;padding:4rem 2rem;background:#161b22;border:1px solid #30363d;border-radius:12px">
            <div style="font-size:3rem;margin-bottom:1rem">📭</div>
            <div style="font-size:1.1rem;font-weight:700;color:#f0f6fc;margin-bottom:0.5rem">No findings yet</div>
            <div style="font-size:0.85rem;color:#8b949e">Go to the <b style="color:#388bfd">Upload Logs</b> tab to analyse your first log file.</div>
        </div>""", unsafe_allow_html=True)
    else:
        crit_n = len(df[df["severity"]=="CRITICAL"])
        high_n = len(df[df["severity"]=="HIGH"])
        bf_n   = int(df["brute_force"].sum())
        avg_r  = df["risk_score"].mean()
        act_n  = int(df["requires_action"].sum())

        # KPI
        kpis = [
            ("Total Scans",    len(df),          "SESSIONS",   "#60a5fa"),
            ("Critical",       crit_n,           "CRITICAL",   "#f87171"),
            ("High Severity",  high_n,           "HIGH",       "#fb923c"),
            ("Brute Force",    bf_n,             "DETECTED",   "#f87171"),
            ("Avg Risk Score", f"{avg_r:.0f}",   "OUT OF 100", "#fbbf24"),
        ]
        cols = st.columns(5)
        for col,(lbl,val,sub,c) in zip(cols,kpis):
            col.markdown(f'<div class="kpi" style="--c:{c}"><div class="kpi-label">{lbl}</div><div class="kpi-value">{val}</div><div class="kpi-sub">{sub}</div></div>', unsafe_allow_html=True)

        st.markdown('<div style="height:0.25rem"></div>', unsafe_allow_html=True)

        # Charts — 3 columns
        c1, c2, c3 = st.columns([5, 4, 3])
        with c1:
            st.markdown('<div class="sec-hdr" style="--dc:#388bfd"><div class="sec-hdr-dot"></div>Risk Score Over Time</div>', unsafe_allow_html=True)
            st.plotly_chart(make_risk_chart(df), use_container_width=True, config={"displayModeBar":False})
        with c2:
            st.markdown('<div class="sec-hdr" style="--dc:#fbbf24"><div class="sec-hdr-dot"></div>Severity Breakdown</div>', unsafe_allow_html=True)
            st.plotly_chart(make_sev_chart(df), use_container_width=True, config={"displayModeBar":False})
        with c3:
            st.markdown('<div class="sec-hdr" style="--dc:#4ade80"><div class="sec-hdr-dot"></div>Log Type Mix</div>', unsafe_allow_html=True)
            st.plotly_chart(make_logtype_chart(df), use_container_width=True, config={"displayModeBar":False})

        st.divider()

        # Findings
        st.markdown('<div class="sec-hdr" style="--dc:#8b949e"><div class="sec-hdr-dot"></div>Findings Log</div>', unsafe_allow_html=True)

        col_f, col_s = st.columns([1,4])
        with col_f:
            sev_filter = st.selectbox("Severity", ["ALL","CRITICAL","HIGH","MEDIUM","LOW","INFO"], label_visibility="collapsed")
        fdf = df if sev_filter=="ALL" else df[df["severity"]==sev_filter]
        st.markdown(f'<div style="font-size:0.72rem;color:#484f58;margin-bottom:0.75rem;font-family:JetBrains Mono,monospace">{len(fdf)} record(s) shown</div>', unsafe_allow_html=True)

        for _, row in fdf.iterrows():
            sev      = row["severity"]
            dot      = SEV_DOT.get(sev,"🔵")
            risk     = int(row["risk_score"])
            rc       = risk_color(risk)
            bf       = bool(row.get("brute_force"))
            ips      = json.loads(row.get("suspicious_ips") or "[]")
            findings = json.loads(row.get("findings_json") or "[]")
            summary  = str(row["summary"])[:90]
            bf_tag   = "  🚨 BRUTE FORCE" if bf else ""
            label    = f"{dot} [{row['log_type']}]  Risk {risk}/100  —  {summary}{bf_tag}"

            with st.expander(label):
                # Brute force banner
                if bf:
                    pills = "".join(f'<span class="ip-pill">{ip}</span>' for ip in ips)
                    st.markdown(f'<div class="bf-banner">🚨 <b>Brute Force Detected</b> &nbsp;·&nbsp; {pills}</div>', unsafe_allow_html=True)

                # Severity explanation — full width, prominent
                sev_title, sev_desc = SEV_EXPLAIN.get(sev, ("", ""))
                sev_fg = SEV_HEX.get(sev,"#60a5fa")
                sev_bg = SEV_BG.get(sev,"#071a2d")
                sev_bc = SEV_BORDER.get(sev,"#1e3a5f")
                st.markdown(f"""
                <div class="sev-box" style="--fg:{sev_fg};--bg:{sev_bg};--bc:{sev_bc};margin-bottom:1.1rem">
                    <div style="display:flex;align-items:center;gap:0.65rem;margin-bottom:0.5rem">
                        {sev_badge_html(sev)}
                        <div class="sev-box-title">— {sev_title}</div>
                    </div>
                    <div class="sev-box-desc">{sev_desc}</div>
                </div>""", unsafe_allow_html=True)

                # Risk + action row
                col_r, col_a = st.columns(2)
                with col_r:
                    st.markdown(f'<div style="font-size:0.7rem;color:#8b949e;margin-bottom:0.4rem;font-weight:600">RISK SCORE</div>{risk_bar_html(risk)}', unsafe_allow_html=True)
                with col_a:
                    act_val = "YES — Immediate Response Required 🚨" if row.get("requires_action") else "No — Monitor Only"
                    act_col = "#f87171" if row.get("requires_action") else "#4ade80"
                    st.markdown(f'<div style="font-size:0.7rem;color:#8b949e;margin-bottom:0.4rem;font-weight:600">IMMEDIATE ACTION</div><div style="font-weight:700;color:{act_col};font-size:0.88rem">{act_val}</div>', unsafe_allow_html=True)

                if not findings:
                    st.markdown('<div style="color:#484f58;font-size:0.82rem;padding:0.75rem 0">No individual findings recorded for this scan.</div>', unsafe_allow_html=True)
                else:
                    st.markdown('<div style="font-size:0.7rem;color:#8b949e;font-weight:600;margin:1rem 0 0.6rem;text-transform:uppercase;letter-spacing:.1em">Individual Findings</div>', unsafe_allow_html=True)

                for f in findings:
                    fsev     = f.get("severity","LOW")
                    ftype    = f.get("type","")
                    fc_color = SEV_HEX.get(fsev,"#60a5fa")
                    ftype_name, ftype_desc = FINDING_EXPLAIN.get(ftype, (ftype, ""))

                    st.markdown(f"""
                    <div class="fc" style="--lc:{fc_color}">
                        <div class="fc-header">
                            {sev_badge_html(fsev)}
                            <span class="fc-type">{ftype}</span>
                            <span class="fc-type-explain"><span class="fc-type-name">{ftype_name}</span> — {ftype_desc}</span>
                            <span class="fc-ts">{f.get('timestamp','')}</span>
                        </div>
                        <div class="fc-desc">{f.get('description','')}</div>
                        <div class="fc-log">{f.get('log_line','') or '(no log line)'}</div>
                        <div class="fc-action">💡 <span>{f.get('recommendation','')}</span></div>
                    </div>""", unsafe_allow_html=True)

# ═════════════════════════════════════════════════════
# TAB 2 — UPLOAD LOGS
# ═════════════════════════════════════════════════════
with tab_upload:
    st.markdown('<div class="sec-hdr" style="--dc:#388bfd"><div class="sec-hdr-dot"></div>Upload & Analyse Log Files</div>', unsafe_allow_html=True)
    st.markdown('<div style="font-size:0.85rem;color:#8b949e;margin-bottom:1.25rem;line-height:1.65">Upload any raw log file. The agent parses it, auto-detects the log type, sends it to Claude in 30-line chunks, and stores findings in the database. Supported: <b style="color:#c9d1d9">.log .txt .csv</b> or any plaintext.</div>', unsafe_allow_html=True)

    uploaded = st.file_uploader("Drop log file here", type=["log","txt","csv","out"], label_visibility="collapsed")
    col_t, col_b = st.columns([2,1])
    with col_t:
        log_type_hint = st.selectbox("Log type hint", ["AUTO-DETECT","APPLICATION","SECURITY","NETWORK","SYSTEM","AUDIT"])
    with col_b:
        st.markdown('<div style="height:1.7rem"></div>', unsafe_allow_html=True)
        run_btn = st.button("⚡  Run Analysis", use_container_width=True)

    st.divider()
    st.markdown('<div class="sec-hdr" style="--dc:#4ade80"><div class="sec-hdr-dot"></div>Or Load a Real Public Dataset</div>', unsafe_allow_html=True)
    st.markdown('<div style="font-size:0.82rem;color:#8b949e;margin-bottom:1rem">Real logs from the <b style="color:#c9d1d9">logpai/loghub</b> benchmark — used in academic research papers. Already downloaded locally.</div>', unsafe_allow_html=True)

    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    datasets = {
        "🖥️  BGL Supercomputer": ("logs/bgl_real.log",  "SYSTEM",      "IBM Blue Gene/L · 2,000 lines · kernel failures"),
        "🔒  Linux Auth Logs":   ("logs/linux_real.log", "SECURITY",    "Real auth.log · 2,000 lines · SSH brute force"),
        "📦  HDFS Hadoop":       ("logs/hdfs_real.log",  "APPLICATION", "Hadoop cluster · 2,000 lines · block failures"),
        "🧪  Sample Security":   ("logs/security.log",   "SECURITY",    "Sample security log with injected attack patterns"),
    }

    preset = None
    dcols = st.columns(4)
    for col, (label, (relpath, ltype, desc)) in zip(dcols, datasets.items()):
        with col:
            fullpath = os.path.join(base, relpath)
            st.markdown(f'<div style="font-size:0.68rem;color:#484f58;margin-bottom:0.4rem">{desc}</div>', unsafe_allow_html=True)
            if st.button(label, use_container_width=True):
                if os.path.exists(fullpath):
                    preset = (fullpath, ltype, label)
                else:
                    st.error(f"File not found: {relpath}")

    if uploaded and run_btn:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".log") as tmp:
            tmp.write(uploaded.getvalue())
            tmp_path = tmp.name
        st.divider()
        try:
            run_upload_analysis(tmp_path, log_type_hint, uploaded.name)
        finally:
            os.unlink(tmp_path)
    elif run_btn and not uploaded:
        st.warning("Please upload a file first, or click one of the dataset buttons below.")

    if preset:
        st.divider()
        run_upload_analysis(preset[0], preset[1], preset[2])

# ═════════════════════════════════════════════════════
# TAB 3 — RAW DATABASE
# ═════════════════════════════════════════════════════
with tab_raw:
    st.markdown('<div class="sec-hdr" style="--dc:#8b949e"><div class="sec-hdr-dot"></div>Raw Database — findings.db</div>', unsafe_allow_html=True)

    if df.empty:
        st.markdown('<div style="color:#484f58;font-size:0.85rem;padding:1.5rem">No records in database yet.</div>', unsafe_allow_html=True)
    else:
        show = df[["id","timestamp","log_type","severity","risk_score","brute_force","requires_action","summary"]].copy()
        show["summary"] = show["summary"].str[:80]
        st.dataframe(show, use_container_width=True, hide_index=True,
            column_config={
                "id":              st.column_config.NumberColumn("ID",     width=55),
                "timestamp":       st.column_config.TextColumn("Timestamp",width=170),
                "log_type":        st.column_config.TextColumn("Type",     width=110),
                "severity":        st.column_config.TextColumn("Severity", width=95),
                "risk_score":      st.column_config.ProgressColumn("Risk",  min_value=0, max_value=100, width=110),
                "brute_force":     st.column_config.CheckboxColumn("Brute Force", width=95),
                "requires_action": st.column_config.CheckboxColumn("Action",      width=75),
                "summary":         st.column_config.TextColumn("Summary"),
            })
        st.markdown(f'<div style="font-size:0.7rem;color:#484f58;margin-top:0.75rem;font-family:JetBrains Mono,monospace">{len(df)} records &nbsp;·&nbsp; {DB_PATH}</div>', unsafe_allow_html=True)

    st.markdown('<div style="height:1rem"></div>', unsafe_allow_html=True)
    cb1, cb2 = st.columns(2)
    with cb1:
        if st.button("🗑️  Clear Database", use_container_width=True):
            conn = sqlite3.connect(DB_PATH)
            conn.execute("DELETE FROM findings")
            conn.commit(); conn.close()
            st.success("Database cleared.")
            st.rerun()
    with cb2:
        if not df.empty:
            st.download_button("⬇️  Export CSV", df.to_csv(index=False), "ssoc_findings.csv", "text/csv", use_container_width=True)

st.markdown('<div style="text-align:center;padding:1.5rem 0 0.5rem;border-top:1px solid #21262d;margin-top:2rem;font-size:0.65rem;color:#30363d;letter-spacing:.1em;text-transform:uppercase;font-weight:600">AI Log Analysis Agent · SSOC Portfolio · Powered by Claude AI</div>', unsafe_allow_html=True)
