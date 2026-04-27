"""
ZAP AI Security Scanner - Streamlit Frontend
"""

import streamlit as st
import requests
import json
import pandas as pd
import time
from datetime import datetime

# ─── Page Config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="ZAP AI Security Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ─── Light Purple Theme CSS ────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@400;500;600;700&display=swap');

:root {
    --bg: #f6f3ff;
    --surface: #ffffff;
    --border: #d6ccff;
    --accent: #8b5cf6;
    --accent-glow: rgba(139,92,246,0.25);
    --green: #10b981;
    --red: #ef4444;
    --yellow: #f59e0b;
    --text: #2d1b69;
    --muted: #6b7280;
}

.stApp { background: var(--bg); font-family: 'Inter', sans-serif; }

/* Sidebar */
section[data-testid="stSidebar"] {
    background: #ede9fe;
    border-right: 1px solid var(--border);
}

/* Header */
.zap-header {
    background: linear-gradient(135deg, #ede9fe 0%, #ddd6fe 50%, #f6f3ff 100%);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.5rem 2rem;
    margin-bottom: 1.5rem;
}
.zap-header h1 {
    font-family: 'JetBrains Mono', monospace;
    color: var(--text);
    margin: 0;
}
.zap-header p { color: var(--muted); }

/* Badges */
.badge {
    display: inline-block;
    padding: .2rem .7rem;
    border-radius: 20px;
    font-size: .75rem;
    font-weight: 600;
}
.badge-high { background: #fee2e2; color: #dc2626; }
.badge-medium { background: #fef3c7; color: #d97706; }
.badge-low { background: #e0e7ff; color: #4f46e5; }
.badge-info { background: #f3f4f6; color: #6b7280; }

/* Cards */
.metric-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1rem;
    text-align: center;
}
.metric-card .value {
    font-size: 2rem;
    font-weight: 700;
    color: var(--accent);
}
.metric-card .label {
    color: var(--muted);
    font-size: .85rem;
}

/* AI Box */
.ai-box {
    background: #faf5ff;
    border: 1px solid #c4b5fd;
    border-left: 4px solid var(--accent);
    border-radius: 8px;
    padding: 1rem;
    font-family: 'JetBrains Mono', monospace;
    color: #4c1d95;
    white-space: pre-wrap;
}

/* Section Tag */
.section-tag {
    font-size: .7rem;
    color: var(--accent);
    letter-spacing: 2px;
    text-transform: uppercase;
}

/* Table */
.cmp-table th {
    background: #8b5cf6;
    color: white;
}
</style>
""", unsafe_allow_html=True)

# ─── Backend Config ─────────────────────────────────────────────────────────────
BACKEND = "http://localhost:8000"

def api(method, path, **kwargs):
    try:
        fn = getattr(requests, method)
        r = fn(f"{BACKEND}{path}", timeout=90, **kwargs)
        return r.json() if "application/json" in r.headers.get("content-type","") else r
    except:
        st.error("Backend not running")
        return None

# ─── Sidebar ────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🛡️ ZAP AI Scanner")
    target_url = st.text_input("Target URL", "http://testphp.vulnweb.com")

    if st.button("🚀 Run Scan"):
        st.success("Scan triggered (demo)")

# ─── Header ────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="zap-header">
<h1>🛡️ ZAP AI Security Scanner</h1>
<p>Light Purple UI Theme</p>
</div>
""", unsafe_allow_html=True)

# ─── Demo Metrics ──────────────────────────────────────────────────────────────
cols = st.columns(4)
for col, val, label in zip(cols, [120, 5, 20, 60], ["Total", "High", "Medium", "Low"]):
    col.markdown(f"""
    <div class="metric-card">
        <div class="value">{val}</div>
        <div class="label">{label}</div>
    </div>
    """, unsafe_allow_html=True)

# ─── Tabs ──────────────────────────────────────────────────────────────────────
tab1, tab2 = st.tabs(["🔐 Auth", "📊 Findings"])

with tab1:
    st.markdown("### Auth Analysis")
    logs = st.text_area("Paste logs")
    if st.button("Analyze"):
        st.markdown('<div class="ai-box">AI output will appear here...</div>', unsafe_allow_html=True)

with tab2:
    st.markdown("### Findings Table")
    df = pd.DataFrame({
        "Finding": ["SQL Injection", "XSS"],
        "Risk": ["High", "Medium"]
    })
    st.dataframe(df)

# ─── Footer ────────────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown("<center>Light Purple Theme Enabled 💜</center>", unsafe_allow_html=True)
