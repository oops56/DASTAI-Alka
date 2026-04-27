"""
ZAP AI Security Scanner - Streamlit Frontend
4-module security analysis dashboard powered by OWASP ZAP + TinyLlama
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

# ─── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@400;500;600;700&display=swap');

:root {
    --bg: #0d1117;
    --surface: #161b22;
    --border: #30363d;
    --accent: #3b82f6;
    --accent-glow: rgba(59,130,246,0.2);
    --green: #10b981;
    --red: #ef4444;
    --yellow: #f59e0b;
    --text: #e6edf3;
    --muted: #8b949e;
}

.stApp { background: var(--bg); font-family: 'Inter', sans-serif; }

/* Sidebar */
section[data-testid="stSidebar"] {
    background: var(--surface);
    border-right: 1px solid var(--border);
}

/* Main header */
.zap-header {
    background: linear-gradient(135deg, #0d1117 0%, #1a2332 50%, #0d1117 100%);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.5rem 2rem;
    margin-bottom: 1.5rem;
    position: relative;
    overflow: hidden;
}
.zap-header::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, transparent, var(--accent), transparent);
}
.zap-header h1 {
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.6rem;
    font-weight: 600;
    color: var(--text);
    margin: 0;
    letter-spacing: -0.5px;
}
.zap-header p { color: var(--muted); margin: .3rem 0 0; font-size: .9rem; }

/* Status badges */
.badge {
    display: inline-block;
    padding: .2rem .7rem;
    border-radius: 20px;
    font-size: .75rem;
    font-weight: 600;
    font-family: 'JetBrains Mono', monospace;
}
.badge-high { background: rgba(239,68,68,.15); color: #ef4444; border: 1px solid rgba(239,68,68,.3); }
.badge-medium { background: rgba(245,158,11,.15); color: #f59e0b; border: 1px solid rgba(245,158,11,.3); }
.badge-low { background: rgba(59,130,246,.15); color: #3b82f6; border: 1px solid rgba(59,130,246,.3); }
.badge-info { background: rgba(139,148,158,.15); color: #8b949e; border: 1px solid rgba(139,148,158,.3); }
.badge-ok { background: rgba(16,185,129,.15); color: #10b981; border: 1px solid rgba(16,185,129,.3); }

/* Cards */
.metric-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1.2rem;
    text-align: center;
}
.metric-card .value {
    font-size: 2rem;
    font-weight: 700;
    font-family: 'JetBrains Mono', monospace;
    color: var(--accent);
}
.metric-card .label { color: var(--muted); font-size: .8rem; margin-top: .2rem; }

/* AI output box */
.ai-box {
    background: linear-gradient(135deg, #0d1117, #111827);
    border: 1px solid rgba(59,130,246,.3);
    border-left: 3px solid var(--accent);
    border-radius: 8px;
    padding: 1rem 1.2rem;
    font-family: 'JetBrains Mono', monospace;
    font-size: .82rem;
    color: #c9d1d9;
    white-space: pre-wrap;
    margin: .8rem 0;
    max-height: 300px;
    overflow-y: auto;
}

/* Section headers */
.section-tag {
    font-family: 'JetBrains Mono', monospace;
    font-size: .7rem;
    color: var(--accent);
    letter-spacing: 2px;
    text-transform: uppercase;
    margin-bottom: .3rem;
}

/* Comparison table */
.cmp-table { width: 100%; border-collapse: collapse; }
.cmp-table th {
    background: #1e3a5f;
    color: white;
    padding: .6rem 1rem;
    text-align: left;
    font-size: .82rem;
}
.cmp-table td {
    padding: .55rem 1rem;
    border-bottom: 1px solid var(--border);
    font-size: .82rem;
    color: var(--text);
}
.cmp-table tr:nth-child(even) td { background: rgba(255,255,255,.02); }
</style>
""", unsafe_allow_html=True)

# ─── Backend Config ─────────────────────────────────────────────────────────────
BACKEND = "https://dastai-alka-1.onrender.com""

def api(method, path, **kwargs):
    try:
        fn = getattr(requests, method)
        r = fn(f"{BACKEND}{path}", timeout=90, **kwargs)
        return r.json() if r.headers.get("content-type", "").startswith("application/json") else r
    except requests.exceptions.ConnectionError:
        st.error("⚠️ Backend not running. Start it with: `uvicorn backend:app --port 8000`")
        return None
    except Exception as e:
        st.error(f"API Error: {e}")
        return None

def risk_badge(risk):
    classes = {"High": "badge-high", "Critical": "badge-high", "Medium": "badge-medium",
                "Low": "badge-low", "Informational": "badge-info"}
    cls = classes.get(risk, "badge-info")
    return f'<span class="badge {cls}">{risk}</span>'

def format_findings_df(findings):
    rows = []
    for f in findings:
        rows.append({
            "Finding": f.get("name", ""),
            "Risk": f.get("risk", ""),
            "Confidence": f.get("confidence", ""),
            "URL": f.get("url", "")[:60],
            "OWASP": f.get("owasp_category", ""),
            "Count": f.get("count", 1),
        })
    return pd.DataFrame(rows)

# ─── Sidebar ────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🛡️ ZAP AI Scanner")
    st.markdown("---")

    # Connection check
    health = api("get", "/health")
    if health:
        zap_st = "🟢 Connected" if health.get("zap") else "🔴 Offline (mock)"
        ollama_st = "🟢 Connected" if health.get("ollama") else "🔴 Offline (fallback)"
        pdf_st = "🟢 Available" if health.get("reportlab") else "🔴 Install reportlab"
        st.markdown(f"**ZAP:** {zap_st}")
        st.markdown(f"**TinyLlama:** {ollama_st}")
        st.markdown(f"**PDF Export:** {pdf_st}")
    else:
        st.warning("Backend offline")

    st.markdown("---")
    st.markdown("### ⚙️ Scan Settings")
    target_url = st.text_input("Target URL", value="http://testphp.vulnweb.com")
    zap_url = st.text_input("ZAP URL", value="http://localhost:8080")
    zap_key = st.text_input("ZAP API Key", value="changeme", type="password")
    app_type = st.selectbox("App Type", ["web", "api", "spa", "mobile-backend"])

    st.markdown("---")
    st.markdown("### 🔧 Quick Start")
    st.code("# Start ZAP headless\nzap.sh -daemon -port 8080\n\n# Start Ollama + TinyLlama\nollama pull tinyllama\nollama serve\n\n# Start backend\nuvicorn backend:app --port 8000", language="bash")

    if st.button("🚀 Run New Scan", use_container_width=True, type="primary"):
        with st.spinner("Starting ZAP scan..."):
            resp = api("post", "/api/scan/start", json={
                "target_url": target_url,
                "zap_url": zap_url,
                "zap_api_key": zap_key,
                "app_type": app_type
            })
            if resp:
                st.session_state["scan_id"] = resp.get("scan_id")
                st.session_state["scan_mode"] = resp.get("mode", "mock")
                mode_label = "✅ Live ZAP" if resp.get("mode") == "live" else "🔁 Mock Data"
                st.success(f"Scan started! Mode: {mode_label}")
                st.session_state["findings"] = None

# ─── Load / cache findings ──────────────────────────────────────────────────────
if "findings" not in st.session_state:
    st.session_state["findings"] = None

if "scan_id" in st.session_state and st.session_state["findings"] is None:
    with st.spinner("Fetching findings..."):
        resp = api("get", f"/api/scan/{st.session_state['scan_id']}/findings")
        if resp:
            st.session_state["findings"] = resp.get("findings", [])

# Use demo findings if none loaded
if not st.session_state.get("findings"):
    demo_resp = api("get", "/api/scan/demo/findings")
    if demo_resp:
        st.session_state["findings"] = demo_resp.get("findings", [])

findings = st.session_state.get("findings") or []

# ─── Header ────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="zap-header">
    <h1>🛡️ ZAP AI Security Scanner</h1>
    <p>OWASP ZAP × TinyLlama — Intelligent Vulnerability Analysis Platform</p>
</div>
""", unsafe_allow_html=True)

# ─── Overview Metrics ───────────────────────────────────────────────────────────
if findings:
    risk_counts = pd.Series([f.get("risk", "Unknown") for f in findings]).value_counts()
    cols = st.columns(5)
    metrics = [
        ("Total", len(findings), "🔍"),
        ("High/Critical", risk_counts.get("High", 0) + risk_counts.get("Critical", 0), "🔴"),
        ("Medium", risk_counts.get("Medium", 0), "🟡"),
        ("Low", risk_counts.get("Low", 0), "🔵"),
        ("Info", risk_counts.get("Informational", 0), "⚪"),
    ]
    for col, (label, val, icon) in zip(cols, metrics):
        col.markdown(f"""
        <div class="metric-card">
            <div class="value">{icon} {val}</div>
            <div class="label">{label}</div>
        </div>""", unsafe_allow_html=True)
    st.markdown("<br>", unsafe_allow_html=True)

# ─── TABS ───────────────────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🔐 Auth Research",
    "🎯 False Positive Reduction",
    "📊 Findings Priority",
    "⚙️ Policy Optimization",
    "📥 Export"
])

# ══════════════════════════════════════════════════════════════════════
# TAB 1 — AUTH RESEARCH
# ══════════════════════════════════════════════════════════════════════
with tab1:
    st.markdown("### 🔐 Authentication Research")
    st.markdown("Detect session expiry, repeated 401/403 sequences, and auth failure patterns using AI.")

    col1, col2 = st.columns([2, 1])
    with col1:
        st.markdown('<p class="section-tag">ACCESS LOGS INPUT</p>', unsafe_allow_html=True)

        sample = api("get", "/api/auth/logs/sample")
        default_logs = sample.get("logs", "") if sample else ""
        logs_input = st.text_area("Paste access logs (or use sample)", value=default_logs, height=200,
                                   placeholder="2024-01-01T12:00:00 192.168.1.1 POST /api/login HTTP/401 ...")

    with col2:
        st.markdown("**What this detects:**")
        st.markdown("- 🔴 Repeated 401/403 sequences")
        st.markdown("- ⏱️ Scan duration increases")
        st.markdown("- 🤖 Automated scanning patterns")
        st.markdown("- 🔑 Session expiry patterns")
        st.markdown("- 🚫 Brute force / credential stuffing")

    if st.button("🔍 Analyze Auth Patterns", type="primary"):
        with st.spinner("TinyLlama analyzing logs..."):
            result = api("post", "/api/auth/analyze", json={"logs": logs_input, "analysis_type": "auth"})

        if result:
            st.markdown("---")
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Total Log Lines", result.get("total_lines", 0))
            c2.metric("401 Errors", result.get("error_401_count", 0))
            c3.metric("403 Errors", result.get("error_403_count", 0))
            c4.metric("Repeated Sequences", len(result.get("repeated_sequences", [])))

            col_a, col_b = st.columns(2)
            with col_a:
                st.markdown("#### 🤖 AI Analysis")
                st.markdown(f'<div class="ai-box">{result.get("ai_analysis", "")}</div>', unsafe_allow_html=True)

            with col_b:
                st.markdown("#### 📋 Failure Sequences")
                seqs = result.get("repeated_sequences", [])
                if seqs:
                    for i, seq in enumerate(seqs[:3]):
                        with st.expander(f"Sequence {i+1}: {seq.get('pattern', '')}"):
                            for line in seq.get("lines", []):
                                st.code(line, language="text")
                else:
                    st.info("No repeated sequences found.")

                durations = result.get("durations", [])
                trend = result.get("duration_trend", "stable")
                if durations:
                    st.markdown(f"**Duration trend:** `{trend}` — {len(durations)} timed requests")
                    df_dur = pd.DataFrame({"Response Time (ms)": durations})
                    st.line_chart(df_dur)

            st.markdown("#### 🚨 Sample Auth Failures")
            for e in result.get("sample_errors", []):
                st.code(e, language="text")

# ══════════════════════════════════════════════════════════════════════
# TAB 2 — FALSE POSITIVE REDUCTION
# ══════════════════════════════════════════════════════════════════════
with tab2:
    st.markdown("### 🎯 False Positive Reduction")
    st.markdown("AI groups duplicates, identifies noise, and compares manual vs automated FPA.")

    if not findings:
        st.warning("No findings loaded. Run a scan from the sidebar first.")
    else:
        if st.button("🤖 Run AI False Positive Analysis", type="primary"):
            with st.spinner("Grouping and analyzing findings..."):
                result = api("post", "/api/fpr/analyze", json={"findings": findings})

            if result:
                cmp = result.get("manual_vs_ai_comparison", {})
                c1, c2, c3, c4 = st.columns(4)
                c1.metric("Total Findings", result.get("total_findings", 0))
                c2.metric("Duplicate Groups", result.get("manual_vs_ai_comparison", {}).get("duplicate_groups", 0))
                c3.metric("Informational", cmp.get("informational_count", 0))
                c4.metric("Suppressible", cmp.get("reduction_potential", ""))

                col_a, col_b = st.columns(2)
                with col_a:
                    st.markdown("#### 🤖 AI FPA Analysis")
                    st.markdown(f'<div class="ai-box">{result.get("ai_fpa_analysis", "")}</div>',
                                unsafe_allow_html=True)

                with col_b:
                    st.markdown("#### 📊 Manual vs AI FPA Comparison")
                    data = {
                        "Metric": ["FP Identified (Manual)", "Estimated FP % (AI)", "Low Risk Findings",
                                   "Informational Findings", "Duplicate Groups", "Unique Finding Types"],
                        "Value": [
                            cmp.get("manual_fp_identified", 0),
                            f"{cmp.get('ai_estimated_fp_percentage', 0)}%",
                            cmp.get("low_risk_count", 0),
                            cmp.get("informational_count", 0),
                            cmp.get("duplicate_groups", 0),
                            cmp.get("total_unique", 0),
                        ]
                    }
                    st.dataframe(pd.DataFrame(data), hide_index=True, use_container_width=True)

                st.markdown("#### 🔁 Duplicate Finding Groups")
                dupes = result.get("duplicate_groups", {})
                if dupes:
                    for name, count in dupes.items():
                        st.markdown(f"- **{name}** — {count} duplicate instances")
                else:
                    st.success("No significant duplicate groups detected.")

                col_c, col_d = st.columns(2)
                with col_c:
                    st.markdown("#### ⚪ Informational Findings (Suppressible)")
                    for item in result.get("informational_findings", []):
                        st.markdown(f"- {item}")
                with col_d:
                    st.markdown("#### 🔵 Low Risk Recurring Noise")
                    for item in result.get("low_risk_findings", []):
                        st.markdown(f"- {item}")

# ══════════════════════════════════════════════════════════════════════
# TAB 3 — FINDINGS PRIORITIZATION
# ══════════════════════════════════════════════════════════════════════
with tab3:
    st.markdown("### 📊 Findings Prioritization")
    st.markdown("AI ranks findings by exploitability and impact, maps to OWASP Top 10, and validates against manual severity.")

    if not findings:
        st.warning("No findings loaded. Run a scan from the sidebar first.")
    else:
        if st.button("🚀 Prioritize & Map Findings", type="primary"):
            with st.spinner("TinyLlama ranking findings..."):
                result = api("post", "/api/priority/rank", json={"findings": findings})

            if result:
                c1, c2, c3, c4 = st.columns(4)
                c1.metric("High Priority", result.get("high_priority_count", 0))
                c2.metric("OWASP Categories", len(result.get("owasp_category_summary", {})))
                c3.metric("Cross-App Patterns", len(result.get("cross_app_patterns", [])))
                c4.metric("Manual/AI Discrepancies", len(result.get("manual_vs_ai_discrepancies", [])))

                col_a, col_b = st.columns([1, 1])
                with col_a:
                    st.markdown("#### 🤖 AI Priority Ranking")
                    st.markdown(f'<div class="ai-box">{result.get("ai_ranking_analysis", "")}</div>',
                                unsafe_allow_html=True)

                with col_b:
                    st.markdown("#### 🗺️ OWASP Top 10 Mapping")
                    owasp = result.get("owasp_category_summary", {})
                    if owasp:
                        df_owasp = pd.DataFrame([
                            {"OWASP Category": k, "Findings": v}
                            for k, v in sorted(owasp.items(), key=lambda x: -x[1])
                        ])
                        st.bar_chart(df_owasp.set_index("OWASP Category"))

                st.markdown("#### 📋 Ranked Findings")
                ranked = result.get("ranked_findings", [])
                if ranked:
                    df = format_findings_df(ranked)
                    st.dataframe(df, hide_index=True, use_container_width=True,
                                 column_config={
                                     "Risk": st.column_config.TextColumn("Risk"),
                                     "Count": st.column_config.NumberColumn("Count", format="%d"),
                                 })

                discrepancies = result.get("manual_vs_ai_discrepancies", [])
                if discrepancies:
                    st.markdown("#### ⚖️ Manual vs AI Severity Discrepancies")
                    df_disc = pd.DataFrame(discrepancies)
                    st.dataframe(df_disc, hide_index=True, use_container_width=True)
                else:
                    st.success("✅ Manual and AI severity assessments align well.")

                cross = result.get("cross_app_patterns", [])
                if cross:
                    st.markdown("#### 🔄 Findings Recurring Across Apps")
                    for item in cross:
                        st.markdown(f"- ⚠️ **{item}** (appears 3+ times)")

# ══════════════════════════════════════════════════════════════════════
# TAB 4 — SCAN POLICY OPTIMIZATION
# ══════════════════════════════════════════════════════════════════════
with tab4:
    st.markdown("### ⚙️ Scan Policy Optimization")
    st.markdown("AI proposes policy changes, disables irrelevant test cases, reduces crawl scope, and measures impact.")

    if not findings:
        st.warning("No findings loaded. Run a scan from the sidebar first.")
    else:
        if st.button("🧠 Optimize Scan Policy", type="primary"):
            with st.spinner("AI generating policy recommendations..."):
                result = api("post", "/api/policy/optimize", json={
                    "findings": findings,
                    "target_url": target_url,
                    "app_type": app_type
                })

            if result:
                metrics = result.get("metrics_comparison", {})
                orig = metrics.get("original", {})
                opt = metrics.get("optimized", {})
                imp = metrics.get("improvement", {})

                c1, c2, c3, c4 = st.columns(4)
                c1.metric("Original Runtime", f"{orig.get('runtime_seconds',0)}s")
                c2.metric("Optimized Runtime", f"{opt.get('runtime_seconds',0)}s",
                          delta=f"-{imp.get('runtime_reduction_pct',0)}%")
                c3.metric("Original Findings", orig.get("findings_count", 0))
                c4.metric("After Tuning", opt.get("findings_count", 0),
                          delta=f"-{imp.get('noise_reduction_pct',0)}% noise")

                col_a, col_b = st.columns(2)
                with col_a:
                    st.markdown("#### 🤖 AI Policy Recommendations")
                    st.markdown(f'<div class="ai-box">{result.get("ai_policy_recommendations", "")}</div>',
                                unsafe_allow_html=True)

                with col_b:
                    st.markdown("#### 🚫 Rules to Disable")
                    disabled = result.get("disabled_rules", [])
                    for rule in disabled:
                        st.markdown(f"**{rule['rule']}**")
                        st.caption(f"↳ {rule['reason']}")
                        st.markdown("")

                col_c, col_d = st.columns(2)
                with col_c:
                    st.markdown("#### 💀 Dead Paths (Exclude from Crawl)")
                    for path in result.get("dead_paths", []):
                        st.code(path, language="text")
                with col_d:
                    st.markdown("#### 🎯 High-Value Paths (Focus Scan)")
                    for path in result.get("high_value_paths", []):
                        st.code(path, language="text")

                # Runtime comparison chart
                st.markdown("#### 📈 Runtime & Findings Before vs After Policy Tuning")
                df_chart = pd.DataFrame({
                    "Metric": ["Runtime (s)", "Findings Count"],
                    "Before": [orig.get("runtime_seconds", 0), orig.get("findings_count", 0)],
                    "After": [opt.get("runtime_seconds", 0), opt.get("findings_count", 0)],
                })
                st.dataframe(df_chart, hide_index=True, use_container_width=True)

# ══════════════════════════════════════════════════════════════════════
# TAB 5 — EXPORT
# ══════════════════════════════════════════════════════════════════════
with tab5:
    st.markdown("### 📥 Export Reports")
    st.markdown("Download findings in your preferred format.")

    if not findings:
        st.warning("No findings loaded. Run a scan first.")
    else:
        st.markdown(f"**Ready to export:** `{len(findings)}` findings")
        st.markdown("---")

        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.markdown("#### 📄 CSV")
            st.markdown("Spreadsheet-friendly format for Excel/Google Sheets")
            if st.button("Download CSV", use_container_width=True):
                try:
                    r = requests.post(f"{BACKEND}/api/export/csv", json={"findings": findings}, timeout=30)
                    st.download_button("⬇️ Save CSV", data=r.content,
                                       file_name=f"zap_findings_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
                                       mime="text/csv", use_container_width=True)
                except Exception as e:
                    st.error(str(e))

        with col2:
            st.markdown("#### 📋 JSON")
            st.markdown("Machine-readable format for integrations and APIs")
            if st.button("Download JSON", use_container_width=True):
                try:
                    r = requests.post(f"{BACKEND}/api/export/json", json={"findings": findings}, timeout=30)
                    st.download_button("⬇️ Save JSON", data=r.content,
                                       file_name=f"zap_findings_{datetime.now().strftime('%Y%m%d_%H%M')}.json",
                                       mime="application/json", use_container_width=True)
                except Exception as e:
                    st.error(str(e))

        with col3:
            st.markdown("#### 🌐 HTML")
            st.markdown("Styled HTML report for sharing with stakeholders")
            if st.button("Download HTML", use_container_width=True):
                try:
                    r = requests.post(f"{BACKEND}/api/export/html", json={"findings": findings}, timeout=30)
                    st.download_button("⬇️ Save HTML", data=r.content,
                                       file_name=f"zap_report_{datetime.now().strftime('%Y%m%d_%H%M')}.html",
                                       mime="text/html", use_container_width=True)
                except Exception as e:
                    st.error(str(e))

        with col4:
            st.markdown("#### 📑 PDF")
            st.markdown("Professional PDF report with tables and summary")
            if st.button("Download PDF", use_container_width=True):
                try:
                    r = requests.post(f"{BACKEND}/api/export/pdf", json={"findings": findings}, timeout=60)
                    if r.status_code == 500:
                        st.error("Install reportlab: `pip install reportlab`")
                    else:
                        st.download_button("⬇️ Save PDF", data=r.content,
                                           file_name=f"zap_report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf",
                                           mime="application/pdf", use_container_width=True)
                except Exception as e:
                    st.error(str(e))

        # Preview table
        st.markdown("---")
        st.markdown("#### 🔍 Findings Preview")
        df = format_findings_df(findings)
        st.dataframe(df, hide_index=True, use_container_width=True,
                     column_config={
                         "Risk": st.column_config.TextColumn("Risk"),
                         "Count": st.column_config.NumberColumn("Count", format="%d"),
                     })

# ─── Footer ────────────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown(
    '<div style="text-align:center;color:#8b949e;font-size:.78rem;font-family:JetBrains Mono,monospace;">'
    '🛡️ ZAP AI Security Scanner &nbsp;|&nbsp; OWASP ZAP × TinyLlama &nbsp;|&nbsp; '
    'Mock mode active when tools are offline</div>',
    unsafe_allow_html=True
)
