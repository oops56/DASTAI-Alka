import streamlit as st
import requests
import os
import pandas as pd
from datetime import datetime

API = os.getenv("API_URL", "http://127.0.0.1:8000")

# =========================
# PAGE CONFIG
# =========================
st.set_page_config(
    page_title="AI Security Intelligence Platform",
    layout="wide",
    page_icon="🛡️"
)

# =========================
# THEME (LIGHT PURPLE + GREY)
# =========================
st.markdown("""
<style>

/* MAIN BACKGROUND */
.stApp {
    background: #f3f4f6;
    color: #111827;
    font-family: Segoe UI;
}

/* SIDEBAR */
section[data-testid="stSidebar"] {
    background: #e9d5ff !important;
    border-right: 1px solid #d1d5db;
}

section[data-testid="stSidebar"] * {
    color: #1f2937 !important;
    font-weight: 600;
}

/* HEADINGS */
h1, h2, h3 {
    color: #6d28d9 !important;
    font-weight: 700;
}

/* CARDS */
.card {
    background: white;
    padding: 16px;
    border-radius: 12px;
    border: 1px solid #e5e7eb;
    box-shadow: 0 1px 6px rgba(0,0,0,0.05);
    margin: 8px 0;
}

/* BUTTONS */
.stButton>button {
    background: #a78bfa !important;
    color: white !important;
    font-weight: 600;
    border-radius: 8px;
    border: none;
    padding: 10px 24px;
}

.stButton>button:hover {
    background: #7c3aed !important;
}

/* STATUS BADGES */
.status-success {
    background: #dcfce7;
    color: #166534;
    padding: 8px 12px;
    border-radius: 6px;
    font-weight: 600;
    display: inline-block;
}

.status-error {
    background: #fee2e2;
    color: #991b1b;
    padding: 8px 12px;
    border-radius: 6px;
    font-weight: 600;
    display: inline-block;
}

.metric-box {
    background: white;
    padding: 12px;
    border-radius: 8px;
    border-left: 4px solid #a78bfa;
    margin: 8px 0;
}

</style>
""", unsafe_allow_html=True)

# =========================
# SAFE API CALL WITH RETRY
# =========================
def safe_post(url, files=None, params=None, max_retries=3):
    """Make API call with error handling and status updates"""
    for attempt in range(max_retries):
        try:
            with st.spinner(f"Processing... (Attempt {attempt+1}/{max_retries})"):
                r = requests.post(url, files=files, params=params, timeout=600)

                if r.status_code != 200:
                    error_msg = r.text
                    if attempt < max_retries - 1:
                        st.warning(f"Attempt {attempt+1} failed. Retrying...")
                        continue
                    return None, f"API Error {r.status_code}: {error_msg}"

                data = r.json()

                if data.get("status") != "success":
                    error_msg = data.get("message", "Unknown error")
                    if attempt < max_retries - 1:
                        st.warning(f"Attempt {attempt+1} failed. Retrying...")
                        continue
                    return None, error_msg

                return data["data"], None

        except requests.exceptions.Timeout:
            if attempt < max_retries - 1:
                st.warning(f"Timeout on attempt {attempt+1}. Retrying...")
                continue
            return None, "Request timeout - Backend may be processing a large task"
        except Exception as e:
            if attempt < max_retries - 1:
                st.warning(f"Connection error on attempt {attempt+1}. Retrying...")
                continue
            return None, f"Connection Error: {str(e)}"
    
    return None, "Max retries exceeded"

# =========================
# CHECK BACKEND HEALTH
# =========================
def check_backend():
    """Check if backend is running"""
    try:
        r = requests.get(f"{API}/health", timeout=5)
        if r.status_code == 200:
            return True, r.json()
    except:
        pass
    return False, None

# =========================
# TITLE & HEALTH CHECK
# =========================
st.title("🛡️ AI Security Intelligence Platform")
st.caption("Enterprise Application Security Dashboard powered by AI")

# Health check banner
backend_ok, health_data = check_backend()
if backend_ok:
    st.markdown(f"""
    <div class="card">
    <span class="status-success">✓ Backend Online</span>
    ZAP: {'Connected' if health_data.get('zap_connected') else 'Disconnected'} | 
    Model: {health_data.get('ai_model', 'Unknown')}
    </div>
    """, unsafe_allow_html=True)
else:
    st.error("⚠️ Backend is offline. Make sure the FastAPI server is running on port 8000")

# =========================
# SIDEBAR NAVIGATION
# =========================
task = st.sidebar.radio(
    "Security Modules",
    [
        "🏠 Dashboard",
        "1️⃣ Authentication Research",
        "2️⃣ False Positive Reduction",
        "3️⃣ Findings Prioritization",
        "4️⃣ Scan Policy Optimization",
        "📥 Reports"
    ]
)

# =========================
# 🏠 DASHBOARD (INTRO + FEATURES)
# =========================
if task == "🏠 Dashboard":

    st.markdown("""
# 🛡️ AI Security Intelligence Platform

### Enterprise-grade Vulnerability Analysis & Automated Security Intelligence

---

## 📌 Overview
This platform is a unified **AI-driven security analytics system** combining log analysis, vulnerability scanning, and intelligent risk prioritization.

It integrates with **OWASP ZAP** dynamic scanner and **Ollama AI** to automate modern **Application Security** workflows.

---

## ⚙️ Core Modules

### 1️⃣ Authentication Research
- Detects 401/403 authentication failure patterns  
- Identifies session expiry anomalies  
- AI-based login failure behavior analysis  
- Detects brute-force / broken session patterns  

---

### 2️⃣ False Positive Reduction
- Groups duplicate findings automatically  
- Removes informational noise  
- Reduces manual analyst workload  
- Compares manual vs AI validation efficiency  

---

### 3️⃣ Findings Prioritization
- AI ranks vulnerabilities by exploitability & impact  
- Maps issues to OWASP Top 10  
- Identifies recurring vulnerabilities across apps  
- Validates severity consistency across systems  

---

### 4️⃣ Scan Policy Optimization
- AI suggests scan tuning improvements  
- Removes irrelevant test cases  
- Detects dead paths to reduce crawl scope  
- Improves scan speed & efficiency  
- Compares before/after scan performance  

---

## 🚀 Platform Benefits
✔ Faster vulnerability analysis  
✔ Reduced false positives  
✔ Smarter scan execution  
✔ AI-driven security decision support  

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│         Streamlit UI (Frontend)                         │
└──────────────────┬──────────────────────────────────────┘
                   │ HTTP/REST
┌──────────────────▼──────────────────────────────────────┐
│    FastAPI Backend (zap-ai-dast.py)                    │
│  ┌────────────────────────────────────────────────────┐ │
│  │ • Auth Research  • Prioritization                  │ │
│  │ • False Positive • Policy Optimization             │ │
│  └────────────────────────────────────────────────────┘ │
└────────┬─────────────────────────────────────┬──────────┘
         │                                      │
    ┌────▼────────────┐         ┌──────────────▼──────┐
    │ Ollama AI       │         │ OWASP ZAP Proxy     │
    │ (tinyllama)     │         │ (http://127.0.0.1:  │
    │                 │         │  8080)              │
    └─────────────────┘         └─────────────────────┘
```

""")

    col1, col2, col3 = st.columns(3)

    col1.markdown('<div class="card">🧠 AI Engine<br><b>Active</b></div>', unsafe_allow_html=True)
    col2.markdown('<div class="card">🛡️ ZAP Scanner<br><b>' + ('Ready' if backend_ok else 'Offline') + '</b></div>', unsafe_allow_html=True)
    col3.markdown('<div class="card">⚡ Platform<br><b>Enterprise Mode</b></div>', unsafe_allow_html=True)

# =========================
# 1. AUTHENTICATION
# =========================
elif task == "1️⃣ Authentication Research":

    st.header("Authentication Intelligence")

    st.info("📌 Upload authentication logs (CSV/Excel) to analyze 401/403 errors and session patterns")

    col1, col2 = st.columns([3, 1])
    
    with col1:
        file = st.file_uploader("Upload Logs", type=["csv", "xlsx"], key="auth_logs")
    
    with col2:
        st.write("")
        st.write("")
        analyze_btn = st.button("🔍 Analyze Authentication", use_container_width=True)

    if analyze_btn:
        if not file:
            st.error("Please upload a file first")
        else:
            data, error = safe_post(
                f"{API}/full-analysis",
                files={"file": file},
                params={"target": ""}
            )

            if error:
                st.error(f"❌ Analysis failed: {error}")
            else:
                auth = data["auth"]

                col1, col2, col3 = st.columns(3)
                col1.metric("401 Errors", auth.get("401_count", 0), delta=None)
                col2.metric("403 Errors", auth.get("403_count", 0), delta=None)
                col3.metric("Session Patterns", auth.get("session_patterns", 0), delta=None)

                st.subheader("🤖 AI Pattern Detection")
                
                ai_analysis = auth.get("ai_analysis", {})
                if ai_analysis:
                    st.json(ai_analysis)
                else:
                    st.warning("No AI analysis available")

# =========================
# 2. FALSE POSITIVE REDUCTION
# =========================
elif task == "2️⃣ False Positive Reduction":

    st.header("False Positive Reduction Engine")

    st.info("📌 Upload security findings (CSV/Excel) to filter duplicates and reduce noise")

    col1, col2 = st.columns([3, 1])
    
    with col1:
        file = st.file_uploader("Upload Findings", type=["csv", "xlsx"], key="fp_findings")
    
    with col2:
        st.write("")
        st.write("")
        process_btn = st.button("🔄 Process Findings", use_container_width=True)

    if process_btn:
        if not file:
            st.error("Please upload a file first")
        else:
            data, error = safe_post(
                f"{API}/full-analysis",
                files={"file": file},
                params={"target": ""}
            )

            if error:
                st.error(f"❌ Processing failed: {error}")
            else:
                fp = data.get("false_positive", {})

                col1, col2, col3 = st.columns(3)
                col1.metric("Manual Findings", fp.get("manual_unique_count", 0), delta=None)
                col2.metric("AI Filtered", fp.get("ai_unique_count", 0), delta=None)
                col3.metric("Reduction", f"{fp.get('reduction_percentage', 0)}%", delta=None)

                st.subheader("📊 Detailed Analysis")
                st.json(fp.get("ai_analysis", {}))

# =========================
# 3. PRIORITIZATION
# =========================
elif task == "3️⃣ Findings Prioritization":

    st.header("AI Risk Prioritization")

    st.info("📌 Upload scan data to rank vulnerabilities by exploitability and impact")

    col1, col2 = st.columns([3, 1])
    
    with col1:
        file = st.file_uploader("Upload Scan Data", type=["csv", "xlsx"], key="prio_scan")
    
    with col2:
        st.write("")
        st.write("")
        rank_btn = st.button("📊 Rank Findings", use_container_width=True)

    if rank_btn:
        if not file:
            st.error("Please upload a file first")
        else:
            data, error = safe_post(
                f"{API}/full-analysis",
                files={"file": file},
                params={"target": ""}
            )

            if error:
                st.error(f"❌ Prioritization failed: {error}")
            else:
                pr = data.get("prioritization", {})

                # Display ranking
                if pr.get("ranking"):
                    st.subheader("🎯 Vulnerability Ranking")
                    for item in pr.get("ranking", [])[:10]:
                        exploit = item.get("exploitability", "unknown").upper()
                        impact = item.get("impact", "unknown").upper()
                        st.markdown(f"**#{item.get('rank', '?')}** - {item.get('finding', 'Unknown')} | Exploitability: `{exploit}` | Impact: `{impact}`")
                else:
                    st.info("No ranking available")

                # OWASP Mapping
                if pr.get("owasp_map"):
                    st.subheader("🔗 OWASP Top 10 Mapping")
                    for owasp in pr.get("owasp_map", []):
                        st.write(f"• {owasp}")

                # Recurring issues
                if pr.get("recurring"):
                    st.subheader("🔄 Recurring Vulnerabilities")
                    for recurring in pr.get("recurring", []):
                        st.write(f"• {recurring}")

# =========================
# 4. SCAN OPTIMIZATION
# =========================
elif task == "4️⃣ Scan Policy Optimization":

    st.header("AI Scan Optimization")

    st.info("📌 Enter a target URL to run ZAP scan and optimize scan policy")

    target = st.text_input(
        "Target URL",
        placeholder="https://example.com",
        help="Full URL including protocol (http:// or https://)"
    )

    col1, col2 = st.columns(2)
    
    with col1:
        optimize_btn = st.button("⚡ Run & Optimize Scan", use_container_width=True)
    
    with col2:
        if st.button("ℹ️ ZAP Connection Check", use_container_width=True):
            backend_ok, health = check_backend()
            if backend_ok and health:
                st.success(f"✓ ZAP Connected: {health.get('zap_connected')}")
                st.json(health)
            else:
                st.error("Cannot reach backend")

    if optimize_btn:
        if not target:
            st.error("❌ Please enter a target URL")
        elif not target.startswith(("http://", "https://")):
            st.error("❌ URL must start with http:// or https://")
        else:
            st.warning(f"🔄 Scanning {target}... This may take 2-5 minutes")
            
            data, error = safe_post(
                f"{API}/full-analysis",
                files={"file": ("dummy.csv", b"dummy")},
                params={"target": target}
            )

            if error:
                st.error(f"❌ Scan failed: {error}")
            else:
                st.success("✓ Scan completed")
                
                # Scan results
                col1, col2 = st.columns(2)
                col1.metric("Before Optimization", data.get("before_scan_count", 0), delta=None)
                col2.metric("After Optimization", data.get("after_scan_count", 0), delta=None)
                
                if data.get("after_scan_count", 0) > 0:
                    reduction = 100 * (1 - data.get("after_scan_count", 0) / max(1, data.get("before_scan_count", 1)))
                    st.metric("Alert Reduction", f"{reduction:.1f}%")

                # Policy recommendations
                policy = data.get("policy_optimization", {})
                
                if policy.get("policy_changes"):
                    st.subheader("🔧 Recommended Policy Changes")
                    for change in policy.get("policy_changes", []):
                        st.write(f"• {change}")
                
                if policy.get("dead_paths"):
                    st.subheader("🗑️ Dead Paths to Exclude")
                    for path in policy.get("dead_paths", []):
                        st.write(f"• {path}")
                
                if policy.get("scan_tuning"):
                    st.subheader("⚙️ Scan Tuning Recommendations")
                    st.write(policy.get("scan_tuning"))

# =========================
# REPORTS
# =========================
elif task == "📥 Reports":

    st.header("📥 Download Reports")

    reports_dir = "reports"
    
    if not os.path.exists(reports_dir):
        st.info("📭 No reports available yet. Run an analysis to generate reports.")
    else:
        files = sorted(os.listdir(reports_dir), reverse=True)
        
        if not files:
            st.info("📭 No reports available yet. Run an analysis to generate reports.")
        else:
            st.success(f"✓ Found {len(files)} report(s)")
            
            # Group by timestamp
            from collections import defaultdict
            reports_by_time = defaultdict(list)
            
            for f in files:
                # Extract timestamp from filename (format: report_YYYYMMDD_HHMMSS.ext)
                if f.startswith("report_"):
                    timestamp = "_".join(f.split("_")[1:3]) if "_" in f else "unknown"
                    reports_by_time[timestamp].append(f)
            
            for timestamp, reports in sorted(reports_by_time.items(), reverse=True):
                with st.expander(f"📅 {timestamp}", expanded=True):
                    for report_file in reports:
                        file_path = os.path.join(reports_dir, report_file)
                        file_size = os.path.getsize(file_path) / 1024  # KB
                        
                        col1, col2 = st.columns([4, 1])
                        
                        with col1:
                            st.write(f"📄 {report_file} ({file_size:.1f} KB)")
                        
                        with col2:
                            with open(file_path, "rb") as f:
                                st.download_button(
                                    label="⬇️",
                                    data=f,
                                    file_name=report_file,
                                    use_container_width=True
                                )

# =========================
# FOOTER
# =========================
st.markdown("---")
st.markdown("""
<div style="text-align: center; color: #6d28d9; font-size: 12px; margin-top: 20px;">
🛡️ AI Security Intelligence Platform | Powered by FastAPI + Streamlit + OWASP ZAP + Ollama
</div>
""", unsafe_allow_html=True)
