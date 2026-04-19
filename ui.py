import streamlit as st
import requests
import os
import pandas as pd

API = "http://127.0.0.1:8000"

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
}

/* BUTTONS */
.stButton>button {
    background: #a78bfa !important;
    color: white !important;
    font-weight: 600;
    border-radius: 8px;
    border: none;
}

.stButton>button:hover {
    background: #7c3aed !important;
}

</style>
""", unsafe_allow_html=True)

# =========================
# SAFE API CALL
# =========================
def safe_post(url, files=None, params=None):
    try:
        r = requests.post(url, files=files, params=params, timeout=300)

        if r.status_code != 200:
            return None, r.text

        data = r.json()

        if data.get("status") != "success":
            return None, data.get("message")

        return data["data"], None

    except Exception as e:
        return None, str(e)

# =========================
# TITLE
# =========================
st.title("🛡️ AI Security Intelligence Platform")
st.caption("Enterprise Application Security Dashboard powered by AI")

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

It integrates with **DAST tool scanner** and AI model to simulate a modern **Application Security** workflow.

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

""")

    col1, col2, col3 = st.columns(3)

    col1.markdown('<div class="card">🧠 AI Engine<br><b>Active</b></div>', unsafe_allow_html=True)
    col2.markdown('<div class="card">🛡️ ZAP Scanner<br><b>Ready</b></div>', unsafe_allow_html=True)
    col3.markdown('<div class="card">⚡ Platform<br><b>Enterprise Mode</b></div>', unsafe_allow_html=True)

# =========================
# 1. AUTHENTICATION
# =========================
elif task == "1️⃣ Authentication Research":

    st.header("Authentication Intelligence")

    file = st.file_uploader("Upload Logs", type=["csv", "xlsx"])

    if st.button("Analyze Authentication"):

        data, error = safe_post(
            f"{API}/full-analysis",
            files={"file": file},
            params={"target": ""}
        )

        if error:
            st.error(error)
        else:
            auth = data["auth"]

            col1, col2 = st.columns(2)
            col1.metric("401 Errors", auth["401_count"])
            col2.metric("403 Errors", auth["403_count"])

            st.subheader("AI Pattern Detection")
            st.json(auth.get("ai_analysis"))

# =========================
# 2. FALSE POSITIVE REDUCTION
# =========================
elif task == "2️⃣ False Positive Reduction":

    st.header("False Positive Reduction Engine")

    file = st.file_uploader("Upload Findings", type=["csv", "xlsx"])

    if st.button("Process Findings"):

        data, error = safe_post(
            f"{API}/full-analysis",
            files={"file": file},
            params={"target": ""}
        )

        if error:
            st.error(error)
        else:

            fp = data["false_positive"]

            col1, col2 = st.columns(2)
            col1.metric("Manual Findings", fp.get("manual_count", 0))
            col2.metric("AI Filtered", fp.get("ai_filtered_count", 0))

            st.json(fp)

# =========================
# 3. PRIORITIZATION
# =========================
elif task == "3️⃣ Findings Prioritization":

    st.header("AI Risk Prioritization")

    file = st.file_uploader("Upload Scan Data", type=["csv", "xlsx"])

    if st.button("Rank Findings"):

        data, error = safe_post(
            f"{API}/full-analysis",
            files={"file": file},
            params={"target": ""}
        )

        if error:
            st.error(error)
        else:

            pr = data["prioritization"]

            st.json(pr)

            st.write("OWASP Mapping:", pr.get("owasp", []))

# =========================
# 4. SCAN OPTIMIZATION
# =========================
elif task == "4️⃣ Scan Policy Optimization":

    st.header("AI Scan Optimization")

    target = st.text_input("Target URL")

    if st.button("Optimize Scan"):

        data, error = safe_post(
            f"{API}/full-analysis",
            files={"file": ("dummy.csv", b"")},
            params={"target": target}
        )

        if error:
            st.error(error)
        else:

            col1, col2 = st.columns(2)
            col1.metric("Before", data["before_scan_count"])
            col2.metric("After", data["after_scan_count"])

            st.json(data["policy_optimization"])

# =========================
# REPORTS
# =========================
elif task == "📥 Reports":

    st.header("Download Reports")

    if not os.path.exists("reports"):
        st.warning("No reports available")
    else:
        for f in os.listdir("reports"):
            with open(f"reports/{f}", "rb") as file:
                st.download_button(f"Download {f}", file, file_name=f)
