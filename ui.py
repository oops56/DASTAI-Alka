import streamlit as st
import requests
import pandas as pd
import plotly.express as px
from streamlit_autorefresh import st_autorefresh

st.set_page_config(layout="wide")

API_SCAN = "http://127.0.0.1:8000/scan"
API_PROGRESS = "http://127.0.0.1:8000/progress"
API_RESULTS = "http://127.0.0.1:8000/results"

st.title("🛡️ AI-Powered ZAP Security Dashboard")


# ---------------- INPUT ----------------
url = st.text_input("Target URL")


# ---------------- SESSION STATE ----------------
if "scan_started" not in st.session_state:
    st.session_state.scan_started = False


# ---------------- FILTER ----------------
st.subheader("🔎 Filter")
filter_option = st.selectbox(
    "Show",
    ["ALL", "REAL", "FALSE_POSITIVE", "UNCERTAIN"],
    key="verdict_filter"
)


# ---------------- START SCAN ----------------
if st.button("🚀 Start Scan"):
    if url:
        try:
            requests.post(API_SCAN, json={"url": url}, timeout=5)
            st.session_state.scan_started = True
            st.success("Scan started successfully")
        except Exception as e:
            st.error(f"Failed to start scan: {e}")
    else:
        st.warning("Please enter a URL")


# ---------------- AUTO REFRESH ----------------
if st.session_state.scan_started:
    st_autorefresh(interval=2000, key="refresh")


    progress_bar = st.progress(0)
    status_text = st.empty()

    try:
        # ---------------- SAFE PROGRESS CALL ----------------
        p = requests.get(API_PROGRESS, timeout=5)

        if p.status_code == 200 and p.text.strip():
            progress_data = p.json()
        else:
            progress_data = {"spider": 0, "active": 0}

        spider = int(progress_data.get("spider", 0))
        active = int(progress_data.get("active", 0))

        progress_bar.progress(min(int((spider + active) / 2), 100))
        status_text.info(f"Spider: {spider}% | Active: {active}%")

        # ---------------- SAFE RESULTS CALL ----------------
        r = requests.get(API_RESULTS, timeout=5)

        if r.status_code != 200 or not r.text.strip():
            st.warning("Waiting for scan results...")
            st.stop()

        try:
            result_data = r.json()
        except Exception:
            st.error(f"Invalid API response: {r.text}")
            st.stop()

        alerts = result_data.get("alerts", [])

        # ---------------- EMPTY STATE ----------------
        if not alerts:
            st.info("No vulnerabilities found yet...")
            st.stop()

        # ---------------- DATAFRAME ----------------
        df = pd.DataFrame([{
            "Risk": a.get("risk"),
            "Alert": a.get("alert"),
            "URL": a.get("url"),
            "Verdict": a.get("verdict"),
            "OWASP": a.get("owasp_category"),
            "CWE": a.get("cwe"),

            # 🔥 REMEDIATION FIXED DISPLAY
            "Short Fix": (a.get("remediation", {}).get("short_fix", "")),
            "How To Prevent": ", ".join(
                a.get("remediation", {}).get("how_to_prevent", [])
            ) if isinstance(a.get("remediation", {}), dict) else "",

            "Code Example": (a.get("remediation", {}).get("code_example", "")),
            "Security Control": (a.get("remediation", {}).get("security_control", "")),

            "Reason": a.get("reason")
        } for a in alerts])

        st.divider()

        # ---------------- SUMMARY ----------------
        col1, col2, col3, col4 = st.columns(4)

        high = len(df[df["Risk"] == "High"]) if not df.empty else 0
        real = len(df[df["Verdict"] == "REAL"]) if not df.empty else 0
        fp = len(df[df["Verdict"] == "FALSE_POSITIVE"]) if not df.empty else 0

        with col1:
            st.metric("Total", len(df))

        with col2:
            st.metric("High Risk", high)

        with col3:
            st.metric("Real Issues", real)

        with col4:
            st.metric("False Positives", fp)

        # ---------------- CHART ----------------
        if not df.empty:
            st.subheader("📊 Risk Distribution")
            fig = px.pie(df, names="Risk", title="Risk Breakdown")
            st.plotly_chart(fig, use_container_width=True)

        # ---------------- FILTER ----------------
        if filter_option != "ALL":
            df = df[df["Verdict"] == filter_option]

        # ---------------- TABLE ----------------
        st.subheader("🚨 Vulnerabilities")

        st.dataframe(df, use_container_width=True)

        # ---------------- DOWNLOAD ----------------
        csv = df.to_csv(index=False).encode("utf-8")
        st.download_button(
            "📥 Download Report",
            csv,
            "zap_ai_report.csv",
            "text/csv"
        )

        # ---------------- COMPLETE ----------------
        if spider == 100 and active == 100:
            st.success("Scan Completed 🎉")
            st.session_state.scan_started = False

    except Exception as e:
        st.error(f"Error fetching data: {e}")