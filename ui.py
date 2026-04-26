import streamlit as st
import requests
import os
import time

API = os.getenv("API_URL", "https://dastai-alka.onrender.com/")

# =========================
# PAGE CONFIG
# =========================
st.set_page_config(
    page_title="AI Security Intelligence Platform",
    layout="wide",
    page_icon="🛡️"
)

# =========================
# THEME
# =========================
st.markdown("""
<style>
.stApp { background: #f3f4f6; color: #111827; }
h1, h2, h3 { color: #6d28d9 !important; }

.stButton>button {
    background: #a78bfa !important;
    color: white !important;
    border-radius: 8px;
    font-weight: 600;
}
</style>
""", unsafe_allow_html=True)

# =========================
# SAFE API CALL
# =========================
def safe_post(url, files=None, params=None):
    try:
        with st.spinner("Processing..."):
            r = requests.post(url, files=files, params=params, timeout=600)

        if r.status_code != 200:
            return None, f"HTTP {r.status_code}: {r.text}"

        data = r.json()

        if data.get("status") != "success":
            return None, data.get("message", "Unknown error")

        return data.get("data"), None

    except Exception as e:
        return None, str(e)

# =========================
# HEALTH CHECK
# =========================
def check_backend():
    try:
        r = requests.get(f"{API}/health", timeout=5)
        return r.status_code == 200
    except:
        return False

# =========================
# HEADER
# =========================
st.title("🛡️ AI Security Intelligence Platform")

if check_backend():
    st.success("✓ Backend Connected")
else:
    st.error("❌ Backend Not Running")

# =========================
# SESSION STATE INIT
# =========================
if "scan_id" not in st.session_state:
    st.session_state.scan_id = None
    st.session_state.scan_done = False
    st.session_state.scan_data = None

# =========================
# SIDEBAR
# =========================
task = st.sidebar.radio(
    "Modules",
    ["Dashboard", "Authentication", "False Positive", "Prioritization", "Scan", "Reports"]
)

# =========================
# DASHBOARD
# =========================
if task == "Dashboard":
    st.write("AI Security Platform with ZAP + AI + Automation")

# =========================
# AUTH
# =========================
elif task == "Authentication":

    file = st.file_uploader("Upload Logs", type=["csv", "xlsx"])

    if st.button("Analyze"):
        if file:
            data, err = safe_post(
                f"{API}/full-analysis",
                files={"file": file},
                params={"target": ""}
            )

            if err:
                st.error(err)
            else:
                st.json(data.get("auth", {}))

# =========================
# FALSE POSITIVE
# =========================
elif task == "False Positive":

    file = st.file_uploader("Upload Findings", type=["csv", "xlsx"])

    if st.button("Process"):
        if file:
            data, err = safe_post(
                f"{API}/full-analysis",
                files={"file": file},
                params={"target": ""}
            )

            if err:
                st.error(err)
            else:
                st.json(data.get("false_positive", {}))

# =========================
# PRIORITIZATION
# =========================
elif task == "Prioritization":

    file = st.file_uploader("Upload Scan Data", type=["csv", "xlsx"])

    if st.button("Rank"):
        if file:
            data, err = safe_post(
                f"{API}/full-analysis",
                files={"file": file},
                params={"target": ""}
            )

            if err:
                st.error(err)
            else:
                st.json(data.get("prioritization", {}))

# =========================
# 🚀 FIXED SCAN MODULE (NO CRASH + LIVE PROGRESS)
# =========================
elif task == "Scan":

    st.header("🚀 Live Security Scan")

    target = st.text_input("Target URL", placeholder="http://testphp.vulnweb.com")

    # =========================
    # START SCAN
    # =========================
    if st.button("Start Scan"):

        if not target:
            st.error("Please enter target URL")

        else:
            data, err = safe_post(
                f"{API}/start-scan",
                params={"target": target}
            )

            # ✅ SAFE CHECK (FIX FOR YOUR ERROR)
            if err or data is None:
                st.error(f"Scan failed: {err}")
                st.stop()

            scan_id = data.get("scan_id")

            if not scan_id:
                st.error("Backend did not return scan_id")
                st.stop()

            st.session_state.scan_id = scan_id
            st.session_state.scan_done = False
            st.session_state.scan_data = None

            st.success(f"Scan started: {scan_id}")

    # =========================
    # LIVE PROGRESS TRACKING
    # =========================
    if st.session_state.scan_id:

        scan_id = st.session_state.scan_id

        progress_bar = st.progress(0)
        status_box = st.empty()
        alert_box = st.empty()

        while True:

            try:
                r = requests.get(f"{API}/scan-status/{scan_id}")

                if r.status_code != 200:
                    st.error("Failed to fetch scan status")
                    break

                data = r.json()

                status = data.get("status", "unknown")
                progress = data.get("progress", 0)

                progress_bar.progress(progress / 100)
                status_box.info(f"Status: {status} | Progress: {progress}%")

                alerts = data.get("alerts", [])
                alert_box.write(f"Alerts Found: {len(alerts)}")

                if status == "done":
                    st.session_state.scan_done = True
                    st.session_state.scan_data = data
                    break

                if status == "error":
                    st.error(data.get("error", "Scan failed"))
                    break

                time.sleep(2)

            except Exception as e:
                st.error(str(e))
                break

    # =========================
    # DOWNLOAD SECTION (ONLY AFTER SCAN)
    # =========================
    if st.session_state.scan_done:

        st.success("✅ Scan Completed Successfully")

        st.subheader("📥 Download Reports")

        cols = st.columns(4)
        types = ["json", "csv", "html", "pdf"]

        for i, t in enumerate(types):

            with cols[i]:

                try:
                    r = requests.get(f"{API}/download/{t}")

                    if r.status_code == 200:
                        st.download_button(
                            f"⬇ {t.upper()}",
                            data=r.content,
                            file_name=f"security_report.{t}",
                            mime="application/octet-stream"
                        )
                    else:
                        st.button(f"{t.upper()} Not Ready", disabled=True)

                except:
                    st.button(f"{t.upper()} Error", disabled=True)

        st.subheader("📊 Scan Result")
        st.json(st.session_state.scan_data)

# =========================
# REPORTS PAGE
# =========================
elif task == "Reports":

    st.header("📥 Reports")

    for t in ["json", "csv", "html", "pdf"]:

        try:
            r = requests.get(f"{API}/download/{t}")

            if r.status_code == 200:
                st.download_button(
                    f"Download {t.upper()}",
                    data=r.content,
                    file_name=f"report.{t}",
                    mime="application/octet-stream"
                )
            else:
                st.warning(f"{t} not available")

        except Exception as e:
            st.error(str(e))

# =========================
# FOOTER
# =========================
st.markdown("---")
st.caption("AI Security Platform")
