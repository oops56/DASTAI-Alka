import streamlit as st
import requests
import os
import time

# =========================
# CONFIG (FIXED URL BUG)
# =========================
API = os.getenv("API_URL", "https://dastai-alka-1.onrender.com").rstrip("/")

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
# SAFE API CALLS
# =========================
def safe_post(url, files=None, params=None):
    try:
        r = requests.post(url, files=files, params=params, timeout=600)

        if r.status_code != 200:
            return None, f"HTTP {r.status_code}: {r.text}"

        data = r.json()

        if data.get("status") != "success":
            return None, data.get("message", "Unknown error")

        return data.get("data"), None

    except Exception as e:
        return None, str(e)


def safe_get(url):
    try:
        r = requests.get(url, timeout=60)
        if r.status_code != 200:
            return None
        return r.json()
    except:
        return None


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
    st.error("❌ Backend Not Reachable")

# =========================
# SESSION STATE
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
    ["Dashboard", "Scan", "Reports"]
)

# =========================
# DASHBOARD
# =========================
if task == "Dashboard":
    st.write("AI Security Platform with ZAP + AI + Automation")

# =========================
# 🚀 SCAN MODULE (FIXED)
# =========================
elif task == "Scan":

    st.header("🚀 Live Security Scan")

    target = st.text_input("Target URL", placeholder="http://testphp.vulnweb.com")

    # START SCAN
    if st.button("Start Scan"):

        if not target:
            st.error("Enter target URL")
        else:
            data, err = safe_post(
                f"{API}/start-scan",
                params={"target": target}
            )

            if err or not data:
                st.error(f"Failed: {err}")
            else:
                st.session_state.scan_id = data["scan_id"]
                st.session_state.scan_done = False
                st.session_state.scan_data = None
                st.success(f"Scan started: {data['scan_id']}")

    # =========================
    # PROGRESS (NON-BLOCKING)
    # =========================
    if st.session_state.scan_id:

        scan_id = st.session_state.scan_id

        st.subheader("📡 Scan Progress")

        data = safe_get(f"{API}/scan-status/{scan_id}")

        if not data:
            st.warning("Waiting for backend...")
        else:
            status = data.get("status", "unknown")
            progress = int(data.get("progress", 0))

            st.progress(progress / 100)
            st.info(f"Status: {status} ({progress}%)")

            alerts = data.get("alerts", [])
            st.write(f"Alerts: {len(alerts)}")

            if status == "done":
                st.session_state.scan_done = True
                st.session_state.scan_data = data

            elif status == "error":
                st.error(data.get("error", "Scan failed"))

        # 🔁 AUTO REFRESH (IMPORTANT FIX)
        if not st.session_state.scan_done:
            time.sleep(2)
            st.rerun()

    # =========================
    # RESULTS
    # =========================
    if st.session_state.scan_done:

        st.success("✅ Scan Completed")

        st.subheader("📊 Results")
        st.json(st.session_state.scan_data)

        st.subheader("📥 Download Reports")

        for t in ["json", "csv"]:
            try:
                r = requests.get(f"{API}/download/{t}")

                if r.status_code == 200:
                    st.download_button(
                        f"Download {t.upper()}",
                        data=r.content,
                        file_name=f"report.{t}"
                    )
                else:
                    st.warning(f"{t} not ready")

            except:
                st.error(f"{t} download error")

# =========================
# REPORTS
# =========================
elif task == "Reports":

    st.header("📥 Reports")

    for t in ["json", "csv"]:
        try:
            r = requests.get(f"{API}/download/{t}")

            if r.status_code == 200:
                st.download_button(
                    f"Download {t.upper()}",
                    data=r.content,
                    file_name=f"report.{t}"
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
