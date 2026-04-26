import streamlit as st
import requests
import time

# 🔥 YOUR RENDER BACKEND URL
API_URL = "https://dastai-alka-1.onrender.com/"

st.set_page_config(page_title="ZAP Scanner", layout="centered")

st.title("🔍 Web Vulnerability Scanner")
st.subheader("Powered by OWASP ZAP")

# =========================
# INPUT
# =========================
target = st.text_input("Enter Target URL", "http://testphp.vulnweb.com")

# =========================
# START SCAN
# =========================
if st.button("Start Scan"):

    res = requests.post(f"{API_URL}/start-scan", params={"target": target})

    if res.status_code == 200:
        scan_id = res.json()["scan_id"]
        st.success(f"Scan started: {scan_id}")

        progress_bar = st.progress(0)
        status_text = st.empty()

        # =========================
        # POLLING LOOP
        # =========================
        while True:
            r = requests.get(f"{API_URL}/scan/{scan_id}")
            data = r.json()

            status = data.get("status")
            progress = data.get("progress", 0)

            progress_bar.progress(progress)
            status_text.text(f"Status: {status} | Progress: {progress}%")

            if status in ["done", "error"]:
                break

            time.sleep(2)

        # =========================
        # RESULT DISPLAY
        # =========================
        if status == "done":
            st.success("Scan Completed")

            alerts = data.get("alerts", [])

            st.write("### 🔥 Vulnerabilities Found")
            for a in alerts:
                st.warning(f"{a.get('risk','')} - {a.get('alert','')}")
                st.text(a.get("url", ""))

        else:
            st.error(data.get("error", "Scan failed"))

    else:
        st.error("Failed to start scan")
