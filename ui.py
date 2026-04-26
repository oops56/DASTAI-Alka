import streamlit as st
import requests
import time

API_URL = "https://dastai-alka-1.onrender.com/"

if "scan_id" not in st.session_state:
    st.session_state.scan_id = None

target = st.text_input("Target URL")

if st.button("Start Scan"):
    r = requests.post(f"{API_URL}/start-scan", params={"target": target})
    st.session_state.scan_id = r.json()["scan_id"]

# =========================
# LIVE STATUS BOX
# =========================
if st.session_state.scan_id:

    scan_id = st.session_state.scan_id

    r = requests.get(f"{API_URL}/scan/{scan_id}")
    data = r.json()

    status = data.get("status")
    progress = data.get("progress", 0)

    st.write(f"Status: {status}")
    st.progress(int(progress))

    # auto refresh
    if status not in ["done", "error"]:
        time.sleep(2)
        st.rerun()
    else:
        st.success("Scan finished")

        for a in data.get("alerts", []):
            st.warning(f"{a.get('risk')} - {a.get('alert')}")
