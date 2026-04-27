import streamlit as st
import requests
import time

API = "https://dastai-alka-1.onrender.com"

st.title("🔐 ZAP Scanner Dashboard")

menu = st.sidebar.selectbox("Menu", [
    "Run Scan",
    "Live Progress"
])

# ---------------- RUN SCAN ----------------
if menu == "Run Scan":

    target = st.text_input("Target URL (http/https required)")

    if st.button("Start Scan"):

        res = requests.post(f"{API}/start-scan", params={"target": target})
        data = res.json()

        st.success("Scan started")
        st.json(data)

        st.session_state["scan_id"] = data["scan_id"]

# ---------------- LIVE ----------------
elif menu == "Live Progress":

    sid = st.text_input("Scan ID")

    if st.button("Track"):

        bar = st.progress(0)
        box = st.empty()

        while True:

            r = requests.get(f"{API}/status/{sid}")
            data = r.json()

            progress = data.get("progress", 0)

            bar.progress(progress)
            box.json(data)

            if data.get("status") in ["done", "spider_failed", "active_failed"]:
                st.success("Finished")
                break

            time.sleep(2)
