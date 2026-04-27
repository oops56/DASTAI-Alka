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

        try:
            res = requests.post(
                f"{API}/start-scan",
                json={"target": target},
                timeout=30
            )

            data = res.json()

            st.success("Scan started")
            st.json(data)

            st.session_state["scan_id"] = data["scan_id"]

        except Exception as e:
            st.error(f"Error: {e}")

# ---------------- LIVE STATUS ----------------
elif menu == "Live Progress":

    sid = st.text_input("Scan ID")

    if st.button("Track Scan"):

        bar = st.progress(0)
        box = st.empty()

        while True:

            try:
                res = requests.get(f"{API}/status/{sid}", timeout=10)
                data = res.json()

                progress = data.get("progress", 0)
                status = data.get("status", "")

                bar.progress(progress)
                box.json(data)

                if status in ["done", "spider_failed", "scan_failed"]:
                    st.success("Scan Finished")
                    break

                time.sleep(2)

            except Exception as e:
                st.error(f"Error: {e}")
                break
