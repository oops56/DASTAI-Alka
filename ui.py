import streamlit as st
import requests
import time

API = "https://dastai-alka-1.onrender.com"
st.title("🔐 ZAP Security Scanner Dashboard")

menu = st.sidebar.selectbox("Menu", ["Run Scan", "Live Status"])

# ---------------- RUN SCAN ----------------
if menu == "Run Scan":

    target = st.text_input("Enter Target URL")

    if st.button("Start Scan"):

        try:
            res = requests.post(
                f"{API}/start-scan",
                json={"target": target}
            )

            st.success("Scan started")
            st.json(res.json())

        except Exception as e:
            st.error(str(e))

# ---------------- LIVE STATUS ----------------
elif menu == "Live Status":

    sid = st.text_input("Scan ID")

    if st.button("Track"):

        bar = st.progress(0)
        box = st.empty()

        while True:

            try:
                res = requests.get(f"{API}/status/{sid}")
                data = res.json()

                progress = data.get("progress", 0)

                bar.progress(progress)
                box.json(data)

                if data.get("status") in ["done", "spider_failed", "scan_failed"]:
                    st.success("Scan finished")
                    break

                time.sleep(2)

            except Exception as e:
                st.error(str(e))
                break
