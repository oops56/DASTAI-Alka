import streamlit as st
import requests
import time
import pandas as pd

API_URL = "https://dastai-alka-1.onrender.com/"
st.title("🔐 AI ZAP Scanner Dashboard")

menu = st.sidebar.selectbox(
    "Menu",
    ["Start Scan", "Live Progress", "History", "Compare", "AI Optimize"]
)

# ---------------- START SCAN ----------------
if menu == "Start Scan":
    target = st.text_input("Enter Target URL")

    if st.button("Start Scan"):
        res = requests.post(f"{BACKEND}/start-scan", json={"target": target})
        scan_id = res.json()["scan_id"]
        st.success(f"Scan started: {scan_id}")

# ---------------- LIVE PROGRESS ----------------
elif menu == "Live Progress":
    scan_id = st.text_input("Enter Scan ID")

    if st.button("Track"):
        progress_bar = st.progress(0)

        while True:
            res = requests.get(f"{BACKEND}/scan-status/{scan_id}")
            data = res.json()

            progress = data.get("progress", 0)
            progress_bar.progress(progress)

            st.write(data)

            if progress >= 100:
                st.success("Scan Completed")
                break

            time.sleep(2)

# ---------------- HISTORY ----------------
elif menu == "History":
    res = requests.get(f"{BACKEND}/history")
    df = pd.DataFrame(res.json())
    st.dataframe(df)

# ---------------- COMPARE ----------------
elif menu == "Compare":
    res = requests.get(f"{BACKEND}/compare")
    df = pd.DataFrame(res.json())
    st.bar_chart(df.set_index("target"))

# ---------------- AI OPTIMIZE ----------------
elif menu == "AI Optimize":
    scan_id = st.text_input("Enter Scan ID")

    if st.button("Get Suggestions"):
        res = requests.get(f"{BACKEND}/ai-optimize/{scan_id}")
        st.json(res.json())

