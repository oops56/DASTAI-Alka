import streamlit as st
import requests
import time
import pandas as pd

API = "https://dastai-alka-1.onrender.com/"
st.title("🔐 AI ZAP Scanner Dashboard")

menu = st.sidebar.selectbox("Menu", [
    "Upload Analysis",
    "Run Scan",
    "Live Progress",
    "Optimize",
    "Trend",
    "Compare"
])

# ---------------- UPLOAD ----------------
if menu == "Upload Analysis":
    file = st.file_uploader("Upload logs/findings")

    if st.button("Analyze"):
        res = requests.post(f"{API}/analyze", files={"file":file})
        st.json(res.json())

# ---------------- RUN SCAN ----------------
elif menu == "Run Scan":
    target = st.text_input("Target URL")

    if st.button("Start"):
        res = requests.post(f"{API}/start-scan", params={"target":target})
        st.success(res.json())

# ---------------- PROGRESS ----------------
elif menu == "Live Progress":
    sid = st.text_input("Scan ID")

    if st.button("Track"):
        bar = st.progress(0)

        while True:
            res = requests.get(f"{API}/scan-status/{sid}")
            data = res.json()

            bar.progress(data.get("progress",0))
            st.write(data)

            if data.get("progress",0) >= 100:
                break

            time.sleep(2)

# ---------------- OPTIMIZE ----------------
elif menu == "Optimize":
    sid = st.text_input("Scan ID")

    if st.button("Optimize"):
        res = requests.get(f"{API}/optimize/{sid}")
        st.json(res.json())

# ---------------- TREND ----------------
elif menu == "Trend":
    res = requests.get(f"{API}/trend")
    df = pd.DataFrame(res.json())
    st.line_chart(df.set_index("date"))

# ---------------- COMPARE ----------------
elif menu == "Compare":
    res = requests.get(f"{API}/compare")
    df = pd.DataFrame(res.json())
    st.bar_chart(df.set_index("target"))
