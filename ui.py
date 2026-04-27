import streamlit as st
import requests
import time

API = "https://dastai-alka-1.onrender.com"

st.title("🔐 AI ZAP Security Platform")

menu = st.sidebar.selectbox("Menu", [
    "Run Scan",
    "Live Analysis",
    "Compare Runs"
])

# ---------------- RUN SCAN ----------------
if menu == "Run Scan":

    target = st.text_input("Target URL")

    if st.button("Start Scan"):

        res = requests.post(
            f"{API}/start-scan",
            json={"target": target}
        )

        st.success(res.json())

# ---------------- LIVE ANALYSIS ----------------
elif menu == "Live Analysis":

    sid = st.text_input("Scan ID")

    if st.button("Fetch Analysis"):

        res = requests.get(f"{API}/status/{sid}")
        data = res.json()

        st.subheader("Authentication Research")
        st.json(data["auth_analysis"])

        st.subheader("False Positive Reduction")
        st.json(data["false_positive"])

        st.subheader("Prioritized Findings")
        st.dataframe(pd.DataFrame(data["prioritized"]))

# ---------------- COMPARE ----------------
elif menu == "Compare Runs":

    res = requests.get(f"{API}/compare")
    df = pd.DataFrame(res.json())

    st.line_chart(df.set_index("id"))
    st.dataframe(df)
