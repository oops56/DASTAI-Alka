import streamlit as st
import requests
import time

API = "https://dastai-alka-1.onrender.com"
st.title("🔐 ZAP Security Scanner Dashboard")

target = st.text_input("Target URL")

if st.button("Start Scan"):
    res = requests.post(f"{API}/scan", json={"target": target}).json()
    st.session_state["scan_id"] = res["scan_id"]

if "scan_id" in st.session_state:
    sid = st.session_state["scan_id"]
    data = requests.get(f"{API}/result/{sid}").json()

    st.subheader("Auth Analysis")
    st.write(data.get("auth"))

    st.subheader("False Positives")
    st.write(data.get("fp"))

    st.subheader("Prioritization")
    st.write(data.get("priority"))

    st.subheader("Optimization")
    st.write(data.get("opt"))

    alerts = data.get("alerts", [])

    if alerts:
        df = pd.DataFrame(alerts)
        st.subheader("Findings")
        st.dataframe(df)

        st.download_button("Download CSV", df.to_csv(index=False), "report.csv")
        st.download_button("Download JSON", str(data), "report.json")
