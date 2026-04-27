import streamlit as st
import requests
import time

API = "https://dastai-alka-1.onrender.com"
st.title("🔐 ZAP Security Scanner Dashboard")
target = st.text_input("Target URL")

if st.button("Run Scan"):
    res = requests.post(API + "/scan", json={"target": target}).json()
    st.session_state["id"] = res["scan_id"]

if "id" in st.session_state:
    sid = st.session_state["id"]

    data = requests.get(API + f"/result/{sid}").json()

    if "error" in data:
        st.error(data["error"])
    else:
        st.subheader("AI Summary")
        st.write(data.get("ai"))

        st.subheader("Findings")

        alerts = data.get("alerts", [])
        if alerts:
            df = pd.DataFrame(alerts)
            st.dataframe(df)

            st.download_button("Download JSON", str(data), "report.json")
            st.download_button("Download CSV", df.to_csv(index=False), "report.csv")
