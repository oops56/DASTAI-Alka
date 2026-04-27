import streamlit as st
import requests
import time

API_URL = "https://dastai-alka-1.onrender.com/"
st.title("🔐 AI Security Scan Analyzer")

menu = st.sidebar.selectbox(
    "Choose Feature",
    ["Auth Analysis", "False Positive", "Prioritize", "Optimize", "Trend"]
)

file = st.file_uploader("Upload Scan File (CSV/JSON)")

if file:
    if st.button("Run Analysis"):
        
        endpoint_map = {
            "Auth Analysis": "/auth-analysis",
            "False Positive": "/false-positive",
            "Prioritize": "/prioritize",
            "Optimize": "/optimize",
            "Trend": "/trend"
        }

        endpoint = endpoint_map[menu]

        response = requests.post(
            BACKEND_URL + endpoint,
            files={"file": file}
        )

        if response.status_code == 200:
            data = response.json()

            st.success("Analysis Complete")

            if isinstance(data, list):
                st.dataframe(pd.DataFrame(data))
            else:
                st.json(data)
        else:
            st.error("Something went wrong")
