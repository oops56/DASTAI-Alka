import streamlit as st
import requests
import time
import pandas as pd

API = "https://dastai-alka-1.onrender.com"

st.set_page_config(page_title="AI ZAP Scanner", layout="wide")

st.title("🔐 AI ZAP Scanner Dashboard")

menu = st.sidebar.selectbox("Menu", [
    "Upload Analysis",
    "Run Scan",
    "Live Progress",
    "Optimize",
    "Trend",
    "Compare"
])

# ---------------- UPLOAD ANALYSIS ----------------
if menu == "Upload Analysis":

    file = st.file_uploader("Upload logs/findings (CSV/JSON)")

    if st.button("Analyze") and file is not None:

        files = {"file": (file.name, file.getvalue())}

        try:
            res = requests.post(f"{API}/analyze", files=files, timeout=60)
            st.json(res.json())
        except Exception as e:
            st.error(f"Error: {e}")

# ---------------- RUN SCAN ----------------
elif menu == "Run Scan":

    target = st.text_input("Target URL (must include http/https)")

    if st.button("Start Scan"):

        try:
            res = requests.post(
                f"{API}/start-scan",
                params={"target": target},
                timeout=30
            )

            data = res.json()

            st.success("Scan started")
            st.code(data)

            st.session_state["scan_id"] = data.get("scan_id")

        except Exception as e:
            st.error(f"Failed to start scan: {e}")

# ---------------- LIVE PROGRESS ----------------
elif menu == "Live Progress":

    sid = st.text_input("Scan ID")

    if st.button("Track Scan"):

        progress_bar = st.progress(0)
        status_box = st.empty()

        while True:
            try:
                res = requests.get(
                    f"{API}/status/{sid}",
                    timeout=10
                )
                data = res.json()

                progress = data.get("progress", 0)

                progress_bar.progress(progress)
                status_box.json(data)

                if progress >= 100:
                    st.success("Scan Completed")
                    break

                time.sleep(2)

            except Exception as e:
                st.error(f"Error fetching status: {e}")
                break

# ---------------- OPTIMIZE ----------------
elif menu == "Optimize":

    sid = st.text_input("Scan ID")

    if st.button("Optimize Scan"):

        try:
            res = requests.get(f"{API}/optimize/{sid}", timeout=30)
            st.json(res.json())
        except Exception as e:
            st.error(f"Error: {e}")

# ---------------- TREND ----------------
elif menu == "Trend":

    try:
        res = requests.get(f"{API}/trend", timeout=30)
        df = pd.DataFrame(res.json())

        if not df.empty:
            st.line_chart(df.set_index("date"))
            st.dataframe(df)
        else:
            st.warning("No trend data available")

    except Exception as e:
        st.error(f"Error: {e}")

# ---------------- COMPARE ----------------
elif menu == "Compare":

    try:
        res = requests.get(f"{API}/compare", timeout=30)
        df = pd.DataFrame(res.json())

        if not df.empty:
            st.bar_chart(df.set_index("target"))
            st.dataframe(df)
        else:
            st.warning("No comparison data available")

    except Exception as e:
        st.error(f"Error: {e}")
