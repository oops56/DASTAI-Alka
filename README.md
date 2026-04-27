# DASTAI-Alka

DASTAI-Alka is a project with setup instructions for running a DAST (Dynamic Application Security Testing) AI tool integration.

The README provides two main setup steps:

Start the ZAP daemon: Navigate to the Zap directory on C drive and run zap.bat -daemon -port 8080 -config api.disablekey=true -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true

Start the application services: Run two commands in VS terminal:

uvicorn zap-ai-dast:app --reload (starts a Python API server)
streamlit run ui.py (starts a Streamlit UI)

The project is a combination of OWASP ZAP (security scanning tool) with an AI component and a web-based user interface.
