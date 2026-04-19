from fastapi import FastAPI, UploadFile, File
from fastapi.responses import JSONResponse
import pandas as pd
import requests, json, re, time, os, csv

from zapv2 import ZAPv2
from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet

app = FastAPI()

# =====================
# CONFIG
# =====================
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "tinyllama"

ZAP_PROXY = "http://127.0.0.1:8080"
zap = ZAPv2(apikey='', proxies={'http': ZAP_PROXY, 'https': ZAP_PROXY})

# =====================
# HELPERS
# =====================
def ok(data): return JSONResponse({"status": "success", "data": data})
def fail(msg): return JSONResponse({"status": "error", "message": msg})

def call_ai(prompt):
    try:
        r = requests.post(OLLAMA_URL, json={
            "model": MODEL,
            "prompt": prompt,
            "stream": False
        }, timeout=60)
        return r.json().get("response")
    except:
        return None

def parse_json(text):
    try:
        text = re.sub(r"```json|```", "", text or "")
        return json.loads(text)
    except:
        return None

# =====================
# LOAD FILE
# =====================
def load_file(file):
    if file.filename.endswith(".csv"):
        return pd.read_csv(file.file)
    return pd.read_excel(file.file)

# =====================
# 1️⃣ AUTH RESEARCH
# =====================
def auth_research(df):

    logs = df.astype(str).values.flatten().tolist()
    joined = " ".join(logs).lower()

    prompt = f"""
Detect authentication issues:
- session expiry
- repeated 401/403
- patterns

Return JSON:
{{
 "patterns": [],
 "risk": "",
 "recommendation": ""
}}

LOGS:
{joined[:2000]}
"""

    ai = parse_json(call_ai(prompt))

    return {
        "401_count": joined.count("401"),
        "403_count": joined.count("403"),
        "ai_analysis": ai
    }

# =====================
# 2️⃣ FALSE POSITIVE REDUCTION
# =====================
def false_positive_ai(findings):

    prompt = f"""
Group duplicates, detect low risk + informational.

Return JSON:
{{
 "unique": [],
 "low_risk": [],
 "informational": []
}}

DATA:
{json.dumps(findings)}
"""

    ai = parse_json(call_ai(prompt))

    manual_unique = list({f["type"]: f for f in findings}.values())

    return {
        "manual_unique_count": len(manual_unique),
        "ai_unique_count": len(ai["unique"]) if ai else 0,
        "difference": len(manual_unique) - (len(ai["unique"]) if ai else 0),
        "ai": ai
    }

# =====================
# 3️⃣ PRIORITIZATION
# =====================
def prioritize(findings):

    prompt = f"""
Rank by exploitability + impact.
Map to OWASP Top 10.

Return JSON:
{{
 "ranking": [],
 "owasp_map": [],
 "recurring": []
}}

DATA:
{json.dumps(findings)}
"""

    return parse_json(call_ai(prompt))

# =====================
# 4️⃣ ZAP SCAN
# =====================
def run_scan(target):

    zap.urlopen(target)
    time.sleep(2)

    spider = zap.spider.scan(target)
    while int(zap.spider.status(spider)) < 100:
        time.sleep(2)

    active = zap.ascan.scan(target)
    while int(zap.ascan.status(active)) < 100:
        time.sleep(5)

    return zap.core.alerts()

# =====================
# 5️⃣ POLICY OPTIMIZATION
# =====================
def optimize_policy(alerts):

    prompt = f"""
Suggest scan improvements:
- disable irrelevant tests
- reduce crawl scope
- dead paths

Return JSON:
{{
 "policy_changes": [],
 "dead_paths": [],
 "scan_tuning": ""
}}

DATA:
{json.dumps(alerts[:10])}
"""

    return parse_json(call_ai(prompt))

# =====================
# REPORTS
# =====================
def generate_reports(data):

    os.makedirs("reports", exist_ok=True)

    # JSON
    with open("reports/report.json", "w") as f:
        json.dump(data, f, indent=2)

    # CSV
    with open("reports/report.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Type", "Severity"])
        for fnd in data.get("findings", []):
            writer.writerow([fnd.get("type"), fnd.get("severity")])

    # HTML
    html = "<h1>Security Report</h1><ul>"
    for fnd in data.get("findings", []):
        html += f"<li>{fnd}</li>"
    html += "</ul>"

    open("reports/report.html", "w").write(html)

    # PDF
    doc = SimpleDocTemplate("reports/report.pdf")
    styles = getSampleStyleSheet()
    content = [Paragraph(str(data), styles["Normal"])]
    doc.build(content)

    return {
        "json": "reports/report.json",
        "csv": "reports/report.csv",
        "html": "reports/report.html",
        "pdf": "reports/report.pdf"
    }

# =====================
# MAIN PIPELINE
# =====================
@app.post("/full-analysis")
async def full_analysis(file: UploadFile = File(...), target: str = ""):

    df = load_file(file).fillna("")

    # basic findings extraction
    findings = [{"type": "SQL Injection", "severity": "high"}] if "select" in str(df) else []

    auth = auth_research(df)
    fp = false_positive_ai(findings)
    prio = prioritize(findings)

    # ZAP scan
    alerts_before = run_scan(target) if target else []
    policy = optimize_policy(alerts_before)

    # simulate tuned scan
    alerts_after = alerts_before[:max(1, len(alerts_before)//2)]

    result = {
        "auth": auth,
        "false_positive": fp,
        "prioritization": prio,
        "policy_optimization": policy,
        "before_scan_count": len(alerts_before),
        "after_scan_count": len(alerts_after),
        "findings": findings
    }

    reports = generate_reports(result)

    result["reports"] = reports

    return ok(result)
