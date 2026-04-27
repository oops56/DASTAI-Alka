from fastapi import FastAPI
from pydantic import BaseModel
import requests, time, uuid, json, csv
from collections import defaultdict

app = FastAPI()

ZAP = "http://127.0.0.1:8080"
AI_URL = "http://127.0.0.1:11434/api/generate"  # TinyLlama via Ollama (example)

scans = {}

# ---------------- REQUEST ----------------
class ScanRequest(BaseModel):
    target: str

# ---------------- ZAP ----------------
def zap_get(path, params=None):
    try:
        r = requests.get(f"{ZAP}{path}", params=params, timeout=30)
        return r.json()
    except:
        return {}

def run_scan(target):
    zap_get("/JSON/core/action/accessUrl/", {"url": target})
    time.sleep(2)

    spider = zap_get("/JSON/spider/action/scan/", {"url": target}).get("scan")

    while True:
        s = int(zap_get("/JSON/spider/view/status/", {"scanId": spider}).get("status", 0))
        if s >= 100: break
        time.sleep(1)

    ascan = zap_get("/JSON/ascan/action/scan/", {"url": target}).get("scan")

    while True:
        s = int(zap_get("/JSON/ascan/view/status/", {"scanId": ascan}).get("status", 0))
        if s >= 100: break
        time.sleep(2)

    alerts = zap_get("/JSON/core/view/alerts/").get("alerts", [])
    return alerts

# ---------------- AI (TinyLlama) ----------------
def ask_ai(prompt):
    try:
        r = requests.post(AI_URL, json={
            "model": "tinyllama",
            "prompt": prompt,
            "stream": False
        })
        return r.json().get("response", "")
    except:
        return "AI not available"

# ---------------- 1. AUTH ANALYSIS ----------------
def auth_analysis(alerts):
    auth_issues = [a for a in alerts if "401" in a.get("description","") or "403" in a.get("description","")]
    
    prompt = f"""
    Analyze authentication failures:
    {auth_issues}
    Detect patterns, session expiry issues, repeated failures.
    """

    ai = ask_ai(prompt)

    return {
        "count": len(auth_issues),
        "ai_analysis": ai
    }

# ---------------- 2. FALSE POSITIVE REDUCTION ----------------
def false_positive_analysis(alerts):
    grouped = defaultdict(list)

    for a in alerts:
        key = (a.get("alert"), a.get("risk"))
        grouped[key].append(a)

    prompt = f"""
    Group duplicate findings and identify false positives:
    {alerts}
    """

    ai = ask_ai(prompt)

    return {
        "groups": len(grouped),
        "ai_analysis": ai
    }

# ---------------- 3. PRIORITIZATION ----------------
def prioritize(alerts):
    prompt = f"""
    Rank findings by exploitability and impact.
    Map to OWASP Top 10.
    {alerts}
    """

    ai = ask_ai(prompt)

    return {"ai_prioritization": ai}

# ---------------- 4. SCAN OPTIMIZATION ----------------
def optimize(alerts):
    prompt = f"""
    Suggest scan optimizations, remove low value tests,
    reduce crawl scope.
    {alerts}
    """

    ai = ask_ai(prompt)

    return {"ai_optimization": ai}

# ---------------- EXPORT ----------------
def export_json(data, filename):
    with open(filename, "w") as f:
        json.dump(data, f)

def export_csv(alerts, filename):
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["alert", "risk", "url"])
        for a in alerts:
            writer.writerow([a.get("alert"), a.get("risk"), a.get("url")])

# ---------------- API ----------------
@app.post("/scan")
def scan(req: ScanRequest):
    sid = str(uuid.uuid4())

    alerts = run_scan(req.target)

    scans[sid] = {
        "alerts": alerts,
        "auth": auth_analysis(alerts),
        "fp": false_positive_analysis(alerts),
        "priority": prioritize(alerts),
        "opt": optimize(alerts)
    }

    export_json(scans[sid], f"{sid}.json")
    export_csv(alerts, f"{sid}.csv")

    return {"scan_id": sid}

@app.get("/result/{sid}")
def result(sid: str):
    return scans.get(sid, {})
