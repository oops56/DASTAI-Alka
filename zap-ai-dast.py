from fastapi import FastAPI
from pydantic import BaseModel
import requests
import time
import uuid
import json
from collections import defaultdict

app = FastAPI()

ZAP = "http://127.0.0.1:8090"

# ---------------- STORAGE ----------------
DB = {}

# ---------------- REQUEST ----------------
class ScanRequest(BaseModel):
    target: str

# ---------------- SAFE REQUEST ----------------
def zap(path, params=None):
    try:
        r = requests.get(ZAP + path, params=params, timeout=30)
        print("➡️", r.url)
        print("⬅️", r.text)
        return r.json()
    except Exception as e:
        print("❌ ZAP ERROR:", e)
        return {}

# ---------------- CHECK ZAP ----------------
def check_zap():
    try:
        r = requests.get(ZAP + "/JSON/core/view/version/", timeout=5)
        return r.status_code == 200
    except:
        return False

# ---------------- SEED TARGET ----------------
def seed(target):
    zap("/JSON/core/action/accessUrl/", {"url": target, "followRedirects": True})
    time.sleep(2)

    for _ in range(10):
        urls = zap("/JSON/core/view/urls/")
        if urls.get("urls"):
            return True
        time.sleep(1)

    return False

# ---------------- SPIDER ----------------
def spider(target):
    r = zap("/JSON/spider/action/scan/", {"url": target})
    sid = r.get("scan")

    if not sid:
        return None

    while True:
        status = zap("/JSON/spider/view/status/", {"scanId": sid})
        if int(status.get("status", 0)) >= 100:
            break
        time.sleep(2)

    return True

# ---------------- AJAX SPIDER FALLBACK ----------------
def ajax_spider(target):
    zap("/JSON/ajaxSpider/action/scan/", {"url": target})

    for _ in range(20):
        s = zap("/JSON/ajaxSpider/view/status/")
        if s.get("status") == "stopped":
            return True
        time.sleep(2)

    return False

# ---------------- ACTIVE SCAN ----------------
def active_scan(target):
    r = zap("/JSON/ascan/action/scan/", {
        "url": target,
        "recurse": True,
        "inScopeOnly": False
    })

    sid = r.get("scan")
    if not sid:
        return []

    while True:
        s = zap("/JSON/ascan/view/status/", {"scanId": sid})
        if int(s.get("status", 0)) >= 100:
            break
        time.sleep(3)

    return True

# ---------------- FINDINGS ----------------
def get_alerts():
    return zap("/JSON/core/view/alerts/").get("alerts", [])

# ---------------- AI PLACEHOLDER ----------------
def ai_process(alerts):
    grouped = defaultdict(list)

    for a in alerts:
        grouped[a.get("alert")].append(a)

    return {
        "total": len(alerts),
        "groups": len(grouped),
        "note": "AI layer placeholder (TinyLlama can be plugged here)"
    }

# ---------------- FULL SCAN PIPELINE ----------------
def run_scan(target):
    print("🚀 Scan started:", target)

    if not check_zap():
        return {"error": "ZAP not running"}

    if not target.startswith("http"):
        target = "http://" + target

    # STEP 1: seed
    if not seed(target):
        return {"error": "No URLs discovered"}

    # STEP 2: spider
    spider_ok = spider(target)

    # STEP 3: fallback if needed
    urls = zap("/JSON/core/view/urls/")
    if not urls.get("urls"):
        print("⚠️ Spider failed → running AJAX spider")
        ajax_spider(target)

    # STEP 4: check again
    urls = zap("/JSON/core/view/urls/")
    if not urls.get("urls"):
        return {"error": "Still no URLs after crawling"}

    # STEP 5: active scan
    active_scan(target)

    # STEP 6: results
    alerts = get_alerts()

    result = {
        "alerts": alerts,
        "ai": ai_process(alerts)
    }

    return result

# ---------------- API ----------------
@app.post("/scan")
def scan(req: ScanRequest):
    sid = str(uuid.uuid4())
    result = run_scan(req.target)
    DB[sid] = result
    return {"scan_id": sid}

@app.get("/result/{sid}")
def result(sid: str):
    return DB.get(sid, {"error": "not found"})
