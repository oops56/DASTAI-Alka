from fastapi import FastAPI
import requests, uuid, time, os, json, traceback
from threading import Thread

app = FastAPI()

# 🔥 CHANGE THIS to your ZAP endpoint
ZAP_API_URL = "https://candle-main-flags-total.trycloudflare.com"

scans = {}
REPORT_DIR = "reports"
os.makedirs(REPORT_DIR, exist_ok=True)

# =========================
# SAFE REQUEST TO ZAP
# =========================
def zap_get(endpoint, params=None):
    r = requests.get(f"{ZAP_API_URL}{endpoint}", params=params)

    if "<!DOCTYPE html>" in r.text:
        raise Exception(
            "Cloudflare returned HTML instead of ZAP API. "
            "Tunnel is misrouting requests."
        )

    return r.json()

# =========================
# SCAN WORKER
# =========================
def run_scan(scan_id, target):

    try:
        scans[scan_id] = {"status": "starting", "progress": 0}

        # open target
        zap_get("/JSON/core/action/accessUrl/", {"url": target})
        time.sleep(2)

        # spider
        scans[scan_id]["status"] = "spidering"
        spider = zap_get("/JSON/spider/action/scan/", {"url": target})
        spider_id = spider.get("scan")

        if not spider_id:
            raise Exception(f"Spider failed: {spider}")

        while True:
            status = zap_get("/JSON/spider/view/status/", {"scanId": spider_id})
            progress = int(status.get("status", 0))
            scans[scan_id]["progress"] = progress
            if progress >= 100:
                break
            time.sleep(2)

        # active scan
        scans[scan_id]["status"] = "scanning"
        ascan = zap_get("/JSON/ascan/action/scan/", {"url": target})
        ascan_id = ascan.get("scan")

        if not ascan_id:
            raise Exception(f"Active scan failed: {ascan}")

        while True:
            status = zap_get("/JSON/ascan/view/status/", {"scanId": ascan_id})
            progress = int(status.get("status", 0))
            scans[scan_id]["progress"] = progress
            if progress >= 100:
                break
            time.sleep(3)

        # alerts
        alerts_data = zap_get("/JSON/core/view/alerts/")
        alerts = alerts_data.get("alerts", [])

        result = {
            "status": "done",
            "progress": 100,
            "alerts": alerts
        }

        scans[scan_id] = result

        with open(f"{REPORT_DIR}/report.json", "w") as f:
            json.dump(result, f, indent=2)

    except Exception as e:
        scans[scan_id] = {
            "status": "error",
            "error": str(e),
            "trace": traceback.format_exc()
        }

# =========================
# API ROUTES
# =========================

@app.get("/")
def home():
    return {"status": "running"}

@app.post("/start-scan")
def start_scan(target: str):
    scan_id = str(uuid.uuid4())
    scans[scan_id] = {"status": "queued", "progress": 0}

    Thread(target=run_scan, args=(scan_id, target), daemon=True).start()

    return {"scan_id": scan_id}

@app.get("/scan/{scan_id}")
def scan_status(scan_id: str):
    return scans.get(scan_id, {"status": "not_found"})
