from fastapi import FastAPI
from fastapi.responses import JSONResponse, FileResponse
import uuid, time, os, json, requests
from threading import Thread

app = FastAPI()

# =========================
# CONFIG
# =========================
ZAP_API_URL = "https://vii-medline-companies-convenience.trycloudflare.com"

scans = {}

def zap(endpoint, params=None):
    try:
        r = requests.get(
            f"{ZAP_API_URL}{endpoint}",
            params=params,
            timeout=15,
            headers={"User-Agent": "Mozilla/5.0"},
            allow_redirects=True
        )
        return r.json()
    except:
        return {}

def run_scan(scan_id, target):

    scans[scan_id] = {"status": "starting", "progress": 0}

    zap("/JSON/core/action/accessUrl/", {"url": target})
    time.sleep(2)

    spider = zap("/JSON/spider/action/scan/", {"url": target})
    spider_id = spider.get("scan")

    for _ in range(60):
        status = zap("/JSON/spider/view/status/", {"scanId": spider_id})
        progress = int(status.get("status", 0))
        scans[scan_id]["progress"] = progress
        if progress >= 100:
            break
        time.sleep(2)

    scans[scan_id] = {"status": "done", "progress": 100}

@app.post("/start-scan")
def start_scan(target: str):
    scan_id = str(uuid.uuid4())
    Thread(target=run_scan, args=(scan_id, target), daemon=True).start()
    return {"scan_id": scan_id}

@app.get("/status/{scan_id}")
def status(scan_id: str):
    return scans.get(scan_id, {})
