from fastapi import FastAPI, UploadFile, File
from fastapi.responses import JSONResponse, FileResponse
import pandas as pd
import requests
import json
import os
import csv
import uuid
import time
import traceback
from threading import Thread

from zapv2 import ZAPv2

app = FastAPI(title="AI Security Pipeline")

# =========================
# CONFIG
# =========================
ZAP_PROXY = "http://127.0.0.1:8080"

zap = ZAPv2(proxies={
    "http": ZAP_PROXY,
    "https": ZAP_PROXY
})

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORT_DIR = os.path.join(BASE_DIR, "reports")
os.makedirs(REPORT_DIR, exist_ok=True)

scans = {}

# =========================
# HEALTH
# =========================
@app.get("/health")
def health():
    try:
        zap.core.version
        zap_ok = True
    except:
        zap_ok = False

    return {
        "status": "running",
        "zap_connected": zap_ok
    }

# =========================
# HELPERS
# =========================
def ok(data):
    return JSONResponse({"status": "success", "data": data})

def fail(msg):
    return JSONResponse({"status": "error", "message": msg})

# =========================
# REPORTS
# =========================
def generate_reports(data):
    json_path = os.path.join(REPORT_DIR, "report.json")
    csv_path = os.path.join(REPORT_DIR, "report.csv")

    with open(json_path, "w") as f:
        json.dump(data, f, indent=2)

    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["alert", "risk", "url"])

        for a in data.get("alerts", []):
            writer.writerow([
                a.get("alert"),
                a.get("risk"),
                a.get("url")
            ])

# =========================
# DOWNLOAD
# =========================
@app.get("/download/{file_type}")
def download(file_type: str):

    mapping = {
        "json": "report.json",
        "csv": "report.csv"
    }

    file_name = mapping.get(file_type)

    if not file_name:
        return fail("Invalid type")

    path = os.path.join(REPORT_DIR, file_name)

    if not os.path.exists(path):
        return fail("File not found")

    return FileResponse(path)

# =========================
# SCAN WORKER (FIXED)
# =========================
def scan_worker(scan_id, target):

    try:
        scans[scan_id]["status"] = "starting"
        scans[scan_id]["progress"] = 5

        if not target.startswith("http"):
            raise Exception("Invalid URL")

        # open target
        zap.core.access_url(target)
        time.sleep(2)

        # =====================
        # SPIDER
        # =====================
        scans[scan_id]["status"] = "spider"
        spider_id = zap.spider.scan(target)

        while True:
            p = int(zap.spider.status(spider_id))
            scans[scan_id]["progress"] = min(p // 2, 50)

            if p >= 100:
                break

            time.sleep(2)

        # =====================
        # ACTIVE SCAN
        # =====================
        scans[scan_id]["status"] = "active"
        ascan_id = zap.ascan.scan(target)

        while True:
            p = int(zap.ascan.status(ascan_id))
            scans[scan_id]["progress"] = 50 + min(p // 2, 50)

            if p >= 100:
                break

            time.sleep(3)

        alerts = zap.core.alerts()

        scans[scan_id]["alerts"] = alerts
        scans[scan_id]["status"] = "done"
        scans[scan_id]["progress"] = 100

        generate_reports({"alerts": alerts})

    except Exception as e:
        scans[scan_id]["status"] = "error"
        scans[scan_id]["error"] = str(e)
        print("SCAN ERROR:", traceback.format_exc())

# =========================
# START SCAN
# =========================
@app.post("/start-scan")
def start_scan(target: str):

    try:
        scan_id = str(uuid.uuid4())

        scans[scan_id] = {
            "status": "queued",
            "progress": 0,
            "alerts": []
        }

        Thread(target=scan_worker, args=(scan_id, target), daemon=True).start()

        return ok({"scan_id": scan_id})

    except Exception as e:
        return fail(str(e))

# =========================
# STATUS
# =========================
@app.get("/scan-status/{scan_id}")
def scan_status(scan_id: str):
    return scans.get(scan_id, {"status": "not_found"})

# =========================
# FULL ANALYSIS (optional)
# =========================
@app.post("/full-analysis")
async def full_analysis(file: UploadFile = File(...), target: str = ""):
    try:
        df = pd.read_csv(file.file).fillna("")

        findings = []

        if "select" in str(df).lower():
            findings.append({
                "type": "SQL Injection",
                "severity": "high"
            })

        return ok({
            "findings": findings,
            "scan_count": 0
        })

    except Exception as e:
        return fail(str(e))
