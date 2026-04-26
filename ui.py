from fastapi import FastAPI, UploadFile, File
from fastapi.responses import JSONResponse, FileResponse
import pandas as pd
import json
import os
import csv
import uuid
import time
import traceback
from threading import Thread

# ⚠️ ZAP is OPTIONAL now (prevents crash on Render)
try:
    from zapv2 import ZAPv2
    ZAP_AVAILABLE = True
except:
    ZAP_AVAILABLE = False

app = FastAPI(title="AI Security Pipeline")

# =========================
# CONFIG (SAFE FOR CLOUD)
# =========================
ZAP_PROXY = "http://127.0.0.1:8080"

zap = None
if ZAP_AVAILABLE:
    try:
        zap = ZAPv2(proxies={"http": ZAP_PROXY, "https": ZAP_PROXY})
    except:
        zap = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORT_DIR = os.path.join(BASE_DIR, "reports")
os.makedirs(REPORT_DIR, exist_ok=True)

scans = {}

# =========================
# HEALTH CHECK (FIXED)
# =========================
@app.get("/health")
def health():
    zap_ok = False

    try:
        if zap:
            zap.core.version
            zap_ok = True
    except:
        zap_ok = False

    return {
        "status": "running",
        "zap_connected": zap_ok,
        "zap_enabled": zap is not None
    }

# =========================
# HELPERS
# =========================
def ok(data):
    return JSONResponse({"status": "success", "data": data})

def fail(msg):
    return JSONResponse({"status": "error", "message": msg})

# =========================
# SAFE ALERT NORMALIZER (IMPORTANT FIX)
# =========================
def normalize_alerts(alerts_raw):
    alerts = []

    for a in alerts_raw or []:
        alerts.append({
            "alert": a.get("alert", "Unknown"),
            "risk": a.get("risk", "Low"),
            "url": a.get("url", ""),
            "confidence": a.get("confidence", "N/A")
        })

    return alerts

# =========================
# REPORT GENERATION (FIXED)
# =========================
def generate_reports(alerts):

    json_path = os.path.join(REPORT_DIR, "report.json")
    csv_path = os.path.join(REPORT_DIR, "report.csv")

    with open(json_path, "w") as f:
        json.dump({"alerts": alerts}, f, indent=2)

    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["alert", "risk", "url"])

        for a in alerts:
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
# SCAN WORKER (FIXED + SAFE)
# =========================
def scan_worker(scan_id, target):

    try:
        scans[scan_id]["status"] = "starting"
        scans[scan_id]["progress"] = 5

        # Validate URL
        if not target or not target.startswith("http"):
            raise Exception("Invalid URL")

        # =========================
        # IF ZAP NOT AVAILABLE → MOCK MODE
        # =========================
        if not zap:
            time.sleep(2)

            mock_alerts = [
                {
                    "alert": "SQL Injection (Mock)",
                    "risk": "High",
                    "url": target,
                    "confidence": "High"
                },
                {
                    "alert": "XSS (Mock)",
                    "risk": "Medium",
                    "url": target,
                    "confidence": "Medium"
                }
            ]

            scans[scan_id]["alerts"] = mock_alerts
            scans[scan_id]["status"] = "done"
            scans[scan_id]["progress"] = 100
            generate_reports(mock_alerts)
            return

        # =========================
        # REAL ZAP SCAN
        # =========================
        zap.core.access_url(target)
        time.sleep(2)

        # SPIDER
        scans[scan_id]["status"] = "spider"
        spider_id = zap.spider.scan(target)

        for _ in range(100):
            p = int(zap.spider.status(spider_id))
            scans[scan_id]["progress"] = min(p // 2, 40)

            if p >= 100:
                break
            time.sleep(2)

        # ACTIVE SCAN
        scans[scan_id]["status"] = "active"
        ascan_id = zap.ascan.scan(target)

        for _ in range(100):
            p = int(zap.ascan.status(ascan_id))
            scans[scan_id]["progress"] = 40 + min(p // 2, 60)

            if p >= 100:
                break
            time.sleep(3)

        # ALERTS
        alerts_raw = zap.core.alerts()
        alerts = normalize_alerts(alerts_raw)

        scans[scan_id]["alerts"] = alerts
        scans[scan_id]["status"] = "done"
        scans[scan_id]["progress"] = 100

        generate_reports(alerts)

    except Exception as e:
        scans[scan_id]["status"] = "error"
        scans[scan_id]["error"] = str(e)
        scans[scan_id]["trace"] = traceback.format_exc()

# =========================
# START SCAN
# =========================
@app.post("/start-scan")
def start_scan(target: str):

    scan_id = str(uuid.uuid4())

    scans[scan_id] = {
        "status": "queued",
        "progress": 0,
        "alerts": []
    }

    Thread(target=scan_worker, args=(scan_id, target), daemon=True).start()

    return ok({"scan_id": scan_id})

# =========================
# STATUS API
# =========================
@app.get("/scan-status/{scan_id}")
def scan_status(scan_id: str):
    return scans.get(scan_id, {"status": "not_found"})

# =========================
# FULL ANALYSIS (SAFE FIX)
# =========================
@app.post("/full-analysis")
async def full_analysis(file: UploadFile = File(...), target: str = ""):

    try:
        df = pd.read_csv(file.file).fillna("")

        findings = []

        text = str(df).lower()

        if any(x in text for x in ["select", "union", "drop"]):
            findings.append({"type": "SQL Injection", "severity": "high"})

        if any(x in text for x in ["<script>", "javascript"]):
            findings.append({"type": "XSS", "severity": "medium"})

        return ok({
            "findings": findings,
            "scan_count": len(findings)
        })

    except Exception as e:
        return fail(str(e))
