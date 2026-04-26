from fastapi import FastAPI
from fastapi.responses import JSONResponse, FileResponse
from zapv2 import ZAPv2
import uuid, time, os, json, requests
from threading import Thread

app = FastAPI()

# =========================
# CONFIG (FIXED FOR DOCKER/WSL)
# =========================

# Use ONE of these depending on your setup:

# LOCAL MACHINE
# ZAP_PROXY = "http://127.0.0.1:8090"

# DOCKER / WSL SAFE OPTION
ZAP_PROXY = "http://host.docker.internal:8090"

# =========================
# GLOBAL STATE
# =========================
scans = {}

REPORT_DIR = "reports"
os.makedirs(REPORT_DIR, exist_ok=True)

# =========================
# CHECK ZAP IS RUNNING
# =========================
def check_zap():
    try:
        r = requests.get(f"{ZAP_PROXY}/JSON/core/view/version/", timeout=5)
        return r.status_code == 200
    except:
        return False

# =========================
# SCAN WORKER
# =========================
def run_scan(scan_id, target):

    try:
        # 🔥 CHECK BEFORE STARTING
        if not check_zap():
            scans[scan_id] = {
                "status": "error",
                "error": "ZAP not reachable on " + ZAP_PROXY
            }
            return

        zap = ZAPv2(
            apikey="",
            proxies={
                "http": ZAP_PROXY,
                "https": ZAP_PROXY
            }
        )

        scans[scan_id] = {
            "status": "starting",
            "progress": 0,
            "alerts": []
        }

        # =========================
        # OPEN TARGET
        # =========================
        zap.urlopen(target)
        time.sleep(2)

        # =========================
        # SPIDER
        # =========================
        scans[scan_id]["status"] = "spidering"
        spider_id = zap.spider.scan(target)

        while True:
            try:
                progress = int(zap.spider.status(spider_id))
            except:
                progress = 0

            scans[scan_id]["progress"] = progress
            if progress >= 100:
                break
            time.sleep(2)

        # =========================
        # ACTIVE SCAN
        # =========================
        scans[scan_id]["status"] = "scanning"
        ascan_id = zap.ascan.scan(target)

        while True:
            try:
                progress = int(zap.ascan.status(ascan_id))
            except:
                progress = 0

            scans[scan_id]["progress"] = progress
            if progress >= 100:
                break
            time.sleep(3)

        # =========================
        # ALERTS (SAFE)
        # =========================
        try:
            alerts_raw = zap.core.alerts()
        except:
            alerts_raw = []

        alerts = []

        for a in alerts_raw:
            alerts.append({
                "alert": a.get("alert", ""),
                "risk": a.get("risk", ""),
                "url": a.get("url", "")
            })

        result = {
            "status": "done",
            "progress": 100,
            "alerts": alerts
        }

        scans[scan_id] = result

        # =========================
        # SAVE REPORT
        # =========================
        with open(f"{REPORT_DIR}/report.json", "w") as f:
            json.dump(result, f, indent=2)

    except Exception as e:
        scans[scan_id] = {
            "status": "error",
            "error": str(e)
        }

# =========================
# API ROUTES
# =========================

@app.get("/")
def home():
    return {"status": "running"}

@app.get("/health")
def health():
    return {
        "status": "ok",
        "zap_connected": check_zap()
    }

# -------------------------
@app.post("/start-scan")
def start_scan(target: str):

    scan_id = str(uuid.uuid4())

    scans[scan_id] = {
        "status": "queued",
        "progress": 0
    }

    Thread(target=run_scan, args=(scan_id, target), daemon=True).start()

    return JSONResponse({
        "status": "success",
        "data": {"scan_id": scan_id}
    })

# -------------------------
@app.get("/scan-status/{scan_id}")
def scan_status(scan_id: str):
    return scans.get(scan_id, {"status": "not_found"})

# -------------------------
@app.get("/download/json")
def download_json():

    path = f"{REPORT_DIR}/report.json"

    if not os.path.exists(path):
        return {"error": "No report found"}

    return FileResponse(path)
