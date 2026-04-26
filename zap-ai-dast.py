from fastapi import FastAPI
from fastapi.responses import JSONResponse, FileResponse
from zapv2 import ZAPv2
import uuid, time, os, json
from threading import Thread

app = FastAPI()

# =========================
# IMPORTANT: ZAP MUST BE LOCAL
# =========================
ZAP_PROXY = "http://127.0.0.1:8090"

scans = {}

REPORT_DIR = "reports"
os.makedirs(REPORT_DIR, exist_ok=True)

# =========================
# SAFE SCAN WORKER
# =========================
def run_scan(scan_id, target):

    try:
        zap = ZAPv2(
            apikey="",
            proxies={
                "http": ZAP_PROXY,
                "https": ZAP_PROXY
            }
        )

        scans[scan_id] = {
            "status": "starting",
            "progress": 5,
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
        # GET ALERTS (SAFE PARSING)
        # =========================
        try:
            alerts_raw = zap.core.alerts()
        except:
            alerts_raw = []

        alerts = []

        for a in alerts_raw:
            try:
                alerts.append({
                    "alert": a.get("alert", ""),
                    "risk": a.get("risk", ""),
                    "url": a.get("url", "")
                })
            except:
                continue

        # =========================
        # FINAL RESULT
        # =========================
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
# HEALTH CHECK
# =========================
@app.get("/")
def home():
    return {"status": "running"}

@app.get("/health")
def health():
    return {"status": "ok"}

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

    Thread(target=run_scan, args=(scan_id, target), daemon=True).start()

    return JSONResponse({
        "status": "success",
        "data": {"scan_id": scan_id}
    })

# =========================
# SCAN STATUS
# =========================
@app.get("/scan-status/{scan_id}")
def scan_status(scan_id: str):
    return scans.get(scan_id, {"status": "not_found"})

# =========================
# DOWNLOAD REPORT
# =========================
@app.get("/download/json")
def download_json():

    path = f"{REPORT_DIR}/report.json"

    if not os.path.exists(path):
        return {"error": "No report found"}

    return FileResponse(path)
