from fastapi import FastAPI
from fastapi.responses import JSONResponse, FileResponse
import uuid, time, os, json, requests
from threading import Thread

app = FastAPI()

# =========================
# CONFIG (Cloudflare URL)
# =========================
ZAP_API_URL = "https://vii-medline-companies-convenience.trycloudflare.com"

scans = {}

REPORT_DIR = "reports"
os.makedirs(REPORT_DIR, exist_ok=True)

# =========================
# CHECK ZAP
# =========================
def check_zap():
    try:
        r = requests.get(
            f"{ZAP_API_URL}/JSON/core/view/version/",
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=10,
            allow_redirects=True
        )
        return r.status_code == 200
    except Exception:
        return False

# =========================
# SAFE REQUEST FUNCTION
# =========================
def zap_get(endpoint, params=None):
    try:
        r = requests.get(
            f"{ZAP_API_URL}{endpoint}",
            params=params,
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=15,
            allow_redirects=True
        )
        return r.json()
    except Exception as e:
        return {"error": str(e)}

# =========================
# SCAN WORKER
# =========================
def run_scan(scan_id, target):

    try:
        if not check_zap():
            scans[scan_id] = {
                "status": "error",
                "error": f"ZAP not reachable at {ZAP_API_URL}"
            }
            return

        scans[scan_id] = {
            "status": "starting",
            "progress": 0,
            "alerts": []
        }

        # =========================
        # OPEN TARGET
        # =========================
        zap_get("/JSON/core/action/accessUrl/", {"url": target})
        time.sleep(2)

        # =========================
        # SPIDER
        # =========================
        scans[scan_id]["status"] = "spidering"

        spider = zap_get("/JSON/spider/action/scan/", {"url": target})
        spider_id = spider.get("scan")

        while True:
            status = zap_get("/JSON/spider/view/status/", {"scanId": spider_id})
            progress = int(status.get("status", 0))

            scans[scan_id]["progress"] = progress

            if progress >= 100:
                break
            time.sleep(2)

        # =========================
        # ACTIVE SCAN
        # =========================
        scans[scan_id]["status"] = "scanning"

        ascan = zap_get("/JSON/ascan/action/scan/", {"url": target})
        ascan_id = ascan.get("scan")

        while True:
            status = zap_get("/JSON/ascan/view/status/", {"scanId": ascan_id})
            progress = int(status.get("status", 0))

            scans[scan_id]["progress"] = progress

            if progress >= 100:
                break
            time.sleep(3)

        # =========================
        # GET ALERTS
        # =========================
        alerts_data = zap_get("/JSON/core/view/alerts/")
        alerts_raw = alerts_data.get("alerts", [])

        alerts = [
            {
                "alert": a.get("alert", ""),
                "risk": a.get("risk", ""),
                "url": a.get("url", "")
            }
            for a in alerts_raw
        ]

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
# ROUTES
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

@app.post("/start-scan")
def start_scan(target: str):

    scan_id = str(uuid.uuid4())

    scans[scan_id] = {
        "status": "queued",
        "progress": 0
    }

    Thread(target=run_scan, args=(scan_id, target), daemon=True).start()

    return {
        "status": "success",
        "scan_id": scan_id
    }

@app.get("/scan-status/{scan_id}")
def scan_status(scan_id: str):
    return scans.get(scan_id, {"status": "not_found"})

@app.get("/download/json")
def download_json():

    path = f"{REPORT_DIR}/report.json"

    if not os.path.exists(path):
        return {"error": "No report found"}

    return FileResponse(path)
