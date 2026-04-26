from fastapi import FastAPI
from fastapi.responses import JSONResponse, FileResponse
import uuid, time, os, json, requests, traceback
from threading import Thread

app = FastAPI()

# =========================
# CONFIG
# =========================
ZAP_API_URL = "https://your-cloudflare-url.trycloudflare.com"

scans = {}

REPORT_DIR = "reports"
os.makedirs(REPORT_DIR, exist_ok=True)

# =========================
# SAFE REQUEST (VERY IMPORTANT)
# =========================
def zap_get(endpoint, params=None):
    try:
        r = requests.get(
            f"{ZAP_API_URL}{endpoint}",
            params=params,
            timeout=20,
            headers={"User-Agent": "Mozilla/5.0"},
            allow_redirects=True
        )

        # DEBUG: print raw response
        print("URL:", r.url)
        print("STATUS:", r.status_code)
        print("TEXT:", r.text[:300])

        if not r.text.strip():
            return {"error": "empty_response"}

        try:
            return r.json()
        except Exception:
            return {"error": "not_json", "raw": r.text[:300]}

    except Exception as e:
        return {"error": str(e)}

# =========================
# CHECK ZAP
# =========================
def check_zap():
    res = zap_get("/JSON/core/view/version/")
    return "version" in str(res)

# =========================
# SCAN WORKER
# =========================
def run_scan(scan_id, target):

    try:
        scans[scan_id] = {
            "status": "starting",
            "progress": 0,
            "alerts": []
        }

        # =========================
        # TEST CONNECTIVITY
        # =========================
        version = zap_get("/JSON/core/view/version/")
        if "error" in version:
            raise Exception(f"ZAP not reachable: {version}")

        # =========================
        # ACCESS TARGET
        # =========================
        zap_get("/JSON/core/action/accessUrl/", {"url": target})
        time.sleep(2)

        # =========================
        # SPIDER
        # =========================
        scans[scan_id]["status"] = "spidering"

        spider = zap_get("/JSON/spider/action/scan/", {"url": target})

        print("SPIDER RESPONSE:", spider)

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

        # =========================
        # ACTIVE SCAN
        # =========================
        scans[scan_id]["status"] = "scanning"

        ascan = zap_get("/JSON/ascan/action/scan/", {"url": target})

        print("ASCAN RESPONSE:", ascan)

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

        # =========================
        # ALERTS
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

        # SAVE REPORT
        with open(f"{REPORT_DIR}/report.json", "w") as f:
            json.dump(result, f, indent=2)

    except Exception as e:
        scans[scan_id] = {
            "status": "error",
            "error": str(e),
            "trace": traceback.format_exc()
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

    return {"scan_id": scan_id}

@app.get("/scan-status/{scan_id}")
def scan_status(scan_id: str):
    return scans.get(scan_id, {"status": "not_found"})

@app.get("/download/json")
def download():
    path = f"{REPORT_DIR}/report.json"

    if not os.path.exists(path):
        return {"error": "No report found"}

    return FileResponse(path)
