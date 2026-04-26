from fastapi import FastAPI
from fastapi.responses import JSONResponse, FileResponse
from zapv2 import ZAPv2
import uuid, time, os, json, csv
from threading import Thread

app = FastAPI()

ZAP_PROXY = "https://speech-morris-warriors-colony.trycloudflare.com/"

scans = {}

REPORT_DIR = "reports"
os.makedirs(REPORT_DIR, exist_ok=True)

# -------------------
def run_scan(scan_id, target):

    try:
        zap = ZAPv2(
            apikey="",
            proxies={
                "http": ZAP_PROXY,
                "https": ZAP_PROXY
            }
        )

        scans[scan_id]["status"] = "starting"

        zap.urlopen(target)
        time.sleep(2)

        scans[scan_id]["status"] = "spidering"
        spider_id = zap.spider.scan(target)

        while int(zap.spider.status(spider_id)) < 100:
            scans[scan_id]["progress"] = int(zap.spider.status(spider_id))
            time.sleep(2)

        scans[scan_id]["status"] = "scanning"
        ascan_id = zap.ascan.scan(target)

        while int(zap.ascan.status(ascan_id)) < 100:
            scans[scan_id]["progress"] = int(zap.ascan.status(ascan_id))
            time.sleep(3)

        alerts_raw = zap.core.alerts()

        alerts = [
            {
                "alert": a["alert"],
                "risk": a["risk"],
                "url": a["url"]
            }
            for a in alerts_raw
        ]

        scans[scan_id] = {
            "status": "done",
            "progress": 100,
            "alerts": alerts
        }

        # save report
        with open(f"{REPORT_DIR}/report.json", "w") as f:
            json.dump(alerts, f, indent=2)

    except Exception as e:
        scans[scan_id]["status"] = "error"
        scans[scan_id]["error"] = str(e)

# -------------------
@app.get("/")
def home():
    return {
        "status": "running",
        "message": "API is working on Render"
    }

@app.get("/health")
def health():
    return {"status": "ok"}
@app.post("/start-scan")
def start_scan(target: str):

    scan_id = str(uuid.uuid4())

    scans[scan_id] = {
        "status": "queued",
        "progress": 0
    }

    Thread(target=run_scan, args=(scan_id, target)).start()

    return {"status": "success", "data": {"scan_id": scan_id}}

# -------------------
@app.get("/scan-status/{scan_id}")
def status(scan_id: str):
    return scans.get(scan_id, {"status": "not_found"})

# -------------------
@app.get("/download/json")
def download():
    return FileResponse(f"{REPORT_DIR}/report.json")
