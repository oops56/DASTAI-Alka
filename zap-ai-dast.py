from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
import requests
import sqlite3
import time
import uuid
from datetime import datetime

app = FastAPI()

ZAP = "http://127.0.0.1:8090"

# ---------------- DB ----------------
conn = sqlite3.connect("scans.db", check_same_thread=False)
cur = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS scans (
    id TEXT,
    target TEXT,
    status TEXT,
    progress INTEGER,
    created TEXT
)
""")
conn.commit()

# ---------------- REQUEST ----------------
class ScanRequest(BaseModel):
    target: str

# ---------------- ZAP CORE ----------------
def zap_get(url, params=None):
    try:
        return requests.get(url, params=params, timeout=20).json()
    except Exception as e:
        print("ZAP ERROR:", e)
        return {}

# ---------------- REQUIRED STEP (CRITICAL) ----------------
def access_url(target):
    zap_get(f"{ZAP}/JSON/core/action/accessUrl/", {
        "url": target,
        "followRedirects": True
    })
    time.sleep(3)

# ---------------- SPIDER ----------------
def spider(target):
    return zap_get(f"{ZAP}/JSON/spider/action/scan/", {
        "url": target
    }).get("scan")

def spider_status(scan_id):
    return int(zap_get(
        f"{ZAP}/JSON/spider/view/status/",
        {"scanId": scan_id}
    ).get("status", 0))

# ---------------- ACTIVE SCAN ----------------
def active_scan(target):
    return zap_get(f"{ZAP}/JSON/ascan/action/scan/", {
        "url": target,
        "recurse": True
    }).get("scan")

def active_status(scan_id):
    return int(zap_get(
        f"{ZAP}/JSON/ascan/view/status/",
        {"scanId": scan_id}
    ).get("status", 0))

# ---------------- BACKGROUND JOB ----------------
def run_scan(scan_id, target):

    print("🚀 Scan started:", target)

    # STEP 1: MUST ACCESS URL
    access_url(target)

    # STEP 2: SPIDER
    spider_id = spider(target)
    if not spider_id:
        cur.execute("UPDATE scans SET status=? WHERE id=?", ("spider_failed", scan_id))
        conn.commit()
        return

    while True:
        p = spider_status(spider_id)
        cur.execute("UPDATE scans SET progress=?, status=? WHERE id=?",
                    (p // 2, "spidering", scan_id))
        conn.commit()

        if p >= 100:
            break

        time.sleep(2)

    # STEP 3: ACTIVE SCAN
    scan_id_zap = active_scan(target)
    if not scan_id_zap:
        cur.execute("UPDATE scans SET status=? WHERE id=?", ("scan_failed", scan_id))
        conn.commit()
        return

    while True:
        p = active_status(scan_id_zap)
        cur.execute("UPDATE scans SET progress=?, status=? WHERE id=?",
                    (50 + p // 2, "scanning", scan_id))
        conn.commit()

        if p >= 100:
            break

        time.sleep(2)

    # STEP 4: DONE
    cur.execute("UPDATE scans SET status=?, progress=? WHERE id=?",
                ("done", 100, scan_id))
    conn.commit()

    print("✅ Scan completed")

# ---------------- API ----------------
@app.post("/start-scan")
def start_scan(req: ScanRequest, bg: BackgroundTasks):

    sid = str(uuid.uuid4())

    cur.execute("""
        INSERT INTO scans VALUES (?,?,?, ?,?)
    """, (sid, req.target, "starting", 0, datetime.now().isoformat()))
    conn.commit()

    bg.add_task(run_scan, sid, req.target)

    return {"scan_id": sid}

@app.get("/status/{scan_id}")
def status(scan_id: str):

    cur.execute("SELECT * FROM scans WHERE id=?", (scan_id,))
    row = cur.fetchone()

    if not row:
        return {"error": "not found"}

    return {
        "id": row[0],
        "target": row[1],
        "status": row[2],
        "progress": row[3]
    }
