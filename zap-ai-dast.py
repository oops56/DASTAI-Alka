from fastapi import FastAPI, BackgroundTasks
import requests
import sqlite3
import uuid
import time
from datetime import datetime

app = FastAPI()

ZAP_URL = "http://127.0.0.1:8090"

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

# ---------------- SAFE CALL ----------------
def zap(url, params=None):
    try:
        r = requests.get(url, params=params, timeout=20)
        return r.json()
    except Exception as e:
        print("ZAP ERROR:", e)
        return {}

# ---------------- STEP 1: ACCESS URL (CRITICAL) ----------------
def access_url(target):
    zap(f"{ZAP_URL}/JSON/core/action/accessUrl/", {
        "url": target,
        "followRedirects": True
    })

# ---------------- STEP 2: SPIDER ----------------
def spider(target):
    return zap(f"{ZAP_URL}/JSON/spider/action/scan/", {"url": target}).get("scan")

def spider_status(scan_id):
    return int(zap(
        f"{ZAP_URL}/JSON/spider/view/status/",
        {"scanId": scan_id}
    ).get("status", 0))

# ---------------- STEP 3: ACTIVE SCAN ----------------
def active_scan(target):
    return zap(
        f"{ZAP_URL}/JSON/ascan/action/scan/",
        {"url": target, "recurse": True}
    ).get("scan")

def active_status(scan_id):
    return int(zap(
        f"{ZAP_URL}/JSON/ascan/view/status/",
        {"scanId": scan_id}
    ).get("status", 0))

# ---------------- BACKGROUND PIPELINE ----------------
def run(scan_id, target):

    print("🚀 Starting scan:", target)

    # STEP 0: MUST ACCESS
    access_url(target)
    time.sleep(2)

    # STEP 1: SPIDER
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

    # STEP 2: ACTIVE SCAN
    scan_id_zap = active_scan(target)
    if not scan_id_zap:
        cur.execute("UPDATE scans SET status=? WHERE id=?", ("active_failed", scan_id))
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

    # STEP 3: DONE
    cur.execute("UPDATE scans SET status=?, progress=? WHERE id=?",
                ("done", 100, scan_id))
    conn.commit()

    print("✅ Scan complete")

# ---------------- START SCAN ----------------
@app.post("/start-scan")
def start_scan(target: str, bg: BackgroundTasks):

    sid = str(uuid.uuid4())

    cur.execute("""
        INSERT INTO scans VALUES (?,?,?, ?,?)
    """, (sid, target, "starting", 0, datetime.now().isoformat()))
    conn.commit()

    bg.add_task(run, sid, target)

    return {"scan_id": sid}

# ---------------- STATUS ----------------
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
