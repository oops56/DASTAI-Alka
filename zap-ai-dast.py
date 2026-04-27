from fastapi import FastAPI, BackgroundTasks
import sqlite3
import requests
import time
import uuid
from datetime import datetime

app = FastAPI()

# ---------------- DB ----------------
conn = sqlite3.connect("scans.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS scans (
    id TEXT,
    target TEXT,
    status TEXT,
    progress INTEGER,
    total INTEGER,
    created TEXT
)
""")
conn.commit()

ZAP_URL = "http://127.0.0.1:8090"

# ---------------- SAFE REQUEST ----------------
def zap_get(url, params=None):
    try:
        r = requests.get(url, params=params, timeout=15)
        print("ZAP RESPONSE:", r.text)
        return r.json()
    except Exception as e:
        print("ZAP ERROR:", e)
        return {}

# ---------------- ZAP INIT CHECK ----------------
def zap_ping():
    return zap_get(f"{ZAP_URL}/JSON/core/view/version/")

# ---------------- FORCE SITE CREATION ----------------
def zap_access(target):
    zap_get(
        f"{ZAP_URL}/JSON/core/action/accessUrl/",
        {"url": target, "followRedirects": True}
    )

# ---------------- SPIDER ----------------
def zap_spider(target):
    return zap_get(
        f"{ZAP_URL}/JSON/spider/action/scan/",
        {"url": target}
    ).get("scan")

def zap_spider_status(scan_id):
    return int(zap_get(
        f"{ZAP_URL}/JSON/spider/view/status/",
        {"scanId": scan_id}
    ).get("status", 0))

# ---------------- ACTIVE SCAN ----------------
def zap_active_scan(target):
    return zap_get(
        f"{ZAP_URL}/JSON/ascan/action/scan/",
        {
            "url": target,
            "recurse": True,
            "inScopeOnly": False
        }
    ).get("scan")

def zap_active_status(scan_id):
    return int(zap_get(
        f"{ZAP_URL}/JSON/ascan/view/status/",
        {"scanId": scan_id}
    ).get("status", 0))

# ---------------- BACKGROUND SCAN ----------------
def run_scan(scan_id, target):

    print("🚀 Starting scan:", target)

    # STEP 0: VERIFY ZAP
    if not zap_ping():
        cursor.execute("UPDATE scans SET status=? WHERE id=?", ("zap-not-running", scan_id))
        conn.commit()
        return

    # STEP 1: FORCE SITE CREATION (CRITICAL FIX)
    zap_access(target)
    time.sleep(2)

    # STEP 2: SPIDER
    spider_id = zap_spider(target)

    if not spider_id:
        cursor.execute("UPDATE scans SET status=? WHERE id=?", ("spider-failed", scan_id))
        conn.commit()
        return

    print("Spider started:", spider_id)

    while True:
        status = zap_spider_status(spider_id)
        print("Spider progress:", status)

        cursor.execute(
            "UPDATE scans SET progress=?, status=? WHERE id=?",
            (status // 2, "spidering", scan_id)
        )
        conn.commit()

        if status >= 100:
            break

        time.sleep(2)

    # STEP 3: ACTIVE SCAN
    zap_id = zap_active_scan(target)

    if not zap_id:
        cursor.execute("UPDATE scans SET status=? WHERE id=?", ("scan-failed", scan_id))
        conn.commit()
        return

    print("Active scan started:", zap_id)

    while True:
        progress = zap_active_status(zap_id)
        print("Active scan progress:", progress)

        cursor.execute(
            "UPDATE scans SET progress=?, status=? WHERE id=?",
            (50 + progress // 2, "scanning", scan_id)
        )
        conn.commit()

        if progress >= 100:
            break

        time.sleep(2)

    # STEP 4: COMPLETE
    cursor.execute(
        "UPDATE scans SET status=?, progress=? WHERE id=?",
        ("done", 100, scan_id)
    )
    conn.commit()

    print("✅ Scan completed")

# ---------------- START SCAN ----------------
@app.post("/start-scan")
def start_scan(target: str, bg: BackgroundTasks):

    if not target.startswith("http"):
        return {"error": "URL must include http/https"}

    scan_id = str(uuid.uuid4())

    cursor.execute("""
        INSERT INTO scans VALUES (?,?,?,?,?,?)
    """, (
        scan_id,
        target,
        "starting",
        0,
        0,
        datetime.now().isoformat()
    ))

    conn.commit()

    bg.add_task(run_scan, scan_id, target)

    return {"scan_id": scan_id}

# ---------------- STATUS ----------------
@app.get("/status/{scan_id}")
def status(scan_id: str):

    cursor.execute("SELECT * FROM scans WHERE id=?", (scan_id,))
    row = cursor.fetchone()

    if not row:
        return {"error": "not found"}

    return {
        "id": row[0],
        "target": row[1],
        "status": row[2],
        "progress": row[3]
    }
