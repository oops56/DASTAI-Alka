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

# ---------------- HELPERS ----------------
def zap_get(url, params=None):
    try:
        r = requests.get(url, params=params, timeout=30)
        print("DEBUG:", r.url)
        print("RESPONSE:", r.text)
        return r.json()
    except Exception as e:
        print("ZAP ERROR:", e)
        return {}

def wait_for_zap():
    print("⏳ Waiting for ZAP...")
    for _ in range(20):
        try:
            r = requests.get(f"{ZAP}/JSON/core/view/version/", timeout=5)
            if r.status_code == 200:
                print("✅ ZAP is ready")
                return
        except:
            pass
        time.sleep(1)
    raise Exception("ZAP not responding")

def ensure_url_format(target):
    if not target.startswith("http"):
        return "http://" + target
    return target

# ---------------- CORE STEP ----------------
def access_url(target):
    print("🌐 Accessing target:", target)

    zap_get(f"{ZAP}/JSON/core/action/accessUrl/", {
        "url": target,
        "followRedirects": True
    })

    # wait until ZAP registers site
    for _ in range(10):
        sites = zap_get(f"{ZAP}/JSON/core/view/sites/")
        if sites.get("sites"):
            print("✅ Site added:", sites)
            return True
        time.sleep(1)

    print("❌ Failed to add site")
    return False

# ---------------- SPIDER ----------------
def spider(target):
    res = zap_get(f"{ZAP}/JSON/spider/action/scan/", {
        "url": target
    })
    return res.get("scan")

def spider_status(scan_id):
    res = zap_get(f"{ZAP}/JSON/spider/view/status/", {
        "scanId": scan_id
    })
    return int(res.get("status", 0))

# ---------------- ACTIVE SCAN ----------------
def active_scan(target):
    res = zap_get(f"{ZAP}/JSON/ascan/action/scan/", {
        "url": target,
        "recurse": True,
        "inScopeOnly": False
    })
    return res.get("scan")

def active_status(scan_id):
    res = zap_get(f"{ZAP}/JSON/ascan/view/status/", {
        "scanId": scan_id
    })
    return int(res.get("status", 0))

# ---------------- BACKGROUND JOB ----------------
def run_scan(scan_id, target):
    try:
        print("🚀 Starting scan:", target)

        target = ensure_url_format(target)

        wait_for_zap()

        # STEP 1: ACCESS
        if not access_url(target):
            cur.execute("UPDATE scans SET status=? WHERE id=?", ("access_failed", scan_id))
            conn.commit()
            return

        # STEP 2: SPIDER
        spider_id = spider(target)
        print("Spider ID:", spider_id)

        if not spider_id:
            cur.execute("UPDATE scans SET status=? WHERE id=?", ("spider_failed", scan_id))
            conn.commit()
            return

        while True:
            p = spider_status(spider_id)
            cur.execute("UPDATE scans SET progress=?, status=? WHERE id=?",
                        (p // 2, "spidering", scan_id))
            conn.commit()

            print("🕷 Spider progress:", p)

            if p >= 100:
                break

            time.sleep(2)

        # STEP 3: ACTIVE SCAN
        scan_id_zap = active_scan(target)
        print("Active Scan ID:", scan_id_zap)

        if not scan_id_zap:
            cur.execute("UPDATE scans SET status=? WHERE id=?", ("scan_failed", scan_id))
            conn.commit()
            return

        while True:
            p = active_status(scan_id_zap)
            cur.execute("UPDATE scans SET progress=?, status=? WHERE id=?",
                        (50 + p // 2, "scanning", scan_id))
            conn.commit()

            print("⚡ Scan progress:", p)

            if p >= 100:
                break

            time.sleep(2)

        # DONE
        cur.execute("UPDATE scans SET status=?, progress=? WHERE id=?",
                    ("done", 100, scan_id))
        conn.commit()

        print("✅ Scan completed")

    except Exception as e:
        print("🔥 SCAN CRASH:", e)
        cur.execute("UPDATE scans SET status=? WHERE id=?", ("crashed", scan_id))
        conn.commit()

# ---------------- API ----------------
@app.post("/start-scan")
def start_scan(req: ScanRequest, bg: BackgroundTasks):
    sid = str(uuid.uuid4())

    cur.execute("""
        INSERT INTO scans VALUES (?,?,?,?,?)
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
