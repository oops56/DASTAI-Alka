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

# ---------------- ZAP HELPER ----------------
def zap_get(endpoint, params=None):
    try:
        url = f"{ZAP}{endpoint}"
        r = requests.get(url, params=params, timeout=30)
        print("➡️", r.url)
        print("⬅️", r.text)
        return r.json()
    except Exception as e:
        print("❌ ZAP ERROR:", e)
        return {}

# ---------------- WAIT FOR ZAP ----------------
def wait_for_zap():
    for _ in range(20):
        try:
            r = requests.get(f"{ZAP}/JSON/core/view/version/")
            if r.status_code == 200:
                print("✅ ZAP ready")
                return True
        except:
            pass
        time.sleep(1)
    return False

# ---------------- FIX URL ----------------
def normalize_url(target):
    if not target.startswith("http"):
        return "http://" + target
    return target

# ---------------- FORCE URL INTO ZAP ----------------
def seed_target(target):
    print("🌐 Seeding target:", target)

    zap_get("/JSON/core/action/accessUrl/", {
        "url": target,
        "followRedirects": True
    })

    # WAIT until URL actually appears
    for _ in range(10):
        urls = zap_get("/JSON/core/view/urls/")
        if urls.get("urls"):
            print("✅ URLs discovered")
            return True
        time.sleep(1)

    print("❌ No URLs found after accessUrl")
    return False

# ---------------- SPIDER ----------------
def start_spider(target):
    res = zap_get("/JSON/spider/action/scan/", {"url": target})
    return res.get("scan")

def spider_progress(scan_id):
    res = zap_get("/JSON/spider/view/status/", {"scanId": scan_id})
    return int(res.get("status", 0))

# ---------------- ACTIVE SCAN ----------------
def start_active_scan(target):
    res = zap_get("/JSON/ascan/action/scan/", {
        "url": target,
        "recurse": True,
        "inScopeOnly": False
    })
    return res.get("scan")

def active_progress(scan_id):
    res = zap_get("/JSON/ascan/view/status/", {"scanId": scan_id})
    return int(res.get("status", 0))

# ---------------- BACKGROUND SCAN ----------------
def run_scan(scan_id, target):
    try:
        print("🚀 Starting scan:", target)

        target = normalize_url(target)

        if not wait_for_zap():
            raise Exception("ZAP not ready")

        # STEP 1: Seed target
        if not seed_target(target):
            cur.execute("UPDATE scans SET status=? WHERE id=?", ("no_urls", scan_id))
            conn.commit()
            return

        # STEP 2: Spider
        spider_id = start_spider(target)
        if not spider_id:
            cur.execute("UPDATE scans SET status=? WHERE id=?", ("spider_failed", scan_id))
            conn.commit()
            return

        while True:
            p = spider_progress(spider_id)
            print("🕷 Spider:", p)

            cur.execute("UPDATE scans SET progress=?, status=? WHERE id=?",
                        (p // 2, "spidering", scan_id))
            conn.commit()

            if p >= 100:
                break
            time.sleep(2)

        # CHECK URLs AGAIN
        urls = zap_get("/JSON/core/view/urls/")
        if not urls.get("urls"):
            cur.execute("UPDATE scans SET status=? WHERE id=?", ("no_urls_after_spider", scan_id))
            conn.commit()
            return

        # STEP 3: Active Scan
        ascan_id = start_active_scan(target)
        if not ascan_id:
            cur.execute("UPDATE scans SET status=? WHERE id=?", ("ascan_failed", scan_id))
            conn.commit()
            return

        while True:
            p = active_progress(ascan_id)
            print("⚡ Active:", p)

            cur.execute("UPDATE scans SET progress=?, status=? WHERE id=?",
                        (50 + p // 2, "scanning", scan_id))
            conn.commit()

            if p >= 100:
                break
            time.sleep(2)

        # DONE
        cur.execute("UPDATE scans SET status=?, progress=? WHERE id=?",
                    ("done", 100, scan_id))
        conn.commit()

        print("✅ Scan finished")

    except Exception as e:
        print("🔥 ERROR:", e)
        cur.execute("UPDATE scans SET status=? WHERE id=?", ("crashed", scan_id))
        conn.commit()

# ---------------- API ----------------
@app.post("/start-scan")
def start_scan(req: ScanRequest, bg: BackgroundTasks):
    sid = str(uuid.uuid4())

    cur.execute("INSERT INTO scans VALUES (?,?,?,?,?)",
                (sid, req.target, "starting", 0, datetime.now().isoformat()))
    conn.commit()

    bg.add_task(run_scan, sid, req.target)

    return {"scan_id": sid}

@app.get("/status/{scan_id}")
def get_status(scan_id: str):
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
