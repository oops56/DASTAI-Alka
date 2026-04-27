from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
import requests
import sqlite3
import time
import uuid
from datetime import datetime

app = FastAPI()

ZAP = "http://127.0.0.1:8080"

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

# ---------------- NORMALIZE URL ----------------
def normalize_url(target):
    if not target.startswith("http"):
        return "http://" + target
    return target

# ---------------- SEED TARGET ----------------
def seed_target(target):
    print("🌐 Seeding:", target)

    zap_get("/JSON/core/action/accessUrl/", {
        "url": target,
        "followRedirects": True
    })

    for _ in range(10):
        urls = zap_get("/JSON/core/view/urls/")
        if urls.get("urls"):
            print("✅ URLs present")
            return True
        time.sleep(1)

    print("❌ No URLs after seeding")
    return False

# ---------------- TRADITIONAL SPIDER ----------------
def run_spider(target):
    print("🕷 Starting spider")

    res = zap_get("/JSON/spider/action/scan/", {
        "url": target,
        "recurse": True
    })

    scan_id = res.get("scan")
    print("Spider ID:", scan_id)

    if not scan_id:
        return False

    while True:
        status = zap_get("/JSON/spider/view/status/", {
            "scanId": scan_id
        })
        progress = int(status.get("status", 0))
        print("Spider progress:", progress)

        if progress >= 100:
            break

        time.sleep(2)

    return True

# ---------------- AJAX SPIDER (for JS apps) ----------------
def run_ajax_spider(target):
    print("🧠 Starting AJAX spider")

    zap_get("/JSON/ajaxSpider/action/scan/", {
        "url": target
    })

    for _ in range(30):
        status = zap_get("/JSON/ajaxSpider/view/status/")
        print("AJAX status:", status)

        if status.get("status") == "stopped":
            return True

        time.sleep(2)

    return False

# ---------------- ACTIVE SCAN ----------------
def run_active_scan(target, scan_id):
    print("⚡ Starting active scan")

    res = zap_get("/JSON/ascan/action/scan/", {
        "url": target,
        "recurse": True,
        "inScopeOnly": False
    })

    ascan_id = res.get("scan")
    print("Active scan ID:", ascan_id)

    if not ascan_id:
        return False

    while True:
        status = zap_get("/JSON/ascan/view/status/", {
            "scanId": ascan_id
        })

        progress = int(status.get("status", 0))
        print("Active progress:", progress)

        cur.execute("UPDATE scans SET progress=?, status=? WHERE id=?",
                    (50 + progress // 2, "scanning", scan_id))
        conn.commit()

        if progress >= 100:
            break

        time.sleep(2)

    return True

# ---------------- BACKGROUND JOB ----------------
def run_scan(scan_id, target):
    try:
        print("🚀 Scan start:", target)

        target = normalize_url(target)

        if not wait_for_zap():
            raise Exception("ZAP not ready")

        # STEP 1: Seed
        if not seed_target(target):
            cur.execute("UPDATE scans SET status=? WHERE id=?", ("seed_failed", scan_id))
            conn.commit()
            return

        # STEP 2: Spider
        run_spider(target)

        # STEP 3: Check URLs
        urls = zap_get("/JSON/core/view/urls/")
        if not urls.get("urls"):
            print("⚠️ No URLs from spider, trying AJAX spider")
            run_ajax_spider(target)

        # STEP 4: Check again
        urls = zap_get("/JSON/core/view/urls/")
        if not urls.get("urls"):
            cur.execute("UPDATE scans SET status=? WHERE id=?", ("no_urls", scan_id))
            conn.commit()
            return

        # STEP 5: Active scan
        if not run_active_scan(target, scan_id):
            cur.execute("UPDATE scans SET status=? WHERE id=?", ("ascan_failed", scan_id))
            conn.commit()
            return

        # DONE
        cur.execute("UPDATE scans SET status=?, progress=? WHERE id=?",
                    ("done", 100, scan_id))
        conn.commit()

        print("✅ Scan complete")

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
