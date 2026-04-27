from fastapi import FastAPI, UploadFile, File, BackgroundTasks
import pandas as pd
import sqlite3
import io, time, uuid, requests
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
    scan_time INTEGER,
    total INTEGER,
    high INTEGER,
    medium INTEGER,
    low INTEGER,
    info INTEGER,
    created TEXT
)
""")
conn.commit()

ZAP_URL = "http://127.0.0.1:8090"

# ---------------- UTIL ----------------
def safe_zap_get(url, params=None):
    try:
        r = requests.get(url, params=params, timeout=10)
        return r.json()
    except Exception as e:
        return {"error": str(e)}

# ---------------- ZAP HELPERS ----------------

def zap_spider(target):
    if not target.startswith("http"):
        raise ValueError("Target must include http/https")

    res = safe_zap_get(
        f"{ZAP_URL}/JSON/spider/action/scan/",
        {"url": target}
    )
    return res.get("scan")

def zap_spider_status(scan_id):
    res = safe_zap_get(
        f"{ZAP_URL}/JSON/spider/view/status/",
        {"scanId": scan_id}
    )
    return int(res.get("status", 0))

def zap_active_scan(target):
    res = safe_zap_get(
        f"{ZAP_URL}/JSON/ascan/action/scan/",
        {"url": target}
    )
    return res.get("scan")

def zap_active_status(scan_id):
    res = safe_zap_get(
        f"{ZAP_URL}/JSON/ascan/view/status/",
        {"scanId": scan_id}
    )
    return int(res.get("status", 0))

def zap_alerts():
    res = safe_zap_get(f"{ZAP_URL}/JSON/core/view/alerts/")
    return res.get("alerts", [])

# ---------------- BACKGROUND SCAN ----------------

def run_scan(scan_id, target):

    start_time = time.time()

    # STEP 1: SPIDER
    spider_id = zap_spider(target)

    if spider_id is None:
        cursor.execute("UPDATE scans SET status=? WHERE id=?", ("failed-spider", scan_id))
        conn.commit()
        return

    while True:
        status = zap_spider_status(spider_id)

        cursor.execute("UPDATE scans SET progress=?, status=? WHERE id=?",
                       (status // 2, "spidering", scan_id))
        conn.commit()

        if status >= 100:
            break

        time.sleep(2)

    # STEP 2: ACTIVE SCAN
    zap_id = zap_active_scan(target)

    if zap_id is None:
        cursor.execute("UPDATE scans SET status=? WHERE id=?", ("failed-scan", scan_id))
        conn.commit()
        return

    while True:
        progress = zap_active_status(zap_id)

        cursor.execute("UPDATE scans SET progress=?, status=? WHERE id=?",
                       (50 + progress // 2, "scanning", scan_id))
        conn.commit()

        if progress >= 100:
            break

        time.sleep(2)

    # STEP 3: RESULTS
    alerts = zap_alerts()
    df = pd.DataFrame(alerts)

    scan_time = int(time.time() - start_time)

    counts = df["risk"].value_counts().to_dict() if "risk" in df.columns else {}

    cursor.execute("""
        UPDATE scans SET 
            status=?, progress=100, scan_time=?, total=?, high=?, medium=?, low=?, info=?
        WHERE id=?
    """, (
        "done",
        scan_time,
        len(df),
        counts.get("High", 0),
        counts.get("Medium", 0),
        counts.get("Low", 0),
        counts.get("Informational", 0),
        scan_id
    ))

    conn.commit()

# ---------------- START SCAN ----------------

@app.post("/start-scan")
def start_scan(target: str, bg: BackgroundTasks):

    sid = str(uuid.uuid4())

    cursor.execute("""
        INSERT INTO scans VALUES (?,?,?,?,?,?,?,?,?,?,?)
    """, (
        sid, target, "starting", 0, 0, 0, 0, 0, 0, 0,
        datetime.now().isoformat()
    ))

    conn.commit()

    bg.add_task(run_scan, sid, target)

    return {"scan_id": sid}

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
        "progress": row[3],
        "total": row[5],
        "high": row[6],
        "medium": row[7],
        "low": row[8],
        "info": row[9]
    }

# ---------------- ANALYZE FILE (unchanged) ----------------

def read_file(file):
    content = file.file.read()
    try:
        return pd.read_csv(io.BytesIO(content))
    except:
        return pd.read_json(io.BytesIO(content))

def ai_summary(text, task):
    return f"[AI-{task}] Insights: {str(text)[:200]}"

def auth_analysis(df):
    df['auth_fail'] = df['status'].isin([401, 403])
    return {"failures": int(df['auth_fail'].sum())}

def false_positive(df):
    return {"total": len(df)}

def prioritize(df):
    return df.to_dict(orient="records")

@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    df = read_file(file)

    return {
        "auth": auth_analysis(df),
        "false_positive": false_positive(df),
        "prioritized": prioritize(df)[:10]
    }
