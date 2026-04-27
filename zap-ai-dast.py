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
def read_file(file):
    content = file.file.read()
    try:
        return pd.read_csv(io.BytesIO(content))
    except:
        return pd.read_json(io.BytesIO(content))

# ---------------- AI LAYER ----------------
def ai_summary(text, task):
    return f"[AI-{task}] Insights: {str(text)[:200]}"

# ---------------- AUTH ANALYSIS ----------------
def auth_analysis(df):
    if "status" not in df.columns:
        return {"error": "missing status column"}

    df['auth_fail'] = df['status'].isin([401, 403])
    df['group'] = (df['auth_fail'] != df['auth_fail'].shift()).cumsum()
    df['streak'] = df.groupby('group')['auth_fail'].cumsum()

    return {
        "total_failures": int(df['auth_fail'].sum()),
        "max_streak": int(df['streak'].max()),
        "ai_insight": ai_summary(df.to_dict(), "auth")
    }

# ---------------- FALSE POSITIVE ----------------
def false_positive(df):
    if "title" not in df.columns or "endpoint" not in df.columns:
        return {"error": "missing columns"}

    df['group'] = df['title'].astype(str) + "_" + df['endpoint'].astype(str)
    grouped = df.groupby('group').size()

    info_count = len(df[df.get("severity","") == "Info"])

    return {
        "total": len(df),
        "duplicates": len(df) - len(grouped),
        "info": info_count,
        "ai_insight": ai_summary(df.to_dict(), "fp")
    }

# ---------------- PRIORITIZATION ----------------
def prioritize(df):
    if "severity" not in df.columns:
        return []

    severity_map = {"Low":1, "Medium":2, "High":3, "Critical":4}
    df['score'] = df['severity'].map(severity_map).fillna(0)

    df['owasp'] = df['title'].apply(lambda x:
        "A1: Injection" if isinstance(x,str) and "sql" in x.lower() else
        "A2: Auth" if isinstance(x,str) and "auth" in x.lower() else
        "Other"
    )

    return df.sort_values(by="score", ascending=False).to_dict(orient="records")

# ---------------- ZAP HELPERS ----------------

def zap_spider(target):
    res = requests.get(f"{ZAP_URL}/JSON/spider/action/scan/", params={"url": target})
    return res.json().get("scan")

def zap_spider_status(scan_id):
    res = requests.get(f"{ZAP_URL}/JSON/spider/view/status/", params={"scanId": scan_id})
    return int(res.json().get("status", 0))

def start_zap_active(target):
    res = requests.get(f"{ZAP_URL}/JSON/ascan/action/scan/", params={"url": target})
    return res.json().get("scan")

def zap_active_status(scan_id):
    res = requests.get(f"{ZAP_URL}/JSON/ascan/view/status/", params={"scanId": scan_id})
    return int(res.json().get("status", 0))

def zap_alerts():
    res = requests.get(f"{ZAP_URL}/JSON/core/view/alerts/")
    return res.json().get("alerts", [])

# ---------------- BACKGROUND SCAN (FIXED FLOW) ----------------
def run_scan(scan_id, target):

    start_time = time.time()

    # STEP 1: SPIDER (CRITICAL FIX)
    spider_id = zap_spider(target)

    while True:
        status = zap_spider_status(spider_id)
        cursor.execute("UPDATE scans SET progress=?, status=? WHERE id=?",
                       (status//2, "spidering", scan_id))
        conn.commit()

        if status >= 100:
            break

        time.sleep(2)

    # STEP 2: ACTIVE SCAN
    zap_id = start_zap_active(target)

    progress = 0
    while progress < 100:
        progress = zap_active_status(zap_id)

        cursor.execute("UPDATE scans SET progress=?, status=? WHERE id=?",
                       (50 + progress//2, "scanning", scan_id))
        conn.commit()

        time.sleep(2)

    # STEP 3: COLLECT RESULTS
    alerts = zap_alerts()
    df = pd.DataFrame(alerts)

    scan_time = int(time.time() - start_time)

    counts = df['risk'].value_counts().to_dict() if "risk" in df.columns else {}

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

# ---------------- ANALYZE FILE ----------------
@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    df = read_file(file)

    return {
        "auth": auth_analysis(df),
        "false_positive": false_positive(df),
        "prioritized": prioritize(df)[:10]
    }

# ---------------- OPTIMIZATION ----------------
@app.get("/optimize/{scan_id}")
def optimize(scan_id: str):
    cursor.execute("SELECT * FROM scans WHERE id=?", (scan_id,))
    row = cursor.fetchone()

    if not row:
        return {"error": "scan not found"}

    suggestions = []

    if row[8] > 30:
        suggestions.append("Disable informational checks")

    if row[4] and row[4] > 300:
        suggestions.append("Reduce crawl depth / scope")

    return {
        "scan_id": scan_id,
        "suggestions": suggestions,
        "ai": ai_summary(row, "optimize")
    }

# ---------------- TREND ----------------
@app.get("/trend")
def trend():
    cursor.execute("SELECT created, scan_time, total FROM scans WHERE status='done'")
    rows = cursor.fetchall()

    df = pd.DataFrame(rows, columns=["date", "time", "findings"])

    return df.to_dict(orient="records")

# ---------------- COMPARE ----------------
@app.get("/compare")
def compare():
    cursor.execute("SELECT target, total, high FROM scans WHERE status='done'")
    rows = cursor.fetchall()

    return [
        {"target": r[0], "findings": r[1], "high": r[2]}
        for r in rows
    ]
