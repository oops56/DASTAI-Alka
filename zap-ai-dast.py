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

ZAP_URL = "http://YOUR_ZAP:8090"

# ---------------- UTIL ----------------
def read_file(file):
    content = file.file.read()
    try:
        return pd.read_csv(io.BytesIO(content))
    except:
        return pd.read_json(io.BytesIO(content))

# ---------------- AI LAYER ----------------
def ai_summary(text, task):
    # Replace with real LLM later
    return f"[AI-{task}] Insights: {str(text)[:200]}"

# ---------------- AUTH ANALYSIS ----------------
def auth_analysis(df):
    df['auth_fail'] = df['status'].isin([401,403])
    df['group'] = (df['auth_fail'] != df['auth_fail'].shift()).cumsum()
    df['streak'] = df.groupby('group')['auth_fail'].cumsum()

    return {
        "total_failures": int(df['auth_fail'].sum()),
        "max_streak": int(df['streak'].max()),
        "ai_insight": ai_summary(df.to_dict(), "auth")
    }

# ---------------- FALSE POSITIVE ----------------
def false_positive(df):
    df['group'] = df['title'] + df['endpoint']
    grouped = df.groupby('group').size()

    return {
        "total": len(df),
        "duplicates": len(df) - len(grouped),
        "info": len(df[df['severity']=="Info"]),
        "ai_insight": ai_summary(df.to_dict(), "fp")
    }

# ---------------- PRIORITIZATION ----------------
def prioritize(df):
    severity_map = {"Low":1,"Medium":2,"High":3,"Critical":4}
    df['score'] = df['severity'].map(severity_map)

    df['owasp'] = df['title'].apply(lambda x:
        "A1: Injection" if "sql" in x.lower() else
        "A2: Auth" if "auth" in x.lower() else
        "Other"
    )

    return df.sort_values(by="score", ascending=False).to_dict(orient="records")

# ---------------- ZAP SCAN ----------------
def start_zap(target):
    return requests.get(f"{ZAP_URL}/JSON/ascan/action/scan/?url={target}").json()["scan"]

def zap_status(scan_id):
    return int(requests.get(f"{ZAP_URL}/JSON/ascan/view/status/?scanId={scan_id}").json()["status"])

def zap_alerts():
    return requests.get(f"{ZAP_URL}/JSON/core/view/alerts/").json()["alerts"]

# ---------------- BACKGROUND SCAN ----------------
def run_scan(scan_id, target):
    zap_id = start_zap(target)
    start_time = time.time()

    progress = 0
    while progress < 100:
        progress = zap_status(zap_id)
        cursor.execute("UPDATE scans SET progress=?, status=? WHERE id=?", (progress,"running",scan_id))
        conn.commit()
        time.sleep(2)

    alerts = zap_alerts()
    df = pd.DataFrame(alerts)

    scan_time = int(time.time() - start_time)

    counts = df['risk'].value_counts().to_dict()

    cursor.execute("""
    UPDATE scans SET status=?, progress=100, scan_time=?, total=?, high=?, medium=?, low=?, info=? WHERE id=?
    """, (
        "done",
        scan_time,
        len(df),
        counts.get("High",0),
        counts.get("Medium",0),
        counts.get("Low",0),
        counts.get("Informational",0),
        scan_id
    ))
    conn.commit()

# ---------------- START SCAN ----------------
@app.post("/start-scan")
def start_scan(target:str, bg:BackgroundTasks):
    sid = str(uuid.uuid4())

    cursor.execute("INSERT INTO scans VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (sid,target,"starting",0,0,0,0,0,0,0,datetime.now().isoformat()))
    conn.commit()

    bg.add_task(run_scan, sid, target)
    return {"scan_id":sid}

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
def optimize(scan_id:str):
    cursor.execute("SELECT * FROM scans WHERE id=?", (scan_id,))
    row = cursor.fetchone()

    suggestions = []

    if row[9] > 30:
        suggestions.append("Disable informational checks")

    if row[4] > 300:
        suggestions.append("Reduce crawl depth")

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

    df = pd.DataFrame(rows, columns=["date","time","findings"])

    return df.to_dict(orient="records")

# ---------------- COMPARE ----------------
@app.get("/compare")
def compare():
    cursor.execute("SELECT target, total, high FROM scans WHERE status='done'")
    rows = cursor.fetchall()

    return [{"target":r[0],"findings":r[1],"high":r[2]} for r in rows]
