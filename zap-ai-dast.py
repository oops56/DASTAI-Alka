from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
import requests
import time
import sqlite3
from datetime import datetime
import uuid

app = FastAPI()

ZAP_URL = "http://YOUR_ZAP_SERVER:8090"

conn = sqlite3.connect("scans.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS scans (
    id TEXT,
    target TEXT,
    status TEXT,
    progress INTEGER,
    total_alerts INTEGER,
    high_risk INTEGER,
    medium_risk INTEGER,
    low_risk INTEGER,
    info_risk INTEGER,
    created_at TEXT
)
""")
conn.commit()

# ---------------- REQUEST MODEL ----------------
class ScanRequest(BaseModel):
    target: str

# ---------------- ZAP HELPERS ----------------
def start_scan(target):
    url = f"{ZAP_URL}/JSON/ascan/action/scan/?url={target}"
    return requests.get(url).json().get("scan")

def get_status(scan_id):
    url = f"{ZAP_URL}/JSON/ascan/view/status/?scanId={scan_id}"
    return int(requests.get(url).json().get("status"))

def get_alerts():
    url = f"{ZAP_URL}/JSON/core/view/alerts/"
    return requests.get(url).json().get("alerts", [])

# ---------------- AI ANALYSIS ----------------
def ai_suggestions(alerts):
    text = str(alerts)[:3000]

    # Replace with real LLM later
    suggestions = []

    if "Informational" in text:
        suggestions.append("Reduce informational alerts to improve signal-to-noise ratio")

    if "login" in text.lower():
        suggestions.append("Authentication issues detected. Use authenticated scan")

    if "sql" not in text.lower():
        suggestions.append("Consider enabling deeper injection tests")

    return suggestions

# ---------------- BACKGROUND SCAN ----------------
def run_scan(scan_id, target, db_id):
    zap_scan_id = start_scan(target)

    progress = 0
    while progress < 100:
        progress = get_status(zap_scan_id)

        cursor.execute("""
        UPDATE scans SET progress=?, status=? WHERE id=?
        """, (progress, "running", db_id))
        conn.commit()

        time.sleep(2)

    alerts = get_alerts()

    # Count risks
    risk_counts = {
        "High": 0, "Medium": 0, "Low": 0, "Informational": 0
    }

    for a in alerts:
        risk_counts[a['risk']] += 1

    cursor.execute("""
    UPDATE scans SET 
        status=?, 
        progress=100,
        total_alerts=?,
        high_risk=?,
        medium_risk=?,
        low_risk=?,
        info_risk=?
    WHERE id=?
    """, (
        "completed",
        len(alerts),
        risk_counts["High"],
        risk_counts["Medium"],
        risk_counts["Low"],
        risk_counts["Informational"],
        db_id
    ))

    conn.commit()

# ---------------- START SCAN ----------------
@app.post("/start-scan")
def start_scan_api(req: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())

    cursor.execute("""
    INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_id,
        req.target,
        "starting",
        0,
        0,0,0,0,0,
        datetime.now().isoformat()
    ))
    conn.commit()

    background_tasks.add_task(run_scan, scan_id, req.target, scan_id)

    return {"scan_id": scan_id}

# ---------------- GET STATUS ----------------
@app.get("/scan-status/{scan_id}")
def scan_status(scan_id: str):
    cursor.execute("SELECT * FROM scans WHERE id=?", (scan_id,))
    row = cursor.fetchone()

    if not row:
        return {"error": "Scan not found"}

    return {
        "id": row[0],
        "target": row[1],
        "status": row[2],
        "progress": row[3],
        "total_alerts": row[4],
        "high": row[5],
        "medium": row[6],
        "low": row[7],
        "info": row[8]
    }

# ---------------- HISTORY ----------------
@app.get("/history")
def history():
    cursor.execute("SELECT * FROM scans ORDER BY created_at DESC")
    rows = cursor.fetchall()

    return [
        {
            "id": r[0],
            "target": r[1],
            "status": r[2],
            "alerts": r[4],
            "high": r[5],
            "created": r[9]
        }
        for r in rows
    ]

# ---------------- COMPARE ----------------
@app.get("/compare")
def compare():
    cursor.execute("SELECT * FROM scans WHERE status='completed'")
    rows = cursor.fetchall()

    return [
        {
            "target": r[1],
            "alerts": r[4],
            "high": r[5],
            "medium": r[6],
            "low": r[7]
        }
        for r in rows
    ]

# ---------------- AI OPTIMIZATION ----------------
@app.get("/ai-optimize/{scan_id}")
def optimize(scan_id: str):
    alerts = get_alerts()
    suggestions = ai_suggestions(alerts)

    return {
        "scan_id": scan_id,
        "suggestions": suggestions
    }
