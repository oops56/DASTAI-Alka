from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
import requests
import sqlite3
import uuid
import time
from datetime import datetime
import pandas as pd

app = FastAPI()

ZAP_URL = "http://127.0.0.1:8090"

# ---------------- DB ----------------
conn = sqlite3.connect("scanner.db", check_same_thread=False)
cur = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS scans (
    id TEXT,
    target TEXT,
    status TEXT,
    progress INTEGER,
    created TEXT,
    duration INTEGER
)
""")

cur.execute("""
CREATE TABLE IF NOT EXISTS findings (
    scan_id TEXT,
    alert TEXT,
    risk TEXT,
    url TEXT
)
""")

conn.commit()

# ---------------- REQUEST ----------------
class ScanRequest(BaseModel):
    target: str

# ---------------- ZAP HELPERS ----------------
def zap(url, params=None):
    try:
        return requests.get(url, params=params, timeout=20).json()
    except:
        return {}

def access(target):
    zap(f"{ZAP_URL}/JSON/core/action/accessUrl/", {"url": target})
    time.sleep(2)

def spider(target):
    return zap(f"{ZAP_URL}/JSON/spider/action/scan/", {"url": target}).get("scan")

def spider_status(sid):
    return int(zap(f"{ZAP_URL}/JSON/spider/view/status/", {"scanId": sid}).get("status", 0))

def active(target):
    return zap(f"{ZAP_URL}/JSON/ascan/action/scan/", {"url": target}).get("scan")

def active_status(sid):
    return int(zap(f"{ZAP_URL}/JSON/ascan/view/status/", {"scanId": sid}).get("status", 0))

def alerts():
    return zap(f"{ZAP_URL}/JSON/core/view/alerts/").get("alerts", [])

# ---------------- AI LAYER (RULE BASED MVP) ----------------

def ai_auth_analysis(df):
    df["auth_fail"] = df["risk"].isin(["High", "Medium"])
    return {
        "auth_failure_count": int(df["auth_fail"].sum()),
        "repeated_patterns": df["alert"].value_counts().head(3).to_dict()
    }

def ai_false_positive(df):
    dup = df.groupby("alert").size().sort_values(ascending=False)
    return {
        "duplicates": dup.head(5).to_dict(),
        "informational": len(df[df["risk"] == "Informational"])
    }

def ai_prioritization(df):
    score_map = {"High": 3, "Medium": 2, "Low": 1, "Informational": 0}
    df["score"] = df["risk"].map(score_map)
    return df.sort_values("score", ascending=False).head(10).to_dict(orient="records")

def ai_trends(all_scans):
    return {
        "avg_duration": sum([s["duration"] for s in all_scans]) / len(all_scans)
    }

# ---------------- SCAN PIPELINE ----------------

def run_scan(scan_id, target):

    start = time.time()

    access(target)

    # SPIDER
    sid = spider(target)
    while spider_status(sid) < 100:
        time.sleep(2)

    # ACTIVE SCAN
    aid = active(target)
    while active_status(aid) < 100:
        time.sleep(2)

    # RESULTS
    data = alerts()
    df = pd.DataFrame(data)

    for _, row in df.iterrows():
        cur.execute("""
            INSERT INTO findings VALUES (?,?,?,?)
        """, (scan_id, row.get("alert"), row.get("risk"), row.get("url")))

    duration = int(time.time() - start)

    cur.execute("""
        UPDATE scans SET status=?, progress=?, duration=? WHERE id=?
    """, ("done", 100, duration, scan_id))

    conn.commit()

# ---------------- API ----------------

@app.post("/start-scan")
def start_scan(req: ScanRequest, bg: BackgroundTasks):

    sid = str(uuid.uuid4())

    cur.execute("""
        INSERT INTO scans VALUES (?,?,?,?,?,?)
    """, (sid, req.target, "starting", 0, datetime.now().isoformat(), 0))
    conn.commit()

    bg.add_task(run_scan, sid, req.target)

    return {"scan_id": sid}

# ---------------- STATUS ----------------

@app.get("/status/{sid}")
def status(sid: str):

    cur.execute("SELECT * FROM scans WHERE id=?", (sid,))
    scan = cur.fetchone()

    cur.execute("SELECT alert, risk, url FROM findings WHERE scan_id=?", (sid,))
    findings = cur.fetchall()

    df = pd.DataFrame(findings, columns=["alert", "risk", "url"])

    return {
        "scan": scan,
        "auth_analysis": ai_auth_analysis(df) if not df.empty else {},
        "false_positive": ai_false_positive(df) if not df.empty else {},
        "prioritized": ai_prioritization(df) if not df.empty else []
    }

# ---------------- COMPARE ----------------

@app.get("/compare")
def compare():

    cur.execute("SELECT * FROM scans")
    rows = cur.fetchall()

    return [
        {"id": r[0], "target": r[1], "duration": r[5]}
        for r in rows
    ]
