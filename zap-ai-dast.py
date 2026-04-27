from fastapi import FastAPI, UploadFile, File
import pandas as pd
import io
from datetime import datetime

app = FastAPI()

# -------------------------------
# Utility: Read CSV/JSON
# -------------------------------
def read_file(file):
    content = file.file.read()
    try:
        return pd.read_csv(io.BytesIO(content))
    except:
        return pd.read_json(io.BytesIO(content))

# -------------------------------
# 1. AUTH ANALYSIS
# -------------------------------
@app.post("/auth-analysis")
async def auth_analysis(file: UploadFile = File(...)):
    df = read_file(file)

    df['is_auth_fail'] = df['status'].isin([401, 403])
    
    # Detect streaks
    df['fail_group'] = (df['is_auth_fail'] != df['is_auth_fail'].shift()).cumsum()
    df['fail_streak'] = df.groupby('fail_group')['is_auth_fail'].cumsum()

    result = {
        "total_requests": len(df),
        "total_auth_failures": int(df['is_auth_fail'].sum()),
        "max_fail_streak": int(df['fail_streak'].max()),
        "insight": "Repeated auth failures detected. Session may expire during scan."
    }

    return result

# -------------------------------
# 2. FALSE POSITIVE REDUCTION
# -------------------------------
@app.post("/false-positive")
async def false_positive(file: UploadFile = File(...)):
    df = read_file(file)

    df['group_key'] = df['title'] + "_" + df['endpoint']
    grouped = df.groupby('group_key').size().reset_index(name='count')

    info_findings = df[df['severity'] == "Info"]

    return {
        "total_findings": len(df),
        "unique_groups": len(grouped),
        "informational_count": len(info_findings),
        "reduction_possible": len(df) - len(grouped)
    }

# -------------------------------
# 3. PRIORITIZATION
# -------------------------------
@app.post("/prioritize")
async def prioritize(file: UploadFile = File(...)):
    df = read_file(file)

    severity_map = {"Low":1, "Medium":2, "High":3, "Critical":4}
    df['score'] = df['severity'].map(severity_map)

    df = df.sort_values(by='score', ascending=False)

    return df.head(20).to_dict(orient="records")

# -------------------------------
# 4. SCAN OPTIMIZATION
# -------------------------------
@app.post("/optimize")
async def optimize(file: UploadFile = File(...)):
    df = read_file(file)

    suggestions = []

    if len(df[df['severity'] == "Info"]) > 30:
        suggestions.append("Disable informational checks")

    if 'endpoint' in df.columns:
        dead_paths = df['endpoint'].nunique()
        if dead_paths > 50:
            suggestions.append("Reduce crawl scope (too many endpoints)")

    return {
        "suggestions": suggestions,
        "message": "Policy optimization recommendations generated"
    }

# -------------------------------
# 5. TREND ANALYSIS
# -------------------------------
@app.post("/trend")
async def trend(file: UploadFile = File(...)):
    df = read_file(file)

    trend = df.groupby('date').agg({
        'scan_time': 'mean',
        'findings': 'sum'
    }).reset_index()

    return trend.to_dict(orient="records")

# -------------------------------
# ROOT
# -------------------------------
@app.get("/")
def root():
    return {"message": "AI Scan Analyzer Backend Running"}
