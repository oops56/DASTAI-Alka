from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel

import requests
import threading
import time
import os
import json
import csv
from collections import defaultdict

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

app = FastAPI()

ZAP_URL = "http://127.0.0.1:8090"
REPORT_DIR = "reports"
os.makedirs(REPORT_DIR, exist_ok=True)


# ================= STATE =================
STATE = {"running": False, "target": None}
SNAPSHOT = None


# ================= INPUT =================
class ScanRequest(BaseModel):
    url: str


# ================= OWASP MAPPING =================
def map_owasp(alert: str):

    a = alert.lower()

    if "sql" in a or "injection" in a:
        return "A03 - Injection"
    if "xss" in a:
        return "A03 - Injection"
    if "auth" in a or "session" in a:
        return "A07 - Authentication Failures"
    if "access" in a or "401" in a or "403" in a:
        return "A01 - Broken Access Control"

    return "A05 - Security Misconfiguration"


# ================= SEVERITY =================
def severity(risk):

    r = str(risk).lower()
    if r == "high":
        return "HIGH"
    if r == "medium":
        return "MEDIUM"
    return "LOW"


# ================= AI PROMPT ENGINE (DETAILED REMEDIATION) =================
def ai_engine(alert, url, risk):

    a = alert.lower()

    # SQL INJECTION
    if "sql" in a:

        return {
            "what_is_it": "SQL Injection is a vulnerability where attacker-controlled input is executed as SQL query.",
            "technical_description": "Occurs when user input is directly concatenated into SQL statements.",
            "root_cause": "Dynamic SQL query construction without parameterization.",
            "attack_scenario": "Attacker injects ' OR 1=1 -- to bypass authentication.",
            "business_impact": "Database leakage, credential theft, full DB compromise.",
            "remediation": [
                "Replace all raw SQL queries with parameterized prepared statements",
                "Disable string concatenation in SQL execution layer",
                "Use ORM (SQLAlchemy/Hibernate) instead of raw queries",
                "Restrict DB user privileges (SELECT only where needed)",
                "Enable database query logging + anomaly detection"
            ],
            "prevention": [
                "Integrate SAST tools in CI/CD pipeline",
                "Enable WAF SQL injection rules",
                "Run periodic penetration tests",
                "Enforce secure coding standards (OWASP ASVS)"
            ]
        }

    # XSS
    if "xss" in a:

        return {
            "what_is_it": "Cross-Site Scripting (XSS) allows attackers to inject malicious JavaScript into web pages.",
            "technical_description": "User input is rendered in browser without proper encoding.",
            "root_cause": "Missing output encoding and unsafe DOM rendering.",
            "attack_scenario": "Attacker injects <script>alert(1)</script> into input field.",
            "business_impact": "Session hijacking, cookie theft, UI manipulation.",
            "remediation": [
                "Escape HTML output using context-aware encoding",
                "Implement Content Security Policy (CSP: script-src 'self')",
                "Sanitize inputs using DOMPurify or equivalent",
                "Disable inline JavaScript execution completely",
                "Use auto-escaping frameworks (React/Angular)"
            ],
            "prevention": [
                "Enable CSP reporting mode",
                "Perform automated XSS scanning in CI/CD",
                "Use secure templating engines only"
            ]
        }

    # ACCESS CONTROL
    if "access" in a or "auth" in a or "403" in a or "401" in a:

        return {
            "what_is_it": "Broken Access Control occurs when users can access resources they should not.",
            "technical_description": "Server fails to validate authorization for protected endpoints.",
            "root_cause": "Missing or inconsistent server-side authorization checks.",
            "attack_scenario": "Attacker modifies URL /admin or API ID to access restricted data.",
            "business_impact": "Data exposure, privilege escalation, account takeover.",
            "remediation": [
                "Enforce server-side authorization on every API request",
                "Implement RBAC (Role-Based Access Control)",
                "Validate JWT signature and expiration on every request",
                "Prevent IDOR by validating object ownership",
                "Centralize authorization middleware"
            ],
            "prevention": [
                "Security unit tests for privilege escalation",
                "Periodic access control audits",
                "Zero-trust API design"
            ]
        }

    # DEFAULT
    return {
        "what_is_it": "Security misconfiguration or weak validation issue.",
        "technical_description": "Application exposes insecure configuration or missing validation.",
        "root_cause": "Improper default configuration or missing hardening.",
        "attack_scenario": "Attacker exploits exposed debug endpoints or weak headers.",
        "business_impact": "System exposure and potential compromise.",
        "remediation": [
            "Disable debug mode in production",
            "Harden HTTP headers (CSP, HSTS, X-Frame-Options)",
            "Remove unused endpoints",
            "Apply CIS benchmark configuration"
        ],
        "prevention": [
            "Regular configuration audits",
            "Infrastructure hardening automation",
            "Security baseline enforcement"
        ]
    }


# ================= FETCH ZAP =================
def fetch_alerts():

    try:
        r = requests.get(
            f"{ZAP_URL}/JSON/core/view/alerts/",
            params={"count": 1000},
            timeout=10
        ).json()

        if isinstance(r, dict):
            return r.get("alerts", [])

        return []

    except:
        return []


# ================= SCAN ENGINE =================
def run_scan(url):

    global SNAPSHOT

    raw = fetch_alerts()

    grouped = defaultdict(lambda: {
        "alerts": [],
        "ai": {},
        "owasp": "",
        "severity": ""
    })

    for a in raw:

        if not isinstance(a, dict):
            continue

        alert = a.get("alert", "")
        u = a.get("url", "")
        risk = severity(a.get("risk", ""))

        ai = ai_engine(alert, u, risk)
        owasp = map_owasp(alert)

        grouped[alert]["alerts"].append({
            "url": u,
            "risk": risk
        })

        grouped[alert]["ai"] = ai
        grouped[alert]["owasp"] = owasp
        grouped[alert]["severity"] = risk

    SNAPSHOT = {
        "target": url,
        "generated_at": time.time(),
        "data": grouped
    }

    STATE["running"] = False


# ================= API =================
@app.post("/scan")
def scan(req: ScanRequest):

    if STATE["running"]:
        return {"error": "scan_running"}

    STATE["running"] = True
    STATE["target"] = req.url

    threading.Thread(target=run_scan, args=(req.url,), daemon=True).start()

    return {"status": "scan_started"}


@app.get("/results")
def results():
    return SNAPSHOT or {"error": "no_data"}


# ================= PDF EXPORT =================
def export_pdf(path):

    doc = SimpleDocTemplate(path, pagesize=A4)
    styles = getSampleStyleSheet()

    elements = []

    elements.append(Paragraph("ENTERPRISE SECURITY REPORT", styles["Title"]))
    elements.append(Spacer(1, 10))

    for k, v in SNAPSHOT["data"].items():

        elements.append(Paragraph(f"<b>{k}</b>", styles["Heading2"]))
        elements.append(Paragraph(f"OWASP: {v['owasp']}", styles["Normal"]))
        elements.append(Paragraph(f"Severity: {v['severity']}", styles["Normal"]))

        elements.append(Paragraph(f"WHAT IS IT: {v['ai']['what_is_it']}", styles["Normal"]))
        elements.append(Paragraph(f"IMPACT: {v['ai']['business_impact']}", styles["Normal"]))

        elements.append(Paragraph("<b>Remediation (Very Specific):</b>", styles["Normal"]))
        for r in v["ai"]["remediation"]:
            elements.append(Paragraph(f"• {r}", styles["Normal"]))

        table = [["URL", "Risk"]]
        for a in v["alerts"]:
            table.append([a["url"], a["risk"]])

        t = Table(table)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.grey),
            ("TEXTCOLOR", (0,0), (-1,0), colors.whitesmoke),
            ("GRID", (0,0), (-1,-1), 0.5, colors.black),
        ]))

        elements.append(t)
        elements.append(Spacer(1, 15))

    doc.build(elements)


# ================= CSV =================
def export_csv(path):

    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Category", "URL", "Risk", "OWASP"])

        for k, v in SNAPSHOT["data"].items():
            for a in v["alerts"]:
                w.writerow([k, a["url"], a["risk"], v["owasp"]])


# ================= HTML =================
def export_html(path):

    html = "<h1>Enterprise Security Report</h1>"

    for k, v in SNAPSHOT["data"].items():

        html += f"<h2>{k}</h2>"
        html += f"<p>{v['ai']['what_is_it']}</p>"
        html += f"<p>{v['ai']['business_impact']}</p>"

        html += "<table border='1'><tr><th>URL</th><th>Risk</th></tr>"

        for a in v["alerts"]:
            html += f"<tr><td>{a['url']}</td><td>{a['risk']}</td></tr>"

        html += "</table>"

    with open(path, "w") as f:
        f.write(html)


# ================= JSON =================
def export_json(path):

    with open(path, "w") as f:
        json.dump(SNAPSHOT, f, indent=2)


# ================= DOWNLOAD =================
@app.get("/download")
def download(fmt: str = "pdf"):

    if not SNAPSHOT:
        return {"error": "no_data"}

    path = os.path.join(REPORT_DIR, f"report_{int(time.time())}.{fmt}")

    if fmt == "pdf":
        export_pdf(path)
    elif fmt == "csv":
        export_csv(path)
    elif fmt == "html":
        export_html(path)
    elif fmt == "json":
        export_json(path)
    else:
        return {"error": "invalid_format"}

    return FileResponse(path)
