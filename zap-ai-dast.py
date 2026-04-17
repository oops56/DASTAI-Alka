from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel
import requests
import threading
import time
import os
from collections import defaultdict

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

app = FastAPI()

ZAP_URL = "http://127.0.0.1:8090"

STATE = {
    "target": None,
    "running": False,
    "seen": set(),
    "alerts": []
}


# ---------------------------
class ScanRequest(BaseModel):
    url: str


# ---------------------------
def safe_alerts(resp):
    if isinstance(resp, dict):
        return resp.get("alerts", [])
    return []


# ---------------------------
def classify(alert):
    t = alert.lower()

    if "sql" in t:
        return "SQL Injection"
    if "xss" in t:
        return "Cross Site Scripting (XSS)"
    if "clickjack" in t:
        return "Clickjacking"
    if "csp" in t:
        return "Content Security Policy Issue"
    if "auth" in t:
        return "Broken Access Control"

    return "Security Misconfiguration"


# ---------------------------
def severity(risk):
    r = str(risk).lower()
    if r == "high":
        return "High"
    if r == "medium":
        return "Medium"
    return "Low"


# ---------------------------
# SOC-LEVEL VULNERABILITY INTELLIGENCE ENGINE
# ---------------------------
def vulnerability_profile(category):

    if category == "SQL Injection":
        return {
            "description": (
                "SQL Injection is a critical database-layer vulnerability that occurs when user-controlled input "
                "is directly embedded into SQL queries without proper sanitization or parameterization. "
                "Attackers exploit this weakness by manipulating query structure, allowing them to alter the intended "
                "database logic. The root cause typically lies in insecure coding practices where dynamic query "
                "construction is used instead of prepared statements. In advanced exploitation scenarios, attackers "
                "can bypass authentication mechanisms, extract sensitive datasets, or modify backend records."
            ),
            "impact": (
                "Successful exploitation can result in unauthorized access to sensitive database records, "
                "complete data exfiltration, data integrity compromise, and authentication bypass. In severe cases, "
                "it may lead to full database takeover and backend system compromise."
            ),
            "remediation": [
                "Enforce parameterized queries or prepared statements for all database interactions.",
                "Eliminate dynamic SQL query construction using string concatenation.",
                "Apply strict input validation and whitelist-based filtering mechanisms.",
                "Restrict database privileges using least-privilege access control principles."
            ]
        }

    if category == "Cross Site Scripting (XSS)":
        return {
            "description": (
                "Cross-Site Scripting (XSS) is a client-side injection vulnerability where attackers inject malicious "
                "JavaScript into web applications that is later executed in the victim's browser. This occurs when "
                "applications fail to properly encode or sanitize user-generated content before rendering it in HTML. "
                "The root cause is improper output encoding and lack of contextual input handling. Attackers exploit "
                "this flaw to execute scripts in the context of trusted sessions."
            ),
            "impact": (
                "Exploitation may lead to session hijacking, credential theft, unauthorized actions on behalf of users, "
                "defacement of web content, and redirection to malicious domains."
            ),
            "remediation": [
                "Apply context-aware output encoding for all user-generated content.",
                "Implement a strict Content Security Policy (CSP).",
                "Use secure frameworks that automatically escape HTML output.",
                "Sanitize and validate all inputs using trusted security libraries."
            ]
        }

    if category == "Clickjacking":
        return {
            "description": (
                "Clickjacking is a UI redress attack where a user is tricked into clicking hidden or disguised elements "
                "on a webpage. This is typically achieved by embedding the target application inside invisible or "
                "translucent iframes layered over malicious content. The vulnerability exists when applications allow "
                "themselves to be framed by external domains."
            ),
            "impact": (
                "Attackers may force users to perform unintended actions such as account changes, fund transfers, "
                "or enabling unauthorized permissions without their knowledge."
            ),
            "remediation": [
                "Set X-Frame-Options header to DENY or SAMEORIGIN.",
                "Implement CSP frame-ancestors directive for modern browsers.",
                "Prevent sensitive pages from being embedded in iframes.",
                "Use UI-based click validation mechanisms where applicable."
            ]
        }

    if category == "Content Security Policy Issue":
        return {
            "description": (
                "A weak or missing Content Security Policy (CSP) allows browsers to load and execute untrusted scripts "
                "from external or inline sources. CSP acts as a critical browser-side security control that restricts "
                "resource loading behavior. Misconfiguration significantly increases exposure to script injection attacks."
            ),
            "impact": (
                "Attackers can inject and execute malicious scripts, leading to data theft, session compromise, "
                "and full client-side exploitation."
            ),
            "remediation": [
                "Define strict CSP rules such as default-src 'self'.",
                "Eliminate unsafe-inline and unsafe-eval directives.",
                "Restrict script sources to trusted domains only.",
                "Use nonce or hash-based CSP enforcement."
            ]
        }

    if category == "Broken Access Control":
        return {
            "description": (
                "Broken Access Control occurs when an application fails to properly enforce authorization rules. "
                "This allows users to access restricted resources or perform actions beyond their intended privileges. "
                "The root cause is missing or improperly implemented server-side authorization checks."
            ),
            "impact": (
                "Attackers may gain unauthorized access to sensitive data, escalate privileges, modify records, "
                "or perform administrative actions."
            ),
            "remediation": [
                "Enforce server-side authorization checks for every request.",
                "Implement Role-Based Access Control (RBAC) or Attribute-Based Access Control (ABAC).",
                "Validate and verify JWT/session permissions correctly.",
                "Monitor and log unauthorized access attempts."
            ]
        }

    return {
        "description": (
            "Security misconfiguration refers to improper or insecure application/server settings that expose "
            "systems to potential exploitation. This typically occurs due to default configurations, enabled debug "
            "features, or unnecessary services being exposed to external users."
        ),
        "impact": (
            "May result in information disclosure, unauthorized access, or exposure of internal system components."
        ),
        "remediation": [
            "Disable debug and development modes in production environments.",
            "Harden server and application configuration settings.",
            "Remove unused services, endpoints, and components.",
            "Follow OWASP secure configuration best practices."
        ]
    }


# ---------------------------
def alert_stream():

    while STATE["running"]:
        try:
            r = requests.get(
                f"{ZAP_URL}/JSON/core/view/alerts/",
                params={"baseurl": STATE["target"], "count": 9999},
                timeout=10
            ).json()

            for a in safe_alerts(r):

                if not isinstance(a, dict):
                    continue

                alert = a.get("alert", "")
                url = a.get("url", "")
                risk = a.get("risk", "Low")

                key = f"{alert}|{url}"
                if key in STATE["seen"]:
                    continue

                STATE["seen"].add(key)

                category = classify(alert)
                profile = vulnerability_profile(category)

                STATE["alerts"].append({
                    "category": category,
                    "alert": alert,
                    "url": url,
                    "risk": severity(risk),
                    "description": profile["description"],
                    "impact": profile["impact"],
                    "remediation": profile["remediation"]
                })

        except:
            pass

        time.sleep(2)


# ---------------------------
@app.post("/scan")
def scan(req: ScanRequest):

    STATE["target"] = req.url
    STATE["alerts"] = []
    STATE["seen"] = set()
    STATE["running"] = True

    def boot():
        try:
            requests.get(f"{ZAP_URL}/JSON/core/action/accessUrl/", params={"url": req.url})
            requests.get(f"{ZAP_URL}/JSON/spider/action/scan/", params={"url": req.url})
            threading.Thread(target=alert_stream, daemon=True).start()
        except:
            STATE["running"] = False

    threading.Thread(target=boot, daemon=True).start()

    return {"status": "scan_started"}


# ---------------------------
def group(alerts):
    grouped = defaultdict(list)
    for a in alerts:
        grouped[a["category"]].append(a)
    return grouped


# ---------------------------
def generate_pdf(alerts, filename="SOC_Detailed_Report.pdf"):

    path = os.path.join(os.getcwd(), filename)

    doc = SimpleDocTemplate(path, pagesize=A4)
    styles = getSampleStyleSheet()
    wrap = ParagraphStyle(name="wrap", fontSize=9, leading=11)

    elements = []

    elements.append(Paragraph("🛡 SOC SECURITY REPORT (DETAILED)", styles["Title"]))
    elements.append(Spacer(1, 10))

    grouped = group(alerts)

    for cat, items in grouped.items():

        elements.append(Paragraph(f"🔴 {cat}", styles["Heading2"]))
        elements.append(Spacer(1, 6))

        elements.append(Paragraph("<b>Affected Endpoints:</b>", wrap))
        for u in set(i["url"] for i in items):
            elements.append(Paragraph(f"• {u}", wrap))

        elements.append(Spacer(1, 6))

        elements.append(Paragraph("<b>Description:</b>", wrap))
        elements.append(Paragraph(items[0]["description"], wrap))

        elements.append(Spacer(1, 5))

        elements.append(Paragraph("<b>Impact:</b>", wrap))
        elements.append(Paragraph(items[0]["impact"], wrap))

        elements.append(Spacer(1, 5))

        elements.append(Paragraph(f"<b>Severity:</b> {items[0]['risk']}", wrap))

        elements.append(Spacer(1, 6))

        elements.append(Paragraph("<b>Remediation:</b>", wrap))
        for r in items[0]["remediation"]:
            elements.append(Paragraph(f"• {r}", wrap))

        elements.append(Spacer(1, 12))
        elements.append(Paragraph("─" * 100, wrap))
        elements.append(Spacer(1, 10))

    doc.build(elements)

    return path


# ---------------------------
@app.get("/download-pdf")
def download_pdf():

    if not STATE["alerts"]:
        return {"error": "No data found"}

    file = generate_pdf(STATE["alerts"])

    return FileResponse(file, media_type="application/pdf")