"""
app.py - WebTrust Flask Web Application Controller
==================================================
This is the main entry point for the WebTrust application.
It connects the user interface (HTML templates) with the Python modules:
- checker.py: Safely scans the website
- risk_score.py: Computes the 0-100 risk score
- graph.py: Generates Matplotlib data visualizations

NO JavaScript is used in this project. All submissions are standard HTML forms.
"""

import json
import os
import re
import time
import csv
import io
import sqlite3
import logging
import threading
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from functools import wraps
from xml.sax.saxutils import escape
from flask import (
    Flask, render_template, request, redirect, url_for, send_from_directory,
    send_file, flash, session
)
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.security import check_password_hash, generate_password_hash

import checker
import risk_score
import graph
from config import Config


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.environ.get("WEBTRUST_LOG_FILE", os.path.join(BASE_DIR, Config.LOG_FILE))
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    handlers=[logging.FileHandler(LOG_FILE, encoding="utf-8"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

# Initialize Flask application
app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = app.config["SECRET_KEY"]


@app.errorhandler(RequestEntityTooLarge)
def handle_request_too_large(error):
    if request.path.startswith("/api/"):
        return {"error": "Request body is too large. Maximum size is 64 KB."}, 413
    flash("Request body is too large.", "error")
    return redirect(url_for("home"))

# Directory paths
STATIC_DIR = os.path.join(BASE_DIR, "static")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
HISTORY_FILE = os.path.join(BASE_DIR, "scan_history.json")
DATABASE_FILE = os.environ.get(
    "WEBTRUST_DATABASE", os.path.join(BASE_DIR, Config.DATABASE_FILE)
)
MAX_BATCH_SIZE = app.config["MAX_BATCH_SIZE"]
MAX_REQUESTS_PER_MINUTE = app.config["MAX_REQUESTS_PER_MINUTE"]
_rate_limit_events: defaultdict[str, deque[float]] = defaultdict(deque)
_rate_limit_lock = threading.Lock()

# Ensure required directories exist
os.makedirs(os.path.join(STATIC_DIR, "graphs"), exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)


def get_db() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE_FILE)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    with get_db() as connection:
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS saved_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                website TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                verdict TEXT NOT NULL,
                scan_time TEXT NOT NULL,
                report_json TEXT NOT NULL,
                favorite INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """)


initialize_database()


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash("Please sign in to access your saved scans.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped_view


def save_user_scan(user_id: int, analysis: dict, risk: dict):
    domain = analysis.get("url_data", {}).get("domain") or analysis.get("original_url", "")
    with get_db() as connection:
        connection.execute(
            """
            INSERT INTO saved_scans
            (user_id, website, risk_score, verdict, scan_time, report_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                domain,
                risk["score"],
                risk["verdict"],
                analysis.get("scan_time") or time.strftime("%Y-%m-%d %H:%M:%S"),
                json.dumps({"analysis": analysis, "risk": risk}, ensure_ascii=False),
            ),
        )


def load_scan_history() -> list:
    """Read past scans from scan_history.json safely."""
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"Warning: Could not read history file: {e}")
        return []


def save_scan_record(website: str, score: int, result: str, scan_time: str):
    """Append a new scan record to scan_history.json."""
    records = load_scan_history()
    new_record = {
        "website": website,
        "risk_score": score,
        "result": result,
        "date": scan_time
    }
    records.append(new_record)
    try:
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(records, f, indent=2)
    except Exception as e:
        print(f"Warning: Could not save scan history: {e}")


def scan_for_api(target_url: str) -> dict:
    """Run the scanner and return the stable machine-readable API payload."""
    analysis = checker.analyze_website(target_url)
    if analysis.get("error_type") == "invalid_url":
        return {
            "url": target_url,
            "success": False,
            "error": analysis.get("error_message", "Invalid URL."),
            "error_type": analysis.get("error_type"),
        }
    risk = risk_score.calculate_risk(analysis)
    return {
        "url": target_url,
        "success": analysis.get("success", False),
        "analysis": analysis,
        "risk": risk,
    }


def request_is_rate_limited(client_id: str) -> bool:
    now = time.time()
    cutoff = now - 60
    with _rate_limit_lock:
        events = _rate_limit_events[client_id]
        while events and events[0] <= cutoff:
            events.popleft()
        if len(events) >= MAX_REQUESTS_PER_MINUTE:
            return True
        events.append(now)
    return False


def generate_text_report(analysis: dict, risk: dict, filename: str):
    """
    Creates a clean, human-readable text report summarizing the scan.
    Stored in reports/ directory for download.
    """
    filepath = os.path.join(REPORTS_DIR, filename)
    url_data = analysis.get("url_data", {})
    headers = analysis.get("security_headers", {})
    trust_pages = analysis.get("trust_pages", {})

    report_content = f"""================================================================================
WEBTRUST - WEBSITE TRUST & RISK ASSESSMENT REPORT
================================================================================
Generated: {analysis.get('scan_time')}
Target Website: {url_data.get('url')}
Domain Name:    {url_data.get('domain')}

--------------------------------------------------------------------------------
1. EXECUTIVE SUMMARY
--------------------------------------------------------------------------------
Risk Score:     {risk.get('score')} / 100
Assessment:     {risk.get('verdict')}
Confidence:     {risk.get('confidence', 'N/A')}
Confidence Score:{risk.get('confidence_score', 'N/A')} / 100
Summary:        {risk.get('summary')}

DISCLAIMER:
This automated assessment evaluates publicly accessible signals and heuristics.
It is an educational risk evaluation and does NOT guarantee that a website is
definitely genuine or fraudulent.

--------------------------------------------------------------------------------
2. RISK SCORE BREAKDOWN
--------------------------------------------------------------------------------
HTTPS & SSL:        {risk.get('breakdown', {}).get('HTTPS', 0)} pts
Domain & Host:      {risk.get('breakdown', {}).get('Domain', 0)} pts
URL Structure:      {risk.get('breakdown', {}).get('URL Structure', 0)} pts
Redirects:          {risk.get('breakdown', {}).get('Redirects', 0)} pts
Website Content:    {risk.get('breakdown', {}).get('Website Content', 0)} pts
Security Headers:   {risk.get('breakdown', {}).get('Security Headers', 0)} pts
Total Risk Score:   {risk.get('score')} pts (Scale 0-100, lower is safer)
Thresholds:          0-29 Likely Trustworthy | 30-65 Needs Caution | 66-100 High Risk

--------------------------------------------------------------------------------
3. DETAILED SIGNALS
--------------------------------------------------------------------------------
[POSITIVE SIGNALS]
"""
    for sig in risk.get("positive_signals", []):
        report_content += f"  [+] {sig}\n"

    report_content += "\n[WARNING SIGNALS]\n"
    for sig in risk.get("warning_signals", []):
        report_content += f"  [!] {sig}\n"

    report_content += "\n[HIGH RISK INDICATORS]\n"
    if risk.get("risk_signals"):
        for sig in risk.get("risk_signals", []):
            report_content += f"  [X] {sig}\n"
    else:
        report_content += "  None detected.\n"

    report_content += "\n[EXPLAINABLE FINDINGS BY CATEGORY]\n"
    for category, findings in risk.get("findings_by_category", {}).items():
        report_content += f"\n{category}:\n"
        if findings:
            for finding in findings:
                report_content += (
                    f"  [{finding['severity']}] {finding['message']}\n"
                    f"      {finding['explanation']}\n"
                )
        else:
            report_content += "  No findings recorded.\n"

    report_content += "\n[RAW EVIDENCE]\n"
    for item in risk.get("evidence", []):
        report_content += (
            f"  [{item.get('confidence', 'N/A')}] "
            f"{item.get('category', 'Uncategorized')}: {item.get('finding', 'N/A')}\n"
        )
    if not risk.get("evidence"):
        report_content += "  No additional evidence recorded.\n"

    report_content += f"""
--------------------------------------------------------------------------------
4. TECHNICAL SPECIFICATIONS
--------------------------------------------------------------------------------
HTTP Status Code:   {analysis.get('status_code', 'N/A')}
Original URL:       {analysis.get('original_url', 'N/A')}
Final URL:          {analysis.get('final_url', 'N/A')}
Response Time:      {analysis.get('response_time', 0.0)} seconds
Number of Redirects:{analysis.get('redirect_count', 0)}
Webpage Title:      {analysis.get('title', 'N/A')}
Total Links Count:  {analysis.get('link_count', 0)}
Total Forms Count:  {analysis.get('form_count', 0)}
Server Software:    {analysis.get('server_info', 'N/A')}
DNS Resolved:       {'Yes' if analysis.get('dns', {}).get('resolved') else 'No'}
IP Addresses:       {', '.join(analysis.get('dns', {}).get('addresses', [])) or 'N/A'}
MX Records:         {', '.join(analysis.get('dns', {}).get('mx_records', [])) or 'N/A'}
Domain Age:         {analysis.get('whois', {}).get('domain_age_days', 'N/A')} days
TLS Issuer:         {analysis.get('tls_certificate', {}).get('issuer', 'N/A')}
TLS Expiry:         {analysis.get('tls_certificate', {}).get('expires_at', 'N/A')}

--------------------------------------------------------------------------------
5. TRUST PAGES DETECTED
--------------------------------------------------------------------------------
About Page:         {'Found' if trust_pages.get('about') else 'Not Found'}
Contact Page:       {'Found' if trust_pages.get('contact') else 'Not Found'}
Privacy Policy:     {'Found' if trust_pages.get('privacy') else 'Not Found'}
Terms of Service:   {'Found' if trust_pages.get('terms') else 'Not Found'}
Refund Policy:      {'Found' if trust_pages.get('refund') else 'Not Found'}

--------------------------------------------------------------------------------
6. SECURITY HEADERS
--------------------------------------------------------------------------------
HSTS (Strict-Transport-Security):   {'Present' if headers.get('hsts') else 'Missing'}
CSP (Content-Security-Policy):      {'Present' if headers.get('csp') else 'Missing'}
X-Frame-Options (Clickjacking):     {'Present' if headers.get('x_frame_options') else 'Missing'}
X-Content-Type-Options:             {'Present' if headers.get('x_content_type_options') else 'Missing'}
Referrer-Policy:                    {'Present' if headers.get('referrer_policy') else 'Missing'}

================================================================================
END OF REPORT - Generated by WebTrust (Python, Flask, Matplotlib)
================================================================================
"""
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(report_content)


def generate_json_report(analysis: dict, risk: dict, filename: str):
    """Write the complete scan as a machine-readable JSON document."""
    filepath = os.path.join(REPORTS_DIR, filename)
    payload = {
        "report_type": "webtrust_scan",
        "generated_at": analysis.get("scan_time"),
        "analysis": analysis,
        "risk": risk,
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def generate_pdf_report(analysis: dict, risk: dict, text_filename: str, pdf_filename: str):
    """Create a portable PDF from the same content used by the text report."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import Flowable, SimpleDocTemplate, Paragraph

    text_path = os.path.join(REPORTS_DIR, text_filename)
    with open(text_path, "r", encoding="utf-8") as f:
        report_content = f.read()

    styles = getSampleStyleSheet()
    body_style = ParagraphStyle(
        "WebTrustBody",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=7.5,
        leading=9,
        spaceAfter=1,
    )
    title_style = ParagraphStyle(
        "WebTrustTitle",
        parent=styles["Title"],
        fontSize=16,
        spaceAfter=8,
    )
    document = SimpleDocTemplate(
        os.path.join(REPORTS_DIR, pdf_filename),
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
        title=f"WebTrust Report - {analysis.get('url_data', {}).get('domain', 'scan')}",
    )
    story: list[Flowable] = [
        Paragraph(
            f"WebTrust Website Trust & Risk Assessment "
            f"(Risk score: {risk.get('score', 'N/A')}/100)",
            title_style,
        )
    ]
    for line in report_content.splitlines():
        if line.startswith("WEBTRUST -"):
            continue
        story.append(Paragraph(escape(line) or " ", body_style))
    document.build(story)


@app.route("/", methods=["GET"])
def home():
    """Renders the clean homepage with URL input."""
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        flash("Enter a valid email address.", "error")
        return render_template("register.html"), 400
    if len(password) < 8:
        flash("Password must contain at least 8 characters.", "error")
        return render_template("register.html"), 400
    try:
        with get_db() as connection:
            cursor = connection.execute(
                "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
                (email, generate_password_hash(password), time.strftime("%Y-%m-%d %H:%M:%S")),
            )
            session["user_id"] = cursor.lastrowid
            session["user_email"] = email
    except sqlite3.IntegrityError:
        flash("An account with that email already exists.", "error")
        return render_template("register.html"), 409
    return redirect(url_for("dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    with get_db() as connection:
        user = connection.execute(
            "SELECT id, email, password_hash FROM users WHERE email = ?", (email,)
        ).fetchone()
    if user is None or not check_password_hash(user["password_hash"], password):
        flash("Email or password is incorrect.", "error")
        return render_template("login.html"), 401
    session.clear()
    session["user_id"] = user["id"]
    session["user_email"] = user["email"]
    return redirect(url_for("dashboard"))


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/dashboard", methods=["GET"])
@login_required
def dashboard():
    with get_db() as connection:
        scans = connection.execute(
            """
            SELECT id, website, risk_score, verdict, scan_time, favorite
            FROM saved_scans WHERE user_id = ?
            ORDER BY id DESC
            """,
            (session["user_id"],),
        ).fetchall()
    return render_template("dashboard.html", scans=scans, user_email=session["user_email"])


@app.route("/dashboard/favorite/<int:scan_id>", methods=["POST"])
@login_required
def toggle_favorite(scan_id: int):
    with get_db() as connection:
        connection.execute(
            """
            UPDATE saved_scans SET favorite = CASE favorite WHEN 1 THEN 0 ELSE 1 END
            WHERE id = ? AND user_id = ?
            """,
            (scan_id, session["user_id"]),
        )
    return redirect(url_for("dashboard"))


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """Analyze one URL or a bounded batch of URLs and return JSON results."""
    client_id = request.remote_addr or "unknown"
    if request_is_rate_limited(client_id):
        return {
            "error": "Rate limit exceeded. Try again in a minute.",
            "retry_after_seconds": 60,
        }, 429
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return {
            "error": "Request body must be a JSON object.",
            "example": {"url": "https://example.com"},
        }, 400

    urls = payload.get("urls")
    if urls is None and "url" in payload:
        urls = [payload["url"]]
    if not isinstance(urls, list) or not urls:
        return {
            "error": "Provide either a non-empty 'url' string or a non-empty 'urls' array."
        }, 400
    if len(urls) > MAX_BATCH_SIZE:
        return {
            "error": f"Batch size exceeds the limit of {MAX_BATCH_SIZE} URLs.",
            "max_batch_size": MAX_BATCH_SIZE,
        }, 413
    if any(not isinstance(item, str) or not item.strip() for item in urls):
        return {"error": "Every URL must be a non-empty string."}, 400

    workers = min(4, len(urls))
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="webtrust-scan") as executor:
        results = list(executor.map(scan_for_api, (target_url.strip() for target_url in urls)))
    logger.info("API scan completed client=%s count=%s batch=%s", client_id, len(results), len(results) > 1)
    return {
        "scan_count": len(results),
        "batch": len(results) > 1,
        "results": results,
    }, 200


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Main analysis route.
    1. Reads user URL input
    2. Runs passive checks via checker.py
    3. Calculates risk score via risk_score.py
    4. Generates 3 Matplotlib charts via graph.py
    5. Saves scan to scan_history.json
    6. Generates downloadable report
    7. Renders result.html
    """
    target_url = request.form.get("url", "").strip()
    if request_is_rate_limited(request.remote_addr or "unknown"):
        flash("Too many scans requested. Please try again in a minute.", "error")
        return redirect(url_for("home"))

    # Input validation: check for empty input
    if not target_url:
        flash("Please enter a website URL to analyze.", "error")
        return redirect(url_for("home"))

    # Step 1: Perform passive check
    analysis = checker.analyze_website(target_url)
    if analysis.get("error_type") == "invalid_url":
        flash(analysis.get("error_message", "Please enter a valid website URL."), "error")
        return redirect(url_for("home"))

    # Step 2: Calculate transparent risk score
    risk = risk_score.calculate_risk(analysis)
    if "user_id" in session:
        save_user_scan(session["user_id"], analysis, risk)

    # Step 3: Load history and append new scan
    domain_name = analysis.get("url_data", {}).get("domain", target_url)
    save_scan_record(
        website=domain_name,
        score=risk["score"],
        result=risk["verdict"],
        scan_time=analysis.get("scan_time") or time.strftime("%Y-%m-%d %H:%M:%S")
    )
    # Refresh history records including the new one
    updated_history = load_scan_history()

    # Step 4: Generate Matplotlib charts
    signal_counts = {
        "positive": len(risk["positive_signals"]),
        "warning": len(risk["warning_signals"]),
        "risk": len(risk["risk_signals"])
    }
    charts = graph.generate_all_graphs(
        breakdown=risk["breakdown"],
        signal_counts=signal_counts,
        history_records=updated_history,
        static_dir=STATIC_DIR
    )

    # Step 5: Generate downloadable report
    safe_domain = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", domain_name)
    timestamp_str = time.strftime("%Y%m%d_%H%M%S")
    report_filename = f"webtrust_report_{safe_domain}_{timestamp_str}.txt"
    generate_text_report(analysis, risk, report_filename)
    json_filename = f"webtrust_report_{safe_domain}_{timestamp_str}.json"
    generate_json_report(analysis, risk, json_filename)
    pdf_filename = f"webtrust_report_{safe_domain}_{timestamp_str}.pdf"
    generate_pdf_report(analysis, risk, report_filename, pdf_filename)

    return render_template(
        "result.html",
        analysis=analysis,
        risk=risk,
        charts=charts,
        report_filename=report_filename,
        json_filename=json_filename,
        pdf_filename=pdf_filename,
    )


@app.route("/history", methods=["GET"])
def history_page():
    """Displays previous scans and historical line chart."""
    records = load_scan_history()
    
    # Generate standalone history chart
    chart_filename = f"history_trend_{int(time.time())}.png"
    chart_path = os.path.join(STATIC_DIR, "graphs", chart_filename)
    graph.generate_scan_history_chart(records, chart_path)
    
    return render_template(
        "history.html",
        records=reversed(records),  # Show newest first
        history_chart=f"graphs/{chart_filename}"
    )


@app.route("/how-it-works", methods=["GET"])
def how_it_works():
    """Explains the pipeline, scoring rules, and passive methodology."""
    return render_template("how_it_works.html")


@app.route("/download-report/<filename>", methods=["GET"])
def download_report(filename):
    """Safely serves the generated scan report from the reports/ directory."""
    # Basic path traversal protection
    safe_name = os.path.basename(filename)
    return send_from_directory(REPORTS_DIR, safe_name, as_attachment=True)


@app.route("/download-history.csv", methods=["GET"])
def download_history_csv():
    """Export all locally stored scan history as an analysis-friendly CSV."""
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["website", "risk_score", "result", "date"])
    for record in load_scan_history():
        writer.writerow([
            record.get("website", ""),
            record.get("risk_score", ""),
            record.get("result", ""),
            record.get("date", ""),
        ])
    response = io.BytesIO(output.getvalue().encode("utf-8-sig"))
    return send_file(
        response,
        mimetype="text/csv",
        as_attachment=True,
        download_name="webtrust_scan_history.csv",
    )


if __name__ == "__main__":
    print("=" * 60)
    print(" WebTrust - Website Trust & Risk Analyzer")
    print(" Running on: http://127.0.0.1:5000")
    print("=" * 60)
    app.run(host="127.0.0.1", port=5000, debug=True)
