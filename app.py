from dotenv import load_dotenv
load_dotenv(override=True)  # loads ANTHROPIC_API_KEY from .env, overriding any empty system env vars

import os
import tempfile
import sqlite3

from flask import Flask, render_template, jsonify, request
from scanner import run_all_checks, get_summary, log_scan, init_history_db, get_scan_history
from ai_analyst import analyze_findings, ask_question
from wazuh_forwarder import forward_findings, forward_summary
from ai_scanner import ai_schema_scan

app = Flask(__name__)

# Create the scan_history table on startup if it doesn't exist yet.
# This runs once when Flask launches — safe to call every time.
init_history_db()

# ─────────────────────────────────────────────────────────────────────────────
# COMPANY REGISTRY
# All five companies are HIPAA-covered healthcare entities.
# Each has its own SQLite database seeded with intentional security violations
# that DataPulse is designed to detect.
#
#   meridian   — Meridian Health Systems      (hospital network)
#   cascade    — Cascade Pharmacy Group       (pharmacy chain)
#   harborview — Harborview Behavioral Health (mental health clinic)
#   summit     — Summit Medical Imaging       (radiology/imaging center)
#   crestline  — Crestline Home Health        (in-home nursing agency)
# ─────────────────────────────────────────────────────────────────────────────
COMPANIES = {
    "meridian":   {"name": "Meridian Health Systems",      "db": "database/meridian_health.db"},
    "cascade":    {"name": "Cascade Pharmacy Group",       "db": "database/cascade_pharmacy.db"},
    "harborview": {"name": "Harborview Behavioral Health", "db": "database/harborview_behavioral.db"},
    "summit":     {"name": "Summit Medical Imaging",       "db": "database/summit_imaging.db"},
    "crestline":  {"name": "Crestline Home Health",        "db": "database/crestline_homehealth.db"},
}

# The company shown when no ?company= param is in the URL.
DEFAULT_COMPANY = "meridian"


def get_company(key):
    # Look up the company by its key (e.g. "apex").
    # Fall back to the default if the key is missing or unrecognized.
    return COMPANIES.get(key, COMPANIES[DEFAULT_COMPANY])


# ─────────────────────────────────────────────────────────────────────────────
# ROUTE: Home Page  "/"
# Reads an optional ?company= query parameter from the URL to decide
# which company's database to scan.
# e.g. http://localhost:5000/?company=apex
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    # request.args is a dictionary of URL query parameters.
    # request.args.get("company") reads ?company=xxx from the URL.
    company_key = request.args.get("company", DEFAULT_COMPANY)
    company = get_company(company_key)

    findings = run_all_checks(db_path=company["db"])
    summary  = get_summary(findings)

    # Forward every finding to the Wazuh log file so the SIEM picks them up.
    # forward_findings writes one JSON line per finding.
    # forward_summary writes a single aggregate line for dashboard trending.
    forward_findings(company["name"], findings)
    forward_summary(company["name"], summary)

    # Pass the full companies dict to the template so we can render
    # the switcher nav showing all available companies.
    return render_template(
        "index.html",
        findings=findings,
        summary=summary,
        company=company,
        company_key=company_key,
        companies=COMPANIES,
    )


# ─────────────────────────────────────────────────────────────────────────────
# ROUTE: API Endpoint  "/api/scan"
# Same as above but returns raw JSON.
# e.g. http://localhost:5000/api/scan?company=fortbridge
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/scan")
def api_scan():
    company_key = request.args.get("company", DEFAULT_COMPANY)
    company = get_company(company_key)

    findings = run_all_checks(db_path=company["db"])
    summary  = get_summary(findings)

    # Also forward on API scans — auto-refresh triggers this route,
    # so continuous monitoring generates a steady stream of Wazuh events.
    forward_findings(company["name"], findings)
    forward_summary(company["name"], summary)

    return jsonify({"company": company["name"], "summary": summary, "findings": findings})


# ─────────────────────────────────────────────────────────────────────────────
# ROUTE: AI Analysis  "/api/analyze"
# Runs the scan for the requested company, then passes all findings to
# ai_analyst.py which sends them to the Anthropic Claude API and returns
# a written report.
#
# This is called by the browser via fetch() (JavaScript) — not a page load.
# The browser sends a request, we respond with JSON, JavaScript displays it.
# That pattern is called an AJAX request (Asynchronous JavaScript).
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/analyze")
def api_analyze():
    company_key = request.args.get("company", DEFAULT_COMPANY)
    company     = get_company(company_key)

    findings = run_all_checks(db_path=company["db"])
    summary  = get_summary(findings)

    # Hand everything to the AI analyst.
    # analyze_findings returns a dict with "report" (markdown text)
    # and "remediations" (list of short fix strings, one per finding).
    mode   = request.args.get("mode", "detailed")   # "brief" or "detailed"
    result = analyze_findings(company["name"], summary, findings, mode=mode)

    return jsonify({
        "company":      company["name"],
        "analysis":     result["report"],
        "remediations": result["remediations"],
    })


# ─────────────────────────────────────────────────────────────────────────────
# ROUTE: Ask a Question  "/api/ask"
# The user types a natural-language question about the current scan findings.
# We run the scan, pass the findings + question to Claude, and return a
# focused answer — not a full report, just what they asked about.
# e.g. "Which findings violate HIPAA?" or "Who has stale API keys?"
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/ask")
def api_ask():
    company_key = request.args.get("company", DEFAULT_COMPANY)
    company     = get_company(company_key)
    question    = request.args.get("q", "").strip()

    findings = run_all_checks(db_path=company["db"])
    answer   = ask_question(company["name"], findings, question)

    return jsonify({"answer": answer})


# ─────────────────────────────────────────────────────────────────────────────
# ROUTE: Upload a database file  POST /api/upload
#
# This lets a user upload ANY .db file (not just our preset companies) and
# immediately scan it for security violations.
#
# How it works:
#   1. Browser sends the file as multipart/form-data (same as a normal HTML form upload)
#   2. Flask reads the file bytes from request.files["file"]
#   3. We write the bytes to a temporary file on disk (tempfile keeps it isolated)
#   4. We validate it's a real SQLite database (SQLite files start with a magic header)
#   5. run_all_checks() scans it exactly like any other company DB
#   6. We delete the temp file immediately after — we never store uploaded data
#   7. Return findings + summary as JSON — the browser renders them in the left panel
#
# Security boundaries:
#   - Only .db files accepted (extension check)
#   - Only real SQLite files accepted (magic byte check)
#   - 10 MB size limit to prevent memory abuse
#   - Temp file is always deleted, even if the scan crashes (try/finally)
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/upload", methods=["POST"])
def api_upload():

    # ── Step 1: make sure a file was actually included in the request ─────────
    if "file" not in request.files:
        return jsonify({"error": "No file included in the request."}), 400

    uploaded_file = request.files["file"]

    # ── Step 2: validate the filename ends in .db ─────────────────────────────
    # werkzeug's secure_filename() strips any path traversal tricks like ../../
    # so a filename like "../../etc/passwd.db" becomes "etc_passwd.db" safely.
    filename = uploaded_file.filename or ""
    if not filename.lower().endswith(".db"):
        return jsonify({"error": "Only .db (SQLite) files are supported."}), 400

    # ── Step 3: enforce a 10 MB size limit ───────────────────────────────────
    # Read all bytes now so we can check size before writing to disk.
    file_bytes = uploaded_file.read()
    max_bytes = 10 * 1024 * 1024  # 10 MB
    if len(file_bytes) > max_bytes:
        return jsonify({"error": "File too large. Maximum size is 10 MB."}), 400

    # ── Step 4: check the SQLite magic header ─────────────────────────────────
    # Every valid SQLite database file starts with exactly this 16-byte string.
    # If it's missing, the file isn't SQLite — it might be renamed JSON, a zip, etc.
    SQLITE_MAGIC = b"SQLite format 3\x00"
    if not file_bytes.startswith(SQLITE_MAGIC):
        return jsonify({"error": "File does not appear to be a valid SQLite database."}), 400

    # ── Step 5: write to a temp file, AI-scan it, then delete it ────────────
    # Unlike preset companies (which use hardcoded SQL checks), uploaded DBs
    # go through ai_scanner.py — Claude reads the schema and sample data
    # and identifies issues regardless of what tables exist.
    # This means ANY SQLite file works, not just DataPulse-format databases.
    tmp = None
    try:
        tmp = tempfile.NamedTemporaryFile(
            suffix=".db",
            prefix="datapulse_upload_",
            delete=False
        )
        tmp.write(file_bytes)
        tmp.close()   # close before scanning — SQLite needs exclusive access

        # ai_schema_scan reads the DB structure and asks Claude to find issues.
        # Returns findings in the same [{severity, category, detail, recommendation}]
        # format as run_all_checks() so everything downstream works unchanged.
        findings = ai_schema_scan(db_path=tmp.name, filename=filename)
        summary  = get_summary(findings)

    finally:
        # Always delete the temp file — even if the scan threw an exception.
        if tmp and os.path.exists(tmp.name):
            os.unlink(tmp.name)

    # ── Step 6: forward to Wazuh ─────────────────────────────────────────────
    # Same forwarding as preset company scans — Wazuh gets one event per finding.
    forward_findings(filename, findings)
    forward_summary(filename, summary)

    # ── Step 7: generate AI report in the same request ───────────────────────
    # For uploaded DBs we can't call /api/analyze later — the file is gone.
    # So we generate the full report now and return it alongside the findings.
    # The frontend will populate both the findings panel AND the report panel
    # automatically when it receives this response.
    report_result = analyze_findings(filename, summary, findings, mode="detailed")

    return jsonify({
        "company":      filename,
        "summary":      summary,
        "findings":     findings,
        "analysis":     report_result["report"],
        "remediations": report_result["remediations"],
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)
