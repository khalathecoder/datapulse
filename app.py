from dotenv import load_dotenv
load_dotenv(override=True)  # loads ANTHROPIC_API_KEY from .env, overriding any empty system env vars

from flask import Flask, render_template, jsonify, request
from scanner import run_all_checks, get_summary, log_scan, init_history_db, get_scan_history
from ai_analyst import analyze_findings, ask_question

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


if __name__ == "__main__":
    app.run(debug=True, port=5000)
