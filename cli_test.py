"""
DataPulse CLI Test Tool
-----------------------
Run this script directly to test the scanner and AI analyst
without starting Flask or opening a browser.

Usage:
    python cli_test.py                          # scan default company (meridian)
    python cli_test.py --company fortbridge     # scan a specific company
    python cli_test.py --company luminary --ai  # scan + run AI analysis
    python cli_test.py --company hargrove --ask "what violates attorney-client privilege?"
    python cli_test.py --list                   # show all available companies

Why this matters:
    If the web UI is down (Flask crash, port conflict, browser issue),
    you can still run a full scan and get AI output directly from the terminal.
    This is how backend engineers verify a system is working independently
    of the frontend.
"""

import argparse
import json
from dotenv import load_dotenv

# Load .env so the AI analyst has the API key
load_dotenv(override=True)

from scanner import run_all_checks, get_summary
from ai_analyst import analyze_findings, ask_question

# ── Company registry — mirrors app.py ────────────────────────────────────────
COMPANIES = {
    "meridian":   {"name": "Meridian Health Systems",     "db": "database/meridian_health.db"},
    "cascade":    {"name": "Cascade Pharmacy Group",      "db": "database/cascade_pharmacy.db"},
    "apex":       {"name": "Apex Payment Solutions",      "db": "database/apex_payment.db"},
    "ironclad":   {"name": "Ironclad DevOps",             "db": "database/ironclad_devops.db"},
    "hargrove":   {"name": "Hargrove & Associates Legal", "db": "database/hargrove_legal.db"},
    "luminary":   {"name": "Luminary AI Research",        "db": "database/luminary_ai.db"},
    "fortbridge": {"name": "Fortbridge Community Bank",   "db": "database/fortbridge_bank.db"},
}


def print_divider(char="-", width=60):
    print(char * width)


def run_scan(company_key, show_ai=False, question=None, mode="detailed"):
    if company_key not in COMPANIES:
        print(f"[!] Unknown company: '{company_key}'")
        print(f"    Available: {', '.join(COMPANIES.keys())}")
        return

    company = COMPANIES[company_key]
    print_divider("=")
    print(f"  DataPulse CLI  |  {company['name']}")
    print_divider("=")

    # ── Run the scanner ───────────────────────────────────────────────────────
    print("\n[>] Running security scan...")
    findings = run_all_checks(db_path=company["db"])
    summary  = get_summary(findings)

    print(f"\n  CRITICAL : {summary['CRITICAL']}")
    print(f"  HIGH     : {summary['HIGH']}")
    print(f"  MEDIUM   : {summary['MEDIUM']}")
    print(f"  TOTAL    : {summary['total']}")
    print_divider()

    # ── Print each finding ────────────────────────────────────────────────────
    for i, f in enumerate(findings, 1):
        sev = f["severity"].ljust(8)
        print(f"  #{str(i).zfill(2)}  [{sev}]  {f['category']}")
        print(f"        {f['detail']}")

    print_divider()

    # ── Optional: run AI analysis ─────────────────────────────────────────────
    if show_ai:
        print(f"\n[>] Running AI analysis (mode: {mode})...")
        result = analyze_findings(company["name"], summary, findings, mode=mode)
        print_divider()
        print(result["report"])

        if result["remediations"]:
            print_divider()
            print("  Per-finding remediations:")
            for i, rec in enumerate(result["remediations"], 1):
                print(f"  #{str(i).zfill(2)}  {rec}")

    # ── Optional: ask a question ──────────────────────────────────────────────
    if question:
        print(f"\n[>] Asking: \"{question}\"")
        print_divider()
        answer = ask_question(company["name"], findings, question)
        print(answer)

    print_divider("=")


def main():
    parser = argparse.ArgumentParser(
        description="DataPulse CLI — scan companies and test AI without the web UI"
    )
    parser.add_argument(
        "--company", "-c",
        default="meridian",
        help="Company key to scan (default: meridian)"
    )
    parser.add_argument(
        "--ai", "-a",
        action="store_true",
        help="Run AI analysis after the scan"
    )
    parser.add_argument(
        "--mode", "-m",
        default="detailed",
        choices=["brief", "detailed"],
        help="Report length: brief or detailed (default: detailed)"
    )
    parser.add_argument(
        "--ask", "-q",
        default=None,
        help="Ask a natural language question about the findings"
    )
    parser.add_argument(
        "--list", "-l",
        action="store_true",
        help="List all available companies"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output scan findings as raw JSON (useful for piping to other tools)"
    )

    args = parser.parse_args()

    if args.list:
        print("\nAvailable companies:")
        for key, co in sorted(COMPANIES.items()):
            print(f"  {key.ljust(10)}  {co['name']}")
        print()
        return

    if args.json:
        # Raw JSON output — useful for piping into jq or other tools
        company = COMPANIES.get(args.company)
        if not company:
            print(f"Unknown company: {args.company}")
            return
        findings = run_all_checks(db_path=company["db"])
        summary  = get_summary(findings)
        print(json.dumps({"company": company["name"], "summary": summary, "findings": findings}, indent=2))
        return

    run_scan(
        company_key = args.company,
        show_ai     = args.ai,
        question    = args.ask,
        mode        = args.mode,
    )


if __name__ == "__main__":
    main()
