import json
import os
from datetime import datetime

# ─────────────────────────────────────────────────────────────────────────────
# WAZUH FORWARDER
#
# Wazuh monitors log files the same way a sysadmin reads log files —
# it watches for new lines, reads them, and runs them through rules.
#
# This module's job: after every DataPulse scan, write each finding as one
# JSON line to a log file. Wazuh picks up those lines and fires alerts.
#
# Think of it like this:
#   DataPulse = the detective that finds problems
#   This file  = the dispatcher that radios findings to the station
#   Wazuh      = the station that logs, escalates, and tracks everything
#
# Log file location: logs/datapulse_wazuh.log
# Override by setting DATAPULSE_LOG_PATH in your .env file.
# ─────────────────────────────────────────────────────────────────────────────

# Where the log file lives. Wazuh agent will be told to watch this path.
# Using an env var makes it easy to change when deploying on Linux/Wazuh server.
LOG_PATH = os.getenv("DATAPULSE_LOG_PATH", "logs/datapulse_wazuh.log")

# Maps our severity labels to Wazuh rule levels (0–15 scale).
# Wazuh uses levels to decide how loud to be:
#   12–15 = CRITICAL  → triggers email/Slack/PagerDuty integrations
#   8–11  = HIGH      → appears in high-priority alert views
#   6–7   = MEDIUM    → tracked but not immediately escalated
#   4–5   = LOW       → informational, good for compliance audit trails
SEVERITY_TO_WAZUH_LEVEL = {
    "CRITICAL": 12,
    "HIGH":     8,
    "MEDIUM":   6,
    "LOW":      4,
}

# Maps finding categories to the HIPAA Technical Safeguard sections they violate.
# This is what makes Wazuh reports meaningful for compliance —
# every alert is tied to a specific regulation, not just a generic warning.
# All references are under 45 CFR §164.312 (HIPAA Technical Safeguards).
HIPAA_REFS = {
    "Plaintext Password":          "164.312(d) — Authentication",
    "Terminated User Still Active":"164.312(a)(2)(i) — Unique User Identification",
    "Over-Permissioned User":      "164.312(a)(1) — Access Control",
    "Stale API Key":               "164.312(d) — Authentication",
    "Public Data Store with PII":  "164.312(a)(4) — Transmission Security",
    "Hardcoded Credential":        "164.312(d) — Authentication",
    "Bulk Data Export":            "164.312(b) — Audit Controls",
    "After-Hours Access":          "164.312(b) — Audit Controls",
    "External IP Access":          "164.312(a)(4) — Transmission Security",
    "Terminated User Activity":    "164.312(a)(2)(i) — Unique User Identification",
    "Unknown User in Access Log":  "164.312(b) — Audit Controls",
}


def _ensure_log_dir():
    """
    Make sure the logs/ directory exists before we try to write to it.
    os.makedirs with exist_ok=True won't crash if the folder is already there.
    """
    log_dir = os.path.dirname(LOG_PATH)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)


def forward_findings(company_name, findings):
    """
    Write each finding from a scan as one JSON line to the Wazuh log file.

    Why one line per finding?
    Wazuh reads log files line by line — each line becomes one event.
    One event = one alert in the Wazuh dashboard.
    If we wrote all findings as one blob, Wazuh would see one event
    and you'd lose the ability to filter/search by individual violations.

    Parameters:
        company_name  — display name, e.g. "Harborview Behavioral Health"
        findings      — list of dicts from run_all_checks(), each with:
                        severity, category, detail, recommendation
    """
    if not findings:
        # Nothing to forward — scan came back clean
        return

    _ensure_log_dir()

    # Open in append mode ("a") so we never overwrite previous scan results.
    # Each run adds new lines to the bottom of the file.
    with open(LOG_PATH, "a", encoding="utf-8") as log_file:
        for finding in findings:
            category = finding.get("category", "Unknown")

            # Build the structured log entry.
            # Every field here becomes searchable in the Wazuh dashboard.
            log_entry = {
                # Wazuh uses the timestamp to sort and correlate events
                "timestamp":    datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),

                # "source" is how our custom Wazuh decoder identifies these logs
                # — it matches the <program_name> tag in the decoder XML
                "source":       "datapulse",

                "company":      company_name,
                "severity":     finding.get("severity", "LOW"),

                # Wazuh rule level — controls alert priority in the dashboard
                "wazuh_level":  SEVERITY_TO_WAZUH_LEVEL.get(
                                    finding.get("severity", "LOW"), 4),

                "category":     category,
                "detail":       finding.get("detail", ""),

                # The HIPAA section this finding violates — key for compliance reports
                "hipaa_ref":    HIPAA_REFS.get(category, "164.312 — General"),

                "recommendation": finding.get("recommendation", ""),
            }

            # json.dumps converts the dict to a single-line JSON string.
            # We write it followed by a newline so each finding is its own line.
            log_file.write(json.dumps(log_entry) + "\n")


def forward_summary(company_name, summary):
    """
    Write a single summary event after all findings are forwarded.
    This gives Wazuh one aggregate event per scan — useful for dashboards
    that track compliance posture over time (e.g., trending CRITICAL count).
    """
    _ensure_log_dir()

    with open(LOG_PATH, "a", encoding="utf-8") as log_file:
        summary_entry = {
            "timestamp":  datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
            "source":     "datapulse",
            "company":    company_name,
            "event_type": "scan_summary",
            "critical":   summary.get("CRITICAL", 0),
            "high":       summary.get("HIGH",     0),
            "medium":     summary.get("MEDIUM",   0),
            "low":        summary.get("LOW",      0),
            "total":      summary.get("total",    0),
            # Overall compliance posture — CRITICAL/HIGH findings = non-compliant
            "hipaa_compliant": summary.get("CRITICAL", 0) == 0 and
                               summary.get("HIGH",     0) == 0,
        }
        log_file.write(json.dumps(summary_entry) + "\n")
