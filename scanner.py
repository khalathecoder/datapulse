import sqlite3
import re
from datetime import datetime, date

# This is the path to our fake hospital's database file.
# SQLite is a simple file-based database — no server needed, just a .db file on disk.
DB_PATH = "database/datapulse.db"

# Separate shared database just for storing scan history across all companies.
# We keep this in its own file so it never interferes with the company scan DBs.
HISTORY_DB_PATH = "database/datapulse.db"


# ─────────────────────────────────────────────────────────────────────────────
# HISTORY DB SETUP
# Creates the scan_history table if it doesn't exist yet.
# Called once when the Flask app starts up.
# "CREATE TABLE IF NOT EXISTS" means it's safe to run every startup —
# it only creates the table if it isn't already there.
# ─────────────────────────────────────────────────────────────────────────────
def init_history_db():
    conn = sqlite3.connect(HISTORY_DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            company_key  TEXT    NOT NULL,
            company_name TEXT    NOT NULL,
            scanned_at   TEXT    NOT NULL,
            critical     INTEGER DEFAULT 0,
            high         INTEGER DEFAULT 0,
            medium       INTEGER DEFAULT 0,
            low          INTEGER DEFAULT 0,
            total        INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# LOG A SCAN
# Inserts one row into scan_history every time a company is scanned.
# company_key  — short key like "meridian" (used in URLs)
# company_name — display name like "Meridian Health Systems"
# summary      — dict from get_summary() with CRITICAL/HIGH/MEDIUM/LOW/total
# ─────────────────────────────────────────────────────────────────────────────
def log_scan(company_key, company_name, summary):
    conn = sqlite3.connect(HISTORY_DB_PATH)
    conn.execute("""
        INSERT INTO scan_history (company_key, company_name, scanned_at, critical, high, medium, low, total)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        company_key,
        company_name,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        summary.get("CRITICAL", 0),
        summary.get("HIGH",     0),
        summary.get("MEDIUM",   0),
        summary.get("LOW",      0),
        summary.get("total",    0),
    ))
    conn.commit()
    conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# GET SCAN HISTORY
# Returns the last 50 scans for a given company, newest first.
# ─────────────────────────────────────────────────────────────────────────────
def get_scan_history(company_key):
    conn = sqlite3.connect(HISTORY_DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, company_name, scanned_at, critical, high, medium, low, total
        FROM scan_history
        WHERE company_key = ?
        ORDER BY scanned_at DESC
        LIMIT 50
    """, (company_key,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def get_connection(db_path=None):
    # Open a connection to the SQLite database.
    # sqlite3.Row makes each row behave like a dictionary,
    # so we can access columns by name (e.g. row["email"]) instead of index (row[0]).
    # db_path lets us swap which company's database we connect to.
    conn = sqlite3.connect(db_path or DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ─────────────────────────────────────────────────────────────────────────────
# CHECK 1: Plaintext Passwords
# We look at the employees table and flag anyone whose password is stored
# as plain readable text. Real systems should store a "hash" — a scrambled
# one-way version of the password — never the actual password itself.
# ─────────────────────────────────────────────────────────────────────────────
def check_plaintext_passwords(db_path=None):
    conn = get_connection(db_path)
    cursor = conn.cursor()

    # Pull every employee's name, email, role, and password from the table.
    cursor.execute("SELECT full_name, email, role, password FROM employees")
    employees = cursor.fetchall()
    conn.close()

    findings = []
    for emp in employees:
        # If there's any value in the password column, it's stored in plaintext.
        # A properly secured system would never store the real password here.
        if emp["password"]:
            findings.append({
                "severity": "CRITICAL",
                "category": "Plaintext Password",
                "detail": f'{emp["full_name"]} ({emp["email"]}) — role: {emp["role"]}',
                "recommendation": "Passwords must be hashed using bcrypt or Argon2 before storing."
            })

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# CHECK 2: Terminated Employees Still Active
# If someone was fired or left the company, their account should be disabled
# immediately. Active accounts for ex-employees are a major security risk —
# they could still log in and access sensitive data.
# ─────────────────────────────────────────────────────────────────────────────
def check_terminated_active_users(db_path=None):
    conn = get_connection(db_path)
    cursor = conn.cursor()

    # Find employees who have a termination date (meaning they left)
    # but whose account is still marked as active (is_active = 1).
    cursor.execute("""
        SELECT full_name, email, role, termination_date
        FROM employees
        WHERE termination_date IS NOT NULL AND is_active = 1
    """)
    terminated = cursor.fetchall()
    conn.close()

    findings = []
    for emp in terminated:
        findings.append({
            "severity": "HIGH",
            "category": "Terminated User Still Active",
            "detail": f'{emp["full_name"]} ({emp["email"]}) — terminated {emp["termination_date"]}, still active',
            "recommendation": "Disable or delete accounts immediately upon employee termination."
        })

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# CHECK 3: Over-Permissioned Users (Interns with Admin Access)
# The "principle of least privilege" means users should only have the
# minimum access they need. Interns having admin-level access is a huge
# red flag — they can read, modify, or delete anything.
# ─────────────────────────────────────────────────────────────────────────────
def check_overpermissioned_users(db_path=None):
    conn = get_connection(db_path)
    cursor = conn.cursor()

    # Find any user whose name suggests a lower-trust role (intern, temp, contractor)
    # but who has admin privileges.
    cursor.execute("""
        SELECT full_name, email, role
        FROM employees
        WHERE role = 'admin'
        AND (
            full_name LIKE '%Intern%'
            OR full_name LIKE '%Temp%'
            OR full_name LIKE '%Contractor%'
        )
    """)
    risky_users = cursor.fetchall()
    conn.close()

    findings = []
    for user in risky_users:
        findings.append({
            "severity": "HIGH",
            "category": "Over-Permissioned User",
            "detail": f'{user["full_name"]} ({user["email"]}) has role: {user["role"]}',
            "recommendation": "Restrict interns/temps to viewer or analyst roles. Apply least-privilege access."
        })

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# CHECK 4: Stale API Credentials
# API keys are like passwords for software integrations. They should be
# rotated (replaced with new ones) regularly. Keys that haven't been
# rotated in over a year are a liability — if leaked, they're still valid.
# ─────────────────────────────────────────────────────────────────────────────
def check_stale_api_keys(db_path=None):
    conn = get_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT service_name, api_key, last_rotated, owner FROM api_credentials")
    keys = cursor.fetchall()
    conn.close()

    findings = []
    today = date.today()

    for key in keys:
        # Parse the last_rotated string into a real date object so we can do math on it.
        last_rotated = datetime.strptime(key["last_rotated"], "%Y-%m-%d").date()

        # Calculate how many days it's been since the key was last rotated.
        days_old = (today - last_rotated).days

        # Flag anything older than 365 days (1 year).
        if days_old > 365:
            # Mask the API key so we're not exposing it in the UI — show first 6 chars only.
            masked_key = key["api_key"][:6] + "..." if len(key["api_key"]) > 6 else "***"
            findings.append({
                "severity": "CRITICAL" if days_old > 1000 else "HIGH",
                "category": "Stale API Key",
                "detail": f'{key["service_name"]} (owner: {key["owner"]}) — key {masked_key} last rotated {key["last_rotated"]} ({days_old} days ago)',
                "recommendation": "Rotate API keys every 90 days. Immediately revoke and replace keys older than 1 year."
            })

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# CHECK 5: Public Data Stores Containing PII
# Some of our storage locations (like S3 buckets) are marked as publicly
# accessible. If they also contain PII (Personally Identifiable Information
# like SSNs, medical records), that's a major compliance violation —
# especially under HIPAA for healthcare data.
# ─────────────────────────────────────────────────────────────────────────────
def check_public_data_stores(db_path=None):
    conn = get_connection(db_path)
    cursor = conn.cursor()

    # Find any data store that is publicly accessible AND contains PII.
    cursor.execute("""
        SELECT store_name, store_type, location, last_audited, notes
        FROM data_store_inventory
        WHERE public_access = 1 AND contains_pii = 1
    """)
    exposed_stores = cursor.fetchall()
    conn.close()

    findings = []
    for store in exposed_stores:
        findings.append({
            "severity": "CRITICAL",
            "category": "Public Data Store with PII",
            "detail": f'{store["store_name"]} ({store["store_type"]}, {store["location"]}) — last audited: {store["last_audited"]}',
            "recommendation": "Immediately restrict public access. Enable encryption at rest. Audit who has accessed this store."
        })

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# CHECK 6: Hardcoded Credentials in Notes Fields
# Developers sometimes paste passwords, connection strings, or secrets into
# notes fields as a shortcut. This is dangerous because those notes fields
# are rarely protected the same way credentials stores are.
# ─────────────────────────────────────────────────────────────────────────────
def check_hardcoded_credentials(db_path=None):
    conn = get_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT store_name, notes FROM data_store_inventory WHERE notes IS NOT NULL")
    stores = cursor.fetchall()
    conn.close()

    # These are patterns we search for — things that look like passwords or connection strings.
    # re.compile() builds a reusable "pattern matcher" (a regex).
    suspicious_patterns = [
        re.compile(r"password=\S+", re.IGNORECASE),       # e.g. password=devpass123
        re.compile(r"secret[_\s]*[:=]\s*\S+", re.IGNORECASE),  # e.g. secret: abc123
        re.compile(r"sqlite:///", re.IGNORECASE),           # database connection string
    ]

    findings = []
    for store in stores:
        for pattern in suspicious_patterns:
            # Search the notes field for anything that looks like a credential.
            if pattern.search(store["notes"]):
                findings.append({
                    "severity": "HIGH",
                    "category": "Hardcoded Credential in Notes",
                    "detail": f'{store["store_name"]} — notes contain a potential credential or connection string',
                    "recommendation": "Remove all credentials from notes fields. Use a secrets manager (e.g. AWS Secrets Manager, HashiCorp Vault)."
                })
                break  # Only report once per store even if multiple patterns match

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# CHECK 7: Anomalous Access Log Activity
# We scan the access log for patterns that look suspicious:
#   - Bulk data exports (grabbing thousands of records at once)
#   - Logins from external/foreign IP addresses
#   - Activity at unusual hours (between midnight and 5am)
#   - Terminated employees still appearing in logs (active after their end date)
#   - Unknown or unrecognized user accounts
# ─────────────────────────────────────────────────────────────────────────────
def check_anomalous_access(db_path=None):
    conn = get_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, user_email, action, table_accessed, record_count, timestamp, ip_address
        FROM access_log
    """)
    logs = cursor.fetchall()

    # Also pull all known employee emails so we can spot unknown users.
    cursor.execute("SELECT email, termination_date FROM employees")
    employee_map = {row["email"]: row["termination_date"] for row in cursor.fetchall()}
    conn.close()

    findings = []

    for log in logs:
        # Parse the timestamp string into a real datetime so we can check the hour.
        timestamp = datetime.strptime(log["timestamp"], "%Y-%m-%d %H:%M:%S")
        hour = timestamp.hour
        ip = log["ip_address"]

        # A "private" IP starts with 10., 192.168., or 172.x — these are internal network IPs.
        # Anything else is considered external (coming from outside the company network).
        is_internal_ip = (
            ip.startswith("10.") or
            ip.startswith("192.168.") or
            ip.startswith("172.")
        )

        # ── Flag 1: Bulk export ──────────────────────────────────────────────
        # Grabbing more than 1000 records in a single query is unusual and
        # could indicate data exfiltration (someone stealing data).
        if log["record_count"] and log["record_count"] > 1000:
            findings.append({
                "severity": "CRITICAL",
                "category": "Bulk Data Export",
                "detail": f'{log["user_email"]} exported {log["record_count"]} records from {log["table_accessed"]} at {log["timestamp"]} from {ip}',
                "recommendation": "Investigate immediately. Implement row-level export limits and alerts for bulk queries."
            })

        # ── Flag 2: After-hours access ───────────────────────────────────────
        # Access between midnight (0:00) and 5:00am is unusual for a health company.
        if hour < 5:
            findings.append({
                "severity": "MEDIUM",
                "category": "After-Hours Access",
                "detail": f'{log["user_email"]} accessed {log["table_accessed"]} at {log["timestamp"]} (hour: {hour:02d}:xx)',
                "recommendation": "Review after-hours access policies. Consider time-based access controls."
            })

        # ── Flag 3: External IP access ───────────────────────────────────────
        if not is_internal_ip:
            findings.append({
                "severity": "HIGH",
                "category": "External IP Access",
                "detail": f'{log["user_email"]} accessed {log["table_accessed"]} from external IP {ip} at {log["timestamp"]}',
                "recommendation": "Enforce VPN requirements for remote access. Whitelist approved IP ranges."
            })

        # ── Flag 4: Terminated user activity ────────────────────────────────
        # If the user appears in our employee list and has a termination date,
        # they should NOT be appearing in access logs after that date.
        if log["user_email"] in employee_map:
            term_date = employee_map[log["user_email"]]
            if term_date:
                term_dt = datetime.strptime(term_date, "%Y-%m-%d")
                if timestamp > term_dt:
                    findings.append({
                        "severity": "CRITICAL",
                        "category": "Terminated User Activity",
                        "detail": f'{log["user_email"]} (terminated {term_date}) accessed {log["table_accessed"]} at {log["timestamp"]}',
                        "recommendation": "Disable accounts on termination date. Audit all post-termination activity for data theft."
                    })
        else:
            # ── Flag 5: Unknown user ─────────────────────────────────────────
            # If the email isn't in our employee list at all, it's an unknown actor.
            findings.append({
                "severity": "CRITICAL",
                "category": "Unknown User in Access Log",
                "detail": f'Unrecognized user "{log["user_email"]}" accessed {log["table_accessed"]} at {log["timestamp"]} from {ip}',
                "recommendation": "Investigate immediately. Unknown accounts may indicate credential compromise or an insider threat."
            })

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# MAIN RUNNER: run_all_checks()
# This is the function our Flask app will call. It runs every check above,
# combines all the findings into one list, and returns them sorted by severity.
# ─────────────────────────────────────────────────────────────────────────────
def run_all_checks(db_path=None):
    # Run every check function and combine their results into one big list.
    all_findings = (
        check_plaintext_passwords(db_path) +
        check_terminated_active_users(db_path) +
        check_overpermissioned_users(db_path) +
        check_stale_api_keys(db_path) +
        check_public_data_stores(db_path) +
        check_hardcoded_credentials(db_path) +
        check_anomalous_access(db_path)
    )

    # Sort findings by severity so the most dangerous ones appear first.
    # We define a custom order: CRITICAL > HIGH > MEDIUM > LOW.
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    all_findings.sort(key=lambda f: severity_order.get(f["severity"], 99))

    return all_findings


# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY STATS
# A helper that counts findings by severity — used to show the dashboard totals.
# ─────────────────────────────────────────────────────────────────────────────
def get_summary(findings):
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "total": len(findings)}
    for f in findings:
        severity = f.get("severity", "LOW")
        if severity in summary:
            summary[severity] += 1
    return summary
