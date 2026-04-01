import sqlite3
import os

# Orbital DevCo — a fictional SaaS/cloud infrastructure company.
# Violations here lean into DevOps/secrets sprawl themes:
# everyone is an admin, GitHub/AWS tokens everywhere, zero key rotation culture.

DB_PATH = "database/orbital_devco.db"

def create_database():
    os.makedirs("database", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Customer data — less medical/financial PII, but still SSNs and personal info
    # that shouldn't be stored in plaintext in a SaaS platform.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS patients (
            id INTEGER PRIMARY KEY,
            full_name TEXT,
            ssn TEXT,
            date_of_birth TEXT,
            diagnosis_code TEXT,
            insurance_id TEXT,
            notes TEXT
        )
    """)
    cursor.executemany("INSERT OR IGNORE INTO patients VALUES (?,?,?,?,?,?,?)", [
        (1, "Kyle Brennan",      "412-55-7890", "1987-04-22", "PLAN-ENTERPRISE", "ORB-1001", "Slack user ID U04XYZ — linked to billing"),
        (2, "Fatima Al-Hassan",  "308-91-2234", "1993-07-11", "PLAN-STARTUP",    "ORB-1002", "No notes"),
        (3, "Dev Patel",         "719-44-6631", "1990-01-30", "PLAN-ENTERPRISE", "ORB-1003", "SSN on file: 719-44-6631. API token: orb_live_xK9mP2qR"),
        (4, "Nina Kowalski",     "554-28-1190", "1982-09-05", "PLAN-GROWTH",     "ORB-1004", "No notes"),
        (5, "Ethan Graves",      "631-77-4420", "1995-03-18", "PLAN-STARTUP",    "ORB-1005", "No notes"),
    ])

    # Employees — classic DevOps org: almost everyone is an admin because
    # "we're all engineers here." Two former employees still active.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY,
            full_name TEXT,
            email TEXT,
            password TEXT,
            role TEXT,
            is_active INTEGER,
            termination_date TEXT
        )
    """)
    cursor.executemany("INSERT OR IGNORE INTO employees VALUES (?,?,?,?,?,?,?)", [
        (1, "Marco Reyes",       "mreyes@orbitaldevco.com",    "orbital123",       "admin",    1, None),
        (2, "Tasha Nkemdirim",   "tnkemdirim@orbitaldevco.com","Tasha2019!",       "admin",    1, None),
        (3, "Intern_SWE_01",     "intern_swe1@orbitaldevco.com","intern2024",      "admin",    1, None),   # intern with prod admin access
        (4, "Contractor_Ops",    "ops_ext@orbitaldevco.com",   "ops_pass_temp",    "admin",    1, None),   # contractor with full admin
        (5, "Former_CTO_Alex",   "alex@orbitaldevco.com",      "CTO_Orbital#1",    "admin",    1, "2024-03-01"),  # CTO left, account still live
        (6, "Former_DevOps_Sam", "sam@orbitaldevco.com",       "samdevops99",      "admin",    1, "2025-01-10"),  # DevOps engineer, recently left
        (7, "Priti Sundaram",    "psundaram@orbitaldevco.com", "priti_secure22",   "analyst",  1, None),
    ])

    # API credentials — GitHub tokens, AWS keys, Slack webhooks, all ancient.
    # This is the "we'll rotate it later" company where later never comes.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS api_credentials (
            id INTEGER PRIMARY KEY,
            service_name TEXT,
            api_key TEXT,
            last_rotated TEXT,
            owner TEXT
        )
    """)
    cursor.executemany("INSERT OR IGNORE INTO api_credentials VALUES (?,?,?,?,?)", [
        (1, "GitHub Actions Token",  "ghp_xKj8mNpQ2rTuVwXyZ0aB1cOrbital",  "2020-02-14", "devops-team"),  # 5+ years stale
        (2, "AWS Prod Deploy Key",   "DEMO_aws_AKIAIOSFODNN7_ORBITAL",       "2019-09-01", "infrastructure"),
        (3, "Datadog API",           "orbital_dd_PROD_DO_NOT_TOUCH_v0",      "2021-03-22", "monitoring"),   # do not touch = hasn't been touched
        (4, "Slack Webhook",         "https://hooks.slack.com/services/T0/B0/orbital_webhook_secret", "2018-06-10", "eng-team"),
        (5, "PagerDuty Key",         "orb_pd_integration_key_prod_legacy",   "2022-04-17", "oncall-team"),
    ])

    # Access log — former CTO and DevOps engineer accessing prod after termination,
    # intern pushing changes to production tables.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS access_log (
            id INTEGER PRIMARY KEY,
            user_email TEXT,
            action TEXT,
            table_accessed TEXT,
            record_count INTEGER,
            timestamp TEXT,
            ip_address TEXT
        )
    """)
    cursor.executemany("INSERT OR IGNORE INTO access_log VALUES (?,?,?,?,?,?,?)", [
        (1, "mreyes@orbitaldevco.com",      "SELECT", "patients",        5,    "2026-03-28 09:55:00", "10.0.2.5"),
        (2, "alex@orbitaldevco.com",         "SELECT", "api_credentials", 5,    "2026-03-29 07:44:21", "198.51.100.23"),  # terminated CTO accessing secrets
        (3, "sam@orbitaldevco.com",          "SELECT", "patients",        2500, "2026-03-28 23:10:05", "203.0.113.88"),   # recently terminated, late night bulk pull
        (4, "intern_swe1@orbitaldevco.com",  "DELETE", "patients",        2,    "2026-03-27 16:02:44", "10.0.2.71"),      # intern deleting customer records
        (5, "intern_swe1@orbitaldevco.com",  "SELECT", "api_credentials", 5,    "2026-03-27 16:05:11", "10.0.2.71"),      # same intern then grabbed all secrets
        (6, "ops_ext@orbitaldevco.com",      "UPDATE", "patients",        15,   "2026-03-28 02:30:00", "10.0.2.90"),      # contractor running updates at 2am
        (7, "psundaram@orbitaldevco.com",    "SELECT", "patients",        3,    "2026-03-28 10:20:00", "10.0.2.12"),
    ])

    # Data stores — public S3, hardcoded secrets in notes, dev DB with real data.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS data_store_inventory (
            id INTEGER PRIMARY KEY,
            store_name TEXT,
            store_type TEXT,
            location TEXT,
            public_access INTEGER,
            contains_pii INTEGER,
            last_audited TEXT,
            notes TEXT
        )
    """)
    cursor.executemany("INSERT OR IGNORE INTO data_store_inventory VALUES (?,?,?,?,?,?,?,?)", [
        (1, "orbital-customer-data",    "S3 Bucket",  "us-west-2",      1, 1, "2020-11-01", "Public — terraform misconfiguration, never caught in review"),
        (2, "orbital-prod-postgres",    "PostgreSQL", "prod-server-03",  0, 1, "2025-03-01", "Main app DB"),
        (3, "orbital-dev-db",           "PostgreSQL", "dev-server-mreyes",1,1, "2021-07-14", "Dev DB uses prod data copy — conn: postgresql://orbital:DevSecret123@dev.orbital.internal/app"),
        (4, "orbital-logs-s3",          "S3 Bucket",  "us-west-2",       1, 0, "2023-01-05", "Log archive — public, assumed non-sensitive but contains IP + user agent logs"),
        (5, "orbital-backups",          "S3 Bucket",  "us-east-1",       1, 1, "2019-04-20", "Nightly DB backups — bucket made public during a 2019 migration, never reverted"),
    ])

    conn.commit()
    conn.close()
    print("[OK] Orbital DevCo database created at:", DB_PATH)
    print("[!] Orbital DevCo left the door wide open. Time to scan.")

if __name__ == "__main__":
    create_database()
