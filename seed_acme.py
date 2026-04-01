import sqlite3
import os

# This script creates our fake "Acme Health Corp" database
# It's intentionally full of security violations — that's the point
# DataPulse will scan this and find all of them

DB_PATH = "database/acme_health.db"

def create_database():
    # Make the database folder if it doesn't exist
    os.makedirs("database", exist_ok=True)
    
    # Connect to SQLite — creates the file if it doesn't exist
    # Think of this like opening a SQL Server connection at Solventum
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # -------------------------------------------------------
    # TABLE 1: patients
    # VIOLATIONS: PII/PHI stored in plaintext, no encryption
    # -------------------------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS patients (
            id INTEGER PRIMARY KEY,
            full_name TEXT,
            ssn TEXT,              -- PII: Social Security Number in plaintext
            date_of_birth TEXT,
            diagnosis_code TEXT,   -- PHI: Medical data
            insurance_id TEXT,
            notes TEXT             -- PHI: Freetext, may contain embedded PII
        )
    """)

    cursor.executemany("INSERT OR IGNORE INTO patients VALUES (?,?,?,?,?,?,?)", [
        (1, "Margaret Collins", "532-88-1234", "1962-04-11", "E11.9", "INS-00423", "Patient mentioned Visa card ending 4242 for copay"),
        (2, "James Whitfield", "291-55-9876", "1978-09-03", "J45.50", "INS-00891", "Recurring patient, no issues"),
        (3, "Priya Nandakumar", "774-32-5511", "1990-12-28", "F32.1", "INS-01204", "SSN confirmed on intake: 774-32-5511"),
        (4, "Carlos Mendez",    "448-71-0023", "1955-07-17", "I10",   "INS-00312", "Patient shared bank routing number 021000021 for billing"),
        (5, "Susan Park",       "663-44-8821", "1983-02-05", "M79.3", "INS-02019", "No notes"),
    ])

    # -------------------------------------------------------
    # TABLE 2: employees
    # VIOLATIONS: plaintext passwords, overpermissioned interns,
    # terminated employees still active
    # -------------------------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY,
            full_name TEXT,
            email TEXT,
            password TEXT,         -- CRITICAL: plaintext passwords
            role TEXT,             -- HIGH: role assignments not reviewed
            is_active INTEGER,     -- HIGH: terminated users still active
            termination_date TEXT
        )
    """)

    cursor.executemany("INSERT OR IGNORE INTO employees VALUES (?,?,?,?,?,?,?)", [
        (1, "Dana Powell",    "dpowell@acmehealth.com",   "password123",      "admin",     1, None),
        (2, "Kevin Tran",     "ktran@acmehealth.com",     "acme2019!",        "admin",     1, None),
        (3, "Intern_01",      "intern1@acmehealth.com",   "intern123",        "admin",     1, None),  # intern with admin!
        (4, "Intern_02",      "intern2@acmehealth.com",   "intern123",        "admin",     1, None),  # intern with admin!
        (5, "Rachel Gomez",   "rgomez@acmehealth.com",    "Summer2021#",      "analyst",   1, "2024-11-15"),  # terminated but active!
        (6, "Former_IT_Dan",  "dmorris@acmehealth.com",   "ChangeMe!1",       "admin",     1, "2023-06-30"),  # terminated admin!
        (7, "Lena Shaw",      "lshaw@acmehealth.com",     "lena_secure99",    "viewer",    1, None),
    ])

    # -------------------------------------------------------
    # TABLE 3: api_credentials
    # VIOLATIONS: secrets in plaintext, severely stale rotation
    # -------------------------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS api_credentials (
            id INTEGER PRIMARY KEY,
            service_name TEXT,
            api_key TEXT,          -- CRITICAL: plaintext secrets
            last_rotated TEXT,     -- CRITICAL: rotation history
            owner TEXT
        )
    """)

    cursor.executemany("INSERT OR IGNORE INTO api_credentials VALUES (?,?,?,?,?)", [
        (1, "Stripe Payments",   "DEMO_stripe_4eC39HqLyjWDarjtT1zdp7dc",  "2019-03-01", "billing-team"),  # 5+ years stale
        (2, "Twilio SMS",        "DEMO_twilio_a1b2c3d4e5f6a1b2c3d4e5f6", "2021-08-14", "dev-team"),
        (3, "Internal API",      "internal_secret_key_v1_DO_NOT_SHARE",   "2018-11-22", "legacy-system"),  # literally says do not share
        (4, "SendGrid Email",    "DEMO_sendgrid_xKj8mNpQ2rTuVwXyZ0aB1c", "2022-01-09", "marketing"),
        (5, "AWS Root Account",  "DEMO_aws_AKIAIOSFODNN7_ROOT_KEY",        "2020-05-30", "infrastructure"),  # ROOT key!!!
    ])

    # -------------------------------------------------------
    # TABLE 4: access_log
    # VIOLATIONS: anomalous access, terminated user activity,
    # bulk exports at odd hours
    # -------------------------------------------------------
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
        (1,  "dpowell@acmehealth.com",  "SELECT",       "patients",        5,     "2026-03-28 09:14:22", "10.0.0.12"),
        (2,  "rgomez@acmehealth.com",   "SELECT",       "patients",        10000, "2026-03-25 02:47:11", "185.220.101.45"),  # terminated user, 2am, bulk export, external IP!
        (3,  "rgomez@acmehealth.com",   "SELECT",       "api_credentials", 5,     "2026-03-25 02:51:03", "185.220.101.45"),  # same session, accessed secrets
        (4,  "intern1@acmehealth.com",  "DELETE",       "patients",        3,     "2026-03-27 14:22:09", "10.0.0.88"),      # intern deleting patient records!
        (5,  "dmorris@acmehealth.com",  "SELECT",       "employees",       7,     "2026-03-29 08:05:44", "203.0.113.77"),   # terminated admin still accessing
        (6,  "lshaw@acmehealth.com",    "SELECT",       "patients",        2,     "2026-03-28 11:30:00", "10.0.0.15"),
        (7,  "ktran@acmehealth.com",    "UPDATE",       "patients",        1,     "2026-03-28 13:45:17", "10.0.0.9"),
        (8,  "unknown_user",            "SELECT",       "api_credentials", 5,     "2026-03-29 03:12:55", "91.108.4.100"),   # unknown user at 3am
    ])

    # -------------------------------------------------------
    # TABLE 5: data_store_inventory
    # VIOLATIONS: public S3 bucket, exposed connection strings
    # -------------------------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS data_store_inventory (
            id INTEGER PRIMARY KEY,
            store_name TEXT,
            store_type TEXT,
            location TEXT,
            public_access INTEGER,  -- HIGH: should never be 1 for sensitive data
            contains_pii INTEGER,
            last_audited TEXT,
            notes TEXT
        )
    """)

    cursor.executemany("INSERT OR IGNORE INTO data_store_inventory VALUES (?,?,?,?,?,?,?,?)", [
        (1, "patient-backups-prod",   "S3 Bucket",   "us-east-1",          1, 1, "2022-06-01", "Public access enabled — legacy config"),  # public S3 with PII!
        (2, "acme-db-prod",           "PostgreSQL",  "prod-server-01",      0, 1, "2025-01-15", "Main prod DB"),
        (3, "dev-test-db",            "SQLite",      "dev-laptop-ktran",    1, 1, "2021-03-10", "Dev DB — connection string: sqlite:///C:/dev/acme_test.db?password=devpass123"),  # hardcoded creds!
        (4, "analytics-warehouse",    "Snowflake",   "us-west-2",           0, 1, "2024-09-20", "BI team access"),
        (5, "email-archive-s3",       "S3 Bucket",   "us-east-1",          1, 0, "2020-11-01", "Old marketing emails — public, assumed safe"),
    ])

    conn.commit()
    conn.close()
    print("[OK] DataPulse database created at:", DB_PATH)
    print("[!] Acme Health Corp is WIDE open. Time to scan.")

if __name__ == "__main__":
    create_database()