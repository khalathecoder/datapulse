import sqlite3
import os

# Nexus Fintech — a fictional payments company.
# Violations here lean into financial/PCI themes:
# leaked payment keys, contractor over-access, bulk account exports.

DB_PATH = "database/nexus_fintech.db"

def create_database():
    os.makedirs("database", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # "patients" table repurposed as "customers" — same schema, financial data instead of medical.
    # PII violations: SSNs, card numbers, and routing numbers stored in plaintext.
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
        (1, "Trevor Caldwell",   "501-77-3322", "1980-06-14", "ACCT-PREMIUM",  "CC-10482", "Visa ending 4111 on file, billing auto-pay"),
        (2, "Aisha Okonkwo",     "334-88-1100", "1975-11-02", "ACCT-BUSINESS", "CC-20841", "Routing number 021000021, acct 887766554 stored for ACH"),
        (3, "Ben Harrington",    "678-23-9900", "1992-03-19", "ACCT-STANDARD", "CC-30019", "SSN confirmed: 678-23-9900. Card: 4532015112830366"),
        (4, "Mei-Ling Zhao",     "229-44-6781", "1988-08-25", "ACCT-PREMIUM",  "CC-40231", "No notes"),
        (5, "Oscar Ndungu",      "551-66-4490", "1965-12-01", "ACCT-BUSINESS", "CC-50987", "Wire transfer details: SWIFT CHASUS33, acct 112233445"),
    ])

    # Employees — mix of admin contractors and a terminated CFO still active.
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
        (1, "Sandra Voss",       "svoss@nexusfintech.com",      "Nexus2020!",       "admin",    1, None),
        (2, "Ryan Cho",          "rcho@nexusfintech.com",        "password1",        "admin",    1, None),
        (3, "Contractor_Dev1",   "cdev1@nexusfintech.com",       "contract99",       "admin",    1, None),   # contractor with admin!
        (4, "Contractor_Dev2",   "cdev2@nexusfintech.com",       "contract99",       "admin",    1, None),   # contractor with admin!
        (5, "Former CFO Dan",    "dknight@nexusfintech.com",     "FinanceQ1#2023",   "admin",    1, "2023-09-01"),  # terminated CFO, still active!
        (6, "Priya Malhotra",    "pmalhotra@nexusfintech.com",   "secure_priya1",    "analyst",  1, None),
        (7, "Joel Ferreira",     "jferreira@nexusfintech.com",   "joel2021",         "viewer",   1, None),
    ])

    # API credentials — payment gateway keys that haven't been rotated in years.
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
        (1, "Stripe Live",       "DEMO_stripe_9fG3hJkL2mNpQrStUvWxYz", "2018-04-10", "payments-team"),  # 6+ years stale
        (2, "Plaid API",         "plaid_prod_aB3cD4eF5gH6iJ7kL8",      "2020-07-22", "bank-link-team"),
        (3, "Marqeta Issuing",   "mq_prod_DO_NOT_ROTATE_legacy_v1",     "2019-01-15", "card-team"),      # literally says don't rotate
        (4, "Twilio Verify",     "DEMO_twilio_z9y8x7w6v5u4t3s2r1q0p9",  "2021-11-03", "fraud-team"),
        (5, "AWS Prod Account",  "DEMO_aws_AKIAIOSFODNN7_NEXUS_ROOT",   "2017-08-19", "infrastructure"), # 7+ year old ROOT key
    ])

    # Access log — terminated CFO bulk-exporting account data, contractors accessing secrets.
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
        (1, "svoss@nexusfintech.com",    "SELECT", "patients",        12,    "2026-03-28 10:02:11", "10.0.1.5"),
        (2, "dknight@nexusfintech.com",  "SELECT", "patients",        50000, "2026-03-27 01:14:55", "77.88.55.60"),   # terminated CFO, 1am, 50k records, external IP!
        (3, "dknight@nexusfintech.com",  "SELECT", "api_credentials", 5,     "2026-03-27 01:18:02", "77.88.55.60"),   # same session, grabbed all API keys
        (4, "cdev1@nexusfintech.com",    "SELECT", "api_credentials", 5,     "2026-03-28 22:45:33", "10.0.1.88"),     # contractor accessing secrets at 10pm
        (5, "rcho@nexusfintech.com",     "UPDATE", "patients",        3,     "2026-03-28 14:30:00", "10.0.1.9"),
        (6, "unknown_scanner",           "SELECT", "patients",        5000,  "2026-03-29 04:55:12", "45.33.32.156"),  # unknown user, 4am bulk scan
        (7, "pmalhotra@nexusfintech.com","SELECT", "patients",        8,     "2026-03-28 11:10:44", "10.0.1.14"),
    ])

    # Data stores — public S3 with financial records, hardcoded DB password in notes.
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
        (1, "nexus-customer-backups",  "S3 Bucket",   "us-east-1",     1, 1, "2021-03-10", "Public — was set for a vendor audit, never locked back down"),
        (2, "nexus-transactions-prod", "PostgreSQL",  "prod-server-02", 0, 1, "2025-02-01", "Main transactions DB"),
        (3, "nexus-dev-mirror",        "MySQL",       "dev-server-rcho",1, 1, "2020-08-15", "Dev copy — connection string: mysql://admin:DevPass99!@dev-db.internal/nexus"),
        (4, "nexus-analytics",         "Redshift",    "us-west-2",      0, 1, "2024-11-20", "BI dashboards"),
        (5, "nexus-statements-s3",     "S3 Bucket",   "us-east-1",      1, 1, "2019-06-30", "Monthly PDF statements — public bucket, contains full account numbers"),
    ])

    conn.commit()
    conn.close()
    print("[OK] Nexus Fintech database created at:", DB_PATH)
    print("[!] Nexus Fintech is leaking payment data. Time to scan.")

if __name__ == "__main__":
    create_database()
