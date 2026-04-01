import sqlite3
import os

# TerraBank Financial Services — regional bank
# Security story: insider threat from a former wire transfer specialist,
# dormant account snooping, and a public S3 bucket with customer statements.
# Compliance focus: GLBA, PCI-DSS, SOX, BSA/AML

DB_PATH = "database/terrabank.db"

def create_database():
    os.makedirs("database", exist_ok=True)
    conn   = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # -------------------------------------------------------
    # TABLE 1: customers
    # Banking PII — account numbers, balances, credit scores
    # -------------------------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY,
            full_name TEXT,
            ssn TEXT,
            account_number TEXT,
            routing_number TEXT,
            balance REAL,
            credit_score INTEGER,
            notes TEXT
        )
    """)
    cursor.executemany("INSERT OR IGNORE INTO customers VALUES (?,?,?,?,?,?,?,?)", [
        (1, "Harold Simmons",    "302-66-9821", "4400123456789",  "021000021", 142300.00, 778, "Preferred banking client"),
        (2, "Deborah Winslow",   "519-44-3302", "4400987654321",  "021000021", 8200.50,   621, "Auto-pay set for mortgage"),
        (3, "Marcus Webb",       "671-28-5540", "4400112233445",  "021000021", 520000.00, 801, "High-net-worth — private banking"),
        (4, "Fatima Al-Hassan",  "408-93-1177", "4400556677889",  "021000021", 3100.75,   589, "Small business checking"),
        (5, "Richard Cho",       "255-87-6634", "4400001122334",  "021000021", 67000.00,  744, "Wire transfer approved — international"),
    ])

    # -------------------------------------------------------
    # TABLE 2: employees
    # Wire transfer desk, compliance, and IT — overpermissioned
    # -------------------------------------------------------
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
        (1, "Sandra Okonkwo",     "sokonkwo@terrabank.com",    "TerraBank#2021",   "admin",            1, None),
        (2, "Paul Estrada",       "pestrada@terrabank.com",    "Banking$ecure1",   "wire-operator",    1, None),
        (3, "Jill Nakamura",      "jnakamura@terrabank.com",   "Compliance99!",    "admin",            1, None),  # compliance officer with full admin
        (4, "Temp_Teller_01",     "teller01@terrabank.com",    "teller123",        "admin",            1, None),  # temp teller with admin!
        (5, "Victor Reyes",       "vreyes@terrabank.com",      "WireDesk2020@",    "wire-operator",    1, "2025-01-10"),  # terminated wire specialist still active!
        (6, "Claire Dubois",      "cdubois@terrabank.com",     "cdubois_pass",     "viewer",           1, None),
        (7, "IT_Contractor_Dan",  "dcontr@terrabank.com",      "Contr@ct0r!",      "admin",            1, "2024-08-01"),  # contractor never deprovisioned
    ])

    # -------------------------------------------------------
    # TABLE 3: api_credentials
    # Fed ACH integration, fraud detection, core banking API
    # -------------------------------------------------------
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
        (1, "Federal Reserve ACH Gateway",  "FED-ACH-LIVE-k9x2mP8qRtVn3wYj",       "2020-02-14", "wire-team"),       # 5 year old key to Fed system!
        (2, "Fiserv Core Banking",          "FISV_PROD_7743aabbcc1122ddeeff",        "2021-11-30", "it-team"),
        (3, "Plaid Account Verification",   "access-prod-sandbox-88xyz99abc",        "2019-07-01", "digital-banking"), # 6 year old third-party key
        (4, "SWIFT Messaging API",          "SWIFTlive_TERRA_91827364ABCD",          "2022-03-15", "international"),
        (5, "Internal Fraud Detection",     "fraud_key_v1_INTERNAL_USE_ONLY_999",    "2018-05-20", "risk-team"),       # nearly 8 years old!
    ])

    # -------------------------------------------------------
    # TABLE 4: access_log
    # Dormant account lookups, wire fraud indicators, after-hours
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
        (1,  "pestrada@terrabank.com",    "SELECT",  "customers",        3,    "2026-03-28 10:11:00", "10.1.0.22"),
        (2,  "vreyes@terrabank.com",      "SELECT",  "customers",        4800, "2026-03-26 01:58:44", "91.108.56.101"),  # terminated wire op, 2am, bulk, external IP
        (3,  "vreyes@terrabank.com",      "UPDATE",  "wire_transfers",   12,   "2026-03-26 02:03:17", "91.108.56.101"),  # same session — modifying wire transfers!
        (4,  "vreyes@terrabank.com",      "SELECT",  "api_credentials",  5,    "2026-03-26 02:04:55", "91.108.56.101"),  # then grabbed API keys
        (5,  "teller01@terrabank.com",    "SELECT",  "customers",        5000, "2026-03-27 23:45:01", "10.1.0.88"),      # temp teller bulk export at midnight
        (6,  "dcontr@terrabank.com",      "SELECT",  "customers",        12,   "2026-03-29 08:30:00", "203.0.113.55"),   # terminated contractor still logging in
        (7,  "sokonkwo@terrabank.com",    "SELECT",  "customers",        2,    "2026-03-28 14:00:00", "10.1.0.5"),
        (8,  "unknown_user",             "SELECT",  "wire_transfers",   20,   "2026-03-29 04:22:33", "185.220.101.47"), # unknown user accessing wire transfers at 4am!
    ])

    # -------------------------------------------------------
    # TABLE 5: data_store_inventory
    # Customer statements in public S3 — huge GLBA violation
    # -------------------------------------------------------
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
        (1, "terrabank-statements-archive",  "S3 Bucket",  "us-east-1",    1, 1, "2021-04-10", "Monthly customer PDF statements — public since migration"),  # public S3 with financial statements!
        (2, "terrabank-core-db",             "PostgreSQL", "prod-db-01",   0, 1, "2025-02-01", "Core banking DB"),
        (3, "wire-transfer-staging",         "MySQL",      "staging-02",   1, 1, "2020-08-15", "Staging DB — connstr: mysql://root:TerraRoot!2018@staging-02/wires"),  # public staging with hardcoded creds!
        (4, "fraud-analytics-dw",            "Snowflake",  "us-west-2",    0, 1, "2024-11-01", "Risk team data warehouse"),
        (5, "loan-documents-s3",             "S3 Bucket",  "us-east-1",    1, 1, "2019-12-01", "Loan applications — SSNs and income data included"),  # another public S3!
    ])

    conn.commit()
    conn.close()
    print("[OK] TerraBank Financial Services database created at:", DB_PATH)
    print("[!] Wire transfers, dormant account access, and stale Fed API keys. Run the scanner.")

if __name__ == "__main__":
    create_database()
