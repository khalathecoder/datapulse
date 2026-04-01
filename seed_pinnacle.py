import sqlite3
import os

# Pinnacle Law Partners — mid-size litigation and M&A law firm
# Security story: terminated associate still accessing confidential M&A case files,
# paralegals with partner-level permissions, and privileged documents in a public S3.
# Compliance focus: attorney-client privilege, state bar rules, GDPR, ABA Model Rules

DB_PATH = "database/pinnacle_law.db"

def create_database():
    os.makedirs("database", exist_ok=True)
    conn   = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # -------------------------------------------------------
    # TABLE 1: cases
    # Highly sensitive — M&A deals, settlements, client SSNs
    # -------------------------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY,
            full_name TEXT,
            ssn TEXT,
            case_type TEXT,
            opposing_counsel TEXT,
            settlement_amount REAL,
            insurance_id TEXT,
            notes TEXT
        )
    """)
    cursor.executemany("INSERT OR IGNORE INTO cases VALUES (?,?,?,?,?,?,?,?)", [
        (1, "Momentum Corp (Plaintiff)",  "83-4412901", "M&A Due Diligence",  "Sullivan & Cromwell",  0,          "CORP-001", "Pending $2.1B acquisition of Vertex Holdings — NDA in place"),
        (2, "Hargrove v. NexGen LLC",     "N/A",        "Employment Lit.",    "Fisher & Phillips",    485000.00,  "LIT-042",  "Wrongful termination — settlement draft attached"),
        (3, "Estate of R. Fontaine",      "512-98-3301","Probate",            "Pro Se",               1800000.00, "PROB-007", "SSN confirmed: 512-98-3301. Will contested by two parties"),
        (4, "DataStream Inc. (Defense)",  "47-9920312", "IP Litigation",      "Cooley LLP",           0,          "IP-019",   "Trade secret misappropriation — source code exhibits under seal"),
        (5, "City of Maplewood",          "N/A",        "Municipal Contract", "City Solicitor",       350000.00,  "MUN-003",  "Infrastructure contract dispute — $350K claim"),
    ])

    # -------------------------------------------------------
    # TABLE 2: employees
    # Partners, associates, and paralegals — badly permissioned
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
        (1, "Diana Osei",        "dosei@pinnaclelaw.com",     "PinnacleP@rtner1",  "admin",     1, None),
        (2, "Tom Gallagher",     "tgallagher@pinnaclelaw.com","Gallagher2022!",    "admin",     1, None),
        (3, "Paralegal_Anna",    "abrown@pinnaclelaw.com",    "paralegal123",      "admin",     1, None),   # paralegal with full admin access!
        (4, "Paralegal_Chris",   "cjones@pinnaclelaw.com",    "paralegal456",      "admin",     1, None),   # another paralegal as admin!
        (5, "Marcus Bell",       "mbell@pinnaclelaw.com",     "MarcusLaw#2021",   "associate", 1, "2025-09-01"),  # terminated associate — still active!
        (6, "Receptionist_Kay",  "ksmith@pinnaclelaw.com",    "frontdesk99",       "admin",     1, None),   # receptionist as admin!
        (7, "Linda Park",        "lpark@pinnaclelaw.com",     "lpark_review",      "viewer",    1, None),
    ])

    # -------------------------------------------------------
    # TABLE 3: api_credentials
    # Case management, court e-filing, document review platform
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
        (1, "Clio Case Management",    "clio_live_sk_a1b2c3d4e5f6g7h8i9j0", "2020-01-15", "it-admin"),        # 6 year old case management key
        (2, "PACER Court Filing",      "PACER_API_KEY_prod_774ABC123DEF",     "2019-06-30", "litigation-team"), # 7 year old federal court filing key!
        (3, "Relativity eDiscovery",   "REL_PROD_SECRET_99887766aabbccdd",    "2021-09-10", "ediscovery"),
        (4, "DocuSign Agreements",     "DS_integrations_key_PROD_xyzxyz",     "2022-04-22", "client-intake"),
        (5, "NetDocuments DMS",        "ND_API_v2_LIVE_DO_NOT_ROTATE_legacy", "2017-03-01", "legacy-system"),   # says DO NOT ROTATE — 9 years old!
    ])

    # -------------------------------------------------------
    # TABLE 4: access_log
    # Terminated associate accessing M&A files, after-hours doc pulls
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
        (1, "dosei@pinnaclelaw.com",       "SELECT", "cases",          2,    "2026-03-28 09:30:00", "10.0.1.10"),
        (2, "mbell@pinnaclelaw.com",       "SELECT", "cases",          5,    "2026-03-27 22:14:09", "77.88.195.33"),   # terminated associate, 10pm, external IP, M&A files
        (3, "mbell@pinnaclelaw.com",       "SELECT", "api_credentials",5,    "2026-03-27 22:17:44", "77.88.195.33"),   # then accessed API keys!
        (4, "abrown@pinnaclelaw.com",      "SELECT", "cases",          5000, "2026-03-28 02:05:11", "10.0.1.44"),      # paralegal bulk export at 2am
        (5, "ksmith@pinnaclelaw.com",      "SELECT", "cases",          3,    "2026-03-29 11:00:00", "10.0.1.8"),       # receptionist accessing M&A files
        (6, "unknown_user",               "SELECT", "cases",          4,    "2026-03-29 03:48:20", "185.220.101.22"), # unknown user at 3am — confidential M&A!
        (7, "tgallagher@pinnaclelaw.com",  "UPDATE", "cases",          1,    "2026-03-28 16:20:00", "10.0.1.7"),
        (8, "mbell@pinnaclelaw.com",       "SELECT", "cases",          8,    "2026-03-26 01:12:05", "77.88.195.33"),   # second incident same external IP
    ])

    # -------------------------------------------------------
    # TABLE 5: data_store_inventory
    # Privileged M&A documents in a public S3 bucket — nightmare scenario
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
        (1, "pinnacle-discovery-docs",    "S3 Bucket",  "us-east-1",   1, 1, "2021-07-01", "eDiscovery export files — attorney-client privileged documents PUBLIC"),  # privileged docs public!
        (2, "pinnacle-case-db-prod",      "PostgreSQL", "prod-svr-01",  0, 1, "2025-01-10", "Primary case management database"),
        (3, "client-intake-staging",      "MySQL",      "dev-laptop-02",1, 1, "2020-09-15", "Staging: connstr mysql://admin:Law#Firm2019@dev-laptop-02/intake"),  # hardcoded creds!
        (4, "ma-deal-room-s3",            "S3 Bucket",  "us-east-1",   1, 1, "2022-01-20", "M&A deal room — NDA documents, term sheets, financial models — PUBLICLY ACCESSIBLE"),  # public M&A room!
        (5, "matter-archive-2020",        "S3 Bucket",  "us-west-2",   0, 1, "2023-06-01", "Closed matters archive — properly secured"),
    ])

    conn.commit()
    conn.close()
    print("[OK] Pinnacle Law Partners database created at:", DB_PATH)
    print("[!] Privileged M&A docs are public. Former associate is still in the system. Bar complaint incoming.")

if __name__ == "__main__":
    create_database()
