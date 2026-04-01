import sqlite3
import os

# MedRx Pharmacy Network — regional chain of 14 pharmacies
# Security story: terminated pharmacist retains DEA system access, cashiers have
# pharmacist-level DB permissions, and Schedule II prescription records are in a public S3.
# Compliance focus: HIPAA, DEA 21 CFR Part 1304, state board of pharmacy rules

DB_PATH = "database/medrx_pharmacy.db"

def create_database():
    os.makedirs("database", exist_ok=True)
    conn   = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # -------------------------------------------------------
    # TABLE 1: prescriptions
    # PHI + DEA controlled substance records
    # Schedule II drugs (oxycodone, adderall) are highly regulated
    # -------------------------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS prescriptions (
            id INTEGER PRIMARY KEY,
            full_name TEXT,
            ssn TEXT,
            drug_name TEXT,
            dea_schedule TEXT,
            insurance_id TEXT,
            notes TEXT
        )
    """)
    cursor.executemany("INSERT OR IGNORE INTO prescriptions VALUES (?,?,?,?,?,?,?)", [
        (1, "Dorothy Haines",    "441-77-2290", "Oxycodone 10mg",        "Schedule II",  "INS-8821", "Chronic pain management — 90 day supply"),
        (2, "George Yuen",       "309-55-8814", "Adderall XR 30mg",      "Schedule II",  "INS-4401", "ADHD — college student"),
        (3, "Maria Santos",      "672-13-9940", "Metformin 500mg",        "Non-controlled","INS-2201","Type 2 diabetes"),
        (4, "Terrence Booker",   "188-96-3305", "Suboxone 8mg/2mg",       "Schedule III", "INS-9934", "MAT program — buprenorphine/naloxone"),
        (5, "Cynthia Park",      "503-44-7712", "Fentanyl Patch 50mcg",   "Schedule II",  "INS-3380", "Palliative care — requires biennial DEA audit trail"),
    ])

    # -------------------------------------------------------
    # TABLE 2: employees
    # Pharmacists, techs, cashiers — wildly overpermissioned
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
        (1, "Dr. Helen Marsh",   "hmarsh@medrx.com",      "PharmD#secure1",    "admin",      1, None),
        (2, "Cashier_Tyler",     "twright@medrx.com",     "tyler123",          "admin",      1, None),  # cashier with full admin!
        (3, "Cashier_Brenda",    "bfoster@medrx.com",     "brenda456",         "admin",      1, None),  # another cashier as admin!
        (4, "Tech_Marcus",       "mthomas@medrx.com",     "marcustech",        "admin",      1, None),  # pharmacy tech as admin
        (5, "Dr. James Cole",    "jcole@medrx.com",       "PharmD_Cole2020!",  "pharmacist", 1, "2025-08-01"),  # terminated pharmacist — DEA access still active!
        (6, "Delivery_Driver_01","driver01@medrx.com",    "driver2025",        "admin",      1, None),   # delivery driver as admin!
        (7, "Dr. Rita Okafor",   "rokafor@medrx.com",     "rokafor_view",      "viewer",     1, None),
    ])

    # -------------------------------------------------------
    # TABLE 3: api_credentials
    # DEA CSOS, pharmacy benefit managers, state PDMP system
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
        (1, "DEA CSOS e-Order System",   "DEA_CSOS_MEDRX_PROD_k8x2nP9qRt",      "2019-04-01", "pharmacy-ops"),   # 7 year old DEA system key!
        (2, "Express Scripts PBM",        "ESI_PROD_API_medrx_334aabb7788cc",     "2021-02-14", "billing-team"),
        (3, "State PDMP Integration",     "PDMP_TX_MEDRX_live_991827ABCD",        "2020-09-30", "compliance"),     # 5+ year old PDMP key
        (4, "CVS Caremark Adjudication",  "CARK_api_MEDRX_0011223344AABB",        "2022-07-01", "insurance"),
        (5, "Internal Rx Database",       "INTERNAL_RX_SECRET_v1_LEGACY_KEEP",    "2017-11-01", "legacy-system"),  # 9 year old internal key that says KEEP!
    ])

    # -------------------------------------------------------
    # TABLE 4: access_log
    # Terminated pharmacist accessing Schedule II records,
    # cashier running reports on controlled substances
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
        (1,  "hmarsh@medrx.com",    "SELECT",  "prescriptions",    3,    "2026-03-28 09:00:00", "10.2.0.5"),
        (2,  "jcole@medrx.com",     "SELECT",  "prescriptions",    8800, "2026-03-27 01:44:11", "104.28.55.209"),  # terminated pharmacist, 1am, bulk Schedule II export, external IP
        (3,  "jcole@medrx.com",     "SELECT",  "api_credentials",  5,    "2026-03-27 01:47:55", "104.28.55.209"),  # same session — grabbed DEA API key
        (4,  "twright@medrx.com",   "SELECT",  "prescriptions",    4500, "2026-03-28 22:05:30", "10.2.0.44"),      # cashier bulk export of prescriptions at 10pm
        (5,  "driver01@medrx.com",  "SELECT",  "prescriptions",    12,   "2026-03-29 10:30:00", "10.2.0.88"),      # delivery driver accessing prescription records
        (6,  "jcole@medrx.com",     "SELECT",  "prescriptions",    5,    "2026-03-25 02:12:04", "104.28.55.209"),  # second incident same terminated pharmacist
        (7,  "rokafor@medrx.com",   "SELECT",  "prescriptions",    2,    "2026-03-28 14:00:00", "10.2.0.11"),
        (8,  "unknown_user",        "SELECT",  "prescriptions",    9200, "2026-03-29 03:55:20", "185.220.101.90"), # unknown user mass-exporting Schedule II records at 4am!
    ])

    # -------------------------------------------------------
    # TABLE 5: data_store_inventory
    # Schedule II prescription records in a public S3 bucket
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
        (1, "medrx-rx-archive-s3",        "S3 Bucket",  "us-east-1",    1, 1, "2020-06-01", "10 years of prescription records incl. Schedule II — PUBLIC — massive HIPAA/DEA violation"),  # public Schedule II records!
        (2, "medrx-prod-db",              "PostgreSQL", "prod-rx-01",   0, 1, "2025-01-20", "Primary dispensing database"),
        (3, "insurance-claims-staging",   "MySQL",      "staging-rx-02",1, 1, "2019-11-15", "Staging: connstr mysql://rxadmin:MedRx#2018@staging-rx-02/claims"),  # staging DB public with hardcoded creds!
        (4, "pdmp-reporting-s3",          "S3 Bucket",  "us-south-1",   1, 1, "2021-03-10", "State PDMP reporting exports — SSNs and controlled substance history — PUBLIC"),  # public PDMP data!
        (5, "dea-audit-archive",          "S3 Bucket",  "us-east-1",    0, 1, "2024-08-01", "DEA biennial audit records — correctly restricted"),
    ])

    conn.commit()
    conn.close()
    print("[OK] MedRx Pharmacy Network database created at:", DB_PATH)
    print("[!] Schedule II records are public. Terminated pharmacist has DEA access. Cashiers are admins.")

if __name__ == "__main__":
    create_database()
