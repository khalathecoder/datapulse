import sqlite3
import os

# Summit Medical Imaging — regional radiology and imaging center with 2 locations.
# Security story: a recently acquired second location brought in a poorly secured
# legacy PACS system (Picture Archiving and Communication System — where MRI/CT
# scans live). The merger left old credentials in place and API keys were never
# rotated. Imaging data is some of the most sensitive PHI because scans are
# biometric and cannot be changed — once exposed, always exposed.

DB_PATH = "database/summit_imaging.db"

def create_database():
    os.makedirs("database", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # ─────────────────────────────────────────────────────────────────────────
    # TABLE: employees
    # Violations:
    #   - All passwords stored in plaintext
    #   - Radiologist terminated after merger still has active credentials
    #   - A temp contractor has admin access to the PACS system
    # ─────────────────────────────────────────────────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS employees (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name        TEXT NOT NULL,
            email            TEXT NOT NULL,
            role             TEXT NOT NULL,
            password         TEXT,
            is_active        INTEGER DEFAULT 1,
            termination_date TEXT
        )
    """)

    employees = [
        # Active staff — all passwords in plaintext
        ("Dr. Nadia Okafor",         "n.okafor@summitimaging.com",   "radiologist",  "Okafor_Rad2022",   1, None),
        ("Dr. Ben Hartley",          "b.hartley@summitimaging.com",  "radiologist",  "BHartley#MRI",     1, None),
        ("Camille Reyes",            "c.reyes@summitimaging.com",    "technologist", "CReyes_XRay!",     1, None),
        ("Jorge Pimentel",           "j.pimentel@summitimaging.com", "technologist", "JPim_CT2023",      1, None),
        ("Diane Sorenson",           "d.sorenson@summitimaging.com", "admin",        "Admin_Summit1",    1, None),
        # VIOLATION: contractor with admin access to PACS — should be read-only
        ("Kevin Marsh Contractor",   "k.marsh@summitimaging.com",    "admin",        "KMarsh_contract",  1, None),
        # VIOLATION: legacy radiologist from acquired clinic, terminated but still active
        ("Dr. Harold Finch",         "h.finch@summitimaging.com",    "radiologist",  "Finch_OldClinic",  1, "2023-07-31"),
    ]

    cursor.executemany("""
        INSERT INTO employees (full_name, email, role, password, is_active, termination_date)
        VALUES (?, ?, ?, ?, ?, ?)
    """, employees)

    # ─────────────────────────────────────────────────────────────────────────
    # TABLE: api_credentials
    # Imaging centers connect to hospital EHR systems, insurance prior-auth
    # platforms, and DICOM routing services. Stale keys here mean an attacker
    # could pull radiology orders and patient scans undetected.
    # ─────────────────────────────────────────────────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS api_credentials (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            service_name TEXT NOT NULL,
            api_key      TEXT NOT NULL,
            last_rotated TEXT NOT NULL,
            owner        TEXT NOT NULL
        )
    """)

    api_credentials = [
        # VIOLATION: PACS integration key from legacy clinic, never rotated post-merger
        ("Legacy PACS Gateway",       "pacs_xk991bba72cc0d3e",  "2021-04-05", "Dr. Harold Finch"),
        # VIOLATION: insurance prior-auth API, stale 2+ years
        ("Emdeon Prior Auth API",     "emd_3f80aac192b44d71",   "2022-11-18", "Diane Sorenson"),
        # OK: recently rotated HL7 router key
        ("Mirth Connect HL7 Router",  "mirth_cc20019fe7d3a81b", "2025-03-01", "Dr. Nadia Okafor"),
        # VIOLATION: cloud backup service key, 18 months old
        ("Azure Blob Imaging Backup", "azblob_aa10bc93d2241fe",  "2023-09-14", "Camille Reyes"),
    ]

    cursor.executemany("""
        INSERT INTO api_credentials (service_name, api_key, last_rotated, owner)
        VALUES (?, ?, ?, ?)
    """, api_credentials)

    # ─────────────────────────────────────────────────────────────────────────
    # TABLE: data_store_inventory
    # PACS stores are the crown jewel — full MRI, CT, X-ray archives.
    # A public PACS endpoint is a catastrophic HIPAA violation because imaging
    # data includes the patient's body and is permanently identifying.
    # ─────────────────────────────────────────────────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS data_store_inventory (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            store_name   TEXT NOT NULL,
            store_type   TEXT NOT NULL,
            location     TEXT NOT NULL,
            public_access INTEGER DEFAULT 0,
            contains_pii  INTEGER DEFAULT 0,
            last_audited TEXT,
            notes        TEXT
        )
    """)

    data_stores = [
        # VIOLATION: legacy PACS archive is publicly accessible — contains full imaging PHI
        ("Legacy PACS Archive",       "DICOM Server", "on-prem (legacy)", 1, 1, "2021-03-15",
         "Migrated from old clinic. password=pacs_admin_old secret: dicom_root_2019"),
        # VIOLATION: cloud imaging bucket is public and contains PII
        ("Cloud Imaging Bucket",      "S3 Bucket",    "us-west-2",        1, 1, "2022-08-10", None),
        # OK: new PACS properly secured
        ("Primary PACS (Summit Main)","DICOM Server", "on-prem",          0, 1, "2025-01-20", None),
        # VIOLATION: radiology report export share — public NFS with PHI
        ("Radiology Report Exports",  "NFS Share",    "on-prem",          1, 1, "2022-04-01", None),
    ]

    cursor.executemany("""
        INSERT INTO data_store_inventory
            (store_name, store_type, location, public_access, contains_pii, last_audited, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, data_stores)

    # ─────────────────────────────────────────────────────────────────────────
    # TABLE: access_log
    # Violations:
    #   - Terminated Dr. Finch pulling patient scan orders post-termination
    #   - Massive bulk export (could be someone archiving before leaving)
    #   - External IP access at 3am
    # ─────────────────────────────────────────────────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS access_log (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email     TEXT NOT NULL,
            action         TEXT NOT NULL,
            table_accessed TEXT NOT NULL,
            record_count   INTEGER,
            timestamp      TEXT NOT NULL,
            ip_address     TEXT NOT NULL
        )
    """)

    access_logs = [
        # Normal operations
        ("n.okafor@summitimaging.com",  "SELECT", "radiology_orders",   18, "2025-03-05 08:45:00", "192.168.1.30"),
        ("c.reyes@summitimaging.com",   "SELECT", "patient_scans",       6, "2025-03-05 09:10:00", "192.168.1.44"),
        ("j.pimentel@summitimaging.com","UPDATE", "scan_results",        4, "2025-03-06 11:00:00", "192.168.1.55"),
        # VIOLATION: terminated radiologist accessing scan orders 8 months post-termination
        ("h.finch@summitimaging.com",   "SELECT", "radiology_orders",   22, "2024-03-15 10:30:00", "192.168.1.30"),
        # VIOLATION: bulk export of patient scans — 3,400 records
        ("h.finch@summitimaging.com",   "SELECT", "patient_scans",    3400, "2024-03-15 10:55:00", "192.168.1.30"),
        # VIOLATION: contractor accessing from external IP at 3am
        ("k.marsh@summitimaging.com",   "SELECT", "patient_scans",      14, "2025-03-08 03:14:00", "74.125.22.100"),
        # VIOLATION: unknown user
        ("scanner_bot@external.net",    "SELECT", "radiology_orders",    2, "2025-03-10 15:22:00", "45.33.12.88"),
    ]

    cursor.executemany("""
        INSERT INTO access_log (user_email, action, table_accessed, record_count, timestamp, ip_address)
        VALUES (?, ?, ?, ?, ?, ?)
    """, access_logs)

    conn.commit()
    conn.close()
    print(f"Created: {DB_PATH}")

if __name__ == "__main__":
    create_database()
