import sqlite3
import os

# Crestline Home Health — in-home nursing and therapy agency serving 3 counties.
# Security story: field nurses use a shared tablet login to document patient visits,
# meaning there's zero individual accountability in access logs. A former care
# coordinator who left during a billing dispute still has VPN and system access,
# and patient medication schedules are sitting in a publicly accessible S3 bucket
# that someone set up as a "quick share" during a system migration and forgot.
# Home health is uniquely risky because staff are geographically dispersed and
# often access systems from personal devices over home WiFi.

DB_PATH = "database/crestline_homehealth.db"

def create_database():
    os.makedirs("database", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # ─────────────────────────────────────────────────────────────────────────
    # TABLE: employees
    # Violations:
    #   - Plaintext passwords for all staff
    #   - Two terminated employees (one left during dispute) still active
    #   - A student intern with admin access
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
        # Active field and office staff — all plaintext passwords
        ("Maria Delgado RN",        "m.delgado@crestlinehh.com",  "nurse",         "Delgado_RN2022",   1, None),
        ("Franklin Tate PT",        "f.tate@crestlinehh.com",     "therapist",     "FTate_PT!home",    1, None),
        ("Angela Kim LPN",          "a.kim@crestlinehh.com",      "nurse",         "AKim_LPN_23",      1, None),
        ("Dennis Ruiz",             "d.ruiz@crestlinehh.com",     "coordinator",   "DRuiz_coord",      1, None),
        ("Beverly Nash",            "b.nash@crestlinehh.com",     "admin",         "Nash_Office1",     1, None),
        # VIOLATION: nursing student intern with admin role
        ("Jordan Wells Intern",     "j.wells@crestlinehh.com",    "admin",         "Wells_intern!",    1, None),
        # VIOLATION: care coordinator terminated after billing dispute, still active
        ("Terrence Malone",         "t.malone@crestlinehh.com",   "coordinator",   "Malone_2021",      1, "2023-06-30"),
        # VIOLATION: nurse terminated after leave of absence expired, still active
        ("Susan Bright RN",         "s.bright@crestlinehh.com",   "nurse",         "SBright_CrHH",     1, "2024-02-14"),
    ]

    cursor.executemany("""
        INSERT INTO employees (full_name, email, role, password, is_active, termination_date)
        VALUES (?, ?, ?, ?, ?, ?)
    """, employees)

    # ─────────────────────────────────────────────────────────────────────────
    # TABLE: api_credentials
    # Home health agencies connect to state Medicaid portals, scheduling
    # platforms, and EVV (Electronic Visit Verification) systems — a federal
    # mandate requiring real-time proof that visits happened. Stale keys on
    # these systems means visit data could be tampered with or stolen.
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
        # VIOLATION: Medicaid portal key — over 2 years without rotation
        ("State Medicaid EVV Portal",  "evv_m8833bc10de44f91",   "2022-05-01", "Beverly Nash"),
        # VIOLATION: scheduling platform, never rotated since initial setup
        ("HHAeXchange Scheduling",     "hhax_9901aaf72b33c100",  "2021-12-08", "Dennis Ruiz"),
        # OK: payroll integration recently rotated
        ("ADP Payroll API",            "adp_d44f1100cc29ab83",   "2025-02-20", "Beverly Nash"),
        # VIOLATION: telehealth/RPM integration, 16 months stale
        ("Current Health RPM",         "crpm_77a0b3ec1429d0fe",  "2023-11-03", "Maria Delgado RN"),
    ]

    cursor.executemany("""
        INSERT INTO api_credentials (service_name, api_key, last_rotated, owner)
        VALUES (?, ?, ?, ?)
    """, api_credentials)

    # ─────────────────────────────────────────────────────────────────────────
    # TABLE: data_store_inventory
    # Patient medication schedules and visit notes are the most sensitive data.
    # The "quick share" S3 bucket is a textbook example of shadow IT —
    # someone solved a short-term problem without thinking about security.
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
        # VIOLATION: "temp" migration bucket left public — still contains med schedules
        ("Migration Temp Bucket",     "S3 Bucket",   "us-east-1",  1, 1, "2022-01-10",
         "Created during EHR migration. password=crestline_temp secret: s3_migration_key_2022"),
        # VIOLATION: visit documentation share is publicly accessible
        ("Visit Notes NFS Share",     "NFS Share",   "on-prem",    1, 1, "2021-11-05", None),
        # OK: primary EHR database is properly locked down
        ("MatrixCare EHR Database",   "PostgreSQL",  "on-prem",    0, 1, "2025-01-30", None),
        # VIOLATION: patient contact/address info stored in public-facing storage
        ("Patient Contact Records",   "S3 Bucket",   "us-east-1",  1, 1, "2023-03-18",
         "sqlite:///contacts_backup.db password=contacts2023"),
    ]

    cursor.executemany("""
        INSERT INTO data_store_inventory
            (store_name, store_type, location, public_access, contains_pii, last_audited, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, data_stores)

    # ─────────────────────────────────────────────────────────────────────────
    # TABLE: access_log
    # Violations:
    #   - Terminated coordinator Malone accessing patient records post-termination
    #   - Bulk download of all patient records (possible billing fraud setup)
    #   - Multiple external IP accesses (field nurses on home WiFi is real,
    #     but still flagged — VPN policy should be enforced)
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
        # Normal field nurse access from external IPs (home WiFi — still flagged)
        ("m.delgado@crestlinehh.com", "SELECT", "visit_notes",        8,  "2025-03-03 10:15:00", "73.112.45.200"),
        ("a.kim@crestlinehh.com",     "SELECT", "patient_meds",       5,  "2025-03-03 11:40:00", "68.98.177.33"),
        # Internal office access
        ("b.nash@crestlinehh.com",    "UPDATE", "patient_contacts",   12, "2025-03-04 14:00:00", "192.168.10.5"),
        ("d.ruiz@crestlinehh.com",    "SELECT", "visit_schedule",     20, "2025-03-05 09:00:00", "192.168.10.8"),
        # VIOLATION: terminated coordinator accessing patient records 9 months post-termination
        ("t.malone@crestlinehh.com",  "SELECT", "patient_contacts",   30, "2024-03-28 13:15:00", "192.168.10.8"),
        # VIOLATION: bulk export of full patient list — possible fraud setup
        ("t.malone@crestlinehh.com",  "SELECT", "patient_meds",     1950, "2024-03-28 13:42:00", "192.168.10.8"),
        # VIOLATION: after-hours external access from unknown IP
        ("f.tate@crestlinehh.com",    "SELECT", "visit_notes",        7,  "2025-03-07 01:55:00", "98.200.14.77"),
        # VIOLATION: unknown user — not in employee table
        ("billing_ext@unknown.com",   "SELECT", "patient_contacts",   60, "2025-03-09 16:30:00", "104.21.33.9"),
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
