import sqlite3
import os

# Harborview Behavioral Health — outpatient mental health clinic with 3 locations.
# Security story: a terminated therapist retains access to patient therapy notes
# after their contract ended, and a shared "admin" login is being used by multiple
# staff with no individual accountability. Mental health records carry extra legal
# protection under HIPAA (42 CFR Part 2), making violations here especially severe.

DB_PATH = "database/harborview_behavioral.db"

def create_database():
    os.makedirs("database", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # ─────────────────────────────────────────────────────────────────────────
    # TABLE: employees
    # Stores staff records. Violations planted here:
    #   - Plaintext passwords across the board
    #   - Two terminated employees still marked active (is_active = 1)
    #   - A billing intern with admin role (over-permissioned)
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
        # Active clinical staff — passwords stored in plaintext (CRITICAL violation)
        ("Dr. Patricia Owens",   "p.owens@harborview.org",    "psychiatrist", "Owens#Psych2021",  1, None),
        ("Marcus Webb",          "m.webb@harborview.org",     "therapist",    "MarcusW!2020",     1, None),
        ("Linda Chu",            "l.chu@harborview.org",      "therapist",    "Chu_Linda99",      1, None),
        ("Raymond Osei",         "r.osei@harborview.org",     "case_manager", "ROsei_Harbor",     1, None),
        # Admin staff
        ("Sandra Flores",        "s.flores@harborview.org",   "admin",        "Harbor@Admin1",    1, None),
        # VIOLATION: intern with admin role — should be read-only at most
        ("Tyler Grant Intern",   "t.grant@harborview.org",    "admin",        "intern2023!",      1, None),
        # VIOLATION: terminated therapist, account still active
        ("Dr. James Alcott",     "j.alcott@harborview.org",   "therapist",    "Alcott_Harbor22",  1, "2023-11-15"),
        # VIOLATION: terminated receptionist, account still active
        ("Priya Nair",           "p.nair@harborview.org",     "receptionist", "PriyaN_front",     1, "2024-01-03"),
    ]

    cursor.executemany("""
        INSERT INTO employees (full_name, email, role, password, is_active, termination_date)
        VALUES (?, ?, ?, ?, ?, ?)
    """, employees)

    # ─────────────────────────────────────────────────────────────────────────
    # TABLE: api_credentials
    # Third-party integrations (EHR system, insurance portal, texting service).
    # Mental health platforms often connect to insurance billing APIs and
    # telehealth platforms — stale keys here are high risk.
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
        # VIOLATION: EHR integration key not rotated in over 3 years
        ("SimplePractice EHR",     "spk_a9f3c1d0e8b24aa1",  "2021-08-10", "Sandra Flores"),
        # VIOLATION: insurance portal key stale over 2 years
        ("Availity Insurance API", "avl_7734bbc920d1e992",  "2022-03-22", "Dr. Patricia Owens"),
        # OK: recently rotated telehealth key
        ("Doxy.me Telehealth",     "doxy_ff2910ab3c7d44e0", "2025-01-15", "Marcus Webb"),
        # VIOLATION: SMS reminder service key — over 400 days old
        ("TwilioSMS Reminders",    "twilio_ac83b2f19cc0011", "2024-01-30", "Linda Chu"),
    ]

    cursor.executemany("""
        INSERT INTO api_credentials (service_name, api_key, last_rotated, owner)
        VALUES (?, ?, ?, ?)
    """, api_credentials)

    # ─────────────────────────────────────────────────────────────────────────
    # TABLE: data_store_inventory
    # Where patient data actually lives. Mental health records (therapy notes,
    # diagnoses, prescriptions) are among the most sensitive PHI categories.
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
        # VIOLATION: therapy session notes bucket is publicly accessible + contains PHI
        ("Therapy Notes Archive",   "S3 Bucket",  "us-east-1",   1, 1, "2022-06-01",
         "Stores session notes. Backup script: sqlite:///backup.db password=session_backup_2022"),
        # VIOLATION: hardcoded DB connection string in notes
        ("Patient Intake Forms",    "PostgreSQL",  "on-prem",    0, 1, "2023-11-20",
         "Primary intake DB. secret: pg_intake_pass_harbor"),
        # OK: prescription records properly secured
        ("Prescription Records",    "PostgreSQL",  "on-prem",    0, 1, "2025-02-10", None),
        # VIOLATION: public billing export folder with PII
        ("Insurance Billing Export","NFS Share",   "on-prem",    1, 1, "2021-09-14", None),
    ]

    cursor.executemany("""
        INSERT INTO data_store_inventory
            (store_name, store_type, location, public_access, contains_pii, last_audited, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, data_stores)

    # ─────────────────────────────────────────────────────────────────────────
    # TABLE: access_log
    # Records who accessed what and when. Key violations:
    #   - Terminated therapist Dr. Alcott accessing patient notes post-termination
    #   - Bulk export of all patient records (possible data theft)
    #   - After-hours access from an external IP
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
        # Normal daytime activity — internal IPs
        ("m.webb@harborview.org",    "SELECT", "therapy_notes",  12,   "2025-03-10 09:15:00", "10.0.1.45"),
        ("l.chu@harborview.org",     "SELECT", "patient_intake",  8,   "2025-03-10 10:30:00", "10.0.1.62"),
        ("r.osei@harborview.org",    "UPDATE", "case_notes",      3,   "2025-03-11 14:00:00", "10.0.1.77"),
        # VIOLATION: terminated therapist accessing therapy notes 4 months after termination
        ("j.alcott@harborview.org",  "SELECT", "therapy_notes",  45,   "2024-03-20 11:05:00", "10.0.1.45"),
        # VIOLATION: bulk export of all patient records — likely data exfiltration
        ("j.alcott@harborview.org",  "SELECT", "patient_intake", 2840, "2024-03-20 11:47:00", "10.0.1.45"),
        # VIOLATION: after-hours access from external IP (possible remote unauthorized access)
        ("s.flores@harborview.org",  "SELECT", "billing_export",  90,  "2025-03-14 02:22:00", "203.45.99.12"),
        # VIOLATION: unknown user — not in the employee table
        ("ghost_user@harborview.org","SELECT", "therapy_notes",   5,   "2025-03-15 16:40:00", "10.0.1.99"),
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
