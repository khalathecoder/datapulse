import sqlite3
import os

# Synapse AI Labs — Series B AI research startup
# Security story: a departed ML engineer is exfiltrating model weights and training data,
# interns have root DB access, and AWS keys are hardcoded everywhere.
# Compliance focus: GDPR (scraped training data contains EU PII), SOC 2, IP theft

DB_PATH = "database/synapse_ai.db"

def create_database():
    os.makedirs("database", exist_ok=True)
    conn   = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # -------------------------------------------------------
    # TABLE 1: ml_models
    # Proprietary models — the crown jewels of an AI company
    # PII embedded in training datasets (GDPR violation)
    # -------------------------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ml_models (
            id INTEGER PRIMARY KEY,
            full_name TEXT,
            ssn TEXT,
            model_version TEXT,
            training_dataset TEXT,
            insurance_id TEXT,
            notes TEXT
        )
    """)
    cursor.executemany("INSERT OR IGNORE INTO ml_models VALUES (?,?,?,?,?,?,?)", [
        (1, "SynapseCore-7B",          "N/A",         "v3.2.1",  "CommonCrawl + scraped Reddit/LinkedIn PII",    "MODEL-001", "Primary language model — estimated IP value $40M+"),
        (2, "MedDiag-Vision-2",        "N/A",         "v1.8.0",  "Hospital records dataset — contains real PHI", "MODEL-002", "Medical imaging classifier — HIPAA gray area on training data"),
        (3, "FraudGuard-Classifier",   "N/A",         "v4.1.3",  "Synthetic + 200K real transaction records",    "MODEL-003", "Licensed to 3 banks — training data includes real customer SSNs"),
        (4, "SynapseCore-7B-FT",       "N/A",         "v3.2.1-ft","Same as 7B + proprietary client fine-tune",  "MODEL-004", "Fine-tuned on Apex Corp confidential docs — under NDA"),
        (5, "SynthVoice-Clone",        "N/A",         "v2.0.0",  "Scraped voice samples without consent",        "MODEL-005", "Voice cloning model — legal review pending on consent"),
    ])

    # -------------------------------------------------------
    # TABLE 2: employees
    # Flat startup structure gone wrong — everyone is admin
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
        (1, "Aisha Patel",       "apatel@synapse.ai",       "SynapseFounder!1",  "admin",  1, None),
        (2, "Dev_Intern_Sam",    "sintern@synapse.ai",       "intern2025",        "admin",  1, None),   # intern with full admin!
        (3, "Dev_Intern_Priya",  "pintern@synapse.ai",       "priya_dev",         "admin",  1, None),   # another intern admin!
        (4, "Carlos Romero",     "cromero@synapse.ai",       "MLEngineer#2022",   "admin",  1, "2025-11-01"),  # departed ML engineer — still active!
        (5, "Temp_DevOps_Lee",   "tlee@synapse.ai",          "devops_temp88",     "admin",  1, None),   # temp contractor as admin
        (6, "Naledi Dlamini",    "ndlamini@synapse.ai",      "ndlamini_read",     "viewer", 1, None),
        (7, "Wei Zhang",         "wzhang@synapse.ai",        "WeiZhang2024!",     "admin",  1, "2025-06-15"),  # second departed engineer still active!
    ])

    # -------------------------------------------------------
    # TABLE 3: api_credentials
    # AWS, Hugging Face, GitHub, GPU clusters — all stale
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
        (1, "AWS Production (Root)",       "DEMO_aws_AKIAIOSFODNN7_SYNAPSE_ROOT",   "2021-03-10", "infra-team"),     # root AWS key, 5 years old!
        (2, "Hugging Face Hub",            "hf_prod_ABCDEFGhijklMNOPQRSTUVwxyz",   "2022-08-01", "ml-team"),
        (3, "GitHub Actions CI/CD",        "ghp_xXxXxXSYNAPSEprodCICDtoken9999",   "2020-11-15", "devops"),         # 5 year old CI/CD token
        (4, "Lambda Labs GPU Cluster",     "lamblabs_api_sk_SYNAPSE_PROD_9988",     "2023-01-20", "training-team"),
        (5, "Weights & Biases Tracking",   "wandb_key_PROD_DO_NOT_DELETE_legacy",   "2019-07-04", "research"),       # 7 year old key that says do not delete!
    ])

    # -------------------------------------------------------
    # TABLE 4: access_log
    # Departed engineer bulk-downloading model weights at 3am
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
        (1,  "apatel@synapse.ai",       "SELECT",   "ml_models",      2,    "2026-03-28 10:00:00", "10.0.2.11"),
        (2,  "cromero@synapse.ai",      "SELECT",   "ml_models",      5,    "2026-03-27 03:14:22", "45.33.32.156"),   # departed engineer, 3am, all models, external IP
        (3,  "cromero@synapse.ai",      "SELECT",   "api_credentials",5,    "2026-03-27 03:17:44", "45.33.32.156"),   # grabbed all API keys in same session
        (4,  "cromero@synapse.ai",      "SELECT",   "ml_models",      5,    "2026-03-25 02:55:09", "45.33.32.156"),   # second breach 2 days earlier, same IP
        (5,  "sintern@synapse.ai",      "DELETE",   "ml_models",      1,    "2026-03-28 14:30:55", "10.0.2.55"),      # intern deleting model records!
        (6,  "wzhang@synapse.ai",       "SELECT",   "ml_models",      5,    "2026-03-26 22:08:11", "185.156.73.44"),  # second departed engineer also accessing
        (7,  "tlee@synapse.ai",         "SELECT",   "api_credentials",3,    "2026-03-28 09:45:00", "10.0.2.9"),
        (8,  "unknown_user",            "SELECT",   "ml_models",      5,    "2026-03-29 04:01:33", "91.108.56.201"),  # unknown user downloading all models at 4am
    ])

    # -------------------------------------------------------
    # TABLE 5: data_store_inventory
    # Public S3 with training data containing scraped PII
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
        (1, "synapse-training-datasets",   "S3 Bucket",  "us-west-2",    1, 1, "2022-01-10", "Raw training corpora — includes scraped LinkedIn/Reddit PII — PUBLIC"),  # public training data with PII!
        (2, "synapse-model-weights-prod",  "S3 Bucket",  "us-west-2",    1, 1, "2021-08-15", "Production model weights and checkpoints — PUBLIC — $40M IP exposed"),    # public model weights!
        (3, "gpu-cluster-db",             "PostgreSQL", "lambda-01",    0, 0, "2025-03-01", "Training job metadata"),
        (4, "synapse-dev-sandbox",         "S3 Bucket",  "us-east-1",    1, 1, "2020-05-01", "Dev sandbox — connstr: postgresql://root:SynapseRoot2019!@dev-db/sandbox"), # public dev DB with hardcoded creds!
        (5, "client-finetune-data",        "S3 Bucket",  "us-west-2",    1, 1, "2023-04-10", "Apex Corp confidential fine-tune dataset — under NDA but PUBLICLY ACCESSIBLE"), # NDA data public!
    ])

    conn.commit()
    conn.close()
    print("[OK] Synapse AI Labs database created at:", DB_PATH)
    print("[!] Model weights are public. Departed engineer took everything. AWS root key is 5 years old.")

if __name__ == "__main__":
    create_database()
