import sqlite3
import json
import anthropic
import os
from dotenv import dotenv_values


def _get_api_key():
    """Same key-loading pattern as ai_analyst.py — env first, then .env file."""
    _env_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    return (os.environ.get("ANTHROPIC_API_KEY") or "").strip() or \
           (dotenv_values(_env_file).get("ANTHROPIC_API_KEY") or "").strip()


# ─────────────────────────────────────────────────────────────────────────────
# SCHEMA READER
# Reads the structure and sample data from any SQLite database,
# regardless of what tables or columns it contains.
#
# This is the key difference from scanner.py — scanner.py only works if
# the DB has our specific tables (employees, api_credentials, etc.).
# This function works on ANY SQLite file by asking the DB to describe itself.
# ─────────────────────────────────────────────────────────────────────────────
def read_schema_and_samples(db_path, max_rows_per_table=5):
    """
    Returns a dict describing the full database:
    {
      "tables": {
        "users": {
          "columns": [{"name": "id", "type": "INTEGER"}, ...],
          "sample_rows": [{"id": 1, "email": "...", ...}, ...]
        },
        ...
      }
    }

    max_rows_per_table limits how many sample rows we pull from each table.
    We don't need hundreds of rows — 5 is enough for Claude to spot patterns
    like plaintext passwords, unencrypted SSNs, missing audit columns, etc.
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # sqlite_master is SQLite's internal catalog table.
    # It lists every table, view, index, and trigger in the database.
    # We filter to type='table' to skip views and internal objects.
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    table_names = [row["name"] for row in cursor.fetchall()]

    schema = {"tables": {}}

    for table_name in table_names:
        # Skip SQLite's internal tables — they start with "sqlite_"
        if table_name.startswith("sqlite_"):
            continue

        # PRAGMA table_info returns one row per column:
        # cid (column index), name, type, notnull, dflt_value, pk (is primary key)
        cursor.execute(f"PRAGMA table_info({table_name})")
        columns = [
            {"name": row["name"], "type": row["type"]}
            for row in cursor.fetchall()
        ]

        # Pull a small sample of rows to give Claude real data to analyze.
        # LIMIT keeps this fast and prevents sending huge amounts of data to the API.
        try:
            cursor.execute(f"SELECT * FROM \"{table_name}\" LIMIT {max_rows_per_table}")
            rows = [dict(row) for row in cursor.fetchall()]
        except sqlite3.OperationalError:
            # Table exists in schema but can't be read (e.g. permissions, corruption)
            rows = []

        schema["tables"][table_name] = {
            "columns":     columns,
            "sample_rows": rows,
        }

    conn.close()
    return schema


# ─────────────────────────────────────────────────────────────────────────────
# SCHEMA FORMATTER
# Converts the schema dict into a clean text block for the Claude prompt.
# Claude understands plain text descriptions better than raw JSON for this task.
# ─────────────────────────────────────────────────────────────────────────────
def format_schema_for_prompt(schema):
    """
    Converts the schema dict into a readable text block like:

    TABLE: users
    Columns: id (INTEGER), email (TEXT), password (TEXT), role (TEXT)
    Sample rows:
      Row 1: {"id": 1, "email": "admin@co.com", "password": "admin123", "role": "admin"}
      Row 2: ...
    """
    lines = []
    for table_name, info in schema["tables"].items():
        # Column summary: "id (INTEGER), email (TEXT), password (TEXT)"
        col_summary = ", ".join(
            f'{c["name"]} ({c["type"]})' for c in info["columns"]
        )
        lines.append(f"TABLE: {table_name}")
        lines.append(f"Columns: {col_summary}")

        if info["sample_rows"]:
            lines.append("Sample rows:")
            for i, row in enumerate(info["sample_rows"], 1):
                lines.append(f"  Row {i}: {json.dumps(row)}")
        else:
            lines.append("(no rows)")
        lines.append("")  # blank line between tables

    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# AI SCHEMA SCAN
# The main function called by the upload route in app.py.
# Takes any SQLite file, reads its structure, and asks Claude to find
# security issues — returning findings in the same format as scanner.py
# so they flow through Wazuh forwarding and report generation unchanged.
# ─────────────────────────────────────────────────────────────────────────────
def ai_schema_scan(db_path, filename):
    """
    Scans any SQLite database for security issues using Claude.
    Works regardless of schema — Claude figures out what's there.

    Returns the same structure as run_all_checks():
    [
      {
        "severity":       "CRITICAL",
        "category":       "Plaintext Password",
        "detail":         "admin@company.com — password column contains plaintext value",
        "recommendation": "Hash all passwords using bcrypt or Argon2."
      },
      ...
    ]
    """
    api_key = _get_api_key()
    if not api_key:
        return [{
            "severity":       "LOW",
            "category":       "AI Scanner Unavailable",
            "detail":         "ANTHROPIC_API_KEY is not set. Cannot run AI schema scan.",
            "recommendation": "Add ANTHROPIC_API_KEY to your .env file."
        }]

    # ── Step 1: Read the database structure ──────────────────────────────────
    try:
        schema = read_schema_and_samples(db_path)
    except Exception as e:
        return [{
            "severity":       "HIGH",
            "category":       "Schema Read Error",
            "detail":         f"Could not read database schema: {str(e)}",
            "recommendation": "Ensure the file is a valid, uncorrupted SQLite database."
        }]

    if not schema["tables"]:
        return [{
            "severity":       "LOW",
            "category":       "Empty Database",
            "detail":         f"{filename} contains no tables.",
            "recommendation": "Nothing to scan."
        }]

    schema_text = format_schema_for_prompt(schema)

    # ── Step 2: Build the prompt ──────────────────────────────────────────────
    # We give Claude a very specific output format to follow.
    # Asking for JSON with a clear schema means we can parse it reliably
    # and feed it directly into the rest of the DataPulse pipeline.
    system_prompt = (
        "You are a senior cybersecurity and data privacy analyst. "
        "You are reviewing a database schema and sample data to identify security violations. "
        "Your output must be a valid JSON array of findings and nothing else — "
        "no explanation before or after the array. "
        "Each finding must have exactly these four fields: "
        "severity (one of: CRITICAL, HIGH, MEDIUM, LOW), "
        "category (a short label like 'Plaintext Password' or 'PII Exposed'), "
        "detail (specific — include table name, column name, and example value), "
        "recommendation (one sentence on how to fix it). "
        "Focus on: plaintext passwords, unencrypted PII (SSNs, DOBs, addresses, phone numbers), "
        "missing audit/timestamp columns, overly permissive roles, hardcoded secrets, "
        "lack of access controls, sensitive data in unexpected columns, and HIPAA risks. "
        "If the database appears clean, return an empty array: []"
    )

    user_prompt = (
        f"Database file: {filename}\n\n"
        f"Schema and sample data:\n\n"
        f"{schema_text}\n"
        f"Return ONLY a JSON array of findings. No other text."
    )

    # ── Step 3: Call Claude ───────────────────────────────────────────────────
    try:
        client   = anthropic.Anthropic(api_key=api_key)
        response = client.messages.create(
            model      = "claude-opus-4-6",
            max_tokens = 2000,
            system     = system_prompt,
            messages   = [{"role": "user", "content": user_prompt}],
        )
        raw = response.content[0].text.strip()

    except Exception as e:
        return [{
            "severity":       "HIGH",
            "category":       "AI Scan Error",
            "detail":         f"Claude API call failed: {str(e)}",
            "recommendation": "Check your API key and network connection."
        }]

    # ── Step 4: Parse Claude's JSON response ──────────────────────────────────
    # Claude should return a clean JSON array, but we handle edge cases:
    # - Wrapped in a markdown code block (```json ... ```)
    # - Extra text before/after the array
    try:
        # Strip markdown code fences if Claude added them
        if "```" in raw:
            # Find the content between the first ``` and the last ```
            start = raw.index("```")
            end   = raw.rindex("```")
            raw   = raw[start:end].lstrip("`").lstrip("json").strip()

        # Find the JSON array boundaries in case there's stray text around it
        start = raw.index("[")
        end   = raw.rindex("]") + 1
        findings = json.loads(raw[start:end])

    except (ValueError, json.JSONDecodeError) as e:
        # If parsing fails completely, return one finding describing the failure
        return [{
            "severity":       "LOW",
            "category":       "AI Parse Error",
            "detail":         f"Could not parse AI response: {str(e)}",
            "recommendation": "Try re-uploading the file."
        }]

    # ── Step 5: Validate and normalize each finding ───────────────────────────
    # Claude usually follows the format, but we enforce it so nothing
    # downstream (Wazuh forwarder, report generator) sees unexpected shapes.
    valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    normalized = []

    for item in findings:
        if not isinstance(item, dict):
            continue
        normalized.append({
            "severity":       item.get("severity", "MEDIUM").upper()
                              if item.get("severity", "").upper() in valid_severities
                              else "MEDIUM",
            "category":       str(item.get("category",       "Security Issue")),
            "detail":         str(item.get("detail",         "")),
            "recommendation": str(item.get("recommendation", "")),
        })

    # Sort by severity — same order as run_all_checks()
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    normalized.sort(key=lambda f: order.get(f["severity"], 99))

    return normalized
