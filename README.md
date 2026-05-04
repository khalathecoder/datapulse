# DataPulse — Database Security Scanner

DataPulse is a security tool that scans a company's database and tells you exactly what's wrong, why it matters, and how to fix it — in plain English, powered by AI.

---

## What It Does

Most companies store sensitive data (patient records, payment info, employee credentials) in databases. DataPulse connects to those databases and automatically checks for common security mistakes across five control domains:

- **Plaintext passwords** — credentials stored in clear text, immediately exploitable if the database is stolen
- **Terminated employees still active** — ex-employees whose accounts were never deprovisioned
- **Over-privileged accounts** — interns or contractors with admin-level database access
- **Stale API credentials** — integration keys not rotated in over a year (Critical if over 1,000 days)
- **Public data stores with PII** — S3 buckets or file shares containing sensitive data with no access controls
- **Hardcoded credentials in notes fields** — connection strings and passwords embedded where they don't belong
- **Anomalous access patterns** — bulk exports over 1,000 records, after-hours logins, external IP access, unknown user accounts

After scanning, results are handed to an AI analyst (Claude by Anthropic) which writes a full security report, provides a specific fix for each issue, and lets you ask follow-up questions in plain English.

---

## Why It Matters

This is the core problem that enterprise security companies like **Cyera** solve at scale — knowing where your sensitive data lives, who can touch it, and whether your security controls are actually working. DataPulse demonstrates that concept as a working prototype with open-source tooling at near-zero cost.

---

## Setup

**Requirements:** Python 3.10+, an Anthropic API key

```bash
# 1. Clone the repo
git clone https://github.com/khalathecoder/datapulse.git
cd datapulse

# 2. Create a virtual environment and install dependencies
python -m venv venv
venv/Scripts/activate        # Windows
# source venv/bin/activate   # Mac/Linux
pip install -r requirements.txt

# 3. Add your Anthropic API key
# Create a .env file in the project root:
echo ANTHROPIC_API_KEY=your_key_here > .env

# 4. Seed the databases (run whichever environments you need)
python seed_meridian.py
python seed_cascade.py
python seed_harborview.py
python seed_summit.py
python seed_crestline.py

# 5. Start the app
python -m flask --app app run --port 5000
```

Then open your browser to `http://localhost:5000`

---

## Demo Environments

### Web Application (5 Healthcare Environments)

The web UI (`app.py`) is scoped to five HIPAA-covered healthcare organizations. Each has a distinct security story:

| Key | Company | Industry | Security Story |
|---|---|---|---|
| meridian | Meridian Health Systems | Healthcare | HIPAA violations, terminated staff still active, plaintext PHI |
| cascade | Cascade Pharmacy Group | Pharmacy | DEA-regulated records exposed, terminated pharmacist still has access |
| harborview | Harborview Behavioral Health | Mental Health | Therapy notes publicly accessible, intern with admin role |
| summit | Summit Medical Imaging | Radiology | Legacy PACS system from acquisition, stale credentials, contractor with admin access |
| crestline | Crestline Home Health | Home Health | Shared tablet login, field nurses on home WiFi, disputed-termination employee still active |

### CLI Tool (7 Environments including Non-Healthcare)

The CLI (`cli_test.py`) includes two additional regulatory scenarios for broader demonstration:

| Key | Company | Industry | Regulatory Focus |
|---|---|---|---|
| apex | Apex Payment Solutions | Fintech | PCI-DSS cardholder data |
| fortbridge | Fortbridge Community Bank | Banking | GLBA / SOX compliance |

---

## How to Run

### Web Interface
```bash
python -m flask --app app run --port 5000
# Open http://localhost:5000
# Select a company from the dropdown
# Click "Run AI Analysis" for the full report
# Use the Ask box for specific questions
# Export PDF via the Export PDF button
```

### CLI Tool
```bash
# List all available environments
python cli_test.py --list

# Scan a company
python cli_test.py --company meridian

# Scan + AI report (detailed mode)
python cli_test.py --company harborview --ai --mode detailed

# Scan + AI report (brief mode)
python cli_test.py --company cascade --ai --mode brief

# Ask a specific question about findings
python cli_test.py --company meridian --ask "which findings violate HIPAA 164.312?"
python cli_test.py --company fortbridge --ask "show me the wire fraud indicators"

# Raw JSON output (pipe to jq or downstream tools)
python cli_test.py --company summit --json
```

---

## REST API Endpoints

All endpoints return `application/json`.

| Endpoint | Method | Description |
|---|---|---|
| `/api/scan?company={key}` | GET | Run full scan, return raw findings + summary counts |
| `/api/analyze?company={key}&mode={brief\|detailed}` | GET | Run scan + AI executive summary + per-finding remediations |
| `/api/ask?company={key}&q={question}` | GET | Run scan + answer a natural language question about findings |
| `/api/upload` | POST | Upload any `.db` file, scan it, return findings (file is not stored) |

**Example:**
```bash
curl "http://localhost:5000/api/scan?company=meridian"
curl "http://localhost:5000/api/analyze?company=cascade&mode=brief"
curl "http://localhost:5000/api/ask?company=harborview&q=what+violates+HIPAA"
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11, Flask |
| Database | SQLite |
| AI | Anthropic Claude API (`claude-opus-4-6`) |
| Frontend | HTML, CSS, JavaScript |
| SIEM | Wazuh 4.7 (custom rules mapped to HIPAA §164.312) |
| Version Control | GitHub |

---

## Severity Model

Findings are classified using a four-tier model aligned with CVSS conventions and CIS Controls v8 Implementation Group prioritization:

| Severity | Meaning | Example |
|---|---|---|
| **Critical** | Immediately exploitable; remediate within 24 hours | Plaintext passwords, bulk data export by terminated user |
| **High** | Enables unauthorized access; remediate within 72 hours | Terminated user still active, stale API key (365–1,000 days) |
| **Medium** | Anomalous pattern requiring investigation; 14-day window | After-hours database access |
| **Low** | Configuration drift; 30-day window | Minor privilege excess |

---

## SIEM Integration

DataPulse forwards Critical and High findings to a Wazuh 4.7 instance as structured JSON alerts. Custom detection rules map each finding to the applicable HIPAA §164.312 subsection. A 60-day breach notification tracking flag is applied to Critical findings that may trigger mandatory reporting obligations under 45 CFR §164.400–414.

---

## Security Design Notes

- **API key handling:** The Anthropic API key is read from `.env` at runtime — never hardcoded. The `.gitignore` excludes `.env`, all `.db` files, and `venv/` from version control.
- **File upload safety:** Uploaded databases are validated by extension (`.db`), size (10 MB limit), and SQLite magic header before scanning. Temp files are deleted immediately after the scan completes, whether or not the scan succeeds.
- **Prompt hardening:** The AI analyst system prompt explicitly restricts Claude to answering only questions about the current scan findings and instructs it to reject off-topic or adversarial inputs.
- **Credential masking:** API key values in stale credential findings are masked to the first 6 characters — DataPulse never surfaces full credential values in output or transmits them to the Claude API.

---

## Built For

WGU Cybersecurity Graduate Capstone — demonstrating applied Data Security Posture Management (DSPM) concepts through a working full-stack prototype.

**Frameworks:** NIST SP 800-53 Rev. 5 · CIS Controls v8 · OWASP Top 10 · HIPAA §164.312
