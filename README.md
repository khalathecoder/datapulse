# DataPulse — Database Security Scanner

DataPulse is a security tool that scans a company's database and tells you exactly what's wrong, why it matters, and how to fix it — in plain English, powered by AI.

---

## What It Does

Most companies store sensitive data (patient records, payment info, employee credentials) in databases. DataPulse connects to those databases and automatically checks for common security mistakes:

- **Passwords stored in plaintext** — anyone who sees the database can read every password
- **Terminated employees still having access** — ex-employees who can still log in
- **Interns or temps with admin-level permissions** — too much access for too low a trust level
- **API keys that haven't been changed in years** — stale credentials that are a liability if leaked
- **Sensitive data exposed to the public** — files or databases that anyone on the internet can access
- **Suspicious access patterns** — bulk data exports, logins at 3am, unknown users in the system

After scanning, it hands everything to an AI analyst (Claude by Anthropic) which writes a full security report, gives a specific fix for each issue, and lets you ask follow-up questions in plain English.

---

## Why It Matters

This is the core problem that enterprise security companies like **Cyera** solve at scale — knowing where your sensitive data lives, who can touch it, and whether your security controls are actually working. DataPulse demonstrates that concept as a working prototype.

---

## Demo Companies

The app ships with 7 fictional companies, each with a unique security story:

| Company | Industry | Story |
|---|---|---|
| Meridian Health Systems | Healthcare | HIPAA violations, plaintext patient data |
| Cascade Pharmacy Group | Pharmacy | DEA-regulated records exposed, terminated pharmacist still active |
| Apex Payment Solutions | Fintech | PCI-DSS violations, stale payment API keys |
| Ironclad DevOps | Tech | Secrets in the dev pipeline, stale deploy keys |
| Hargrove & Associates Legal | Legal | M&A documents publicly accessible, attorney-client privilege at risk |
| Luminary AI Research | AI/ML | Departed engineer exfiltrating model weights, exposed training data |
| Fortbridge Community Bank | Banking | Wire fraud indicators, dormant accounts, stale Federal Reserve credentials |

---

## How to Run It

**Requirements:** Python 3.x, an Anthropic API key

```bash
# Install dependencies
pip install -r requirements.txt

# Start the app
python -m flask --app app run --port 5000
```

Then open your browser to `http://localhost:5000`

**No browser? Use the CLI:**
```bash
python cli_test.py --company meridian --ai
python cli_test.py --company fortbridge --ask "show me the wire fraud indicators"
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python, Flask |
| Database | SQLite |
| AI | Anthropic Claude API |
| Frontend | HTML, CSS, JavaScript |

---

## Built For

WGU Cybersecurity Graduate Capstone — demonstrating applied data security posture management (DSPM) concepts through a working full-stack prototype.
