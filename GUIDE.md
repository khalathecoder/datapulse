# DataPulse — Guide

## Start the App
```
venv/Scripts/python.exe -m flask --app app run --port 5000
```
Then open: `localhost:5000`

---

## CLI Tool (no browser needed)
```
# List all companies
python cli_test.py --list

# Scan a company
python cli_test.py --company fortbridge
python cli_test.py --company luminary

# Scan + AI report
python cli_test.py --company hargrove --ai --mode brief
python cli_test.py --company cascade --ai --mode detailed

# Ask a question without the UI
python cli_test.py --company fortbridge --ask "show me the wire fraud indicators"
python cli_test.py --company cascade --ask "what DEA regulations are violated"

# Raw JSON output
python cli_test.py --company meridian --json
```

---

## Flask API Endpoints (browser or curl)
```
localhost:5000/api/scan?company=fortbridge
localhost:5000/api/analyze?company=fortbridge&mode=brief
localhost:5000/api/ask?company=fortbridge&q=what+are+the+wire+fraud+indicators
```

---

## Companies
| Key        | Name                          | Best Demo Question                               |
|------------|-------------------------------|--------------------------------------------------|
| meridian   | Meridian Health Systems       | What are my HIPAA violations?                    |
| cascade    | Cascade Pharmacy Group        | Which findings violate DEA regulations?          |
| apex       | Apex Payment Solutions        | Which findings violate PCI-DSS?                  |
| ironclad   | Ironclad DevOps               | Where are secrets exposed in my dev pipeline?    |
| hargrove   | Hargrove & Associates Legal   | What findings threaten attorney-client privilege?|
| luminary   | Luminary AI Research          | What intellectual property is at risk?           |
| fortbridge | Fortbridge Community Bank     | Show me the wire fraud indicators                |

---

## Rename Database Files (one-time setup)
```
cd C:\Scripts\DataPulse\database

ren acme_health.db      meridian_health.db
ren medrx_pharmacy.db   cascade_pharmacy.db
ren nexus_fintech.db    apex_payment.db
ren orbital_devco.db    ironclad_devops.db
ren pinnacle_law.db     hargrove_legal.db
ren synapse_ai.db       luminary_ai.db
ren terrabank.db        fortbridge_bank.db
```

---

## Key Concepts to Explain

**DSPM** — Data Security Posture Management. Discover where sensitive data lives,
who has access, and what the risk is. That's what DataPulse does.

**System prompt** — The "job contract" given to Claude before it sees user input.
Defines its role and what to do if someone tries to go off-topic.

**Prompt hardening** — Closing the escape hatch. Telling Claude explicitly what
off-topic looks like and how to respond, rather than hoping it figures it out.

**AbortController** — Browser's kill switch for HTTP requests. Cancels a fetch()
call mid-flight when the user clicks Stop.

**f-string** — Python string with `{}` slots that get filled with variable values
at runtime. `f"Hello {name}"` → `"Hello Khala"`

**load_dotenv(override=True)** — Reads the .env file and loads keys into the
environment, overriding any existing empty values from Windows.

**Lazy client init** — Creating API clients (Anthropic, etc.) inside functions
rather than at module level, so a missing key doesn't crash the app on startup.
