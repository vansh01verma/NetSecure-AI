# NetSecure AI

Defensive network exposure assessment built with Python, FastAPI and Pydantic. This upgrade adds a responsive dashboard, official NVD CVE keyword search and a deterministic assistant that requires no LLM provider or paid key.

## Features
- Explicit authorization required for every scan and report.
- RFC1918 private IPv4 targets only; public, loopback, link-local, reserved and IPv6 targets are rejected.
- TCP reachability checks bounded to 20 unique ports.
- Deterministic risk scoring and defensive remediation guidance.
- On-demand JSON and CSV reports.
- `/dashboard` responsive SOC-style frontend served by FastAPI.
- `/cves/search?q=Apache%20HTTP%20Server&limit=8` asynchronous NVD API 2.0 integration using HTTPX.
- `/chat` deterministic rule-based assistant; `/ai/status` explicitly reports that no model is connected.

## Local run
```bash
cd NetSecure_AI_starter/netsecure_ai
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```
Open `http://127.0.0.1:8000/dashboard` or `/docs`.

## Tests
From `NetSecure_AI_starter/netsecure_ai` run `pytest -q`.

## Render configuration
Preserve the existing service settings:
- Root Directory: `NetSecure_AI_starter/netsecure_ai`
- Build: `pip install -r requirements.txt`
- Start: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`

Optional environment variable: `NVD_API_KEY`. The integration works without a key; adding one may provide a higher NVD request allowance. Never put the key in frontend code or commit it. `SCAN_TIMEOUT_SECONDS` remains optional and is clamped by the scanner.

## API
| Method | Path | Purpose |
|---|---|---|
| GET | `/` | API information |
| GET | `/health` | Health check |
| GET | `/dashboard` | Frontend |
| POST | `/scan` | Authorized TCP check |
| POST | `/analyze` | Risk assessment |
| POST | `/report` | JSON or CSV download |
| GET | `/reports` | Report capability information |
| POST | `/chat` | Deterministic assistant |
| GET | `/ai/status` | Assistant configuration status |
| GET | `/cves/search` | NVD CVE keyword search |

## Safety and limitations
Use only on networks you own or are explicitly authorized to assess. This scanner does not exploit services, attempt credentials, evade monitoring, or modify targets. Port labels are hints, not service fingerprints. Closed and filtered ports cannot be distinguished. A reachable port is not a vulnerability. NVD keyword matches do not establish that a scanned host is affected: verify exact product, version, configuration and vendor guidance. Risk scores and severity labels are prioritization heuristics, not probabilities or CVSS ratings. Reports are generated on demand and are not persisted.

## Deployment note
A GitHub commit does not guarantee a Render deployment has completed. After publishing changes, wait for Render's deploy to finish, then verify `/health`, `/dashboard`, `/ai/status`, and `/cves/search` independently.
