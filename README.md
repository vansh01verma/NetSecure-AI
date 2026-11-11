# NetSecure AI

A defensive network exposure assessment API built with Python, FastAPI, and Pydantic.

**Live API:** https://netsecure-ai.onrender.com  
**Interactive API docs:** https://netsecure-ai.onrender.com/docs  
**Health check:** https://netsecure-ai.onrender.com/health

## Features

- Explicit authorization required before a scan or analysis.
- Restricts scan targets to RFC1918 private IPv4 addresses; public, loopback, link-local, and IPv6 targets are rejected.
- Bounded TCP reachability checks with a maximum of 20 unique ports.
- Evidence-based results distinguish `open` from `closed_or_filtered`.
- Deterministic risk scoring with explanations and remediation guidance.
- On-demand JSON and CSV reports.
- Deterministic chat fallback when a live model is not configured.

## API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/` | API welcome/status |
| GET | `/health` | Health check |
| POST | `/scan` | Authorized TCP reachability assessment |
| POST | `/analyze` | Authorized assessment and risk analysis |
| POST | `/report` | Generate an on-demand report |
| GET | `/reports` | Report capability/status information |
| POST | `/chat` | Deterministic assistant response |

For request and response schemas, visit the [interactive API documentation](https://netsecure-ai.onrender.com/docs).

## Project Structure

```text
NetSecure-AI/
├── NetSecure_AI_starter/
│   └── netsecure_ai/
│       ├── app/
│       │   ├── __init__.py
│       │   ├── main.py
│       │   ├── reports.py
│       │   ├── risk.py
│       │   ├── scanner.py
│       │   ├── schemas.py
│       │   └── validation.py
│       ├── tests/
│       │   ├── test_api.py
│       │   └── test_validation.py
│       ├── requirements.txt
│       ├── .env.example
│       └── .gitignore
└── README.md
```

## Run Locally

From the repository root:

```bash
cd NetSecure_AI_starter/netsecure_ai
python -m venv .venv
```

Activate the virtual environment:

```bash
# Windows PowerShell
.venv\Scripts\Activate.ps1

# macOS/Linux
source .venv/bin/activate
```

Install dependencies and start the API:

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000/docs.

## Run Tests

From `NetSecure_AI_starter/netsecure_ai`:

```bash
pytest -q
```

## Deployment on Render

The live service is hosted on Render.

| Setting | Value |
|---|---|
| Service type | Web Service |
| Runtime | Python |
| Branch | `main` |
| Root Directory | `NetSecure_AI_starter/netsecure_ai` |
| Build Command | `pip install -r requirements.txt` |
| Start Command | `uvicorn app.main:app --host 0.0.0.0 --port $PORT` |
| Instance | Free |

Render's free web services may spin down after inactivity, so the first request after a quiet period can take longer.

## Safety and Limitations

Use this tool only on systems and networks you own or have explicit permission to assess. The scanner performs basic TCP reachability checks only; it does not exploit services, attempt credentials, evade monitoring, or modify targets.

- Port-based service names are hints, not verified service fingerprints or version detection.
- An open port is not proof that a vulnerability exists.
- A CVE match, if added in a future version, must not be treated as proof that a target is vulnerable.
- The current implementation provides deterministic risk scoring and a deterministic chat fallback; it does not connect to a live LLM.
- Current report formats are JSON and CSV; PDF and HTML report generation are not implemented.
- Report history is not persisted.
- NVD/CVE enrichment, Nonilion Bot API integration, and authentication are not implemented.

## Technology Stack

- Python
- FastAPI
- Uvicorn
- Pydantic
- Pytest
- HTTPX
