# NetSecure AI

A defensive network exposure assessment API built with Python and FastAPI.

## Implemented
- Explicit authorization required for scans.
- RFC1918 private IPv4 targets only; public, loopback, link-local and IPv6 targets are rejected.
- TCP reachability checks with bounded timeouts and a maximum of 20 unique ports.
- Evidence-based results distinguish `open` from `closed_or_filtered`.
- Deterministic risk scoring with explanations and remediation guidance.
- On-demand JSON and CSV reports.
- Health, scan, analyze, report, reports and deterministic chat-fallback endpoints.

## Run
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```
Open http://127.0.0.1:8000/docs

## Test
```bash
pytest -q
```

## Safety and limitations
Use only against systems and networks you own or are explicitly authorized to assess. This project performs basic TCP reachability checks only; it does not exploit services, attempt credentials, evade monitoring, or modify targets. Port-based service names are hints, not verified fingerprints. An open port is not proof of a vulnerability. NVD/CVE enrichment, a live LLM, PDF/HTML reports, persistent report storage, Nonilion Bot API integration, authentication, and deployment configuration are not yet implemented.
