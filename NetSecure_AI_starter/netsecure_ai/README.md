# NetSecure AI

A defensive network-security assessment starter built with Python and FastAPI.
The first milestone provides a bounded TCP reachability scanner for a single
private IPv4 host. It does not exploit services, authenticate to hosts, or scan
public IP addresses.

## Current milestone
- Private IPv4 validation
- Explicit authorization confirmation
- Bounded TCP connection checks against a fixed list of common ports
- Structured JSON results
- FastAPI health and scan endpoints
- Unit tests for validation and safe scan behaviour

## Setup (Windows CMD)
```bat
py -m venv .venv
.venv\Scripts\activate
py -m pip install -r requirements.txt
copy .env.example .env
py -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```
Open http://127.0.0.1:8000/docs

## Run tests
```bat
py -m pytest -q
```

## API example
`POST /scan`
```json
{
  "target": "192.168.1.10",
  "authorized": true,
  "timeout_seconds": 0.5
}
```

Only private IPv4 addresses are accepted. The scanner checks a fixed set of
common TCP ports and applies a short timeout. Use it only on systems and
networks you own or have explicit permission to assess.

## Planned milestones
1. Stabilise scanner and service evidence.
2. Add transparent rule-based risk findings.
3. Add NVD vulnerability intelligence.
4. Add AI analyst with validated tool calls and deterministic fallback.
5. Add JSON/CSV/HTML/PDF reports.
6. Add authenticated API deployment.
7. Integrate Nonilion only after obtaining and verifying its official Bot API guide.
