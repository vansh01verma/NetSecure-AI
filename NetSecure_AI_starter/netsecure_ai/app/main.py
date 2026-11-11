from fastapi import FastAPI, HTTPException
from fastapi.responses import Response
from .schemas import ScanRequest, AnalyzeRequest, ChatRequest, ReportRequest
from .validation import validate_target, validate_ports
from .scanner import scan_tcp
from .risk import assess
from .reports import render_report

app = FastAPI(title="NetSecure AI", version="0.2.0",
              description="Authorized, defensive network exposure assessment.")

def run_assessment(target: str, authorized: bool, ports: list[int]):
    if not authorized:
        raise HTTPException(status_code=403, detail="Explicit authorization is required.")
    target = validate_target(target)
    ports = validate_ports(ports)
    return assess(scan_tcp(target, ports))

@app.get("/")
def root():
    return {"name": "NetSecure AI", "status": "running", "docs": "/docs"}

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/scan")
def scan(req: ScanRequest):
    if not req.authorized:
        raise HTTPException(status_code=403, detail="Explicit authorization is required.")
    target = validate_target(req.target)
    ports = validate_ports(req.ports)
    return scan_tcp(target, ports)

@app.post("/analyze")
def analyze(req: AnalyzeRequest):
    return run_assessment(req.target, req.authorized, req.ports)

@app.post("/report")
def report(req: ReportRequest):
    data = run_assessment(req.target, req.authorized, req.ports)
    try:
        body, media = render_report(data, req.format.lower())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return Response(content=body, media_type=media)

@app.get("/reports")
def reports():
    return {"reports": [], "note": "Reports are generated on demand by POST /report; persistent storage is not configured."}

@app.post("/chat")
def chat(req: ChatRequest):
    return {"reply": "I can explain scan findings, risk scores, and defensive remediation. Run an authorized private-network assessment with POST /analyze to provide evidence for analysis.",
            "mode": "deterministic_fallback", "model_connected": False}
