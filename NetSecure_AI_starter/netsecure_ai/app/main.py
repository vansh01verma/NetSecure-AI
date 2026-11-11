from fastapi import FastAPI, HTTPException
from app.schemas import ScanRequest, ScanResponse
from app.scanner import scan_private_host
from app.validation import validate_private_ipv4

app = FastAPI(
    title="NetSecure AI",
    description="Defensive network assessment API. Private IPv4 targets only.",
    version="0.1.0",
)

@app.get("/")
def root():
    return {"name": "NetSecure AI", "status": "starter", "docs": "/docs"}

@app.get("/health")
def health():
    return {"status": "healthy"}

@app.post("/scan", response_model=ScanResponse)
def scan(request: ScanRequest):
    if not request.authorized:
        raise HTTPException(status_code=403, detail="Explicit authorization is required.")
    try:
        target = validate_private_ipv4(request.target)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    result = scan_private_host(target, timeout_seconds=request.timeout_seconds)
    return result
