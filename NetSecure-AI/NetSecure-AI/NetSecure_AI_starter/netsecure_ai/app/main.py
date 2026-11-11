from pathlib import Path
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import Response, FileResponse
from fastapi.staticfiles import StaticFiles
import httpx
from .schemas import ScanRequest, AnalyzeRequest, ChatRequest, ReportRequest
from .validation import validate_target, validate_ports
from .scanner import scan_tcp
from .risk import assess
from .reports import render_report
from .ai import answer
from .nvd import search_cves

app = FastAPI(title="NetSecure AI", version="0.3.0", description="Authorized, defensive network exposure assessment.")
STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def run_assessment(target: str, authorized: bool, ports: list[int]):
    if not authorized:
        raise HTTPException(status_code=403, detail="Explicit authorization is required.")
    target = validate_target(target)
    ports = validate_ports(ports)
    return assess(scan_tcp(target, ports))


@app.get("/")
def root():
    return {"name": "NetSecure AI", "status": "running", "docs": "/docs", "dashboard": "/dashboard"}


@app.get("/dashboard", include_in_schema=False)
def dashboard():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/ai/status")
def ai_status():
    return {"configured": False, "mode": "deterministic_fallback", "provider_required": False}


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
    return Response(content=body, media_type=media, headers={"Content-Disposition": f'attachment; filename="netsecure-report.{req.format.lower()}"'})


@app.get("/reports")
def reports():
    return {"reports": [], "note": "Reports are generated on demand by POST /report; persistent storage is not configured."}


@app.post("/chat")
def chat(req: ChatRequest):
    return {"reply": answer(req.message), "mode": "deterministic_fallback", "model_connected": False}


@app.get("/cves/search")
async def cve_search(q: str = Query(..., min_length=2, max_length=100), limit: int = Query(8, ge=1, le=20)):
    keyword = q.strip()
    if len(keyword) < 2 or any(ord(ch) < 32 for ch in keyword):
        raise HTTPException(status_code=422, detail="Search keyword must contain at least 2 printable characters.")
    try:
        results = await search_cves(keyword, limit)
    except (httpx.TimeoutException, httpx.RequestError):
        raise HTTPException(status_code=503, detail="NVD is temporarily unavailable. Please retry later.")
    except httpx.HTTPStatusError:
        raise HTTPException(status_code=502, detail="NVD returned an unsuccessful response.")
    except (ValueError, KeyError):
        raise HTTPException(status_code=502, detail="NVD returned an unreadable response.")
    return {"query": keyword, "count": len(results), "results": results,
            "notice": "Keyword matches are not proof of applicability. Verify product, version, and configuration."}
