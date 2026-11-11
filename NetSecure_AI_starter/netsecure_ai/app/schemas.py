from datetime import datetime, timezone
from pydantic import BaseModel, Field, IPvAnyAddress, field_validator

class ScanRequest(BaseModel):
    target: str = Field(..., description="Private IPv4 address of an authorized host")
    authorized: bool = Field(..., description="Must be true to confirm permission")
    timeout_seconds: float = Field(default=0.5, ge=0.1, le=2.0)

class PortResult(BaseModel):
    port: int
    expected_service: str
    status: str
    evidence: str

class ScanResponse(BaseModel):
    target: str
    scanned_at: datetime
    ports_checked: int
    open_ports: int
    results: list[PortResult]
    limitations: list[str]
