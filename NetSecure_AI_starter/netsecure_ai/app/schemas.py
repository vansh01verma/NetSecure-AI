from pydantic import BaseModel, Field

DEFAULT_PORTS = [22, 53, 80, 443, 445, 3306, 5432, 8080]

class ScanRequest(BaseModel):
    target: str
    authorized: bool = False
    ports: list[int] = Field(default_factory=lambda: DEFAULT_PORTS, max_length=20)

class AnalyzeRequest(BaseModel):
    target: str
    authorized: bool = False
    ports: list[int] = Field(default_factory=lambda: DEFAULT_PORTS, max_length=20)

class ChatRequest(BaseModel):
    message: str

class ReportRequest(BaseModel):
    target: str
    authorized: bool = False
    ports: list[int] = Field(default_factory=lambda: DEFAULT_PORTS, max_length=20)
    format: str = "json"
