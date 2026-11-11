import socket
from datetime import datetime, timezone
from app.schemas import PortResult, ScanResponse

# Deliberately fixed and small: no arbitrary port ranges or user-supplied payloads.
COMMON_PORTS = {
    22: "SSH",
    23: "Telnet",
    53: "DNS",
    80: "HTTP",
    139: "NetBIOS",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    5432: "PostgreSQL",
    8080: "HTTP-alt",
    3389: "RDP",
}

def scan_private_host(target: str, timeout_seconds: float = 0.5) -> ScanResponse:
    results: list[PortResult] = []
    for port, service in COMMON_PORTS.items():
        status = "closed_or_filtered"
        evidence = "TCP connection was not established within the timeout."
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout_seconds)
        try:
            code = sock.connect_ex((target, port))
            if code == 0:
                status = "open"
                evidence = "TCP connection established; service identity is inferred from the port."
        except OSError as exc:
            evidence = f"Connection check failed: {type(exc).__name__}"
        finally:
            sock.close()

        results.append(PortResult(
            port=port,
            expected_service=service,
            status=status,
            evidence=evidence,
        ))

    open_count = sum(item.status == "open" for item in results)
    return ScanResponse(
        target=target,
        scanned_at=datetime.now(timezone.utc),
        ports_checked=len(results),
        open_ports=open_count,
        results=results,
        limitations=[
            "A reachable TCP port does not prove that the expected service is running.",
            "No service-version detection or vulnerability verification is performed.",
            "A timeout may indicate filtering or network unreachability, not necessarily a closed port.",
        ],
    )
