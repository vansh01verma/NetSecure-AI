import os
import socket

SERVICE_HINTS = {22: "SSH (port-based hint)", 53: "DNS (port-based hint)", 80: "HTTP (port-based hint)", 443: "HTTPS (port-based hint)", 445: "SMB (port-based hint)", 3306: "MySQL (port-based hint)", 5432: "PostgreSQL (port-based hint)", 8080: "HTTP alternate (port-based hint)"}

def scan_tcp(target: str, ports: list[int]) -> dict:
    timeout = min(max(float(os.getenv("SCAN_TIMEOUT_SECONDS", "0.6")), 0.2), 1.5)
    results = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            code = sock.connect_ex((target, port))
            state = "open" if code == 0 else "closed_or_filtered"
            evidence = "TCP connection established" if code == 0 else f"TCP connection not established (socket code {code})"
        except OSError as exc:
            state, evidence = "unknown", f"Socket error: {type(exc).__name__}"
        finally:
            sock.close()
        results.append({"port": port, "state": state, "service_hint": SERVICE_HINTS.get(port, "Unknown"), "evidence": evidence})
    return {"target": target, "results": results, "limitations": ["Reachability is not proof of a vulnerability.", "Service names are port-based hints; versions are not verified.", "Closed and filtered ports cannot be distinguished by this check."]}
