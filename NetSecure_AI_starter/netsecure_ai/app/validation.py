import ipaddress
from fastapi import HTTPException

def validate_target(target: str) -> str:
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        raise HTTPException(status_code=422, detail="Target must be an IP address.")
    if ip.version != 4 or not ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
        raise HTTPException(status_code=403, detail="Only private, non-loopback IPv4 targets are permitted.")
    # Restrict to RFC1918 ranges, rather than relying only on is_private semantics.
    allowed = any(ip in ipaddress.ip_network(net) for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
    if not allowed:
        raise HTTPException(status_code=403, detail="Target must be within an RFC1918 private network.")
    return str(ip)

def validate_ports(ports: list[int]) -> list[int]:
    if not ports or len(ports) > 20:
        raise HTTPException(status_code=422, detail="Provide between 1 and 20 ports.")
    if len(set(ports)) != len(ports) or any(p < 1 or p > 65535 for p in ports):
        raise HTTPException(status_code=422, detail="Ports must be unique integers from 1 to 65535.")
    return ports
