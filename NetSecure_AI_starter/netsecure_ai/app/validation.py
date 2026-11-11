import ipaddress

def validate_private_ipv4(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError("Target must be a valid IPv4 address.") from exc

    if not isinstance(address, ipaddress.IPv4Address):
        raise ValueError("Only IPv4 targets are supported.")
    if not address.is_private or address.is_loopback or address.is_link_local:
        raise ValueError("Target must be an RFC1918 private IPv4 address.")
    return str(address)
