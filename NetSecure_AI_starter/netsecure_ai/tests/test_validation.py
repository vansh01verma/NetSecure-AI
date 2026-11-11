import pytest
from fastapi import HTTPException
from app.validation import validate_target, validate_ports

def test_private_ip_allowed():
    assert validate_target("192.168.1.10") == "192.168.1.10"

@pytest.mark.parametrize("target", ["8.8.8.8", "127.0.0.1", "169.254.1.1", "::1", "not-an-ip"])
def test_unsafe_or_invalid_target_rejected(target):
    with pytest.raises(HTTPException):
        validate_target(target)

def test_port_validation():
    assert validate_ports([22, 443]) == [22, 443]

@pytest.mark.parametrize("ports", [[], [0], [65536], [80, 80], list(range(1, 22))])
def test_bad_ports_rejected(ports):
    with pytest.raises(HTTPException):
        validate_ports(ports)
