import pytest
from app.validation import validate_private_ipv4

@pytest.mark.parametrize("value", ["192.168.1.10", "10.0.0.5", "172.16.0.2"])
def test_accepts_private_ipv4(value):
    assert validate_private_ipv4(value) == value

@pytest.mark.parametrize("value", ["8.8.8.8", "127.0.0.1", "169.254.1.1", "not-an-ip", "::1"])
def test_rejects_non_private_or_invalid_targets(value):
    with pytest.raises(ValueError):
        validate_private_ipv4(value)
