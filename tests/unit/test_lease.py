import pytest
from ephemguard.security.lease_manager import LeaseManager, LeaseViolation

def test_single_use_and_binding():
    lm = LeaseManager(b"x" * 32)
    token = lm.mint("filesystem_read", "/workspace/a.py", "read")
    args = {"path": "/workspace/a.py", "operation": "read"}
    lm.consume(token, "filesystem_read", args)
    with pytest.raises(LeaseViolation):
        lm.consume(token, "filesystem_read", args)

def test_tool_mismatch():
    lm = LeaseManager(b"x" * 32)
    token = lm.mint("filesystem_read", "/workspace/a.py")
    with pytest.raises(LeaseViolation):
        lm.consume(token, "filesystem_write", {"path": "/workspace/a.py", "operation": "read"})

def test_single_use():
    lm = LeaseManager(b"x" * 32, ttl_seconds=15)
    tok = lm.mint("filesystem_read", "/workspace/a.py")
    args = {"path": "/workspace/a.py", "operation": "read"}
    lm.consume(tok, "filesystem_read", args)
    try:
        lm.consume(tok, "filesystem_read", args)
        assert False
    except LeaseViolation:
        pass

