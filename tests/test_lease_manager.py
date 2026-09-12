import time
import pytest
from ephemguard.security.lease_manager import LeaseManager

def test_lease_issuance_and_verification():
    manager = LeaseManager(default_ttl=2)
    
    # Issue a lease
    token = manager.issue_lease("read_file")
    assert token is not None
    assert token.startswith("read_file:")
    
    # Verify valid lease
    assert manager.verify_lease(token, "read_file") is True
    
    # Single-use protection: verifying again should fail
    assert manager.verify_lease(token, "read_file") is False

def test_lease_wrong_tool():
    manager = LeaseManager()
    token = manager.issue_lease("read_file")
    
    # Verify with wrong tool name
    assert manager.verify_lease(token, "write_file") is False

def test_lease_expiry():
    manager = LeaseManager(default_ttl=1)
    token = manager.issue_lease("read_file")
    
    # Wait for expiry
    time.sleep(1.1)
    
    # Verify should fail due to expiry
    assert manager.verify_lease(token, "read_file") is False

def test_lease_tampering():
    manager = LeaseManager()
    token = manager.issue_lease("read_file")
    
    # Tamper with the token (change expiry or tool)
    parts = token.split(':')
    parts[0] = "write_file"
    tampered_token = ":".join(parts)
    
    assert manager.verify_lease(tampered_token, "write_file") is False
    assert manager.verify_lease(tampered_token, "read_file") is False
