import pytest
from ephemguard.security.lease_manager import LeaseManager
from ephemguard.security.path_jailer import PathJailer, PathTraversalError
from ephemguard.security.replay_guard import ReplayGuard
from ephemguard.security.schema_verifier import SchemaVerifier, SchemaTamperingError

def test_single_use():
    lm = LeaseManager(default_ttl=15)
    tok = lm.issue_lease("filesystem_read|/workspace/a.py")
    # First consume succeeds (returns True)
    assert lm.verify_lease(tok, "filesystem_read|/workspace/a.py")
    
    # Second consume should fail (single-use)
    try:
        if not lm.verify_lease(tok, "filesystem_read|/workspace/a.py"):
            raise ValueError("LeaseViolation")
        assert False
    except ValueError:
        pass

def test_confined_relative(tmp_path):
    jailer = PathJailer([str(tmp_path)])
    # check_path raises PathTraversalError on failure, returns Path on success
    assert jailer.check_path(str(tmp_path / "src/a.py")) is not None

def test_traversal_blocked(tmp_path):
    jailer = PathJailer([str(tmp_path)])
    try:
        jailer.check_path(str(tmp_path / "../secret.txt"))
        assert False
    except PathTraversalError:
        pass

def test_replay_guard():
    g = ReplayGuard()
    assert g.claim("x")
    assert not g.claim("x")

def test_schema_pin_and_verify():
    v = SchemaVerifier()
    s = {"tools": [{"name": "filesystem_read"}]}
    v.pin_schema("srv", s)
    assert v.verify_schema("srv", s)

    bad = {"tools": [{"name": "filesystem_write"}]}
    try:
        v.verify_schema("srv", bad)
        assert False
    except SchemaTamperingError:
        pass
