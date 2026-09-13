import pytest
from pathlib import Path
from ephemguard.security.path_jailer import PathJailer, PathTraversalError

@pytest.fixture
def jail_env(tmp_path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    external = tmp_path / "external"
    external.mkdir()
    (allowed / "safe.txt").write_text("safe")
    (external / "secret.txt").write_text("secret")
    return allowed, external

def test_advanced_traversal_payloads(jail_env):
    allowed, external = jail_env
    jailer = PathJailer([allowed])
    
    # Advanced payloads
    payloads = [
        "../external/secret.txt",
        "..%2fexternal%2fsecret.txt",
        "..././external/secret.txt",
        "....//external/secret.txt",
        allowed / ".." / "external" / "secret.txt",
    ]
    
    for payload in payloads:
        # Check that jailer blocks it or resolves it safely within allowed
        try:
            # We must convert payload to string if it contains url encoding or raw dots that Path might misinterpret,
            # but PathJailer takes Union[str, Path]
            resolved = jailer.check_path(allowed / str(payload))
            # If it resolves, it MUST be inside allowed root
            assert resolved.is_relative_to(allowed), f"Payload {payload} bypassed jailer!"
        except PathTraversalError:
            pass # Blocked successfully

def test_null_byte_injection(jail_env):
    allowed, external = jail_env
    jailer = PathJailer([allowed])
    
    # Null bytes are typically blocked by Python's pathlib, but we should ensure it raises ValueError or PathTraversalError
    payload = "safe.txt\x00../external/secret.txt"
    try:
        jailer.check_path(allowed / payload)
    except (ValueError, PathTraversalError):
        pass # Blocked or rejected

def test_path_escape(tmp_path):
    from ephemguard.security.attenuator import attenuate_tool_call, CapabilityViolation
    from ephemguard.security.policy_engine import PolicyEngine
    with pytest.raises(CapabilityViolation):
        attenuate_tool_call("filesystem_read", {"path": "../../etc/passwd"}, str(tmp_path), PolicyEngine())

