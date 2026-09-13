import os
import sys
import pytest
from pathlib import Path, PureWindowsPath
from ephemguard.security.path_guard import resolve_confined, PathViolation

@pytest.fixture
def jail_env(tmp_path):
    """Creates a temporary environment with allowed and external directories."""
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    
    external = tmp_path / "external"
    external.mkdir()
    
    # Create some files
    (allowed / "safe.txt").write_text("safe")
    (external / "secret.txt").write_text("secret")
    
    # Create a symlink in allowed pointing to external (if OS supports it)
    symlink_path = allowed / "escape_link"
    try:
        symlink_path.symlink_to(external)
    except OSError:
        pass # Symlinks might not be supported on all Windows setups without admin
        
    return tmp_path, allowed, external, symlink_path

def test_safe_paths(jail_env):
    _, allowed, _, _ = jail_env
    
    # Inside allowed root
    safe_file = allowed / "safe.txt"
    resolved = resolve_confined(allowed if 'allowed' in locals() else tmp_path, safe_file)
    assert resolved.name == "safe.txt"
    
    # Non-existent file inside allowed root should also pass (strict=False)
    new_file = allowed / "new.txt"
    resolved = resolve_confined(allowed if 'allowed' in locals() else tmp_path, new_file)
    assert resolved.name == "new.txt"

def test_path_traversal_blocked(jail_env):
    tmp_path, allowed, external, _ = jail_env
    
    # Attempting to go up and out
    sneaky_path = allowed / ".." / "external" / "secret.txt"
    with pytest.raises(PathViolation, match="path escapes workspace"):
        resolve_confined(allowed if 'allowed' in locals() else tmp_path, sneaky_path)
        
    # Absolute path outside
    with pytest.raises(PathViolation, match="path escapes workspace"):
        resolve_confined(allowed if 'allowed' in locals() else tmp_path, external / "secret.txt")

def test_symlink_escape_blocked(jail_env):
    _, allowed, _, symlink_path = jail_env
    if not symlink_path.exists():
        pytest.skip("Symlinks not supported on this environment")
        
    
    # Accessing through symlink should be blocked because it resolves outside
    escape_attempt = symlink_path / "secret.txt"
    with pytest.raises(PathViolation, match="path escapes workspace"):
        resolve_confined(allowed if 'allowed' in locals() else tmp_path, escape_attempt)
