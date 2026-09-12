import os
import sys
import pytest
from pathlib import Path, PureWindowsPath
from ephemguard.security.path_jailer import PathJailer, PathTraversalError

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
    jailer = PathJailer([allowed])
    
    # Inside allowed root
    safe_file = allowed / "safe.txt"
    resolved = jailer.check_path(safe_file)
    assert resolved.name == "safe.txt"
    
    # Non-existent file inside allowed root should also pass (strict=False)
    new_file = allowed / "new.txt"
    resolved = jailer.check_path(new_file)
    assert resolved.name == "new.txt"

def test_path_traversal_blocked(jail_env):
    tmp_path, allowed, external, _ = jail_env
    jailer = PathJailer([allowed])
    
    # Attempting to go up and out
    sneaky_path = allowed / ".." / "external" / "secret.txt"
    with pytest.raises(PathTraversalError, match="escapes allowed roots"):
        jailer.check_path(sneaky_path)
        
    # Absolute path outside
    with pytest.raises(PathTraversalError, match="escapes allowed roots"):
        jailer.check_path(external / "secret.txt")

def test_symlink_escape_blocked(jail_env):
    _, allowed, _, symlink_path = jail_env
    if not symlink_path.exists():
        pytest.skip("Symlinks not supported on this environment")
        
    jailer = PathJailer([allowed])
    
    # Accessing through symlink should be blocked because it resolves outside
    escape_attempt = symlink_path / "secret.txt"
    with pytest.raises(PathTraversalError, match="escapes allowed roots"):
        jailer.check_path(escape_attempt)

def test_unc_path_blocked(tmp_path, monkeypatch):
    jailer = PathJailer([tmp_path])
    
    # UNC paths are mainly a Windows concept. 
    # To test our _is_unc_path logic across platforms, we can mock the drive property check 
    # or just use PureWindowsPath if we were taking PureWindowsPath.
    # We will mock _is_unc_path to simulate a Windows UNC path being passed.
    
    # Using real Path, on Posix, '//server/share' is just '/server/share'
    # So we force the UNC check by passing a string and modifying _is_unc_path for testing
    
    # Test standard UNC
    unc_path = r"\\server\share\file.txt"
    if sys.platform == "win32":
        with pytest.raises(PathTraversalError, match="UNC paths are not allowed"):
            jailer.check_path(unc_path)
    else:
        # On Posix, we can mock _is_unc_path since Path won't parse UNC drives natively
        original_is_unc = jailer._is_unc_path
        def mock_is_unc(p):
            return str(p).startswith(r"\\") or original_is_unc(p)
        monkeypatch.setattr(jailer, '_is_unc_path', mock_is_unc)
        
        with pytest.raises(PathTraversalError, match="UNC paths are not allowed"):
            jailer.check_path(unc_path)
