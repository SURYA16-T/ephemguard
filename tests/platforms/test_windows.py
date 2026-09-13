import pytest
import sys
from ephemguard.platform.windows import validate_command
from ephemguard.security.command_guard.base import CommandInjectionError
from ephemguard.security.path_jailer import PathJailer, PathTraversalError

def test_windows_safe_command():
    safe_commands = [
        "Get-ChildItem",
        "Get-Process",
        "Get-Service",
        "Get-Volume"
    ]
    for cmd in safe_commands:
        validate_command(cmd, shell="powershell")

def test_windows_command_injection_blocked():
    malicious_commands = [
        "Get-ChildItem & whoami",
        "Get-Process && dir",
        "Get-Service | Stop-Service",
        "Get-Volume || echo failed",
        "Get-Item > C:\\hacked.txt",
        "powershell.exe -EncodedCommand ZWNobyBoYWNr",
        "powershell -enc ZWNobyBoYWNr"
    ]
    for cmd in malicious_commands:
        with pytest.raises(CommandInjectionError):
            validate_command(cmd, shell="powershell")

def test_windows_path_confinement(tmp_path, monkeypatch):
    jailer = PathJailer([tmp_path])
    safe_file = tmp_path / "data.txt"
    safe_file.write_text("safe")
    assert jailer.check_path(safe_file).name == "data.txt"
    
    # UNC paths must be blocked across platforms
    unc_path = r"\\attacker-server\share\payload.exe"
    if sys.platform == "win32":
        with pytest.raises(PathTraversalError):
            jailer.check_path(unc_path)
    else:
        # Simulate UNC path on non-Windows
        original_is_unc = jailer._is_unc_path
        monkeypatch.setattr(jailer, '_is_unc_path', lambda p: str(p).startswith(r"\\") or original_is_unc(p))
        with pytest.raises(PathTraversalError):
            jailer.check_path(unc_path)

def test_windows_safe():
    validate_command("Get-ChildItem")

