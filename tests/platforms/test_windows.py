import pytest
import sys
from ephemguard.platform.windows import validate_command
from ephemguard.security.command_guard.base import CommandInjectionError
from ephemguard.security.path_guard import resolve_confined, PathViolation

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
    safe_file = tmp_path / "data.txt"
    safe_file.write_text("safe")
    assert resolve_confined(tmp_path, safe_file).name == "data.txt"
    
    # UNC paths must be blocked on Windows (on Posix they just resolve safely as relative or absolute without drives)
    if sys.platform == "win32":
        unc_path = r"\\attacker-server\share\payload.exe"
        with pytest.raises(PathViolation):
            resolve_confined(tmp_path, unc_path)

def test_windows_safe():
    validate_command("Get-ChildItem")

