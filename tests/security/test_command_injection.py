import pytest
from ephemguard.security.command_guard import PosixCommandGuard, WindowsCommandGuard, CommandInjectionError
from ephemguard.platform.posix import AllowAllList

def test_posix_command_injection_payloads():
    guard = PosixCommandGuard(AllowAllList())
    payloads = [
        "ls -la ; cat /etc/passwd",
        "ls -la | grep root",
        "ls -la && whoami",
        "ls -la || echo failed",
        "echo `whoami`",
        "echo $(whoami)",
        "ls &",
    ]
    for payload in payloads:
        with pytest.raises(CommandInjectionError):
            guard.check_command(payload)

def test_windows_command_injection_payloads():
    guard = WindowsCommandGuard(AllowAllList())
    payloads = [
        "dir & whoami",
        "dir && whoami",
        "dir | findstr root",
        "dir || echo failed",
        "dir > out.txt",
        "powershell -EncodedCommand ZWNobyBoYWNr",
        "powershell -eNc ZWNobyBoYWNr",
    ]
    for payload in payloads:
        with pytest.raises(CommandInjectionError):
            guard.check_command(payload)

def test_posix_chain():
    from ephemguard.security.command_guard import inspect_posix, CommandViolation
    with pytest.raises(CommandViolation):
        inspect_posix("echo safe && whoami")

def test_powershell_risky_primitive():
    from ephemguard.security.command_guard import inspect_powershell, CommandViolation
    with pytest.raises(CommandViolation):
        inspect_powershell("Invoke-Expression $x")

