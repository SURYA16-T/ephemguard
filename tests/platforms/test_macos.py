import pytest
from ephemguard.platform.posix import validate_command
from ephemguard.security.command_guard.base import CommandInjectionError
from ephemguard.security.path_jailer import PathJailer, PathTraversalError

def test_posix_safe_command():
    # Safe commands commonly used on macOS
    safe_commands = [
        "printf hello",
        "sw_vers",
        "vm_stat",
        "launchctl list",
        "defaults read -g"
    ]
    for cmd in safe_commands:
        validate_command(cmd)

def test_macos_command_injection_blocked():
    # Dangerous macOS attack vectors
    malicious_commands = [
        "sw_vers && whoami",
        "printf hello ; osascript -e 'display dialog \"pwned\"'",
        "vm_stat | grep free",
        "echo `id`",
        "defaults read || rm -rf ~/"
    ]
    for cmd in malicious_commands:
        with pytest.raises(CommandInjectionError):
            validate_command(cmd)

def test_macos_path_confinement(tmp_path):
    jailer = PathJailer([tmp_path])
    safe_file = tmp_path / "config.plist"
    safe_file.write_text("<plist/>")
    assert jailer.check_path(safe_file).name == "config.plist"
    
    with pytest.raises(PathTraversalError):
        jailer.check_path("/Library/Preferences/com.apple.loginwindow.plist")

def test_macos_safe():
    validate_command("printf hello")

