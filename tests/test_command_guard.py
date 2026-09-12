import pytest
from ephemguard.security.command_guard import PosixCommandGuard, WindowsCommandGuard, CommandInjectionError

def test_posix_guard_safe():
    guard = PosixCommandGuard(["ls", "cat"])
    # Standard single command
    assert guard.check_command("ls -la /var/log") is True
    assert guard.check_command("cat file.txt") is True

def test_posix_guard_injection():
    guard = PosixCommandGuard(["ls"])
    
    # Not allowed command
    with pytest.raises(CommandInjectionError, match="not allowed"):
        guard.check_command("rm -rf /")
        
    # Command chaining
    with pytest.raises(CommandInjectionError, match="Command chaining"):
        guard.check_command("ls -la ; cat /etc/passwd")
        
    # Pipelines
    with pytest.raises(CommandInjectionError, match="Command chaining|Multiple commands"):
        guard.check_command("ls -la | grep secret")
        
    # Command substitution
    with pytest.raises(CommandInjectionError, match="Command substitution"):
        guard.check_command("ls -la $(whoami)")
        
    # Multiple commands in bashlex
    with pytest.raises(CommandInjectionError, match="Multiple commands"):
        guard.check_command("ls -la\ncat /etc/passwd")

def test_windows_guard_safe():
    guard = WindowsCommandGuard(["dir", "type"])
    assert guard.check_command("dir C:\\Windows") is True
    assert guard.check_command("type file.txt") is True
    
    # Check quotes around executable
    assert guard.check_command('"dir" C:\\Windows') is True

def test_windows_guard_injection():
    guard = WindowsCommandGuard(["dir"])
    
    # Not allowed command
    with pytest.raises(CommandInjectionError, match="not allowed"):
        guard.check_command("del /F /S /Q C:\\")
        
    # Chaining/Redirects
    with pytest.raises(CommandInjectionError, match="Command chaining"):
        guard.check_command("dir & type secret.txt")
        
    with pytest.raises(CommandInjectionError, match="Command chaining"):
        guard.check_command("dir | findstr secret")
        
    with pytest.raises(CommandInjectionError, match="Command chaining"):
        guard.check_command("dir > output.txt")
        
    # Powershell encoded command
    with pytest.raises(CommandInjectionError, match="Encoded commands"):
        guard.check_command("powershell -EncodedCommand ZQBjAGgAbwAgAGgAYQBjAGsAZQBkAA==")
        
    with pytest.raises(CommandInjectionError, match="Encoded commands"):
        guard.check_command("pwsh -enc ZQBjAGgAbwAgAGgAYQBjAGsAZQBkAA==")
