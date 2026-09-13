import re
from .base import BaseCommandGuard, CommandInjectionError
from .posix_guard import PosixCommandGuard
from .windows_guard import WindowsCommandGuard

class CommandViolation(PermissionError):
    """Raised when a command violates the active shell policy."""
    pass

_CHAIN = re.compile(r"(?:;|&&|\|\||(?<!\|)\|(?!\|)|`|\$\(|\n)")
_BASE64 = re.compile(r"(?:base64|frombase64string|\s-enc(?:odedcommand)?\b)", re.I)

def inspect_posix(command: str) -> None:
    if not isinstance(command, str):
        raise CommandViolation("command must be a string")
    if _CHAIN.search(command):
        raise CommandViolation("shell chaining/substitution is disabled by default")
    if _BASE64.search(command):
        raise CommandViolation("encoded command pattern detected")

def inspect_powershell(command: str) -> None:
    if not isinstance(command, str):
        raise CommandViolation("command must be a string")
    if _CHAIN.search(command):
        raise CommandViolation("command chaining/substitution is disabled by default")
    if re.search(r"\b(?:Invoke-Expression|IEX|Start-Process|Invoke-WebRequest|irm|iwr)\b", command, re.I):
        raise CommandViolation("high-risk PowerShell primitive blocked")
    if _BASE64.search(command):
        raise CommandViolation("encoded PowerShell command detected")

__all__ = [
    "BaseCommandGuard",
    "CommandInjectionError",
    "PosixCommandGuard",
    "WindowsCommandGuard",
    "CommandViolation",
    "inspect_posix",
    "inspect_powershell",
]
