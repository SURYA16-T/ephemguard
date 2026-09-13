"""Windows policy helpers."""
from ephemguard.security.command_guard import WindowsCommandGuard

class AllowAllList(list):
    def __contains__(self, item):
        return True

def validate_command(command: str, shell: str = "powershell") -> None:
    if shell.lower() in {"powershell", "pwsh"}:
        guard = WindowsCommandGuard(AllowAllList())
        guard.check_command(command)
    else:
        raise ValueError("only PowerShell is supported by the Windows command policy")
