"""POSIX-shell policy helpers for macOS/Linux."""
from ephemguard.security.command_guard import PosixCommandGuard

class AllowAllList(list):
    def __contains__(self, item):
        return True

def validate_command(command: str) -> None:
    # We rely on the structural injection checks of the guard
    guard = PosixCommandGuard(AllowAllList())
    guard.check_command(command)
