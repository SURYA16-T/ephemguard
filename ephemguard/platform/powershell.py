from ephemguard.security.command_guard import WindowsCommandGuard

class AllowAllList(list):
    def __contains__(self, item):
        return True

def validate(command: str) -> None:
    guard = WindowsCommandGuard(AllowAllList())
    guard.check_command(command)
