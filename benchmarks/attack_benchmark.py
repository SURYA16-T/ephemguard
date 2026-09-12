import os
import sys

# Add parent directory to path to allow running directly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ephemguard.platform.detector import current_os
from ephemguard.security.path_jailer import PathJailer, PathTraversalError
from ephemguard.security.command_guard.posix_guard import PosixCommandGuard
from ephemguard.security.command_guard.windows_guard import WindowsCommandGuard
from ephemguard.security.command_guard.base import CommandInjectionError

def main():
    os_name = current_os()
    print(f"Running EphemGuard Attack Benchmark on [{os_name.upper()}]...")
    jailer = PathJailer(allowed_roots=[os.getcwd()])
    
    if os_name == "windows":
        guard = WindowsCommandGuard(allowed_commands=["dir", "echo", "Get-Process"])
        attacks = [
            ("../secret", "path"),
            ("..\\..\\Windows\\System32\\cmd.exe", "path"),
            (r"\\evil-server\share\exploit.exe", "path"),
            ("dir & whoami", "cmd"),
            ("echo x && whoami", "cmd"),
            ("powershell -EncodedCommand ZWNobyBoYWNr", "cmd"),
            ("dir | findstr secret", "cmd")
        ]
    else:
        guard = PosixCommandGuard(allowed_commands=["echo", "foo", "ls"])
        attacks = [
            ("../secret", "path"),
            ("../../etc/passwd", "path"),
            ("foo;whoami", "cmd"),
            ("echo x && whoami", "cmd"),
            ("ls `id`", "cmd"),
            ("echo $(whoami)", "cmd"),
            ("foo | grep root", "cmd")
        ]
    
    blocked_count = 0
    for attack, kind in attacks:
        blocked = False
        if kind == "path":
            try:
                jailer.check_path(attack)
            except PathTraversalError:
                blocked = True
        else:
            try:
                guard.check_command(attack)
            except CommandInjectionError:
                blocked = True
        
        status = "BLOCKED" if blocked else "REVIEW"
        if blocked:
            blocked_count += 1
        print(f"  [{kind.upper():<4}] {attack!r:<42} : {status}")
        
    print(f"\nResult: {blocked_count}/{len(attacks)} attacks blocked ({blocked_count/len(attacks)*100:.1f}%)")

if __name__ == "__main__":
    main()
