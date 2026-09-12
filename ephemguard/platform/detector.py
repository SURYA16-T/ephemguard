import sys

def current_os() -> str:
    system = sys.platform.lower()
    if system == "darwin": return "macos"
    if system == "win32": return "windows"
    if system.startswith("linux"): return "linux"
    return system
