from typing import Dict, Any
import sys

from ephemguard.security.path_guard import PathViolation, resolve_confined
from ephemguard.security.command_guard import (
    PosixCommandGuard, WindowsCommandGuard, CommandInjectionError,
    CommandViolation, inspect_posix, inspect_powershell
)
from ephemguard.security.policy_engine import PolicyEngine
from ephemguard.platform.detector import current_os

class CapabilityViolation(PermissionError):
    """Raised when a tool argument violates capability constraints (e.g., path traversal)."""
    pass

def attenuate_tool_call(tool: str, arguments: Dict[str, Any], workspace: str, policy: Any) -> Dict[str, Any]:
    """
    Apply constraints to tool arguments, such as path canonicalization
    and command sanitization.
    """
    attenuated = arguments.copy()
    
    for key, value in list(attenuated.items()):
        if isinstance(value, str):
            key_lower = key.lower()
            # Attenuate path arguments
            if "path" in key_lower or key_lower.endswith("file") or key_lower.endswith("filename"):
                try:
                    out_path = resolve_confined(workspace, value)
                    attenuated[key] = str(out_path)
                except PathViolation as e:
                    raise CapabilityViolation(f"path violation in '{key}': {e}") from e
                except ValueError as e:
                    raise CapabilityViolation(f"path violation in '{key}': {e}") from e
            
            # Attenuate command arguments
            elif "cmd" in key_lower or "command" in key_lower:
                try:
                    if current_os() == "windows":
                        inspect_powershell(value)
                    else:
                        inspect_posix(value)
                except CommandViolation as e:
                    raise CapabilityViolation(f"command violation in '{key}': {e}")
                except Exception:
                    guard_cls = WindowsCommandGuard if sys.platform == "win32" else PosixCommandGuard
                    guard = guard_cls([])
                    try:
                        if sys.platform != "win32":
                            import bashlex
                            try:
                                parts = bashlex.parse(value)
                                for ast in parts:
                                    guard._verify_node(ast)
                            except bashlex.errors.ParsingError as e:
                                raise CommandInjectionError(f"Failed to parse command: {e}")
                        else:
                            guard.check_command(value)
                    except CommandInjectionError as e:
                        raise CapabilityViolation(f"command violation in '{key}': {e}")

    if tool.startswith("filesystem_"):
        attenuated.setdefault("operation", "read" if tool == "filesystem_read" else "write")

    return attenuated
