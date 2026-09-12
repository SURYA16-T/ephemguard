from typing import Dict, Any
import sys

from ephemguard.security.path_jailer import PathJailer, PathTraversalError
from ephemguard.security.command_guard import PosixCommandGuard, WindowsCommandGuard, CommandInjectionError
from ephemguard.security.policy_engine import PolicyEngine

class CapabilityViolation(Exception):
    """Raised when a tool argument violates capability constraints (e.g., path traversal)."""
    pass

def attenuate_tool_call(tool: str, arguments: Dict[str, Any], workspace: str, policy: PolicyEngine) -> Dict[str, Any]:
    """
    Apply constraints to tool arguments, such as path canonicalization
    and command sanitization.
    """
    attenuated = arguments.copy()
    jailer = PathJailer([workspace])
    
    # Provide basic structural structural analysis on arguments
    # by matching keys. In a production system, this would be 
    # strictly driven by the tool's JSON schema.
    for key, value in list(attenuated.items()):
        if isinstance(value, str):
            # Attenuate path arguments
            if "path" in key.lower() or "file" in key.lower():
                try:
                    safe_path = jailer.check_path(value)
                    attenuated[key] = str(safe_path)
                except PathTraversalError as e:
                    raise CapabilityViolation(f"Path violation in argument '{key}': {e}")
            
            # Attenuate command arguments
            elif "cmd" in key.lower() or "command" in key.lower():
                guard_cls = WindowsCommandGuard if sys.platform == "win32" else PosixCommandGuard
                # Allow all base executables in this heuristic check, 
                # relying solely on the structural injection checks (e.g. blocking `|`, `&&`)
                # We achieve this by overriding the executable check in this instance
                guard = guard_cls([])
                
                # Check structural safety
                try:
                    # For PosixCommandGuard, parse the AST to check for shell operators
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
                    raise CapabilityViolation(f"Command injection detected in argument '{key}': {e}")

    return attenuated
