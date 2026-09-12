import os
from pathlib import Path
from typing import Dict, Any, List

from ephemguard.config.loader import load_policy

class PolicyViolation(Exception):
    """Raised when a tool is not authorized by the policy."""
    pass

class PolicyEngine:
    def __init__(self, allowed_tools: List[str]):
        self.allowed_tools = allowed_tools

    @classmethod
    def for_current_platform(cls, config_path: str = None):
        """Initialize the PolicyEngine from a configuration file."""
        if config_path is None:
            from ephemguard.platform.detector import current_os
            config_path = f"policies/{current_os()}.yaml"
            
        if not os.path.exists(config_path):
            return cls([])
            
        policy = load_policy(config_path)
        allowed_tools = policy.get("allowed_tools", [])
        return cls(allowed_tools)

    def authorize(self, tool: str, arguments: Dict[str, Any]) -> None:
        """
        Authorize a tool call based on the policy.
        Raises PolicyViolation if unauthorized.
        """
        if tool not in self.allowed_tools:
            raise PolicyViolation(f"Tool '{tool}' is not authorized by the current policy.")
