"""Centralized least-privilege policy engine."""
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import platform
import yaml

class PolicyViolation(PermissionError):
    """Raised when a tool call violates policy."""
    pass

@dataclass
class PolicyEngine:
    allowed_tools: Union[Set[str], List[str]] = field(
        default_factory=lambda: {"filesystem_read", "filesystem_write"}
    )
    read_only_tools: Union[Set[str], List[str]] = field(
        default_factory=lambda: {"filesystem_read"}
    )
    blocked_argument_fragments: Tuple[str, ...] = (
        "curl ", "wget ", "powershell -enc", "base64 -d", "invoke-webrequest", "invoke-expression"
    )

    def __post_init__(self):
        if isinstance(self.allowed_tools, list):
            self.allowed_tools = set(self.allowed_tools)
        if isinstance(self.read_only_tools, list):
            self.read_only_tools = set(self.read_only_tools)

    @classmethod
    def for_current_platform(cls, config_path: Optional[str] = None) -> "PolicyEngine":
        engine = cls()
        if config_path:
            engine._load_yaml(Path(config_path))
        else:
            default_p = Path(f"policies/{cls.os_name()}.yaml")
            if default_p.exists():
                try:
                    engine._load_yaml(default_p)
                except Exception:
                    pass
        return engine

    def _load_yaml(self, path: Path) -> None:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            raise ValueError("policy must be a mapping")
        tools = data.get("allowed_tools")
        if isinstance(tools, list):
            self.allowed_tools = {str(x) for x in tools}

    @staticmethod
    def os_name() -> str:
        value = platform.system().lower()
        return {"darwin": "macos"}.get(value, value)

    def authorize(self, tool: str, arguments: Dict[str, Any]) -> None:
        if tool not in self.allowed_tools:
            raise PolicyViolation(f"tool not allowed: {tool}")
        flattened = " ".join(str(v) for v in arguments.values()).lower()
        if any(fragment.lower() in flattened for fragment in self.blocked_argument_fragments):
            raise PolicyViolation("blocked argument pattern detected")
        if tool in self.read_only_tools:
            operation = str(arguments.get("operation", "read")).lower()
            if operation not in {"read", "list", "stat"}:
                raise PolicyViolation("read-only capability violated")
