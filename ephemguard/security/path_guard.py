from typing import Union
from pathlib import Path

class PathViolation(ValueError):
    """Raised when a requested path escapes the configured workspace."""
    pass

def resolve_workspace(workspace: Union[str, Path]) -> Path:
    return Path(workspace).expanduser().resolve(strict=False)

def resolve_confined(workspace: Union[str, Path], candidate: Union[str, Path]) -> Path:
    root = resolve_workspace(workspace)
    raw = Path(candidate).expanduser()
    if not raw.is_absolute():
        raw = root / raw
    target = raw.resolve(strict=False)
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise PathViolation(f"path escapes workspace: {candidate}") from exc
    return target

def is_confined(workspace: Union[str, Path], candidate: Union[str, Path]) -> bool:
    try:
        resolve_confined(workspace, candidate)
        return True
    except (OSError, RuntimeError, PathViolation):
        return False
