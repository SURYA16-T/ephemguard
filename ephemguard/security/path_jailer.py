import os
import sys
from pathlib import Path
from typing import List, Union

class PathTraversalError(Exception):
    """Raised when a path traversal attempt is detected."""
    pass

class PathJailer:
    """
    Prevents path traversal by confining paths to a set of allowed root directories.
    Handles symlink escapes, UNC paths, and Windows drive letter mismatches.
    """
    def __init__(self, allowed_roots: List[Union[str, Path]]):
        self.allowed_roots: List[Path] = []
        for root in allowed_roots:
            p = Path(root)
            # Resolve to get absolute canonical path, ignoring if it doesn't exist yet
            # but getting the canonical base. We use strict=False.
            resolved = p.resolve(strict=False)
            self.allowed_roots.append(resolved)

    def _is_unc_path(self, path: Path) -> bool:
        """Check if a path is a UNC path (e.g., \\\\server\\share)."""
        drive = path.drive
        return drive.startswith(r'\\') or drive.startswith('//')

    def check_path(self, requested_path: Union[str, Path]) -> Path:
        """
        Validates and returns the canonical absolute path if it is safe.
        Raises PathTraversalError if it attempts to escape allowed roots.
        """
        p = Path(requested_path)
        
        # Reject UNC paths immediately as they can bypass local drive restrictions
        if self._is_unc_path(p):
            raise PathTraversalError(f"UNC paths are not allowed: {requested_path}")
            
        try:
            # Resolve resolves symlinks and canonicalizes the path.
            # strict=False allows checking paths that don't exist yet (e.g., for creating new files)
            resolved = p.resolve(strict=False)
        except RuntimeError as e:
            # Can happen with infinite symlink loops
            raise PathTraversalError(f"Failed to resolve path: {e}")

        # Check if the resolved path is relative to any of the allowed roots
        for root in self.allowed_roots:
            try:
                # In Python 3.9+, is_relative_to is available
                if resolved.is_relative_to(root):
                    # For Windows, also ensure the drive letters match exactly 
                    # to prevent bypassing via case differences or other tricks
                    if sys.platform == "win32":
                        if resolved.drive.lower() != root.drive.lower():
                            continue
                    return resolved
            except ValueError:
                pass

        raise PathTraversalError(f"Path escapes allowed roots: {requested_path}")
