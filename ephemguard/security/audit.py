"""Structured tamper-evident audit logger with file locking and rotation."""
import json
import os
import sys
import time
from pathlib import Path

try:
    import fcntl
except ImportError:
    fcntl = None

from .integrity import chain_hash


class AuditLogger:
    MAX_LOG_SIZE = 10 * 1024 * 1024  # 10 MB before rotation
    MAX_ROTATED_FILES = 5

    def __init__(self, path: str = None, client_name: str = "Unknown Agent", log_dir: str = None):
        # Use absolute paths to prevent CWD manipulation attacks
        if path is not None:
            self.path = Path(os.path.abspath(path))
        elif log_dir is not None:
            self.path = Path(os.path.abspath(log_dir)) / "audit.jsonl"
        else:
            self.path = Path(os.path.abspath("logs")) / "audit.jsonl"

        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.prev = "0" * 64
        self.client_name = client_name

        # Detect current OS for audit context
        if sys.platform == "darwin":
            self._os_platform = "macos"
        elif sys.platform == "win32":
            self._os_platform = "windows"
        elif sys.platform.startswith("linux"):
            self._os_platform = "linux"
        else:
            self._os_platform = sys.platform

        if self.path.exists():
            try:
                with self.path.open("r", encoding="utf-8") as f:
                    lines = [line.strip() for line in f if line.strip()]
                    if lines:
                        last_entry = json.loads(lines[-1])
                        self.prev = last_entry.get("hash", "0" * 64)
            except Exception:
                pass

    def _rotate_if_needed(self):
        """Rotate log file if it exceeds MAX_LOG_SIZE."""
        if not self.path.exists():
            return
        try:
            if self.path.stat().st_size > self.MAX_LOG_SIZE:
                # Rotate existing files
                for i in range(self.MAX_ROTATED_FILES - 1, 0, -1):
                    older = self.path.with_suffix(f".{i}.jsonl")
                    newer = self.path.with_suffix(f".{i - 1}.jsonl") if i > 1 else self.path
                    if (newer if i > 1 else self.path.with_suffix(".1.jsonl")).exists():
                        pass  # handled below

                for i in range(self.MAX_ROTATED_FILES, 0, -1):
                    src = self.path.with_suffix(f".{i - 1}.jsonl") if i > 1 else self.path
                    dst = self.path.with_suffix(f".{i}.jsonl")
                    if i == 1:
                        src = self.path
                    if src.exists():
                        if dst.exists():
                            dst.unlink()
                        src.rename(dst)

                # Reset chain for new file
                self.prev = "0" * 64
        except Exception:
            pass  # Don't let rotation errors block logging

    def record(self, event: str, **fields):
        """Record a tamper-evident audit entry with file locking."""
        self._rotate_if_needed()

        entry = {
            "ts": time.time(),
            "client": self.client_name,
            "event": event,
            "platform": self._os_platform,
            **fields,
            "prev_hash": self.prev,
        }
        self.prev = chain_hash(entry)
        entry["hash"] = self.prev

        serialized = json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n"

        # Use file locking for concurrent write safety (cross-platform)
        try:
            with self.path.open("a", encoding="utf-8") as f:
                if fcntl is not None and sys.platform != "win32":
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    f.write(serialized)
                finally:
                    if fcntl is not None and sys.platform != "win32":
                        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except (ImportError, AttributeError, OSError):
            # fcntl not available or locking failed — fallback to basic write
            with self.path.open("a", encoding="utf-8") as f:
                f.write(serialized)

        return entry
