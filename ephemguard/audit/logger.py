"""Tamper-evident structured JSONL audit logger."""
import json
import os
import sys
import threading
import time
from pathlib import Path
from typing import Optional, Union

try:
    import fcntl
except ImportError:
    fcntl = None

try:
    import msvcrt
except ImportError:
    msvcrt = None

from .integrity import chain_hash

class AuditLogger:
    def __init__(self, path: str = "logs/audit.jsonl", client_name: str = "Unknown Agent", log_dir: Optional[str] = None):
        if log_dir:
            self.path = Path(os.path.abspath(log_dir)) / "audit.jsonl"
        else:
            self.path = Path(os.path.abspath(path))
            
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.client_name = client_name
        self._lock = threading.Lock()
        self.prev = self._load_last_hash()

    def _load_last_hash(self) -> str:
        if not self.path.exists():
            return "0" * 64
        last_hash = "0" * 64
        try:
            with self.path.open("r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        entry = json.loads(line)
                        if isinstance(entry, dict) and isinstance(entry.get("hash"), str):
                            last_hash = entry["hash"]
        except (OSError, json.JSONDecodeError):
            return "0" * 64
        return last_hash

    def _lock_file(self, f):
        """Apply cross-process file lock."""
        if fcntl:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        elif msvcrt:
            self._win_lock_pos = f.tell()
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
            f.seek(self._win_lock_pos)

    def _unlock_file(self, f):
        """Release cross-process file lock."""
        if fcntl:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        elif msvcrt:
            pos = f.tell()
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
            f.seek(pos)

    def record(self, event: str, **fields):
        with self._lock:  # Thread lock
            entry = {"ts": time.time(), "client": self.client_name, "event": event, **fields, "prev_hash": self.prev}
            digest = chain_hash(entry)
            entry["hash"] = digest
            
            # Cross-process file lock
            with self.path.open("a", encoding="utf-8") as f:
                self._lock_file(f)
                try:
                    f.write(json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")
                    f.flush()
                    os.fsync(f.fileno())
                finally:
                    self._unlock_file(f)
                    
            self.prev = digest
            return entry
