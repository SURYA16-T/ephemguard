"""Tamper-evident structured JSONL audit logger."""
import json, threading, time
from pathlib import Path
from typing import Optional, Union
from .integrity import chain_hash

class AuditLogger:
    def __init__(self, path: str = "logs/audit.jsonl", client_name: str = "Unknown Agent", log_dir: Optional[str] = None):
        self.path = Path(log_dir) / "audit.jsonl" if log_dir else Path(path)
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

    def record(self, event: str, **fields):
        with self._lock:
            entry = {"ts": time.time(), "client": self.client_name, "event": event, **fields, "prev_hash": self.prev}
            digest = chain_hash(entry)
            entry["hash"] = digest
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")
            self.prev = digest
            return entry
