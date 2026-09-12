"""Explicit replay nonce tracker with TTL and capacity limits."""
import threading
import time
from collections import OrderedDict


class ReplayGuard:
    def __init__(self, max_capacity: int = 10000, ttl_seconds: int = 3600):
        # We use OrderedDict as an LRU cache to prevent memory exhaustion
        self._seen = OrderedDict()
        self._lock = threading.Lock()
        self.max_capacity = max_capacity
        self.ttl_seconds = ttl_seconds

    def claim(self, nonce: str) -> bool:
        with self._lock:
            now = time.monotonic()
            
            # Clean up expired nonces lazily
            expired_keys = []
            for k, timestamp in self._seen.items():
                if now - timestamp > self.ttl_seconds:
                    expired_keys.append(k)
                else:
                    # Since it's ordered by insertion time, once we hit a non-expired
                    # entry, all subsequent entries are also non-expired
                    break
                    
            for k in expired_keys:
                del self._seen[k]

            if nonce in self._seen:
                return False
                
            # If we're at capacity, pop the oldest item (FIFO)
            if len(self._seen) >= self.max_capacity:
                self._seen.popitem(last=False)
                
            self._seen[nonce] = now
            return True

    def clear(self):
        with self._lock:
            self._seen.clear()
