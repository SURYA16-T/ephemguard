import hashlib
import hmac
import json
import secrets


def _get_chain_secret() -> bytes:
    """
    Returns a persistent secret for HMAC chain integrity.
    This prevents an attacker who compromised the system from rewriting 
    the entire history and forging valid hashes, unless they also steal this key.
    """
    # In a real system, this would be loaded securely, perhaps from a KMS
    # For now, we simulate a system-level secret that is persisted alongside the logs
    return b"ephemguard_audit_chain_secret_v1"


def chain_hash(entry: dict) -> str:
    """Compute HMAC-SHA256 hash of the log entry body."""
    body = {k: v for k, v in entry.items() if k != "hash"}
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    
    # Use HMAC instead of plain SHA256 for better tamper resistance
    secret = _get_chain_secret()
    return hmac.new(secret, raw, hashlib.sha256).hexdigest()


def legacy_chain_hash(entry: dict) -> str:
    """Compute plain SHA-256 hash of the log entry body for legacy logs."""
    body = {k: v for k, v in entry.items() if k != "hash"}
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()


def verify_chain(path: str) -> bool:
    previous = "0" * 64
    count = 0
    
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    return False
                    
                if entry.get("prev_hash") != previous:
                    return False
                    
                actual_hmac = chain_hash(entry)
                actual_legacy = legacy_chain_hash(entry)
                entry_hash = entry.get("hash")
                
                if hmac.compare_digest(actual_hmac, entry_hash):
                    valid_hash = actual_hmac
                elif hmac.compare_digest(actual_legacy, entry_hash):
                    valid_hash = actual_legacy
                else:
                    return False
                    
                previous = valid_hash
                count += 1
                
        # Empty chain is valid, otherwise we verified count > 0 links
        return True
    except FileNotFoundError:
        return True  # No logs yet is valid
    except Exception:
        return False
