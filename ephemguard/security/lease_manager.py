import base64
import time
import hmac
import hashlib
import json
import secrets
import threading
from typing import Optional, Set, Dict, Any

class LeaseViolation(PermissionError):
    """Raised when a capability lease is invalid, expired, or replayed."""
    pass

class LeaseManager:
    """
    Issues and verifies single-use, time-to-live HMAC-SHA256 tokens 
    linked to specific tool names, resources, and operations.
    """
    
    def __init__(self, secret_key: Optional[bytes] = None, default_ttl: int = 15):
        self.secret: bytes = secret_key or secrets.token_bytes(32)
        self._secret_key: bytes = self.secret
        self.ttl_seconds: int = default_ttl
        self.default_ttl: int = default_ttl
        
        # Store used tokens to prevent replay attacks (token -> expiry time)
        self._used_tokens: Dict[str, float] = {}
        self._used: Set[str] = set()
        self._lock = threading.Lock()
        
    def _cleanup_expired_tokens(self, current_time: float):
        """Remove tokens that have expired from the used tokens store."""
        expired = [token for token, expiry in self._used_tokens.items() if current_time > expiry]
        for token in expired:
            del self._used_tokens[token]

    def issue_lease(self, tool_name: str, ttl: Optional[int] = None) -> str:
        """Issue a new lease token for the given tool."""
        if ttl is None:
            ttl = self.default_ttl
            
        current_time = time.time()
        expiry = int(current_time + ttl)
        nonce = secrets.token_hex(8)
        message = f"{tool_name}:{expiry}:{nonce}".encode('utf-8')
        signature = hmac.new(self._secret_key, message, hashlib.sha256).hexdigest()
        return f"{tool_name}:{expiry}:{nonce}:{signature}"
        
    def verify_lease(self, token: str, expected_tool: str) -> bool:
        """
        Verify that a lease is valid, hasn't expired, is for the correct tool,
        and hasn't been used before.
        """
        current_time = time.time()
        self._cleanup_expired_tokens(current_time)
        
        with self._lock:
            if token in self._used_tokens:
                return False
                
            parts = token.split(':')
            if len(parts) != 4:
                return False
                
            tool_name, expiry_str, nonce, signature = parts
            if tool_name != expected_tool:
                return False
                
            try:
                expiry = int(expiry_str)
            except ValueError:
                return False
                
            if current_time > expiry:
                return False
                
            message = f"{tool_name}:{expiry}:{nonce}".encode('utf-8')
            expected_signature = hmac.new(self._secret_key, message, hashlib.sha256).hexdigest()
            
            if not hmac.compare_digest(signature, expected_signature):
                return False
                
            self._used_tokens[token] = expiry
            return True

    def mint(self, tool: str, resource: str = "", operation: str = "read", ttl: Optional[int] = None) -> str:
        """Mint a signed capability lease token (PDF reference specification)."""
        lifetime = self.ttl_seconds if ttl is None else int(ttl)
        if lifetime <= 0 or lifetime > 300:
            raise ValueError("TTL must be between 1 and 300 seconds")
        now = int(time.time())
        payload = {
            "v": 1,
            "jti": secrets.token_urlsafe(18),
            "tool": tool,
            "resource": resource,
            "operation": operation,
            "iat": now,
            "exp": now + lifetime
        }
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        sig = hmac.new(self.secret, raw, hashlib.sha256).hexdigest().encode("ascii")
        return base64.urlsafe_b64encode(raw).decode() + "." + sig.decode("ascii")

    def _decode(self, token: str) -> dict:
        """Decode and verify the signature of a minted capability lease."""
        try:
            encoded_raw, sig_hex = token.split(".", 1)
            raw = base64.urlsafe_b64decode(encoded_raw.encode("ascii"))
            sig = bytes.fromhex(sig_hex)
            expected = hmac.new(self.secret, raw, hashlib.sha256).digest()
            if not hmac.compare_digest(sig, expected):
                raise LeaseViolation("invalid lease signature")
            payload = json.loads(raw.decode("utf-8"))
            if not isinstance(payload, dict) or payload.get("v") != 1:
                raise LeaseViolation("invalid lease payload")
            return payload
        except LeaseViolation:
            raise
        except (ValueError, json.JSONDecodeError, UnicodeError) as exc:
            raise LeaseViolation("invalid lease encoding") from exc

    def consume(self, token: str, expected_tool: str, arguments: dict = None) -> dict:
        """Consume a lease token for the given tool and arguments, enforcing single-use."""
        if arguments is None:
            arguments = {}
        if "." in token:
            payload = self._decode(token)
            now = int(time.time())
            if int(payload.get("exp", 0)) <= now:
                raise LeaseViolation("lease expired")
            if payload.get("tool") != expected_tool:
                raise LeaseViolation("lease tool mismatch")
            requested_resource = str(arguments.get("path", arguments.get("resource", "")))
            if payload.get("resource") and requested_resource != payload["resource"]:
                raise LeaseViolation("lease resource mismatch")
            requested_operation = str(arguments.get("operation", "read"))
            if payload.get("operation") != requested_operation:
                raise LeaseViolation("lease operation mismatch")
            jti = str(payload.get("jti", ""))
            if not jti:
                raise LeaseViolation("missing lease identifier")
            with self._lock:
                if jti in self._used:
                    raise LeaseViolation("lease replay detected")
                self._used.add(jti)
            return payload
        else:
            if not self.verify_lease(token, expected_tool):
                raise LeaseViolation("capability lease required or invalid")
            return {"tool": expected_tool}
