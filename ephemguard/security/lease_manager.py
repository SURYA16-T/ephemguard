import time
import hmac
import hashlib
import secrets
from typing import Optional, Set, Dict

class LeaseManager:
    """
    Issues and verifies single-use, time-to-live HMAC-SHA256 tokens 
    linked to specific tool names.
    """
    
    def __init__(self, secret_key: Optional[bytes] = None, default_ttl: int = 30):
        # Generate a random secret key if none provided
        self._secret_key = secret_key or secrets.token_bytes(32)
        self.default_ttl = default_ttl
        
        # Store used tokens to prevent replay attacks (token -> expiry time)
        self._used_tokens: Dict[str, float] = {}
        
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
        
        # Nonce to ensure uniqueness even if same tool requested at same second
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
            
        # Mark as used (single-use)
        self._used_tokens[token] = expiry
        return True

    def consume(self, token: str, expected_tool: str, arguments: dict) -> None:
        """Consume a lease token for the given tool, raising LeaseViolation if invalid."""
        if not self.verify_lease(token, expected_tool):
            raise LeaseViolation("capability lease required or invalid")

class LeaseViolation(Exception):
    """Raised when a lease token is invalid, expired, or already used."""
    pass
