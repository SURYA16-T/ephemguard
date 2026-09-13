import json
import hashlib
import hmac
from typing import Dict, Any, Optional

class SchemaTamperingError(ValueError):
    """Raised when runtime schema mutation is detected."""
    pass

SchemaMismatch = SchemaTamperingError

class SchemaVerifier:
    """
    Computes and pins SHA-256 fingerprints of tool definitions to prevent
    runtime schema mutations.
    """
    
    def __init__(self):
        # tool_name / server_id -> sha256 hash of its schema
        self._pinned_schemas: Dict[str, str] = {}
        self._pins: Dict[str, str] = self._pinned_schemas
        
    @staticmethod
    def canonical_schema(schema: Dict[str, Any]) -> bytes:
        return json.dumps(schema, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

    def digest(self, schema: Dict[str, Any]) -> str:
        return hashlib.sha256(self.canonical_schema(schema)).hexdigest()

    def _compute_fingerprint(self, schema: Dict[str, Any]) -> str:
        return self.digest(schema)
        
    def pin_schema(self, tool_name: str, schema: Dict[str, Any]):
        """Pin a schema for a given tool during initialization."""
        self._pinned_schemas[tool_name] = self.digest(schema)

    def pin(self, server_id: str, schema: Dict[str, Any]) -> str:
        """Pin a schema for a given server ID (PDF compatibility)."""
        value = self.digest(schema)
        self._pinned_schemas[server_id] = value
        return value
        
    def verify_schema(self, tool_name: str, schema: Dict[str, Any]) -> bool:
        """
        Verify that the provided schema matches the pinned schema for the tool.
        Raises SchemaTamperingError if they do not match or if the tool is unpinned.
        """
        if tool_name not in self._pinned_schemas:
            raise SchemaTamperingError(f"Tool '{tool_name}' has no pinned schema")
            
        current_fingerprint = self.digest(schema)
        expected_fingerprint = self._pinned_schemas[tool_name]
        
        if not hmac.compare_digest(current_fingerprint, expected_fingerprint):
            raise SchemaTamperingError(
                f"Schema for tool '{tool_name}' has mutated. "
                f"Expected fingerprint: {expected_fingerprint[:8]}..., "
                f"Got: {current_fingerprint[:8]}..."
            )
            
        return True

    def verify(self, server_id: str, schema: Dict[str, Any]) -> None:
        """Verify schema for server_id (PDF compatibility)."""
        expected = self._pinned_schemas.get(server_id)
        if expected is None:
            raise SchemaMismatch("schema has not been pinned")
        actual = self.digest(schema)
        if not hmac.compare_digest(actual, expected):
            raise SchemaMismatch("tool schema hash mismatch")

    def pin_or_verify(self, server_id: str, schema: Dict[str, Any]) -> str:
        """Pin on first seen, verify on subsequent calls (PDF compatibility)."""
        actual = self.digest(schema)
        expected = self._pinned_schemas.get(server_id)
        if expected is None:
            self._pinned_schemas[server_id] = actual
            return actual
        if not hmac.compare_digest(actual, expected):
            raise SchemaMismatch("tool schema hash mismatch")
        return actual
