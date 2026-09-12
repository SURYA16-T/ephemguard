import json
import hashlib
from typing import Dict, Any, Optional

class SchemaTamperingError(Exception):
    """Raised when runtime schema mutation is detected."""
    pass

class SchemaVerifier:
    """
    Computes and pins SHA-256 fingerprints of tool definitions to prevent
    runtime schema mutations.
    """
    
    def __init__(self):
        # tool_name -> sha256 hash of its schema
        self._pinned_schemas: Dict[str, str] = {}
        
    def _compute_fingerprint(self, schema: Dict[str, Any]) -> str:
        """
        Computes a consistent SHA-256 fingerprint for a schema dictionary.
        Uses json.dumps with sort_keys=True to ensure consistent ordering.
        """
        serialized = json.dumps(schema, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(serialized.encode('utf-8')).hexdigest()
        
    def pin_schema(self, tool_name: str, schema: Dict[str, Any]):
        """
        Pin a schema for a given tool during initialization.
        If the tool already has a pinned schema, this will overwrite it 
        (assuming initialization phase).
        """
        fingerprint = self._compute_fingerprint(schema)
        self._pinned_schemas[tool_name] = fingerprint
        
    def verify_schema(self, tool_name: str, schema: Dict[str, Any]) -> bool:
        """
        Verify that the provided schema matches the pinned schema for the tool.
        Raises SchemaTamperingError if they do not match or if the tool is unpinned.
        """
        if tool_name not in self._pinned_schemas:
            raise SchemaTamperingError(f"Tool '{tool_name}' has no pinned schema")
            
        current_fingerprint = self._compute_fingerprint(schema)
        expected_fingerprint = self._pinned_schemas[tool_name]
        
        if current_fingerprint != expected_fingerprint:
            raise SchemaTamperingError(
                f"Schema for tool '{tool_name}' has mutated. "
                f"Expected fingerprint: {expected_fingerprint[:8]}..., "
                f"Got: {current_fingerprint[:8]}..."
            )
            
        return True
