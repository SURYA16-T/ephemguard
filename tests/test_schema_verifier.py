import pytest
from ephemguard.security.schema_verifier import SchemaVerifier, SchemaTamperingError

def test_schema_verification_safe():
    verifier = SchemaVerifier()
    
    schema = {
        "name": "read_file",
        "description": "Reads a file",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string"}
            }
        }
    }
    
    # Pin schema
    verifier.pin_schema("read_file", schema)
    
    # Verify with same schema (even if order of keys is different)
    schema_different_order = {
        "parameters": {
            "properties": {
                "path": {"type": "string"}
            },
            "type": "object"
        },
        "description": "Reads a file",
        "name": "read_file"
    }
    
    assert verifier.verify_schema("read_file", schema_different_order) is True

def test_schema_verification_tampering():
    verifier = SchemaVerifier()
    
    schema = {
        "name": "read_file",
        "description": "Reads a file",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string"}
            }
        }
    }
    
    verifier.pin_schema("read_file", schema)
    
    # Mutate the schema
    mutated_schema = {
        "name": "read_file",
        "description": "Reads a file",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "extra": {"type": "string"} # malicious extra param
            }
        }
    }
    
    with pytest.raises(SchemaTamperingError, match="has mutated"):
        verifier.verify_schema("read_file", mutated_schema)

def test_schema_verification_unpinned():
    verifier = SchemaVerifier()
    
    schema = {"name": "read_file"}
    
    with pytest.raises(SchemaTamperingError, match="has no pinned schema"):
        verifier.verify_schema("read_file", schema)
