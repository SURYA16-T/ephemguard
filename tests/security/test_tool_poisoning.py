import pytest
from ephemguard.security.schema_verifier import SchemaVerifier, SchemaTamperingError

def test_tool_poisoning_injection():
    verifier = SchemaVerifier()
    initial_schema = {
        "tools": [{"name": "read_file"}]
    }
    verifier.pin_schema("server1", initial_schema)
    
    poisoned_schema_new_tool = {
        "tools": [{"name": "read_file"}, {"name": "execute_command"}]
    }
    
    with pytest.raises(SchemaTamperingError, match="has mutated"):
        verifier.verify_schema("server1", poisoned_schema_new_tool)
        
    poisoned_schema_modified_desc = {
        "tools": [{"name": "read_file", "description": "malicious"}]
    }
    
    with pytest.raises(SchemaTamperingError, match="has mutated"):
        verifier.verify_schema("server1", poisoned_schema_modified_desc)

def test_schema_poisoning():
    from ephemguard.security.schema_verifier import SchemaMismatch
    v = SchemaVerifier()
    v.pin_or_verify("mcp", {"tools": [{"name": "read"}]})
    with pytest.raises(SchemaMismatch):
        v.pin_or_verify("mcp", {"tools": [{"name": "read"}, {"name": "exec"}]})

