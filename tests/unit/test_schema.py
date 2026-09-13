import pytest
from ephemguard.security.schema_verifier import SchemaVerifier, SchemaMismatch

def test_pin_verify():
    v = SchemaVerifier()
    s = {"tools": [{"name": "read"}]}
    v.pin_or_verify("srv", s)
    v.pin_or_verify("srv", s)

def test_schema_change():
    v = SchemaVerifier()
    v.pin_or_verify("srv", {"tools": [{"name": "read"}]})
    with pytest.raises(SchemaMismatch):
        v.pin_or_verify("srv", {"tools": [{"name": "exec"}]})

def test_schema_pin_and_verify():
    v = SchemaVerifier()
    s = {"tools": [{"name": "filesystem_read"}]}
    v.pin("srv", s)
    v.verify("srv", s)
    bad = {"tools": [{"name": "filesystem_write"}]}
    try:
        v.verify("srv", bad)
        assert False
    except SchemaMismatch:
        pass

