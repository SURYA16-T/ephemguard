import pytest
from ephemguard.proxy.protocol import parse_jsonrpc, ProtocolError

def test_protocol_ok():
    assert parse_jsonrpc('{"jsonrpc":"2.0","id":1,"method":"ping"}')['method'] == 'ping'

def test_protocol_bad():
    with pytest.raises(ProtocolError):
        parse_jsonrpc('{"jsonrpc":"1.0","id":1,"method":"ping"}')
