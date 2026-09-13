import json
from ephemguard.proxy.interceptor import SecurityInterceptor
from ephemguard.security.lease_manager import LeaseManager

def test_interceptor_allows_valid_call(tmp_path):
    secret = b"z" * 32
    interceptor = SecurityInterceptor(str(tmp_path), secret, log_path=str(tmp_path / "audit.jsonl"))
    lm = LeaseManager(secret)
    target = str(tmp_path / "a.py")
    token = lm.mint("filesystem_read", target, "read")
    req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "filesystem_read",
            "arguments": {"path": "a.py", "operation": "read"}
        }
    }
    result = interceptor.inspect(req, lease=token, nonce="n1", user_intent="read this file")
    assert result.allowed
    assert result.transformed_params["path"] == target
