"""Mock AI agent that emits safe JSON-RPC examples."""
import json

def tool_call(name, arguments, lease=None, request_id=1, intent=""):
    params = {"name": name, "arguments": arguments}
    if lease is not None or intent:
        params["_meta"] = {
            "lease": lease,
            "intent": intent,
            "nonce": "demo-1"
        }
    return json.dumps({"jsonrpc": "2.0", "id": request_id, "method": "tools/call", "params": params})

if __name__ == "__main__":
    print(tool_call("filesystem_read", {"path": "src/example.py"}))
