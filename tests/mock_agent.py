"""Mock AI agent that emits safe JSON-RPC examples."""
import json

def tool_call(name, arguments, request_id=1):
    return json.dumps({"jsonrpc":"2.0","id":request_id,"method":"tools/call","params":{"name":name,"arguments":arguments}})

if __name__ == "__main__":
    print(tool_call("filesystem_read", {"path":"src/example.py"}))
