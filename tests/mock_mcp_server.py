"""Mock downstream MCP-like server for integration tests."""
import json
import sys

def tools_list():
    return {"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "filesystem_read", "inputSchema": {"type": "object"}}]}}

def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        req = json.loads(line)
        if req.get("method") == "tools/list":
            print(json.dumps({"jsonrpc": "2.0", "id": req.get("id"), "result": {"tools": [{"name": "filesystem_read", "inputSchema": {"type": "object"}}]}}), flush=True)
        else:
            print(json.dumps({"jsonrpc": "2.0", "id": req.get("id"), "result": {"ok": True}}), flush=True)

if __name__ == "__main__":
    if not sys.stdin.isatty():
        main()
    else:
        print(json.dumps(tools_list()))
