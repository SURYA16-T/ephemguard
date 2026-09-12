"""Mock downstream MCP-like server for integration tests."""
import json

def tools_list():
    return {"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"filesystem_read","inputSchema":{"type":"object"}}]}}

if __name__ == "__main__":
    print(json.dumps(tools_list()))
