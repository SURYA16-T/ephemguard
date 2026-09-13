"""Strict, small JSON-RPC 2.0 validation layer with security hardening."""
import json
from typing import Any, Dict, Optional

# Security limits
MAX_MESSAGE_SIZE = 1 * 1024 * 1024  # 1 MB
MAX_JSON_DEPTH = 32
KNOWN_MCP_METHODS = frozenset({
    "initialize", "initialized", "shutdown",
    "tools/list", "tools/call",
    "resources/list", "resources/read",
    "prompts/list", "prompts/get",
    "completion/complete",
    "logging/setLevel",
    "notifications/cancelled",
    "notifications/progress",
    "notifications/message",
    "notifications/resources/updated",
    "notifications/resources/list_changed",
    "notifications/tools/list_changed",
    "notifications/prompts/list_changed",
    "ping",
})


class ProtocolError(ValueError):
    pass


def _check_json_depth(obj: Any, current_depth: int = 0) -> None:
    """Recursively check JSON nesting depth to prevent stack overflow attacks."""
    if current_depth > MAX_JSON_DEPTH:
        raise ProtocolError(f"JSON nesting depth exceeds maximum of {MAX_JSON_DEPTH}")

    if isinstance(obj, dict):
        for value in obj.values():
            _check_json_depth(value, current_depth + 1)
    elif isinstance(obj, list):
        for item in obj:
            _check_json_depth(item, current_depth + 1)


def parse_jsonrpc(line: str) -> Dict[str, Any]:
    """Parse and validate a JSON-RPC 2.0 message with security checks."""
    # Enforce size limit before parsing
    if len(line) > MAX_MESSAGE_SIZE:
        raise ProtocolError(f"Message exceeds maximum size of {MAX_MESSAGE_SIZE} bytes")

    try:
        obj = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ProtocolError("invalid JSON") from exc

    if not isinstance(obj, dict):
        raise ProtocolError("JSON-RPC message must be an object")

    # Check nesting depth to prevent DoS via deeply nested structures
    _check_json_depth(obj)

    if obj.get("jsonrpc") != "2.0":
        raise ProtocolError("invalid JSON-RPC 2.0 object")
    if "method" in obj:
        if not isinstance(obj["method"], str):
            raise ProtocolError("method must be a string")
    elif "result" not in obj and "error" not in obj:
        raise ProtocolError("message must contain method, result, or error")
    if "id" in obj and isinstance(obj["id"], (dict, list)):
        raise ProtocolError("id must be scalar or null")
    if "params" in obj and not isinstance(obj["params"], (dict, list)):
        raise ProtocolError("params must be object or array")

    return obj


def encode_jsonrpc_response(request_id: Any, result: Any = None, error: Optional[Dict] = None) -> str:
    response = {"jsonrpc": "2.0", "id": request_id}
    if error is not None:
        response["error"] = error
    else:
        response["result"] = result
    return json.dumps(response, separators=(",", ":"))
