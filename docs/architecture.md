# Architecture

AI Agent → JSON-RPC/MCP → EphemGuard → validated MCP server → OS/tooling

Security flow:

1. Parse and size-limit JSON-RPC messages.
2. Inspect `tools/call` requests.
3. Apply least-privilege policy.
4. Canonicalize and confine filesystem paths.
5. Enforce shell-language command policy when command arguments are present.
6. Require a short-lived, single-use HMAC lease.
7. Optionally require a one-time replay nonce and intent check.
8. Pin the upstream `tools/list` response and stop on schema changes.
9. Audit allow/block decisions with a hash chain.
10. Forward only after the hard checks pass.
