# Architecture

AI Agent → JSON-RPC/MCP → EphemGuard → validated MCP server → OS/tooling

Security flow:
1. Parse protocol.
2. Apply policy.
3. Attenuate paths/arguments.
4. Require a short-lived single-use HMAC lease.
5. Verify schema pin when a server tool definition is used.
6. Run optional intent divergence checks.
7. Audit allow/block decisions.
8. Forward only after all required checks pass.
