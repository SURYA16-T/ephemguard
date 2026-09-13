# EphemGuard

[![CI](https://github.com/SURYA16-T/ephemguard/actions/workflows/ci.yml/badge.svg)](https://github.com/SURYA16-T/ephemguard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue)
![Platforms](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey)

EphemGuard is a cross-platform, user-space security gateway for AI-agent tool calls.
It applies defense-in-depth controls before a tool request can reach a downstream MCP/JSON-RPC server.

## About This Project

EphemGuard operates as an invisible **security middleware** (or plugin wrapper) between your AI Client (Claude Desktop, Cursor, Local LLMs like Ollama) and the actual MCP server. Instead of configuring your AI client to launch the MCP server directly, you configure it to launch `ephemguard wrap`, which spins up the target server internally and filters the JSON-RPC traffic with all code checked to be safe, enhanced by security code and all aspects of it.

## Where to Use This Project

- **Local AI Development:** Protect your personal files and operating system when running experimental AI agents locally (e.g., using Cursor or Claude Desktop).
- **Automated Workflows:** Secure continuous integration or scripting environments that rely on LLM-driven actions.
- **Enterprise Endpoint Security:** Add an extra layer of auditability and policy enforcement for employees using AI coding assistants.

## Security controls

- JSON-RPC 2.0 request validation
- Centralized policy checks
- Workspace path confinement and symlink/junction-aware resolution
- Short-lived, single-use HMAC capability leases
- Replay protection
- SHA-256 MCP tool-schema pinning
- Lightweight semantic intent checks
- OS-aware command policy for POSIX and PowerShell
- Tamper-evident hash-chain audit logs
- Security tests for traversal, injection, poisoning, replay, and capability escalation

## Supported operating systems

- macOS
- Linux
- Windows

## Supported Operating Systems & OS-Specific Commands

EphemGuard comes with a built-in interactive diagnostics dashboard. Depending on your operating system, the dashboard securely authorizes specific diagnostic commands.

### macOS

- `sysinfo`: `sw_vers` (OS version)
- `disk`: `df -h` (Disk usage)
- `memory`: `vm_stat` (Virtual memory statistics)
- `network`: `netstat -an | grep LISTEN | head -n 20` (Listening ports)
- `services`: `launchctl list | head -n 20` (Running services)
- `processes`: `ps aux -m | head -n 15` (Top memory processes)
- `firewall`: `pfctl -sr` (PF firewall rules - req. root)
- `users`: `who` (Logged in users)

### Linux

- `sysinfo`: `uname -a` (Kernel information)
- `disk`: `df -h` (Disk usage)
- `memory`: `free -m` (Memory usage)
- `network`: `ss -tlnp` (Listening ports)
- `services`: `systemctl list-units --type=service --state=running | head -n 20` (Running services)
- `processes`: `ps aux --sort=-%mem | head -n 15` (Top memory processes)
- `firewall`: `iptables -L -n | head -n 20` (Firewall rules - req. root)
- `users`: `who` (Logged in users)

### Windows (PowerShell)

- `sysinfo`: `systeminfo | Select-String 'OS Name','OS Version','System Type'` (System info)
- `disk`: `Get-Volume | Select-Object DriveLetter, FileSystemLabel, Size, SizeRemaining` (Disk usage)
- `memory`: `Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize, FreePhysicalMemory` (Memory usage)
- `network`: `Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort | Select -First 20` (Listening ports)
- `services`: `Get-Service | Where-Object Status -eq 'Running' | Select -First 20` (Running services)
- `processes`: `Get-Process | Sort-Object WorkingSet -Descending | Select-Object Name, Id, WorkingSet -First 15` (Top memory processes)
- `firewall`: `Get-NetFirewallRule -Enabled True -Direction Inbound | Select -First 10` (Inbound firewall rules)
- `users`: `quser` (Logged in users)

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[test]"
pytest -q
```

Windows PowerShell:

```powershell
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[test]"
pytest -q
```

## Usage (MCP Client Plugin)

Instead of configuring your AI client to launch the MCP server directly, you configure it to launch `ephemguard wrap`.

### 1. Claude Desktop Example

To protect your local filesystem when using Claude Desktop with the `sqlite` or `filesystem` MCP servers, edit your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "sqlite-protected": {
      "command": "/path/to/ephemguard/.venv/bin/python3",
      "args": [
        "-m", "ephemguard.cli", "wrap", "--", 
        "uvx", "mcp-server-sqlite", "--db-path", "/Users/me/data.db"
      ]
    }
  }
}
```

### 2. Cursor / Local LLM Example

If you are using Cursor, AnythingLLM, or building a custom LangChain agent that supports MCP over `stdio`, you configure the agent's tool execution command exactly the same way:

```bash
/path/to/ephemguard/.venv/bin/python3 -m ephemguard.cli wrap -- npx -y @modelcontextprotocol/server-filesystem /Users/me/Documents
```

### 3. Real-time Audit Dashboard

To actively monitor the AI agent's actions and see what EphemGuard is blocking in real-time, launch the built-in dashboard in a separate terminal:

```bash
python -m ephemguard.cli dashboard --port 8080
```

Open [http://localhost:8080](http://localhost:8080) to view the tamper-evident security stream and access the interactive terminal.
