"""Terminal diagnostics command execution engine."""
import asyncio
import os
import sys
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass

from .system_info import get_system_info

logger = logging.getLogger(__name__)

# Pre-approved diagnostic commands per OS
LINUX_COMMANDS = {
    "sysinfo": {"cmd": "uname -a", "desc": "Kernel information"},
    "disk": {"cmd": "df -h", "desc": "Disk usage"},
    "memory": {"cmd": "free -m", "desc": "Memory usage"},
    "network": {"cmd": "ss -tlnp", "desc": "Listening ports"},
    "services": {"cmd": "systemctl list-units --type=service --state=running | head -n 20", "desc": "Running services"},
    "processes": {"cmd": "ps aux --sort=-%mem | head -n 15", "desc": "Top memory processes"},
    "firewall": {"cmd": "iptables -L -n | head -n 20", "desc": "Firewall rules (req. root)"},
    "users": {"cmd": "who", "desc": "Logged in users"}
}

MACOS_COMMANDS = {
    "sysinfo": {"cmd": "sw_vers", "desc": "OS version"},
    "disk": {"cmd": "df -h", "desc": "Disk usage"},
    "memory": {"cmd": "vm_stat", "desc": "Virtual memory statistics"},
    "network": {"cmd": "netstat -an | grep LISTEN | head -n 20", "desc": "Listening ports"},
    "services": {"cmd": "launchctl list | head -n 20", "desc": "Running services"},
    "processes": {"cmd": "ps aux -m | head -n 15", "desc": "Top memory processes"},
    "firewall": {"cmd": "pfctl -sr", "desc": "PF firewall rules (req. root)"},
    "users": {"cmd": "who", "desc": "Logged in users"}
}

WINDOWS_COMMANDS = {
    "sysinfo": {"cmd": "systeminfo | Select-String 'OS Name','OS Version','System Type'", "desc": "System info"},
    "disk": {"cmd": "Get-Volume | Select-Object DriveLetter, FileSystemLabel, Size, SizeRemaining", "desc": "Disk usage"},
    "memory": {"cmd": "Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize, FreePhysicalMemory", "desc": "Memory usage"},
    "network": {"cmd": "Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort | Select -First 20", "desc": "Listening ports"},
    "services": {"cmd": "Get-Service | Where-Object Status -eq 'Running' | Select -First 20", "desc": "Running services"},
    "processes": {"cmd": "Get-Process | Sort-Object WorkingSet -Descending | Select-Object Name, Id, WorkingSet -First 15", "desc": "Top memory processes"},
    "firewall": {"cmd": "Get-NetFirewallRule -Enabled True -Direction Inbound | Select -First 10", "desc": "Inbound firewall rules"},
    "users": {"cmd": "quser", "desc": "Logged in users"}
}


@dataclass
class CommandResult:
    id: str
    command: str
    stdout: str
    stderr: str
    returncode: int
    duration_ms: float


class DiagnosticsEngine:
    def __init__(self):
        self.os_type = self._detect_os()
        self.commands = self._get_commands_for_os()
        
    def _detect_os(self) -> str:
        if sys.platform == "darwin":
            return "macos"
        elif sys.platform == "win32":
            return "windows"
        elif sys.platform.startswith("linux"):
            return "linux"
        else:
            return "unknown"
            
    def _get_commands_for_os(self) -> Dict:
        if self.os_type == "macos":
            return MACOS_COMMANDS
        elif self.os_type == "windows":
            return WINDOWS_COMMANDS
        elif self.os_type == "linux":
            return LINUX_COMMANDS
        return {}

    def get_catalog(self) -> List[Dict]:
        """Return the list of available commands for the current OS."""
        return [
            {"id": k, "command": v["cmd"], "description": v["desc"]}
            for k, v in self.commands.items()
        ]

    async def execute_command(self, cmd_id: str, timeout: int = 10) -> CommandResult:
        """Execute a pre-approved diagnostic command securely."""
        if cmd_id not in self.commands:
            raise ValueError(f"Unknown or unauthorized diagnostic command: {cmd_id}")
            
        cmd_str = self.commands[cmd_id]["cmd"]
        
        import time
        start_time = time.monotonic()
        
        try:
            if self.os_type == "windows":
                # Run in PowerShell
                process = await asyncio.create_subprocess_exec(
                    "powershell", "-NoProfile", "-NonInteractive", "-Command", cmd_str,
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
            else:
                # Run in bash/sh
                shell = "/bin/bash" if os.path.exists("/bin/bash") else "/bin/sh"
                process = await asyncio.create_subprocess_exec(
                    shell, "-c", cmd_str,
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
            
            duration_ms = (time.monotonic() - start_time) * 1000
            
            return CommandResult(
                id=cmd_id,
                command=cmd_str,
                stdout=stdout.decode('utf-8', errors='replace'),
                stderr=stderr.decode('utf-8', errors='replace'),
                returncode=process.returncode,
                duration_ms=duration_ms
            )
            
        except asyncio.TimeoutError:
            duration_ms = (time.monotonic() - start_time) * 1000
            if 'process' in locals() and process:
                try:
                    process.kill()
                except Exception:
                    pass
            return CommandResult(
                id=cmd_id,
                command=cmd_str,
                stdout="",
                stderr=f"Command timed out after {timeout} seconds",
                returncode=-1,
                duration_ms=duration_ms
            )
        except Exception as e:
            duration_ms = (time.monotonic() - start_time) * 1000
            logger.error(f"Error executing diagnostic command {cmd_id}: {e}")
            return CommandResult(
                id=cmd_id,
                command=cmd_str,
                stdout="",
                stderr=str(e),
                returncode=-1,
                duration_ms=duration_ms
            )

    def get_system_report(self) -> dict:
        """Get full system status report."""
        return get_system_info()
