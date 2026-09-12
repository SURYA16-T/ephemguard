import pytest
import os
import sys

from ephemguard.diagnostics import DiagnosticsEngine
from ephemguard.system_info import get_system_info

def test_system_info():
    info = get_system_info()
    assert "os" in info
    assert "platform" in info
    assert "processor" in info
    
    if info.get("has_psutil"):
        assert "cpu" in info
        assert "memory" in info
        assert "disk" in info
        assert "network" in info
        assert "processes" in info

def test_diagnostics_engine_init():
    engine = DiagnosticsEngine()
    assert engine.os_type in ["linux", "macos", "windows", "unknown"]
    
    # We should have commands mapped for the detected OS
    if engine.os_type != "unknown":
        catalog = engine.get_catalog()
        assert len(catalog) > 0
        assert any(cmd["id"] == "sysinfo" for cmd in catalog)

def test_diagnostics_all_three_os_catalogs(monkeypatch):
    # Test macOS
    monkeypatch.setattr(sys, 'platform', 'darwin')
    mac_engine = DiagnosticsEngine()
    assert mac_engine.os_type == "macos"
    mac_catalog = {c["id"]: c["command"] for c in mac_engine.get_catalog()}
    assert "sw_vers" in mac_catalog["sysinfo"]
    assert "vm_stat" in mac_catalog["memory"]

    # Test Linux
    monkeypatch.setattr(sys, 'platform', 'linux')
    linux_engine = DiagnosticsEngine()
    assert linux_engine.os_type == "linux"
    linux_catalog = {c["id"]: c["command"] for c in linux_engine.get_catalog()}
    assert "uname -a" in linux_catalog["sysinfo"]
    assert "free -m" in linux_catalog["memory"]

    # Test Windows
    monkeypatch.setattr(sys, 'platform', 'win32')
    win_engine = DiagnosticsEngine()
    assert win_engine.os_type == "windows"
    win_catalog = {c["id"]: c["command"] for c in win_engine.get_catalog()}
    assert "systeminfo" in win_catalog["sysinfo"]
    assert "Get-Volume" in win_catalog["disk"]


@pytest.mark.asyncio
async def test_execute_safe_command():
    engine = DiagnosticsEngine()
    
    # Check if we are on a known OS
    if engine.os_type == "unknown":
        pytest.skip("Unsupported OS for execution test")
        
    # Execute a safe sysinfo command
    result = await engine.execute_command("sysinfo")
    
    assert result.id == "sysinfo"
    assert result.returncode == 0
    assert len(result.stdout) > 0
    assert result.duration_ms > 0

@pytest.mark.asyncio
async def test_execute_unauthorized_command():
    engine = DiagnosticsEngine()
    
    with pytest.raises(ValueError, match="Unknown or unauthorized diagnostic command"):
        await engine.execute_command("rm -rf /")
