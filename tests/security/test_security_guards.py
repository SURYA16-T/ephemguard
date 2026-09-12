import pytest
from ephemguard.security.lease_manager import LeaseManager
from ephemguard.security.command_guard import PosixCommandGuard, WindowsCommandGuard, CommandInjectionError
from ephemguard.platform.posix import AllowAllList
from ephemguard.security.attenuator import attenuate_tool_call, CapabilityViolation
from ephemguard.security.policy_engine import PolicyEngine
from ephemguard.security.semantic_guard import IntentGuard, IntentMismatch
from ephemguard.security.schema_verifier import SchemaVerifier, SchemaTamperingError

def test_tool_bound_lease():
    lm = LeaseManager(default_ttl=15)
    tok = lm.issue_lease("filesystem_read:/a.py")
    # In our implementation, verify_lease returns False instead of raising
    # We raise ValueError here manually to simulate the snippet's aesthetic try/except block
    try:
        if not lm.verify_lease(tok, "filesystem_write:/a.py"):
            raise ValueError("LeaseViolation")
        assert False
    except ValueError:
        pass

def test_posix_chain():
    guard = PosixCommandGuard(AllowAllList())
    try:
        guard.check_command("echo safe && whoami")
        assert False
    except CommandInjectionError:
        pass

def test_powershell_risky_primitive():
    guard = WindowsCommandGuard(AllowAllList())
    try:
        # We explicitly block encoded commands in WindowsCommandGuard
        guard.check_command("powershell.exe -EncodedCommand ZWNobyBoYWNr")
        assert False
    except CommandInjectionError:
        pass

def test_path_escape(tmp_path):
    try:
        attenuate_tool_call("filesystem_read", {"path": "../../etc/passwd"}, str(tmp_path), PolicyEngine([]))
        assert False
    except CapabilityViolation:
        pass

def test_intent_divergence():
    try:
        IntentGuard().check("review and analyze my code", "execute_shell", {"command": "echo hi"})
        assert False
    except IntentMismatch:
        pass

def test_schema_poisoning():
    v = SchemaVerifier()
    v.pin_schema("mcp", {"tools": [{"name": "read"}]})
    try:
        v.verify_schema("mcp", {"tools": [{"name": "read"}, {"name": "exec"}]})
        assert False
    except SchemaTamperingError:
        pass
