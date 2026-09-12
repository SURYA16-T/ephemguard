import json
import pytest
from pathlib import Path
from ephemguard.security.audit import AuditLogger
from ephemguard.security.integrity import verify_chain, chain_hash

def test_audit_logger_valid_chain(tmp_path):
    log_file = tmp_path / "audit.jsonl"
    logger = AuditLogger(str(log_file))
    
    # Record some events
    logger.record("start", user="admin")
    logger.record("action", tool="filesystem_read", path="/etc/passwd")
    logger.record("stop", status="success")
    
    # Verify the chain is intact
    assert verify_chain(str(log_file)) is True

def test_audit_logger_tamper_detection(tmp_path):
    log_file = tmp_path / "audit.jsonl"
    logger = AuditLogger(str(log_file))
    
    logger.record("start", user="admin")
    logger.record("action", tool="filesystem_read", path="/etc/passwd")
    
    assert verify_chain(str(log_file)) is True
    
    # Simulate an attacker tampering with the logs (changing the action path)
    lines = log_file.read_text().splitlines()
    tampered_lines = []
    for i, line in enumerate(lines):
        if i == 1:
            entry = json.loads(line)
            entry["path"] = "/etc/shadow"  # malicious change
            tampered_lines.append(json.dumps(entry))
        else:
            tampered_lines.append(line)
            
    log_file.write_text("\n".join(tampered_lines) + "\n")
    
    # The chain validation should now fail
    assert verify_chain(str(log_file)) is False
