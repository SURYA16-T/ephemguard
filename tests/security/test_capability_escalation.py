import pytest
from ephemguard.security.lease_manager import LeaseManager

def test_capability_escalation():
    lm = LeaseManager(default_ttl=15)
    
    # Valid attempt
    read_lease_1 = lm.issue_lease("filesystem_read_data")
    assert lm.verify_lease(read_lease_1, "filesystem_read_data") is True
    
    # Invalid attempt - privilege escalation (read to write)
    read_lease_2 = lm.issue_lease("filesystem_read_data")
    assert lm.verify_lease(read_lease_2, "filesystem_write_data") is False
    
    # Invalid attempt - lateral movement (read to read different file)
    read_lease_3 = lm.issue_lease("filesystem_read_data")
    assert lm.verify_lease(read_lease_3, "filesystem_read_secret") is False

    # Valid attempt command
    cmd_lease_1 = lm.issue_lease("execute_command_ls")
    assert lm.verify_lease(cmd_lease_1, "execute_command_ls") is True
    
    # Invalid attempt - command escalation
    cmd_lease_2 = lm.issue_lease("execute_command_ls")
    assert lm.verify_lease(cmd_lease_2, "execute_command_rm") is False
