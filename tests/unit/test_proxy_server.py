import asyncio
import sys
import os
import pytest

# Ensure ephemguard module is in path for tests
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

@pytest.mark.asyncio
async def test_bidirectional_forwarding():
    """
    Test that the proxy correctly forwards stdin to the upstream server
    and forwards upstream stdout back to its own stdout.
    """
    import tempfile
    
    echo_script = """
import sys
while True:
    line = sys.stdin.readline()
    if not line:
        break
    sys.stdout.write("ACK:" + line)
    sys.stdout.flush()
"""
    
    secret_file = os.path.join(tempfile.gettempdir(), "dummy_secret_test")
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../'))
    env = os.environ.copy()
    env["PYTHONPATH"] = repo_root + (os.pathsep + env["PYTHONPATH"] if "PYTHONPATH" in env else "")
    
    # Run the proxy, passing the echo server as the upstream command
    proxy_process = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "ephemguard.cli", "proxy", "--secret-file", secret_file, "--",
        sys.executable, "-u", "-c", echo_script,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env
    )
    
    assert proxy_process.stdin is not None
    assert proxy_process.stdout is not None
    
    try:
        # Test 1: Standard \n newline
        msg1 = b'{"jsonrpc": "2.0", "method": "test1", "id": 1}\n'
        proxy_process.stdin.write(msg1)
        await proxy_process.stdin.drain()
        
        resp1 = await asyncio.wait_for(proxy_process.stdout.readline(), timeout=5.0)
        if resp1 == b'':
            stderr_out = await proxy_process.stderr.read()
            raise AssertionError(f"proxy_process exited prematurely. Stderr: {stderr_out.decode('utf-8', errors='replace')}")
        assert resp1 == b'ACK:{"jsonrpc": "2.0", "method": "test1", "id": 1}\n'
        
        # Test 2: Windows \r\n newline
        msg2 = b'{"jsonrpc": "2.0", "method": "test2", "id": 2}\r\n'
        proxy_process.stdin.write(msg2)
        await proxy_process.stdin.drain()
        
        resp2 = await asyncio.wait_for(proxy_process.stdout.readline(), timeout=5.0)
        assert resp2 == b'ACK:{"jsonrpc": "2.0", "method": "test2", "id": 2}\r\n'
        
    finally:
        # Cleanup: close stdin to let the proxy and echo server exit
        if proxy_process.stdin:
            try:
                proxy_process.stdin.close()
            except Exception:
                pass
        try:
            proxy_process.kill()
        except Exception:
            pass
        try:
            await asyncio.wait_for(proxy_process.wait(), timeout=3.0)
        except Exception:
            pass
        try:
            if os.path.exists(secret_file):
                os.remove(secret_file)
        except OSError:
            pass
