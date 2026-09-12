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
    # Create a simple echo server script that reads lines and prefixes with ACK:
    # also handles \r\n explicitly to test both newline formats.
    echo_script = """
import sys
for line in sys.stdin:
    sys.stdout.write("ACK:" + line)
    sys.stdout.flush()
"""
    
    # Path to the cli module
    cli_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../ephemguard/cli.py'))
    
    # Run the proxy, passing the echo server as the upstream command
    # We run the proxy itself as a subprocess so we can write to its stdin and read its stdout
    proxy_process = await asyncio.create_subprocess_exec(
        sys.executable, cli_path, "proxy", "--secret-file", "/tmp/dummy_secret", "--",
        sys.executable, "-c", echo_script,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    
    assert proxy_process.stdin is not None
    assert proxy_process.stdout is not None
    
    try:
        # Test 1: Standard \\n newline
        msg1 = b'{"jsonrpc": "2.0", "method": "test1", "id": 1}\n'
        proxy_process.stdin.write(msg1)
        await proxy_process.stdin.drain()
        
        resp1 = await asyncio.wait_for(proxy_process.stdout.readline(), timeout=2.0)
        assert resp1 == b'ACK:{"jsonrpc": "2.0", "method": "test1", "id": 1}\n'
        
        # Test 2: Windows \\r\\n newline
        msg2 = b'{"jsonrpc": "2.0", "method": "test2", "id": 2}\r\n'
        proxy_process.stdin.write(msg2)
        await proxy_process.stdin.drain()
        
        resp2 = await asyncio.wait_for(proxy_process.stdout.readline(), timeout=2.0)
        assert resp2 == b'ACK:{"jsonrpc": "2.0", "method": "test2", "id": 2}\r\n'
        
    finally:
        # Cleanup: close stdin to let the proxy and echo server exit
        if proxy_process.stdin:
            proxy_process.stdin.close()
            try:
                await proxy_process.wait()
            except ProcessLookupError:
                pass
