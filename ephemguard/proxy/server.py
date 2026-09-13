import asyncio
import os
import re
import sys
import logging
import json
import uuid
import secrets
import signal
from typing import Optional, List

from ephemguard.security.command_guard import CommandInjectionError
from ephemguard.security.schema_verifier import SchemaTamperingError

from ephemguard.proxy.protocol import parse_jsonrpc, encode_jsonrpc_response, ProtocolError
from ephemguard.proxy.interceptor import SecurityInterceptor

logger = logging.getLogger(__name__)

# Security constants
MAX_MESSAGE_SIZE = 1 * 1024 * 1024  # 1 MB max JSON-RPC message size
UUID_PATTERN = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
SUBPROCESS_TERMINATE_TIMEOUT = 5  # seconds


def setup_event_loop_policy():
    """Set the WindowsProactorEventLoopPolicy on Windows for subprocess support."""
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())


def _validate_uuid(value: str) -> bool:
    """Validate that a string is a proper UUID to prevent path traversal in IPC file paths."""
    return bool(UUID_PATTERN.match(value))


def _generate_secret(secret_file: Optional[str] = None) -> bytes:
    """
    Generate or load a cryptographic secret for HMAC lease signing.
    If secret_file is provided and exists, loads from it. Otherwise generates
    a new 32-byte random secret and optionally persists it.
    """
    if secret_file and os.path.exists(secret_file):
        with open(secret_file, "rb") as f:
            secret = f.read()
            if len(secret) < 32:
                raise ValueError(f"Secret file {secret_file} must contain at least 32 bytes")
            return secret

    secret = secrets.token_bytes(32)

    if secret_file:
        # Create parent directories if they don't exist
        os.makedirs(os.path.dirname(os.path.abspath(secret_file)), exist_ok=True)
        old_umask = os.umask(0o177)  # rw------- permissions
        try:
            with open(secret_file, "wb") as f:
                f.write(secret)
        finally:
            os.umask(old_umask)
        logger.info(f"Generated and saved new HMAC secret to {secret_file}")

    return secret


class StdioBridge:
    def __init__(
        self,
        command: List[str],
        workspace: str = None,
        secret: bytes = None,
        secret_file: str = None,
        client_name: str = "Unknown Agent",
        mode: str = "auto",
        log_dir: str = None,
    ):
        self.command = command
        self.process: Optional[asyncio.subprocess.Process] = None
        self.workspace = workspace or os.getcwd()
        self.mode = mode
        self.client_name = client_name

        # Generate a secure secret — never use a hardcoded value
        if secret is None:
            secret = _generate_secret(secret_file)
        self.interceptor = SecurityInterceptor(
            self.workspace, secret, client_name=client_name, log_dir=log_dir
        )

        # IPC directories for interactive mode — use absolute paths
        base_log_dir = log_dir or os.path.join(self.workspace, "logs")
        self.pending_dir = os.path.abspath(os.path.join(base_log_dir, "pending"))
        self.decisions_dir = os.path.abspath(os.path.join(base_log_dir, "decisions"))
        os.makedirs(self.pending_dir, exist_ok=True)
        os.makedirs(self.decisions_dir, exist_ok=True)

    async def start(self):
        """Start the upstream MCP server process."""
        self.process = await asyncio.create_subprocess_exec(
            *self.command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=1024 * 1024 * 10  # 10 MB limit for buffering
        )
        logger.info(f"Started upstream process: {' '.join(self.command)} (PID: {self.process.pid})")

    async def _handle_client_message(self, line: bytes, writer) -> None:
        """Inspect and forward a single message from client to upstream server."""
        if len(line) > MAX_MESSAGE_SIZE:
            logger.warning(f"Message exceeds {MAX_MESSAGE_SIZE} byte limit, dropping")
            return

        try:
            line_str = line.decode('utf-8').strip()
            if not line_str:
                return

            req = parse_jsonrpc(line_str)

            params = req.get("params", {})
            lease = None
            nonce = None
            if isinstance(params, dict):
                lease = params.get("_meta", {}).get("lease")
                nonce = params.get("_meta", {}).get("nonce")

            # Inspect with Security Interceptor
            result = self.interceptor.inspect(req, lease=lease, nonce=nonce)

            # Interactive Mode Check
            if self.mode == "interactive" and result.allowed and req.get("method") == "tools/call":
                req_id = str(uuid.uuid4())

                pending_file = os.path.join(self.pending_dir, f"{req_id}.json")
                decision_file = os.path.join(self.decisions_dir, f"{req_id}.json")

                pending_data = {
                    "id": req_id,
                    "client": self.client_name,
                    "request": req
                }

                with open(pending_file, "w") as f:
                    json.dump(pending_data, f)

                # Wait for decision with timeout (5 minutes max)
                approved = False
                timeout = 300  # 5 minutes
                elapsed = 0
                while elapsed < timeout:
                    if os.path.exists(decision_file):
                        try:
                            with open(decision_file, "r") as f:
                                decision_data = json.load(f)
                                approved = decision_data.get("approved", False)
                            break
                        except json.JSONDecodeError:
                            pass  # File still being written
                    await asyncio.sleep(0.1)
                    elapsed += 0.1

                # Cleanup IPC files
                try:
                    os.remove(pending_file)
                except OSError:
                    pass
                try:
                    os.remove(decision_file)
                except OSError:
                    pass

                if not approved:
                    result.allowed = False
                    result.reason = "Denied by user via Dashboard interactive mode"

            if not result.allowed:
                error_resp = {
                    "code": -32001,
                    "message": f"Security Violation: {result.reason}"
                }
                error_line = encode_jsonrpc_response(req.get("id"), error=error_resp)
                error_bytes = error_line.encode('utf-8') + b'\n'

                sys.stdout.buffer.write(error_bytes)
                sys.stdout.buffer.flush()
                return  # Skip forwarding this request

            # If allowed and arguments were transformed
            if result.transformed_params is not None:
                req["params"]["arguments"] = result.transformed_params
                line = (json.dumps(req) + "\n").encode('utf-8')

        except ProtocolError:
            pass  # Let the server handle JSON-RPC protocol errors
        except Exception as e:
            logger.error(f"Interceptor failed: {e}")

        writer.write(line)
        await writer.drain()

    async def _forward_stream(self, reader: asyncio.StreamReader, writer, direction: str):
        """Read lines from reader and write to writer."""
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break

                if direction == "client->server":
                    await self._handle_client_message(line, writer)
                else:
                    writer.write(line)
                    await writer.drain()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Error in stream forwarding ({direction}): {e}")
        finally:
            if hasattr(writer, 'close'):
                writer.close()

    async def _forward_stderr(self, reader: asyncio.StreamReader):
        """Read stderr from the subprocess and output it to our stderr."""
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                sys.stderr.buffer.write(line)
                sys.stderr.buffer.flush()
        except asyncio.CancelledError:
            pass

    async def _read_stdin(self, writer):
        """Read from our stdin and forward to the subprocess stdin."""
        loop = asyncio.get_running_loop()
        if sys.platform == "win32":
            # On Windows ProactorEventLoop, connect_read_pipe is not supported.
            # Read from sys.stdin using a background thread and asyncio queue.
            queue: asyncio.Queue = asyncio.Queue()

            def _reader():
                try:
                    while True:
                        line = sys.stdin.readline()
                        if not line:
                            break
                        loop.call_soon_threadsafe(queue.put_nowait, line)
                except Exception:
                    pass
                finally:
                    loop.call_soon_threadsafe(queue.put_nowait, None)

            import threading
            thread = threading.Thread(target=_reader, daemon=True)
            thread.start()

            try:
                while True:
                    line = await queue.get()
                    if line is None:
                        break
                    line_bytes = line.encode('utf-8') if isinstance(line, str) else line
                    await self._handle_client_message(line_bytes, writer)
            except asyncio.CancelledError:
                pass
            finally:
                if hasattr(writer, 'close'):
                    writer.close()
        else:
            reader = asyncio.StreamReader(limit=1024 * 1024 * 10)
            protocol = asyncio.StreamReaderProtocol(reader)
            await loop.connect_read_pipe(lambda: protocol, sys.stdin)
            await self._forward_stream(reader, writer, "client->server")

    async def _read_stdout(self, reader: asyncio.StreamReader):
        """Read from subprocess stdout and forward to our stdout."""
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break

                # Enforce message size limit
                if len(line) > MAX_MESSAGE_SIZE:
                    logger.warning("Server response exceeds size limit, dropping")
                    continue

                # Check for schema verification on the server response side
                try:
                    resp = json.loads(line.decode('utf-8'))
                except json.JSONDecodeError:
                    pass
                except SchemaTamperingError as e:
                    # Modify response to error out
                    msg_id = resp.get("id") if isinstance(resp, dict) else None
                    error_resp = {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {
                            "code": -32001,
                            "message": f"Security Violation: {str(e)}"
                        }
                    }
                    line = json.dumps(error_resp).encode('utf-8') + b'\n'

                sys.stdout.buffer.write(line)
                sys.stdout.buffer.flush()
        except asyncio.CancelledError:
            pass

    async def _terminate_process(self):
        """Gracefully terminate the subprocess with timeout."""
        if self.process and self.process.returncode is None:
            self.process.terminate()
            try:
                await asyncio.wait_for(
                    self.process.wait(),
                    timeout=SUBPROCESS_TERMINATE_TIMEOUT
                )
            except asyncio.TimeoutError:
                logger.warning("Process did not terminate gracefully, killing")
                self.process.kill()
                await self.process.wait()

    async def run(self):
        """Run the bidirectional bridge."""
        if not self.process:
            await self.start()

        assert self.process is not None
        assert self.process.stdin is not None
        assert self.process.stdout is not None
        assert self.process.stderr is not None

        # Create tasks for bidirectional forwarding
        tasks = [
            asyncio.create_task(self._read_stdin(self.process.stdin)),
            asyncio.create_task(self._read_stdout(self.process.stdout)),
            asyncio.create_task(self._forward_stderr(self.process.stderr)),
            asyncio.create_task(self.process.wait())
        ]

        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

        # If any task finishes (e.g. process dies, or stdin closes), cancel the rest
        for task in pending:
            task.cancel()

        await self._terminate_process()

        return self.process.returncode


def main():
    setup_event_loop_policy()

    # Normally handled by cli.py
    if len(sys.argv) < 2:
        print("Usage: ephemguard <upstream_command...>", file=sys.stderr)
        sys.exit(1)

    command = sys.argv[1:]
    bridge = StdioBridge(command)

    try:
        returncode = asyncio.run(bridge.run())
        sys.exit(returncode)
    except KeyboardInterrupt:
        sys.exit(130)

if __name__ == "__main__":
    main()
