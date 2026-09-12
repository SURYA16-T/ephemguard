import os
import sys
import json
import uuid
import re
from aiohttp import web
from pathlib import Path

# Attempt to import our new diagnostics system
try:
    from ephemguard.diagnostics import DiagnosticsEngine
    diagnostics_engine = DiagnosticsEngine()
except ImportError:
    diagnostics_engine = None

class DashboardServer:
    def __init__(self, workspace: str, port: int = 8080, log_dir: str = None):
        self.workspace = workspace
        self.port = port
        
        # Absolute paths to prevent path traversal in API endpoints
        base_log_dir = log_dir or os.path.join(self.workspace, "logs")
        self.pending_dir = os.path.abspath(os.path.join(base_log_dir, "pending"))
        self.decisions_dir = os.path.abspath(os.path.join(base_log_dir, "decisions"))
        self.audit_file = os.path.abspath(os.path.join(base_log_dir, "audit.jsonl"))
        
        os.makedirs(self.pending_dir, exist_ok=True)
        os.makedirs(self.decisions_dir, exist_ok=True)
        
        # UUID regex for validation
        self.uuid_pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')

    @web.middleware
    async def security_middleware(self, request, handler):
        """Middleware for CORS, CSP, and request validation."""
        # Check origins for API calls
        if request.path.startswith('/api/'):
            origin = request.headers.get('Origin')
            if origin and origin not in [f'http://localhost:{self.port}', f'http://127.0.0.1:{self.port}']:
                return web.json_response({'error': 'Invalid Origin'}, status=403)
                
            # CSRF token check on state-changing requests
            if request.method in ('POST', 'PUT', 'DELETE'):
                # In a real app we'd check a token, for this local dashboard we just enforce 
                # that it must be an AJAX request (fetch/XHR) to mitigate simple CSRF
                if request.headers.get('Sec-Fetch-Site') == 'cross-site':
                    return web.json_response({'error': 'Cross-site requests forbidden'}, status=403)
        
        response = await handler(request)
        
        # Add security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:;"
        return response

    async def get_pending(self, request):
        pending = []
        try:
            for filename in os.listdir(self.pending_dir):
                if filename.endswith(".json"):
                    filepath = os.path.join(self.pending_dir, filename)
                    try:
                        with open(filepath, "r") as f:
                            pending.append(json.load(f))
                    except Exception:
                        pass
        except FileNotFoundError:
            pass
        return web.json_response(pending)

    async def post_decision(self, request):
        try:
            data = await request.json()
            req_id = data.get("id")
            approved = data.get("approved", False)
            
            if not req_id or not isinstance(req_id, str):
                return web.json_response({"error": "Missing or invalid id"}, status=400)
                
            # SECURITY FIX: Validate req_id is a UUID to prevent path traversal
            if not self.uuid_pattern.match(req_id):
                return web.json_response({"error": "Invalid request ID format"}, status=400)

            # SECURITY FIX: Path traversal mitigation (already absolute, but safe path join)
            decision_file = os.path.join(self.decisions_dir, f"{req_id}.json")
            
            # Double check it didn't traverse
            if not os.path.abspath(decision_file).startswith(self.decisions_dir):
                return web.json_response({"error": "Invalid path"}, status=403)

            with open(decision_file, "w") as f:
                json.dump({"id": req_id, "approved": approved}, f)

            return web.json_response({"status": "ok"})
        except json.JSONDecodeError:
            return web.json_response({"error": "Invalid JSON"}, status=400)
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)

    async def get_audit_log(self, request):
        limit = int(request.query.get("limit", 100))
        logs = []
        try:
            if os.path.exists(self.audit_file):
                with open(self.audit_file, "r") as f:
                    # Read all lines
                    lines = [line.strip() for line in f if line.strip()]
                    # Take the last N lines
                    for line in lines[-limit:]:
                        try:
                            logs.append(json.loads(line))
                        except Exception:
                            pass
        except Exception:
            pass
            
        # Reverse to show newest first
        logs.reverse()
        return web.json_response(logs)

    async def get_system_info(self, request):
        """API endpoint for system diagnostic information."""
        if not diagnostics_engine:
            return web.json_response({"error": "Diagnostics engine not available"}, status=503)
        try:
            info = diagnostics_engine.get_system_report()
            return web.json_response(info)
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)

    async def get_terminal_commands(self, request):
        """API endpoint listing available terminal commands for this OS."""
        if not diagnostics_engine:
            return web.json_response({"error": "Diagnostics engine not available"}, status=503)
        try:
            catalog = diagnostics_engine.get_catalog()
            return web.json_response({"os": diagnostics_engine.os_type, "commands": catalog})
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)

    async def post_terminal_execute(self, request):
        """API endpoint to execute a specific terminal command."""
        if not diagnostics_engine:
            return web.json_response({"error": "Diagnostics engine not available"}, status=503)
            
        try:
            data = await request.json()
            cmd_id = data.get("id")
            
            if not cmd_id:
                return web.json_response({"error": "Command ID required"}, status=400)
                
            result = await diagnostics_engine.execute_command(cmd_id)
            
            return web.json_response({
                "id": result.id,
                "command": result.command,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
                "duration_ms": result.duration_ms
            })
        except ValueError as e:
            return web.json_response({"error": str(e)}, status=403)
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)

    async def serve_index(self, request):
        public_dir = os.path.join(os.path.dirname(__file__), "public")
        index_path = os.path.join(public_dir, "index.html")
        return web.FileResponse(index_path)

    def run(self):
        app = web.Application(middlewares=[self.security_middleware])
        app.router.add_get("/api/pending", self.get_pending)
        app.router.add_post("/api/decide", self.post_decision)
        app.router.add_get("/api/audit", self.get_audit_log)
        
        # Diagnostic endpoints
        app.router.add_get("/api/system", self.get_system_info)
        app.router.add_get("/api/terminal/commands", self.get_terminal_commands)
        app.router.add_post("/api/terminal/execute", self.post_terminal_execute)
        
        app.router.add_get("/", self.serve_index)

        # Serve static files properly
        public_dir = os.path.join(os.path.dirname(__file__), "public")
        app.router.add_static("/", public_dir, name="static")

        print(f"Starting dashboard on http://localhost:{self.port}")
        web.run_app(app, port=self.port, host="127.0.0.1")

if __name__ == "__main__":
    server = DashboardServer(workspace=os.getcwd())
    server.run()
