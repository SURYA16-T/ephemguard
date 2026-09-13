"""Command-line interface for EphemGuard."""
import argparse
import sys
import os
import json
import asyncio
from pathlib import Path

from ephemguard.proxy.server import StdioBridge


def main():
    parser = argparse.ArgumentParser(description="EphemGuard: AI Agent Security Gateway")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Proxy / Wrap Command
    proxy_parser = subparsers.add_parser("proxy", aliases=["wrap"], help="Run the security proxy (alias: wrap)")
    proxy_parser.add_argument("--mode", choices=["auto", "interactive"], default="auto",
    help="Operation mode (interactive requires HITL approval)")
    proxy_parser.add_argument("--workspace", default=os.getcwd(), help="Allowed workspace path")
    proxy_parser.add_argument("--client-name", default="Unknown Agent", help="Name of the AI client for audit logging")
    proxy_parser.add_argument("--secret-file", help="Path to file for persistent HMAC secret")
    proxy_parser.add_argument("--log-dir", help="Directory for audit and IPC logs")
    proxy_parser.add_argument("upstream", nargs=argparse.REMAINDER, help="Upstream MCP server command")

    # Dashboard Command
    dash_parser = subparsers.add_parser("dashboard", help="Run the security dashboard")
    dash_parser.add_argument("--port", type=int, default=8080, help="Dashboard port")
    dash_parser.add_argument("--log-dir", help="Directory where logs are stored")

    # Diagnose Command
    subparsers.add_parser("diagnose", help="Run full system diagnostics and print report")

    # Terminal Command
    subparsers.add_parser("terminal", help="List available diagnostic terminal commands for this OS")

    # Audit Verify Command
    verify_parser = subparsers.add_parser("audit-verify", help="Verify the tamper-evident audit log chain")
    verify_parser.add_argument("--file", default="logs/audit.jsonl", help="Path to audit.jsonl")

    args = parser.parse_args()

    if args.command in ("proxy", "wrap"):
        if not args.upstream:
            print("Error: Upstream command required.", file=sys.stderr)
            sys.exit(1)
        
        # Remove '--' if present
        if args.upstream[0] == "--":
            args.upstream = args.upstream[1:]

        bridge = StdioBridge(
            command=args.upstream,
            workspace=args.workspace,
            client_name=args.client_name,
            mode=args.mode,
            secret_file=args.secret_file,
            log_dir=args.log_dir
        )
        try:
            sys.exit(asyncio.run(bridge.run()))
        except KeyboardInterrupt:
            sys.exit(130)

    elif args.command == "dashboard":
        try:
            from ephemguard.dashboard.server import DashboardServer
        except ImportError as e:
            print(f"Error: Dashboard dependencies missing ({e}). Run `pip install ephemguard[dashboard]`", file=sys.stderr)
            sys.exit(1)
            
        server = DashboardServer(workspace=os.getcwd(), port=args.port, log_dir=args.log_dir)
        server.run()

    elif args.command == "diagnose":
        try:
            from ephemguard.diagnostics import DiagnosticsEngine
            engine = DiagnosticsEngine()
            report = engine.get_system_report()
            print(json.dumps(report, indent=2))
        except ImportError as e:
            print(f"Error: missing dependencies ({e}).", file=sys.stderr)
            sys.exit(1)

    elif args.command == "terminal":
        try:
            from ephemguard.diagnostics import DiagnosticsEngine
            engine = DiagnosticsEngine()
            catalog = engine.get_catalog()
            print(f"\nAvailable secure terminal commands for {engine.os_type}:\n")
            for cmd in catalog:
                print(f"  {cmd['id']:<15} : {cmd['description']} ({cmd['command']})")
            print()
        except ImportError as e:
            print(f"Error: missing dependencies ({e}).", file=sys.stderr)
            sys.exit(1)
            
    elif args.command == "audit-verify":
        from ephemguard.security.integrity import verify_chain
        
        path = args.file
        if not os.path.exists(path):
            print(f"Audit log not found at {path}")
            sys.exit(1)
            
        if verify_chain(path):
            print(f"✅ PASS: Cryptographic chain verified for {path}")
            sys.exit(0)
        else:
            print(f"❌ FAIL: Audit log at {path} has been tampered with or is corrupted!")
            sys.exit(1)

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
