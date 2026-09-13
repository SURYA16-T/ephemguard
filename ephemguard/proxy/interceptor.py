import os
import time
import json
import uuid
import logging
from dataclasses import dataclass, field
from typing import Any, Optional, Dict

from ephemguard.security.policy_engine import PolicyEngine, PolicyViolation
from ephemguard.security.attenuator import attenuate_tool_call, CapabilityViolation
from ephemguard.security.lease_manager import LeaseManager, LeaseViolation
from ephemguard.security.schema_verifier import SchemaVerifier, SchemaTamperingError
from ephemguard.security.semantic_guard import IntentGuard, IntentMismatch

from ephemguard.security.replay_guard import ReplayGuard
from ephemguard.audit.logger import AuditLogger

logger = logging.getLogger(__name__)

# Rate limiting constants
MAX_REQUESTS_PER_SECOND = 50
RATE_WINDOW_SECONDS = 1.0


@dataclass
class InterceptionResult:
    allowed: bool
    reason: str
    transformed_params: Optional[Dict[str, Any]] = None
    pipeline_duration_ms: float = 0.0
    checks_performed: list = field(default_factory=list)


class ReplayViolation(Exception):
    pass


class RateLimitExceeded(Exception):
    pass


class SecurityInterceptor:
    def __init__(self, workspace: str, secret: bytes, client_name: str = "Unknown Agent", log_dir: str = None, log_path: str = None):
        if log_path is None and (client_name.endswith(".jsonl") or "/" in client_name or "\\" in client_name):
            log_path = client_name
            client_name = "Unknown Agent"
        self.workspace = workspace
        self.policy = PolicyEngine.for_current_platform()
        self.lease_manager = LeaseManager(secret)
        self.schema_verifier = SchemaVerifier()
        self.intent_guard = IntentGuard()
        self.replay_guard = ReplayGuard()
        if log_path is not None:
            self.audit_logger = AuditLogger(path=log_path, client_name=client_name)
            self.log_dir = os.path.dirname(os.path.abspath(log_path))
        else:
            self.audit_logger = AuditLogger(client_name=client_name, log_dir=log_dir)
            self.log_dir = log_dir or os.path.join(self.workspace, "logs")
        self.audit = self.audit_logger
        self.workspace = workspace
        self.client_name = client_name
        self.approval_flag_file = os.path.join(self.log_dir, "require_approval.flag")
        self.pending_dir = os.path.join(self.log_dir, "pending")
        self.decisions_dir = os.path.join(self.log_dir, "decisions")
        
        os.makedirs(self.pending_dir, exist_ok=True)
        os.makedirs(self.decisions_dir, exist_ok=True)

        # Rate limiting state
        self._request_timestamps: list = []
        self._rate_limit = MAX_REQUESTS_PER_SECOND

    def observe_tools_list(self, server_id: str, response: Dict[str, Any]) -> None:
        """Pin or verify tool definitions when tools/list is received from upstream."""
        result = response.get("result")
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
            return
        if hasattr(self.schema_verifier, "pin_or_verify"):
            self.schema_verifier.pin_or_verify(server_id, {"tools": result["tools"]})
        else:
            self.schema_verifier.pin_schema(server_id, {"tools": result["tools"]})
        self.audit_logger.record("ToolSchemaVerified", server_id=server_id, tool_count=len(result["tools"]))

    def _check_rate_limit(self) -> None:
        """Enforce per-second rate limiting to prevent abuse."""
        now = time.monotonic()
        # Remove timestamps outside the current window
        self._request_timestamps = [
            ts for ts in self._request_timestamps
            if now - ts < RATE_WINDOW_SECONDS
        ]
        if len(self._request_timestamps) >= self._rate_limit:
            raise RateLimitExceeded(
                f"Rate limit exceeded: {self._rate_limit} requests per second"
            )
        self._request_timestamps.append(now)

    def inspect(self, request: Dict[str, Any], lease: Optional[str] = None, user_intent: str = "", nonce: Optional[str] = None) -> InterceptionResult:
        start_time = time.monotonic()
        checks_performed = []

        if request.get("method") != "tools/call":
            return InterceptionResult(True, "non-tool request")

        params = request.get("params")
        if not isinstance(params, dict):
            return InterceptionResult(False, "tool params must be an object")

        tool = params.get("name")
        arguments = params.get("arguments", {})

        if not isinstance(tool, str) or not isinstance(arguments, dict):
            return InterceptionResult(False, "invalid tool call structure")

        try:
            # 0. Rate limiting
            self._check_rate_limit()
            checks_performed.append("rate_limit")

            # 1. Replay verification (if nonce is provided)
            if nonce is not None:
                if hasattr(self.replay_guard, "claim"):
                    if not self.replay_guard.claim(nonce):
                        raise ReplayViolation("replay nonce already consumed")
                checks_performed.append("replay_guard")

            # 2. Check if tool is authorized globally by policy
            self.policy.authorize(tool, arguments)
            checks_performed.append("policy_engine")

            # 3. Attenuate arguments (Path Jailer, Command Guard)
            attenuated = attenuate_tool_call(tool, arguments, self.workspace, self.policy)
            checks_performed.append("attenuator")

            # 4. Verify cryptographic lease for this specific capability
            if lease is None:
                raise LeaseViolation("capability lease required")
            self.lease_manager.consume(lease, tool, attenuated)
            checks_performed.append("lease_manager")

            # 5. Semantic intent matching
            if user_intent:
                self.intent_guard.check(user_intent, tool, attenuated)
                checks_performed.append("intent_guard")

            # 6. Human-in-the-loop Approval check
            if os.path.exists(self.approval_flag_file):
                checks_performed.append("hitl_approval")
                req_id = str(uuid.uuid4())
                pending_file = os.path.join(self.pending_dir, f"{req_id}.json")
                decision_file = os.path.join(self.decisions_dir, f"{req_id}.json")
                
                # Write to pending
                with open(pending_file, "w") as f:
                    json.dump({"id": req_id, "client": self.client_name, "request": request}, f)
                
                # Wait for decision
                timeout = 300  # 5 minutes
                start_wait = time.monotonic()
                approved = False
                decision_found = False
                
                while time.monotonic() - start_wait < timeout:
                    if os.path.exists(decision_file):
                        try:
                            with open(decision_file, "r") as f:
                                dec = json.load(f)
                                approved = dec.get("approved", False)
                                decision_found = True
                        except Exception:
                            pass
                        break
                    time.sleep(0.5)
                
                # Cleanup
                if os.path.exists(pending_file):
                    os.remove(pending_file)
                if os.path.exists(decision_file):
                    os.remove(decision_file)
                
                if not decision_found:
                    raise PolicyViolation("human-in-the-loop approval timed out")
                if not approved:
                    raise PolicyViolation("denied by human administrator")

            duration_ms = (time.monotonic() - start_time) * 1000
            self.audit_logger.record(
                "ToolCallAllowed",
                tool=tool,
                reason="allowed",
                user_intent=user_intent,
                pipeline_ms=round(duration_ms, 3),
                checks=checks_performed,
            )
            return InterceptionResult(
                True, "allowed", attenuated,
                pipeline_duration_ms=duration_ms,
                checks_performed=checks_performed,
            )

        except (PolicyViolation, CapabilityViolation, LeaseViolation,
                SchemaTamperingError, IntentMismatch, ReplayViolation,
                RateLimitExceeded) as exc:
            reason = str(exc)
            duration_ms = (time.monotonic() - start_time) * 1000
            self.audit_logger.record(
                "ToolCallDenied",
                tool=tool,
                reason=reason,
                user_intent=user_intent,
                pipeline_ms=round(duration_ms, 3),
                checks=checks_performed,
            )
            return InterceptionResult(
                False, reason,
                pipeline_duration_ms=duration_ms,
                checks_performed=checks_performed,
            )
