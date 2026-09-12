"""Lightweight intent-vs-tool alignment guard. This is heuristic, not an authorization boundary."""
import re

class IntentMismatch(ValueError):
    pass

class IntentGuard:
    SAFE_INTENT_WORDS={"read", "inspect", "analyze", "review", "list", "document", "check"}
    DANGEROUS_TOOL_WORDS={"execute", "shell", "powershell", "bash", "delete", "write"}

    def check(self, user_intent: str, tool: str, arguments: dict) -> None:
        intent_words=set(re.findall(r"[a-zA-Z]+", user_intent.lower()))
        tool_lower=tool.lower()
        if self.SAFE_INTENT_WORDS & intent_words and any(w in tool_lower for w in self.DANGEROUS_TOOL_WORDS):
            raise IntentMismatch("tool action diverges from a read/review-oriented user intent")
