"""The gate: evaluate a tool call and fail closed on any error."""
from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .audit import AuditLog
from .policy import Policy


class Denied(Exception):
    def __init__(self, tool: str, reason: str):
        super().__init__(f"denied {tool!r}: {reason}")
        self.tool, self.reason = tool, reason


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    latency_ms: float


class Gate:
    def __init__(self, policy: Policy, audit: AuditLog | None = None, *, require_audit: bool = False):
        """``require_audit=True``: if the audit record cannot be written, the call is denied
        (reason ``audit_failure``). Default False keeps v0.1 behaviour: an audit failure never
        turns a deny into an allow, but an allowed call still runs unlogged."""
        self.policy = policy
        self.audit = audit
        self.require_audit = require_audit
        self.policy_error: str | None = None

    @classmethod
    def from_policy_file(cls, path: str | Path, audit: AuditLog | None = None, **kw: Any) -> "Gate":
        """Build a gate from a JSON policy file, failing CLOSED: if the file is missing or
        malformed the gate is still returned, but denies every call with
        ``policy_invalid:<ErrorType>``. Use ``Policy.from_json`` directly to get the exception."""
        try:
            policy = Policy.from_json(path)
            err = None
        except Exception as exc:
            policy, err = Policy({}), type(exc).__name__
        gate = cls(policy, audit, **kw)
        gate.policy_error = err
        return gate

    def evaluate(self, tool: str, arguments: Any) -> Decision:
        start = time.perf_counter()
        try:
            if self.policy_error is not None:
                allowed, reason = False, f"policy_invalid:{self.policy_error}"
            else:
                allowed, reason = self.policy.check(tool, arguments)
        except Exception as exc:  # any failure inside the gate means DENY
            allowed, reason = False, f"internal_error:{type(exc).__name__}"
        latency = (time.perf_counter() - start) * 1000
        if self.audit is not None:
            try:
                self.audit.write(tool, arguments, allowed, reason, latency)
            except Exception as exc:
                # audit failure must not turn a deny into an allow, nor crash the caller
                if self.require_audit:
                    allowed, reason = False, f"audit_failure:{type(exc).__name__}"
        return Decision(allowed, reason, latency)

    def call(self, tool: str, arguments: dict, handler: Callable[..., Any]) -> Any:
        """Run handler(**arguments) only if the policy allows it; otherwise raise Denied."""
        d = self.evaluate(tool, arguments)
        if not d.allowed:
            raise Denied(tool, d.reason)
        return handler(**arguments)
