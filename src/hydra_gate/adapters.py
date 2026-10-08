"""Framework-agnostic decorator for guarding tool handlers (sync or async).

    @mcp.tool()                       # your MCP framework's decorator (outer)
    @guard(gate, "transfer")          # hydra-gate (inner)
    def transfer(to: str, amount: float): ...

The wrapper keeps the handler's name, docstring, annotations and signature
(``functools.wraps`` plus an explicit ``__signature__``), so frameworks that build a tool
schema from the signature still see the original parameters.

Verified by tests/integration/ against fastmcp 4.0.11 (``FastMCP``) and the official MCP
Python SDK mcp 2.3.0 (``mcp.server.mcpserver.MCPServer``, the class formerly named FastMCP),
using each library's in-process client. See README for exact scope.
"""
from __future__ import annotations

import functools
import inspect
from typing import Any, Callable

from .gate import Denied, Gate


def guard(gate: Gate, tool_name: str | None = None) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    def deco(fn: Callable[..., Any]) -> Callable[..., Any]:
        name = tool_name or fn.__name__
        sig = inspect.signature(fn)

        def _deny_bad_call(detail: str) -> None:
            if gate.audit is not None:   # log the attempt as a DENY (never as an evaluation of {})
                try:
                    gate.audit.write(name, {}, False, "bad_call_signature", 0.0)
                except Exception:
                    pass
            raise Denied(name, f"bad_call_signature:{detail}")

        def _check(args: tuple, kwargs: dict) -> None:
            try:
                bound = sig.bind(*args, **kwargs)
            except TypeError as exc:
                _deny_bad_call(str(exc))
            arguments: dict = {}            # defaults are NOT applied: only what the caller sent
            for pname, value in bound.arguments.items():
                kind = sig.parameters[pname].kind
                if kind is inspect.Parameter.VAR_KEYWORD:
                    arguments.update(value)  # **kwargs are checked individually against the policy
                elif kind is inspect.Parameter.VAR_POSITIONAL:
                    if value:                # unnamed *args cannot be policy-checked
                        _deny_bad_call("positional varargs not allowed")
                else:
                    arguments[pname] = value
            d = gate.evaluate(name, arguments)
            if not d.allowed:
                raise Denied(name, d.reason)

        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def awrapper(*args, **kwargs):
                _check(args, kwargs)
                return await fn(*args, **kwargs)
            awrapper.__signature__ = sig  # type: ignore[attr-defined]
            awrapper.hydra_gate = gate    # type: ignore[attr-defined]
            return awrapper

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            _check(args, kwargs)
            return fn(*args, **kwargs)
        wrapper.__signature__ = sig  # type: ignore[attr-defined]
        wrapper.hydra_gate = gate    # type: ignore[attr-defined]
        return wrapper
    return deco
