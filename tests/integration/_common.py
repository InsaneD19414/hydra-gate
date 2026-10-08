import inspect

from hydra_gate import ArgRule, AuditLog, Gate, Policy, ToolRule, guard

POLICY = Policy({
    "read_file": ToolRule(args={
        "path": ArgRule(type="str", pattern=r"/data/[A-Za-z0-9_.\-]+", max_len=128),
        "limit": ArgRule(type="int", required=False, min=1, max=100),
    }),
    "toggle": ToolRule(args={"on": ArgRule(type="bool")}),
})


def make_tools(audit_path):
    """Return (gate, calls, guarded async read_file, guarded sync toggle)."""
    gate = Gate(POLICY, AuditLog(audit_path, chain=True))
    calls = []

    async def read_file(path: str, limit: int = 10) -> str:
        """Read a file under /data."""
        calls.append(("read_file", path, limit))
        return f"read {path} x{limit}"

    def toggle(on: bool) -> str:
        """Flip a switch."""
        calls.append(("toggle", on))
        return f"on={on}"

    g_read = guard(gate, "read_file")(read_file)
    g_toggle = guard(gate, "toggle")(toggle)
    assert inspect.signature(g_read) == inspect.signature(read_file)
    return gate, calls, g_read, g_toggle


def reasons(gate):
    import json
    return [json.loads(x)["reason"] for x in gate.audit.path.read_text().splitlines()]
