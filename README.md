# hydra-gate

**A default-deny, fail-closed policy gate for AI-agent tool calls.**
By Hydra Advanced Intelligence Labs (H.A.I.L.).

AI agents call tools: payments, files, shells, APIs. If a model is wrong or manipulated,
the bad call should be *stopped*, not logged afterward. `hydra-gate` sits between the
agent and its tools. A call runs only if a policy explicitly allows it.

## Guarantees (and tests that back them)

- **Default deny:** tools not named in the policy are blocked.
- **Strict arguments:** unexpected args, wrong types, out-of-range values, and pattern mismatches are blocked.
  Types are checked exactly: `True` is not an int, `NaN`/`inf` are not numbers, nested objects are not strings.
- **Bounded inputs:** every string has a length cap (the rule's `max_len`, else the policy's `max_str_len`, default 65,536), checked before any regex runs.
- **Fail closed:** any internal error (bad rule, crash, missing or malformed policy file via `Gate.from_policy_file`) results in a deny.
- **Audit log:** every decision is written as JSONL; argument *values* are hashed, not stored.
- **Tamper-evident (opt-in):** `AuditLog(path, chain=True)` hash-chains records; `verify(path)` detects edited, inserted, deleted, or reordered records.
- **Zero dependencies**, pure Python 3.10+.

The test suite (93 core tests, plus 4 MCP integration tests) includes adversarial cases:
bool-as-int, NaN/inf, 20 MB strings, Unicode look-alike tool names, nested objects, `*args`/`**kwargs`
smuggling, malformed or missing policy files, and audit-log tampering.

## Quickstart

```bash
pip install -e ".[dev]"
pytest -q
python examples/demo.py
```

```python
from hydra_gate import ArgRule, Gate, Policy, ToolRule, guard

policy = Policy({"transfer": ToolRule(args={
    "to": ArgRule(type="str", pattern=r"acct_[0-9]{6}"),
    "amount": ArgRule(type="number", min=0.01, max=100),
})})
gate = Gate(policy)
gate.call("transfer", {"to": "acct_123456", "amount": 5}, handler=my_transfer)  # runs
gate.call("transfer", {"to": "acct_123456", "amount": 5000}, handler=my_transfer)  # raises Denied

# or guard a tool function directly (sync or async; signature is preserved):
@guard(gate, "transfer")
def transfer(to: str, amount: float): ...
```

Policies can also live in JSON. Loading is strict (unknown keys, bad regexes, duplicate keys, NaN literals are refused):

```python
gate = Gate.from_policy_file("policy.json", audit=AuditLog("audit.jsonl", chain=True))
# missing/malformed file -> the gate denies everything with reason "policy_invalid:..."
```

```json
{"tools": {"transfer": {"args": {
  "to":     {"type": "str", "pattern": "acct_[0-9]{6}"},
  "amount": {"type": "number", "min": 0.01, "max": 100}
}}}}
```

## Using it with MCP servers

`guard` sits under your framework's tool registration. Tested with each library's in-process client:

| Framework | Version tested | Server class |
|---|---|---|
| `fastmcp` | 4.0.11 | `fastmcp.FastMCP` |
| official MCP Python SDK (`mcp`) | 2.3.0 | `mcp.server.mcpserver.MCPServer` (formerly `FastMCP`) |

The tool schema is still generated from your function signature, allowed calls run, and denied calls
never reach the handler (FastMCP returns a `ToolError` carrying the reason; the official SDK returns an
`is_error=True` result). See `tests/integration/` and `examples/mcp_server_example.py`.
Note: the framework validates/coerces arguments *before* the gate sees them (e.g. `5` becomes `5.0` for a
`float` parameter), so the gate checks the values your handler would actually receive.
Not yet tested: stdio/HTTP transports end to end, mcp 1.x, other frameworks.

## Status: v0.1, early

Working: the policy engine, gate, audit log (with opt-in hash chain + `verify()`), JSON policy loading, test suite.
Working, tested in-process: the `guard` decorator with fastmcp 4.0.11 and the official MCP SDK 2.3.0.
Not built yet: Rust core, rate limits, human-approval flow, nested-object/array argument rules.
Known limits: an audit failure does not block an allowed call unless you pass `Gate(..., require_audit=True)`;
the hash chain cannot detect the newest records being cut off, or a full rewrite, unless you store `verify(path).head` somewhere else;
`allow_extra_args=True` lets extra arguments through unchecked.
Not claimed: this is not a complete security solution. It enforces the policy you write;
it does not judge whether a policy is wise.

## Measuring performance

`python benchmarks/bench_latency.py` prints median and p99 decision latency on your
hardware (`--write` saves `BENCH.json` and `benchmarks/RESULTS.md`). We publish numbers only from
this script, with hardware and Python version noted. Latest run: [benchmarks/RESULTS.md](benchmarks/RESULTS.md).

## Roadmap

1. ~~Verify the guard against real MCP libraries~~ (done in-process for fastmcp 4.0.11 and mcp 2.3.0); next: transport-level tests
2. Grow the adversarial suite; add fuzzing
3. Rate limits and human-approval hooks
4. Rust core with Python bindings (only if profiling shows a need)

## License

MIT. See [SECURITY.md](SECURITY.md) to report vulnerabilities.
