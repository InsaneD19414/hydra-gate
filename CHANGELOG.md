# Changelog

## 0.1.0 (unreleased)

Initial public release. Built on the original v0.1 (policy engine, gate, audit log, `guard`, 21 tests), with:

### Added
- `AuditLog(path, chain=True)`: opt-in hash-chained records (`seq`, `prev`, `hash`) and `verify(path)` returning `VerifyResult(ok, records, head, error, bad_line)`. Refuses to extend an existing broken chain.
- `AuditLog(hash_key=...)` for HMAC-SHA256 argument digests; `fsync=True` option; thread-safe writes.
- `Gate(..., require_audit=True)`: deny when the audit record cannot be written.
- `Policy.from_json(path)` and strict `Policy.from_dict` validation (unknown keys, bad types/regex/bounds/enums, duplicate JSON keys, NaN literals, non-ASCII tool names) raising `PolicyError`; `Policy.validate()`.
- `Gate.from_policy_file(path)`: fail-closed loader; a missing/malformed file yields a gate that denies everything (`policy_invalid:<Error>`).
- `Policy(max_str_len=65536)`: default length cap for every string argument.
- `guard` sets `__signature__` explicitly and exposes `.hydra_gate`; `**kwargs` handlers have each keyword checked against the policy; non-empty `*args` are denied.
- Tests: 72 adversarial/audit-chain tests (`tests/test_adversarial.py`, `tests/test_audit_chain.py`) and 4 integration tests against fastmcp 4.0.11 and mcp 2.3.0 (`tests/integration/`, skipped if not installed).
- `examples/mcp_server_example.py`; benchmark `--write` mode producing `BENCH.json` and `benchmarks/RESULTS.md`.

### Fixed
- **NaN was allowed** for `number` arguments (NaN fails every `<`/`>` comparison, so min/max never rejected it). NaN and ±inf are now denied (`not_finite:<arg>`).
- Type checks are now exact: subclasses of `str`/`int`/`float` (which can override `__eq__` to defeat `enum`) are denied.
- Strings had no length limit unless `max_len` was set; a policy-wide cap now applies, and length is checked before enum/regex.
- A malformed call to a `guard`ed function was audited by evaluating `{}`, which could be logged as `allowed` for tools with no required args; it is now logged as a deny (`bad_call_signature`).
- Non-string tool names are denied explicitly.
