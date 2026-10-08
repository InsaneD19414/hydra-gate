# Contributing

1. `pip install -e ".[dev]"` then `pytest -q`
2. Every new rule type needs tests, including at least one "should be denied" case.
3. Design rule: **if in doubt, deny.** Any new code path that can raise must result in a deny, never an allow.
4. Found a bypass? Add a failing test in `tests/` and open a PR (or report privately via SECURITY.md).
5. MCP integration tests: `pip install -e ".[dev,integration]"` then `pytest -q tests/integration` (they skip if the frameworks are missing).
6. Benchmarks: publish only numbers produced by `python benchmarks/bench_latency.py --write`, with the hardware it reports.
