"""Measure gate decision latency on YOUR machine. Publish what you get, with hardware and Python version.

    python benchmarks/bench_latency.py            # print results
    python benchmarks/bench_latency.py --write    # also write benchmarks/RESULTS.md and BENCH.json

The headline number is the same workload as v0.1's original script: one allowed `transfer`
call (regex + range check), no audit log, timed per call with time.perf_counter().
A second scenario adds the opt-in hash-chained audit log (file I/O included, no fsync).
"""
import datetime
import json
import os
import platform
import statistics
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))  # works without `pip install -e .`

from hydra_gate import ArgRule, AuditLog, Gate, Policy, ToolRule

POLICY = Policy({"transfer": ToolRule(args={
    "to": ArgRule(type="str", pattern=r"acct_[0-9]{6}"),
    "amount": ArgRule(type="number", min=0.01, max=100)})})
ARGS = {"to": "acct_123456", "amount": 5}
N = 50_000


def cpu_model() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def run(gate: Gate, n: int) -> dict:
    for _ in range(1000):  # warm-up, not recorded
        gate.evaluate("transfer", ARGS)
    samples = []
    for _ in range(n):
        t = time.perf_counter()
        d = gate.evaluate("transfer", ARGS)
        samples.append((time.perf_counter() - t) * 1000)
        assert d.allowed
    samples.sort()
    return {"n": n, "median_ms": round(statistics.median(samples), 4),
            "p99_ms": round(samples[int(n * 0.99)], 4), "mean_ms": round(statistics.fmean(samples), 4)}


def main() -> None:
    results = {"no_audit": run(Gate(POLICY), N)}
    with tempfile.TemporaryDirectory() as d:
        results["chained_audit_log"] = run(Gate(POLICY, AuditLog(os.path.join(d, "a.jsonl"), chain=True)), N)
    env = {
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "cpu_model": cpu_model(),
        "logical_cpus": os.cpu_count(),
        "measured_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    }
    print(f"python {env['python']} on {env['platform']}")
    print(f"cpu: {env['cpu_model']} ({env['logical_cpus']} logical CPUs)")
    for name, r in results.items():
        print(f"[{name}] n={r['n']} median={r['median_ms']:.4f} ms  p99={r['p99_ms']:.4f} ms")

    if "--write" in sys.argv:
        root = Path(__file__).resolve().parent.parent
        (root / "BENCH.json").write_text(json.dumps({"environment": env, "results": results}, indent=2) + "\n")
        md = ["# Benchmark results", "",
              "Produced by `python benchmarks/bench_latency.py --write`. Numbers are copied verbatim from that run.", "",
              f"- Python: {env['implementation']} {env['python']}",
              f"- Platform: {env['platform']}",
              f"- CPU: {env['cpu_model']} ({env['logical_cpus']} logical CPUs, shared cloud VM)",
              f"- Measured: {env['measured_at_utc']}", "",
              "| Scenario | n | median (ms) | p99 (ms) | mean (ms) |", "|---|---|---|---|---|"]
        for name, r in results.items():
            md.append(f"| {name} | {r['n']} | {r['median_ms']:.4f} | {r['p99_ms']:.4f} | {r['mean_ms']:.4f} |")
        md += ["", "Workload: one allowed `transfer` call (regex + numeric range check) per iteration, "
               "1,000 warm-up calls discarded. `chained_audit_log` includes writing one hash-chained JSONL "
               "record per call (no fsync). Your numbers will differ; publish them with your hardware."]
        (root / "benchmarks" / "RESULTS.md").write_text("\n".join(md) + "\n")
        print("wrote BENCH.json and benchmarks/RESULTS.md")


if __name__ == "__main__":
    main()
