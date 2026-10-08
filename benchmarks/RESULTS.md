# Benchmark results

Produced by `python benchmarks/bench_latency.py --write`. Numbers are copied verbatim from that run.

- Python: CPython 3.13.5
- Platform: Linux-6.12.94+-x86_64-with-glibc2.41
- CPU: Intel(R) Xeon(R) Processor (8 logical CPUs, shared cloud VM)
- Measured: 2026-10-08T06:57:09+00:00

| Scenario | n | median (ms) | p99 (ms) | mean (ms) |
|---|---|---|---|---|
| no_audit | 50000 | 0.0024 | 0.0053 | 0.0027 |
| chained_audit_log | 50000 | 0.0270 | 0.0522 | 0.0300 |

Workload: one allowed `transfer` call (regex + numeric range check) per iteration, 1,000 warm-up calls discarded. `chained_audit_log` includes writing one hash-chained JSONL record per call (no fsync). Your numbers will differ; publish them with your hardware.
