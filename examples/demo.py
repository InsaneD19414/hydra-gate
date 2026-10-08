"""Run: python examples/demo.py  -- shows allow and deny decisions, then verifies the audit chain."""
import sys
from pathlib import Path

# Run from a fresh checkout without `pip install -e .`: fall back to ../src.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from hydra_gate import ArgRule, AuditLog, Denied, Gate, Policy, ToolRule, verify

policy = Policy({"read_file": ToolRule(args={"path": ArgRule(type="str", pattern=r"docs/[a-z0-9_\-]+\.md")})})
log_path = Path("demo_audit.jsonl")
log_path.unlink(missing_ok=True)
gate = Gate(policy, AuditLog(log_path, chain=True))

def read_file(path): return f"(pretend contents of {path})"

for tool, args in [("read_file", {"path": "docs/intro.md"}),
                   ("read_file", {"path": "../../etc/passwd"}),
                   ("read_file", {"path": "docs/intro.md", "mode": "w"}),
                   ("delete_all", {})]:
    try:
        print("ALLOWED:", gate.call(tool, args, read_file))
    except Denied as e:
        print("BLOCKED:", e)

res = verify(log_path)
print(f"audit log: {res.records} records, chain intact={res.ok}, head={res.head[:16]}...")
