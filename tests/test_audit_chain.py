"""Opt-in hash-chained audit log and verify()."""
import json

import pytest

from hydra_gate import ArgRule, AuditLog, Gate, Policy, ToolRule, verify

POLICY = Policy({"transfer": ToolRule(args={
    "to": ArgRule(type="str", pattern=r"acct_[0-9]{6}"),
    "amount": ArgRule(type="number", min=0.01, max=100)})})


def make(tmp_path, n=5, **kw):
    log = AuditLog(tmp_path / "audit.jsonl", chain=True, **kw)
    g = Gate(POLICY, log)
    for i in range(n):
        g.evaluate("transfer", {"to": f"acct_{i:06d}", "amount": i + 1, "secret": "hunter2"} if i == 2
                   else {"to": f"acct_{i:06d}", "amount": i + 1})
    g.evaluate("rm_rf", {"path": "/"})
    return log.path


def test_chain_verifies_and_reports_head(tmp_path):
    p = make(tmp_path)
    recs = [json.loads(x) for x in p.read_text().splitlines()]
    assert [r["seq"] for r in recs] == list(range(6))
    assert recs[0]["prev"] == "0" * 64
    res = verify(p)
    assert res.ok and res.records == 6 and res.head == recs[-1]["hash"]
    assert "hunter2" not in p.read_text()


def test_unchained_log_is_unchanged_and_not_verifiable(tmp_path):
    log = AuditLog(tmp_path / "plain.jsonl")
    Gate(POLICY, log).evaluate("rm_rf", {})
    rec = json.loads(log.path.read_text())
    assert "hash" not in rec and set(rec) == {"ts", "tool", "arg_keys", "args_sha256", "allowed", "reason", "latency_ms"}
    assert not verify(log.path).ok


def _rewrite(rec):
    return json.dumps(rec, sort_keys=True, separators=(",", ":")) + "\n"


@pytest.mark.parametrize("tamper", ["flip_allowed", "edit_reason", "delete", "swap", "duplicate", "garbage", "truncate_mid_line"])
def test_tampering_detected(tmp_path, tamper):
    p = make(tmp_path)
    lines = p.read_text().splitlines(keepends=True)
    if tamper == "flip_allowed":
        r = json.loads(lines[5]); r["allowed"] = True; lines[5] = _rewrite(r)
    elif tamper == "edit_reason":
        r = json.loads(lines[1]); r["reason"] = "allowed"; r["args_sha256"] = "0" * 64; lines[1] = _rewrite(r)
    elif tamper == "delete":
        del lines[2]
    elif tamper == "swap":
        lines[1], lines[3] = lines[3], lines[1]
    elif tamper == "duplicate":
        lines.insert(2, lines[2])
    elif tamper == "garbage":
        lines[0] = "{oops\n"
    elif tamper == "truncate_mid_line":
        lines[-1] = lines[-1][:20]
    p.write_text("".join(lines))
    res = verify(p)
    assert not res.ok and res.error


def test_resume_extends_chain_and_refuses_broken_log(tmp_path):
    p = make(tmp_path, n=2)
    Gate(POLICY, AuditLog(p, chain=True)).evaluate("transfer", {"to": "acct_000009", "amount": 1})
    assert verify(p).ok and verify(p).records == 4
    p.write_text(p.read_text().replace('"seq":1', '"seq":9'))
    with pytest.raises(ValueError):
        AuditLog(p, chain=True)


def test_keyed_digest(tmp_path):
    p = make(tmp_path, n=1, hash_key=b"k" * 32)
    rec = json.loads(p.read_text().splitlines()[0])
    assert rec["args_digest_alg"] == "hmac-sha256" and verify(p).ok


def test_require_audit_denies_when_log_unwritable(tmp_path):
    g = Gate(POLICY, AuditLog(tmp_path / "missing_dir" / "a.jsonl", chain=True), require_audit=True)
    d = g.evaluate("transfer", {"to": "acct_123456", "amount": 5})
    assert not d.allowed and d.reason.startswith("audit_failure")
