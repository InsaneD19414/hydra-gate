import json

import pytest

from hydra_gate import ArgRule, Denied, Gate, Policy, ToolRule, AuditLog

POLICY = Policy({
    "transfer": ToolRule(args={
        "to": ArgRule(type="str", pattern=r"acct_[0-9]{6}"),
        "amount": ArgRule(type="number", min=0.01, max=100),
        "memo": ArgRule(type="str", required=False, max_len=40),
    }),
    "read_status": ToolRule(args={"env": ArgRule(type="str", enum=("dev", "staging"))}),
})


def gate(**kw):
    return Gate(POLICY, **kw)


def test_unknown_tool_denied_by_default():
    d = gate().evaluate("rm_rf", {})
    assert not d.allowed and d.reason == "tool_not_allowed"


def test_valid_call_allowed():
    assert gate().evaluate("transfer", {"to": "acct_123456", "amount": 5}).allowed


@pytest.mark.parametrize("args,reason", [
    ({"to": "acct_123456", "amount": 5, "x": 1}, "unexpected_args:x"),
    ({"to": "acct_123456"}, "missing_arg:amount"),
    ({"to": "acct_123456", "amount": "5"}, "bad_type:amount"),
    ({"to": "acct_123456", "amount": True}, "bad_type:amount"),
    ({"to": "acct_123456", "amount": 1000}, "above_max:amount"),
    ({"to": "acct_12345; DROP", "amount": 5}, "pattern_mismatch:to"),
    ({"to": "acct_123456", "amount": 5, "memo": "x" * 41}, "too_long:memo"),
])
def test_bad_arguments_denied(args, reason):
    d = gate().evaluate("transfer", args)
    assert not d.allowed and d.reason == reason


def test_enum_enforced():
    assert gate().evaluate("read_status", {"env": "dev"}).allowed
    assert not gate().evaluate("read_status", {"env": "prod"}).allowed


def test_non_mapping_arguments_denied():
    assert not gate().evaluate("transfer", "not a dict").allowed


def test_internal_error_fails_closed():
    broken = Policy({"t": ToolRule(args={"a": ArgRule(type="str", pattern="(")})})  # invalid regex
    d = Gate(broken).evaluate("t", {"a": "x"})
    assert not d.allowed and d.reason.startswith("internal_error")


def test_call_does_not_run_handler_when_denied():
    ran = []
    with pytest.raises(Denied):
        gate().call("transfer", {"to": "bad", "amount": 1}, lambda **k: ran.append(1))
    assert ran == []


def test_call_runs_handler_when_allowed():
    out = gate().call("read_status", {"env": "dev"}, lambda env: f"ok:{env}")
    assert out == "ok:dev"


def test_audit_logs_decisions_without_raw_values(tmp_path):
    log = tmp_path / "audit.jsonl"
    g = gate(audit=AuditLog(log))
    g.evaluate("transfer", {"to": "acct_123456", "amount": 5})
    g.evaluate("rm_rf", {"secret": "hunter2"})
    lines = [json.loads(x) for x in log.read_text().splitlines()]
    assert [r["allowed"] for r in lines] == [True, False]
    assert "hunter2" not in log.read_text()


def test_audit_failure_does_not_flip_decision(tmp_path):
    g = gate(audit=AuditLog(tmp_path / "missing_dir" / "a.jsonl"))
    assert g.evaluate("transfer", {"to": "acct_123456", "amount": 5}).allowed
    assert not g.evaluate("nope", {}).allowed
