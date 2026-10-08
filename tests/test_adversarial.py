"""Adversarial inputs. Every case here must be DENIED (or, for policy errors, refused at load)."""
import json
import math

import pytest

from hydra_gate import ArgRule, Denied, Gate, Policy, PolicyError, ToolRule, guard

POLICY = Policy({
    "transfer": ToolRule(args={
        "to": ArgRule(type="str", pattern=r"acct_[0-9]{6}"),
        "amount": ArgRule(type="number", min=0.01, max=100),
        "memo": ArgRule(type="str", required=False),          # no max_len -> policy default applies
    }),
    "page": ToolRule(args={"n": ArgRule(type="int")}),        # no bounds at all
    "flag": ToolRule(args={"on": ArgRule(type="bool")}),
    "pick": ToolRule(args={"env": ArgRule(type="str", enum=("dev", "staging"))}),
}, max_str_len=1024)

OK = {"to": "acct_123456", "amount": 5}


def ev(tool, args):
    return Gate(POLICY).evaluate(tool, args)


# --- type confusion -------------------------------------------------------------------------
@pytest.mark.parametrize("val", [True, False])
def test_bool_as_int_denied(val):
    assert ev("page", {"n": val}).reason == "bad_type:n"


@pytest.mark.parametrize("val", [1, 0, "true", None])
def test_int_or_str_as_bool_denied(val):
    assert ev("flag", {"on": val}).reason == "bad_type:on"


@pytest.mark.parametrize("val", ["5", 5.0, None, b"5", [5]])
def test_type_confusion_on_int(val):
    assert ev("page", {"n": val}).reason == "bad_type:n"


def test_subclasses_rejected():
    class EvilStr(str):
        def __eq__(self, other):
            return True
        __hash__ = str.__hash__

    class EvilInt(int):
        pass

    assert ev("pick", {"env": EvilStr("prod")}).reason == "bad_type:env"
    assert ev("page", {"n": EvilInt(3)}).reason == "bad_type:n"


# --- NaN / infinity -------------------------------------------------------------------------
@pytest.mark.parametrize("val", [math.nan, math.inf, -math.inf, float("nan")])
def test_nan_and_inf_denied(val):
    assert ev("transfer", {**OK, "amount": val}).reason == "not_finite:amount"


def test_nan_denied_even_without_bounds():
    p = Policy({"t": ToolRule(args={"x": ArgRule(type="number")})})
    assert not Gate(p).evaluate("t", {"x": math.nan}).allowed
    assert Gate(p).evaluate("t", {"x": 1e308}).allowed


# --- huge inputs ----------------------------------------------------------------------------
def test_huge_string_denied_by_default_cap():
    assert ev("transfer", {**OK, "memo": "x" * 1025}).reason == "too_long:memo"
    assert ev("transfer", {**OK, "memo": "x" * 1024}).allowed


def test_huge_string_rejected_before_regex():
    d = ev("transfer", {**OK, "to": "acct_" + "1" * 20_000_000})
    assert d.reason == "too_long:to" and d.latency_ms < 100


def test_huge_int_does_not_crash_gate_or_audit(tmp_path):
    from hydra_gate import AuditLog
    g = Gate(POLICY, AuditLog(tmp_path / "a.jsonl"))
    assert g.evaluate("page", {"n": 10**5000}).allowed       # no bounds declared -> allowed
    assert g.evaluate("transfer", {**OK, "amount": 10**5000}).reason == "above_max:amount"
    assert len((tmp_path / "a.jsonl").read_text().splitlines()) == 2


# --- unicode tricks -------------------------------------------------------------------------
@pytest.mark.parametrize("name", [
    "tr\u0430nsfer",       # Cyrillic a
    "transfer\u200b",      # zero-width space
    "\uff54ransfer",       # full-width t (NFKC would fold it)
    "transfer ",           # trailing space
    "TRANSFER",
    "",
    None,
    42,
    ("transfer",),
])
def test_tool_name_lookalikes_denied(name):
    d = ev(name, OK)
    assert not d.allowed
    assert d.reason == "tool_not_allowed"


def test_unhashable_tool_name_fails_closed():
    d = ev(["transfer"], OK)
    assert not d.allowed


def test_unicode_argument_name_denied():
    assert ev("transfer", {"t\u043e": "acct_123456", "amount": 5}).reason.startswith("unexpected_args")


def test_policy_with_lookalike_tool_name_refused_at_load():
    with pytest.raises(PolicyError):
        Policy.from_dict({"tools": {"tr\u0430nsfer": {}}})


def test_unicode_digits_do_not_satisfy_ascii_pattern():
    # \d would accept Arabic-Indic digits; the policy uses [0-9]
    assert ev("transfer", {"to": "acct_\u0661\u0662\u0663\u0664\u0665\u0666", "amount": 5}).reason == "pattern_mismatch:to"


# --- nested objects -------------------------------------------------------------------------
@pytest.mark.parametrize("val", [{"$gt": ""}, ["acct_123456"], ("acct_123456",), {"acct_123456"}, object()])
def test_nested_or_container_values_denied(val):
    assert ev("transfer", {**OK, "to": val}).reason == "bad_type:to"


def test_nested_extra_args_denied():
    assert ev("transfer", {**OK, "options": {"sudo": True}}).reason == "unexpected_args:options"


# --- missing / malformed policy -------------------------------------------------------------
def test_missing_policy_file(tmp_path):
    with pytest.raises(PolicyError):
        Policy.from_json(tmp_path / "nope.json")
    g = Gate.from_policy_file(tmp_path / "nope.json")
    d = g.evaluate("transfer", OK)
    assert not d.allowed and d.reason.startswith("policy_invalid")


@pytest.mark.parametrize("text", [
    "{not json",
    "[]",
    '{"tools": {}, "tools": {}}',                                          # duplicate key
    '{"tools": {"t": {"args": {"x": {"type": "number", "max": NaN}}}}}',   # NaN literal
    '{"tools": {"t": {"args": {"x": {"type": "object"}}}}}',               # unsupported type
    '{"tools": {"t": {"args": {"x": {"type": "str", "pattern": "("}}}}}',  # bad regex
    '{"tools": {"t": {"args": {"x": {"type": "str", "maxlen": 3}}}}}',     # typo'd key
    '{"tools": {"t": {"arg": {}}}}',                                        # typo'd key
    '{"tools": {"t": {"args": {"x": {"type": "int", "enum": ["1"]}}}}}',   # enum type mismatch
    '{"tools": {"t": {"args": {"x": {"type": "int", "min": "0"}}}}}',      # non-numeric bound
    '{"tool": {}}',
])
def test_malformed_policy_refused_and_gate_fails_closed(tmp_path, text):
    p = tmp_path / "bad.json"
    p.write_text(text, encoding="utf-8")
    with pytest.raises(PolicyError):
        Policy.from_json(p)
    assert Gate.from_policy_file(p).evaluate("t", {"x": 1}).reason.startswith("policy_invalid")


def test_valid_policy_file_roundtrip(tmp_path):
    p = tmp_path / "ok.json"
    p.write_text(json.dumps({"tools": {"t": {"args": {"x": {"type": "int", "min": 0, "max": 9,
                                                              "enum": [1, 2]}}}}}))
    g = Gate.from_policy_file(p)
    assert g.evaluate("t", {"x": 1}).allowed
    assert g.evaluate("t", {"x": 3}).reason == "not_in_enum:x"


def test_none_policy_fails_closed():
    assert Gate(None).evaluate("t", {}).reason.startswith("internal_error")


def test_unknown_type_in_hand_built_rule_fails_closed():
    p = Policy({"t": ToolRule(args={"x": ArgRule(type="object")})})
    assert Gate(p).evaluate("t", {"x": {}}).reason.startswith("internal_error")
    assert p.validate()


def test_exploding_mapping_fails_closed():
    class Boom(dict):
        def __iter__(self):
            raise RuntimeError("boom")
    assert Gate(POLICY).evaluate("transfer", Boom(OK)).reason == "internal_error:RuntimeError"


# --- determinism ----------------------------------------------------------------------------
def test_same_input_same_decision():
    calls = [("transfer", {"zz": 1, "aa": 2}), ("transfer", {**OK, "amount": -1}), ("rm", {}), ("transfer", OK)]
    for tool, args in calls:
        seen = {(d.allowed, d.reason) for d in (ev(tool, dict(args)) for _ in range(5))}
        seen |= {(lambda d: (d.allowed, d.reason))(ev(tool, dict(reversed(list(args.items())))))}
        assert len(seen) == 1
    assert ev("transfer", {"zz": 1, "aa": 2}).reason == "unexpected_args:aa,zz"


# --- guard edge cases -----------------------------------------------------------------------
def test_guard_kwargs_handler_checks_each_kwarg():
    g = Gate(POLICY)

    @guard(g, "transfer")
    def handler(**kwargs):
        return "ran"

    assert handler(**OK) == "ran"
    with pytest.raises(Denied, match="unexpected_args:exfil"):
        handler(**OK, exfil="evil.example")


def test_guard_varargs_smuggling_denied():
    ran = []

    @guard(Gate(POLICY), "transfer")
    def handler(to, amount, *rest):
        ran.append(1)

    with pytest.raises(Denied, match="bad_call_signature"):
        handler("acct_123456", 5, "smuggled")
    assert ran == []


def test_guard_bad_call_logged_as_deny(tmp_path):
    from hydra_gate import AuditLog
    log = AuditLog(tmp_path / "a.jsonl")
    g = Gate(Policy({"noargs": ToolRule()}), log)

    @guard(g, "noargs")
    def noargs():
        return 1

    with pytest.raises(Denied):
        noargs(1, 2)
    rec = json.loads((tmp_path / "a.jsonl").read_text())
    assert rec["allowed"] is False and rec["reason"] == "bad_call_signature"


def test_guard_preserves_signature_and_metadata():
    import asyncio
    import inspect

    async def transfer(to: str, amount: float, memo: str = "") -> str:
        """Move money."""
        return to

    w = guard(Gate(POLICY), "transfer")(transfer)
    assert w.__signature__ == inspect.signature(transfer) == inspect.signature(w)
    assert w.__name__ == "transfer" and w.__doc__ == "Move money."
    assert w.__annotations__ == transfer.__annotations__
    assert inspect.iscoroutinefunction(w)
    assert asyncio.run(w("acct_123456", 5)) == "acct_123456"
