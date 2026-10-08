import asyncio

import pytest

from hydra_gate import ArgRule, Denied, Gate, Policy, ToolRule, guard

gate = Gate(Policy({"add": ToolRule(args={"a": ArgRule(type="int", min=0, max=10), "b": ArgRule(type="int", min=0, max=10)})}))


@guard(gate, "add")
def add(a, b):
    return a + b


@guard(gate, "add")
async def aadd(a, b):
    return a + b


def test_sync_allowed_and_denied():
    assert add(1, 2) == 3
    assert add(a=1, b=2) == 3
    with pytest.raises(Denied):
        add(1, 99)


def test_async_allowed_and_denied():
    assert asyncio.run(aadd(1, 2)) == 3
    with pytest.raises(Denied):
        asyncio.run(aadd(1, 99))


def test_wrong_call_shape_denied():
    with pytest.raises(Denied):
        add(1)


def test_unlisted_function_name_denied():
    @guard(gate)
    def delete_everything():
        raise AssertionError("must not run")
    with pytest.raises(Denied):
        delete_everything()


def test_signature_preserved():
    import inspect
    assert list(inspect.signature(add).parameters) == ["a", "b"]
