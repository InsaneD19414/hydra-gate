"""Integration with the standalone `fastmcp` package, via its in-process Client (no network).

Skipped automatically when fastmcp is not installed (pip install -e ".[integration]").
"""
import asyncio

import pytest

pytest.importorskip("fastmcp")
from fastmcp import Client, FastMCP  # noqa: E402
from fastmcp.exceptions import ToolError  # noqa: E402

from hydra_gate import verify  # noqa: E402

from ._common import make_tools, reasons  # noqa: E402


def _server(tmp_path):
    gate, calls, g_read, g_toggle = make_tools(tmp_path / "audit.jsonl")
    server = FastMCP("hydra-gate-it")
    server.tool(g_read)
    server.tool(g_toggle)
    return gate, calls, server


def _schema(tool):
    return getattr(tool, "input_schema", None) or tool.inputSchema


def test_fastmcp_schema_generated_from_signature(tmp_path):
    _, _, server = _server(tmp_path)

    async def run():
        async with Client(server) as c:
            return {t.name: t for t in await c.list_tools()}

    tools = asyncio.run(run())
    s = _schema(tools["read_file"])
    assert s["properties"]["path"]["type"] == "string"
    assert s["properties"]["limit"]["type"] == "integer"
    assert s["properties"]["limit"]["default"] == 10
    assert s["required"] == ["path"]
    assert tools["read_file"].description == "Read a file under /data."
    assert _schema(tools["toggle"])["properties"]["on"]["type"] == "boolean"


def test_fastmcp_allowed_and_denied_calls(tmp_path):
    gate, calls, server = _server(tmp_path)

    async def run():
        async with Client(server) as c:
            ok = await c.call_tool("read_file", {"path": "/data/a.txt", "limit": 3})
            ok2 = await c.call_tool("toggle", {"on": True})
            with pytest.raises(ToolError, match="pattern_mismatch:path"):
                await c.call_tool("read_file", {"path": "/etc/passwd"})
            with pytest.raises(ToolError, match="above_max:limit"):
                await c.call_tool("read_file", {"path": "/data/a.txt", "limit": 1000})
            return ok, ok2

    ok, ok2 = asyncio.run(run())
    assert ok.data == "read /data/a.txt x3" and not ok.is_error
    assert ok2.data == "on=True"
    assert calls == [("read_file", "/data/a.txt", 3), ("toggle", True)]   # denied calls never ran
    assert reasons(gate) == ["allowed", "allowed", "pattern_mismatch:path", "above_max:limit"]
    assert verify(gate.audit.path).ok
