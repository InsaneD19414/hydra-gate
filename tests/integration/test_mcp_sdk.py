"""Integration with the official MCP Python SDK (`mcp`), via its in-process Client (no network).

In mcp 2.x the high-level server formerly named ``FastMCP`` is ``mcp.server.mcpserver.MCPServer``
(importing ``mcp.server.fastmcp`` raises ModuleNotFoundError). These tests target mcp>=2 and are
skipped when it is not installed. mcp 1.x (``mcp.server.fastmcp.FastMCP``) is NOT tested here.
"""
import asyncio

import pytest

pytest.importorskip("mcp")
try:
    from mcp import Client
    from mcp.server.mcpserver import MCPServer
except ImportError:  # pragma: no cover - mcp 1.x layout
    pytest.skip("requires mcp>=2 (MCPServer + in-process Client)", allow_module_level=True)

from hydra_gate import verify  # noqa: E402

from ._common import make_tools, reasons  # noqa: E402


def _server(tmp_path):
    gate, calls, g_read, g_toggle = make_tools(tmp_path / "audit.jsonl")
    server = MCPServer("hydra-gate-it")
    server.tool()(g_read)
    server.tool()(g_toggle)
    return gate, calls, server


def test_mcp_sdk_schema_generated_from_signature(tmp_path):
    _, _, server = _server(tmp_path)

    async def run():
        async with Client(server) as c:
            return {t.name: t for t in (await c.list_tools()).tools}

    tools = asyncio.run(run())
    s = tools["read_file"].input_schema
    assert s["properties"]["path"]["type"] == "string"
    assert s["properties"]["limit"]["type"] == "integer"
    assert s["properties"]["limit"]["default"] == 10
    assert s["required"] == ["path"]
    assert tools["read_file"].description == "Read a file under /data."
    assert tools["toggle"].input_schema["properties"]["on"]["type"] == "boolean"


def test_mcp_sdk_allowed_and_denied_calls(tmp_path):
    gate, calls, server = _server(tmp_path)

    async def run():
        async with Client(server) as c:
            return [
                await c.call_tool("read_file", {"path": "/data/a.txt", "limit": 3}),
                await c.call_tool("toggle", {"on": False}),
                await c.call_tool("read_file", {"path": "/etc/passwd"}),
                await c.call_tool("read_file", {"path": "/data/a.txt", "limit": 1000}),
            ]

    ok, ok2, bad1, bad2 = asyncio.run(run())
    assert not ok.is_error and ok.content[0].text == "read /data/a.txt x3"
    assert not ok2.is_error and ok2.content[0].text == "on=False"
    # The SDK converts the Denied exception into an error result (is_error=True, generic text).
    assert bad1.is_error and bad2.is_error
    assert calls == [("read_file", "/data/a.txt", 3), ("toggle", False)]   # denied calls never ran
    assert reasons(gate) == ["allowed", "allowed", "pattern_mismatch:path", "above_max:limit"]
    assert verify(gate.audit.path).ok
