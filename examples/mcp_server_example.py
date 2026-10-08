"""EXAMPLE: guarding tools on an MCP server.

Requires `pip install fastmcp` (or the official SDK: `pip install "mcp>=2"`, see the bottom).
Not required by hydra-gate itself, which has zero runtime dependencies.

The same pattern is exercised by tests/integration/ (fastmcp 4.0.11 and mcp 2.3.0 at the time
of writing, in-process clients only). Stdio/HTTP transports and other MCP frameworks have not
been tested.

Run: python examples/mcp_server_example.py   (calls the tools in-process and prints results)
"""
import asyncio
import sys
from pathlib import Path

# Run from a fresh checkout without `pip install -e .`: fall back to ../src.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from hydra_gate import ArgRule, AuditLog, Gate, Policy, ToolRule, guard

gate = Gate(Policy({
    "transfer": ToolRule(args={
        "to": ArgRule(type="str", pattern=r"acct_[0-9]{6}"),
        "amount": ArgRule(type="number", min=0.01, max=100),
    }),
}), AuditLog("mcp_audit.jsonl", chain=True))


async def transfer(to: str, amount: float) -> str:
    """Send a small payment to an allow-listed account format."""
    return f"sent {amount} to {to}"


guarded_transfer = guard(gate, "transfer")(transfer)   # hydra-gate wraps the handler first


async def main() -> None:
    from fastmcp import Client, FastMCP

    server = FastMCP("hydra-gate-example")
    server.tool(guarded_transfer)                     # framework registers the guarded handler

    async with Client(server) as client:
        print((await client.call_tool("transfer", {"to": "acct_123456", "amount": 5})).data)
        try:
            await client.call_tool("transfer", {"to": "acct_123456", "amount": 5000})
        except Exception as exc:
            print("BLOCKED:", exc)

    # Official SDK (mcp>=2) equivalent:
    #   from mcp.server.mcpserver import MCPServer
    #   server = MCPServer("hydra-gate-example"); server.tool()(guarded_transfer)


if __name__ == "__main__":
    asyncio.run(main())
