"""Spawn the real server over stdio, the way an MCP host does, with a scrubbed environment."""

import asyncio
import json
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from mcp_elasticache_ops import server


def result_is_crash(text: str) -> bool:
    """True unless the tool returned a JSON object carrying a structured ``error``."""
    try:
        data = json.loads(text)
    except ValueError:
        return True
    return not (isinstance(data, dict) and data.get("error"))


async def _session_checks() -> tuple[int, bool, str]:
    params = StdioServerParameters(
        # The running interpreter, not `uv run`: with a scrubbed env uv may re-sync or recreate the project venv
        # in the middle of the suite and delete packages (botocore data) other tests still need.
        command=sys.executable,
        args=["-I", "-m", "mcp_elasticache_ops"],
        # nothing from the parent env except the mcp SDK's safe defaults; no ELASTICACHE_HOST, AWS creds or tokens
        env={"ELASTICACHE_PORT": "1", "ELASTICACHE_TIMEOUT": "0.2"},
    )
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        init = await session.initialize()
        assert init.server_info.name
        listed = (await session.list_tools()).tools
        read_only = all(t.annotations and t.annotations.read_only_hint is True for t in listed)
        result = await session.call_tool("node_health", {})
        text = "".join(getattr(c, "text", "") for c in result.content)
        return len(listed), read_only, text


def test_stdio_server_lists_read_only_tools_and_returns_structured_errors():
    expected = len(asyncio.run(server.mcp.list_tools()))
    count, read_only, text = asyncio.run(asyncio.wait_for(_session_checks(), timeout=45))
    assert count == expected
    assert read_only
    # no ELASTICACHE_HOST and nothing listening: a structured error, not a crash or a hang
    assert not result_is_crash(text)
