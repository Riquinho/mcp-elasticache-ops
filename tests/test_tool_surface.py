"""tools/list footprint: a byte budget and a pinned snapshot of tool names and input schemas.

Every client pays the tools/list payload on each session, so growth must be deliberate. When a tool or parameter
changes on purpose, regenerate ``tests/tool_schemas.json`` (``uv run python -I -m tests.test_tool_surface``) and
review the diff.
"""

import asyncio
import json
from pathlib import Path

from mcp_elasticache_ops import server

SNAPSHOT = Path(__file__).with_name("tool_schemas.json")
MAX_TOOLS_LIST_BYTES = 49_500  # 58 tools in round 21 (was 48_500 with 57); raise only with a reason in CHANGELOG


async def _dumped() -> list[dict]:
    tools = await server.mcp.list_tools()
    return [t.to_mcp_tool().model_dump(mode="json", by_alias=True, exclude_none=True) for t in tools]


def _schemas(dumped: list[dict]) -> dict:
    return {t["name"]: t["inputSchema"] for t in sorted(dumped, key=lambda x: x["name"])}


async def test_tools_list_payload_stays_within_the_byte_budget():
    payload = json.dumps({"tools": await _dumped()}, separators=(",", ":"), ensure_ascii=False)
    size = len(payload.encode())
    assert size <= MAX_TOOLS_LIST_BYTES, f"tools/list is {size} bytes (budget {MAX_TOOLS_LIST_BYTES}); shorten text"


async def test_tool_names_and_input_schemas_match_the_pinned_snapshot():
    pinned = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    current = _schemas(await _dumped())
    assert sorted(current) == sorted(pinned), (
        f"added: {sorted(set(current) - set(pinned))}, removed: {sorted(set(pinned) - set(current))}"
    )
    changed = [name for name in current if current[name] != pinned[name]]
    assert not changed, f"input schema changed for {changed}; regenerate tests/tool_schemas.json if intended"


if __name__ == "__main__":
    SNAPSHOT.write_text(
        json.dumps(_schemas(asyncio.run(_dumped())), indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
