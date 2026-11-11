"""S11b's machinery: amx-mcp over real MCP stdio against the dev stack (no model needed).

The recorded S11b run (docs/scenarios.md) puts a Claude Code session behind these same tools.
Here a plain MCP client drives them: scheduler asks intake (the scripted contoso agent) for work,
waits for the answer, reads the thread, and finds a first-contact send parked in its hold queue.
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from typing import Any

import pytest

from scenarios.support import ROOT

pytestmark = pytest.mark.integration


def _result(call: Any) -> Any:
    assert not call.isError, call.content
    if call.structuredContent is not None:
        value = call.structuredContent
        return value.get("result", value) if set(value) == {"result"} else value
    return json.loads(call.content[0].text)


async def _session(checks) -> None:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    server = StdioServerParameters(
        command="uv",
        args=["run", "amx-mcp", "--agent", "scheduler@agents.northwind.test"],
        env={
            **{key: os.environ[key] for key in ("PATH", "HOME", "TMPDIR") if key in os.environ},
            "AMX_IMAP_PASSWORD": "dev-scheduler",
            "AMX_SUBMIT_TOKEN": "dev-scheduler-token",
        },
        cwd=str(ROOT),
    )
    async with stdio_client(server) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        await checks(session)


def test_s11_mcp_server_sends_waits_reads_and_shows_holds() -> None:
    suffix = uuid.uuid4().hex[:8]

    async def checks(session) -> None:
        tools = {tool.name for tool in (await session.list_tools()).tools}
        assert tools == {
            "list_inbox",
            "read_thread",
            "send",
            "reply",
            "wait_for_reply",
            "list_held",
            "declare_state",  # PLAN §5.10, after S11b was recorded
            "save_attachment",  # SH-42
            "done",  # SH-24a
            "refuse",
        }

        sent = _result(
            await session.call_tool(
                "send",
                {
                    "to": ["intake@agents.contoso.test"],
                    "subject": f"S11 MCP {suffix}",
                    "text": "Please confirm the site inspection request.",
                },
            )
        )
        assert sent["held"] is None and sent["task"].startswith("t_")
        answer = _result(
            await session.call_tool("wait_for_reply", {"task": sent["task"], "timeout_seconds": 60})
        )
        assert answer["status"] == "received"
        message = answer["message"]
        assert (message["intent"], message["lane"], message["verified"]) == (
            "response",
            "agent",
            "agents.contoso.test/intake",
        )
        assert message["tainted"] is False
        assert message["text"] == "Intake completed the request."
        thread = _result(await session.call_tool("read_thread", {"task": sent["task"]}))
        assert [item["folder"] for item in thread] == ["Sent", "INBOX"]
        inbox = _result(await session.call_tool("list_inbox", {"limit": 5}))
        assert any(item["message_id"] == message["message_id"] for item in inbox)

        # A send the gateway parks for a person: a never-seen domain is a first contact for
        # scheduler (hold rule first-contact-domain), whoever asks to send.
        held = _result(
            await session.call_tool(
                "send",
                {
                    "to": [f"pat@first-contact-{suffix}.test"],
                    "subject": f"S11 MCP hold {suffix}",
                    "text": "Hello Pat.",
                },
            )
        )
        assert held["held"] == "first-contact-domain"
        queue = _result(await session.call_tool("list_held", {}))
        assert any(
            item["message_id"] == held["message_id"]
            and item["hold_rule"] == "first-contact-domain"
            and item["hold_recipients"] == f"pat@first-contact-{suffix}.test"
            for item in queue
        )
        # A bad argument comes back as a tool error, and the session stays usable.
        refused = await session.call_tool(
            "send",
            {"to": ["intake@agents.contoso.test"], "subject": "x", "text": "y", "intent": "bogus"},
        )
        assert refused.isError
        assert _result(await session.call_tool("list_held", {}))
        # The agent's own state goes to its own gateway, which applies it and relays nothing.
        try:
            capped = _result(
                await session.call_tool(
                    "declare_state",
                    {"command": "capacity", "max_messages": 1, "ttl_seconds": 60},
                )
            )
            assert capped["applied"].startswith("capacity max=1 until=")
            assert capped["applied"].endswith("effective=1")
        finally:  # never leave scheduler capped for the scenarios that follow
            resumed = _result(await session.call_tool("declare_state", {"command": "resume"}))
        assert resumed["applied"] == "resume"
        print(f"S11 MCP: task {sent['task']} answered by intake; hold {held['held']} listed")

    asyncio.run(_session(checks))
