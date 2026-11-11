"""SH-24a: real MCP read/reply/done with no runner attached, on either mailhost.

Run only inside the fleet-safe suite lifecycle; never against an unrelated stack.
No model or AX binary is needed. Fixture credentials are repository test accounts.
"""

from __future__ import annotations

import asyncio
import os
import sys
import uuid

import pytest

from amx.mailbox import HANDLED_KEYWORD, TAKEN_KEYWORD
from amx.testkit import wait_for_message
from scenarios.support import ROOT, compose, ct_hold_folder
from scenarios.test_s11_mcp_server import _result
from scenarios.test_s18_control import _outpost
from scenarios.test_s18_remote_agent import OUTPOST, _copies, _scheduler, _wait

pytestmark = pytest.mark.integration


def test_s24_mcp_reads_replies_and_finishes_without_runner() -> None:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    compose("stop", "runner-ct")
    try:
        assert not compose("ps", "--status", "running", "-q", "runner-ct").stdout.strip()
        _outpost().resume()  # clear any previous AX fixture's offline pause
        sent = _scheduler().send(
            to=OUTPOST[1],
            intent="request",
            subject=f"S24 MCP custody {uuid.uuid4().hex[:10]}",
            text="Please confirm the site inspection request.",
        )
        _wait(lambda: _copies(sent.message_id), 30, "gateway did not file S24 request")
        [flags] = [flags for flags, _headers in _copies(sent.message_id)]
        assert not {"\\Seen", TAKEN_KEYWORD, HANDLED_KEYWORD} & flags
        # Explicit allowlist: provider credentials never enter the fixture child.
        environment = {
            key: os.environ[key] for key in ("PATH", "HOME", "TMPDIR") if key in os.environ
        }
        environment.update(AMX_IMAP_PASSWORD="dev-outpost", AMX_SUBMIT_TOKEN="dev-outpost-token")
        server = StdioServerParameters(
            command=sys.executable,
            args=[
                "-m",
                "amx.mcp_server",
                "--agent",
                OUTPOST[1],
                "--held-folder",
                ct_hold_folder("outpost", "Held"),
            ],
            env=environment,
            cwd=str(ROOT),
        )

        async def exchange():
            async with stdio_client(server) as (read, write), ClientSession(read, write) as session:
                await session.initialize()
                answer = _result(
                    await session.call_tool(
                        "wait_for_reply",
                        {"task": sent.task, "timeout_seconds": 30},
                    )
                )
                assert answer["status"] == "received"
                message = answer["message"]
                assert message["message_id"] == sent.message_id
                assert message["taken"] and not message["seen"] and not message["handled"]
                assert message["verified"] == "agents.northwind.test/scheduler"
                thread = _result(await session.call_tool("read_thread", {"task": sent.task}))
                assert any(
                    item["message_id"] == sent.message_id and item["text"] for item in thread
                )
                [claimed] = [flags for flags, _ in _copies(sent.message_id)]
                assert TAKEN_KEYWORD in claimed and "\\Seen" not in claimed
                replied = _result(
                    await session.call_tool(
                        "reply",
                        {"message_id": sent.message_id, "text": "S24 confirmed."},
                    )
                )
                assert replied["task"] == sent.task and replied["held"] is None
                assert all(HANDLED_KEYWORD not in flags for flags, _ in _copies(sent.message_id))
                done = _result(await session.call_tool("done", {"message_id": sent.message_id}))
                assert done == {"message_id": sent.message_id, "status": "handled"}
                assert (
                    _result(await session.call_tool("done", {"message_id": sent.message_id}))
                    == done
                )

        asyncio.run(exchange())
        [finished] = [flags for flags, _ in _copies(sent.message_id)]
        assert {TAKEN_KEYWORD, HANDLED_KEYWORD} <= finished and "\\Seen" not in finished
        received = wait_for_message(
            "127.0.0.1",
            "scheduler@agents.northwind.test",
            "dev-scheduler",
            lambda message: message.get("In-Reply-To") == sent.message_id,
            port=1431,
        )
        assert received["Agent-Task"] == sent.task
        assert "S24 confirmed." in received.get_body().get_content()
        assert not compose("ps", "--status", "running", "-q", "runner-ct").stdout.strip()
        print(f"S24 MCP-only read/reply/done task={sent.task}; runner stopped")
    finally:
        compose("start", "runner-ct")
        _outpost().resume()
