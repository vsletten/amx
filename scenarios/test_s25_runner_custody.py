"""S25: native same-user runner/MCP custody, then attach the pinned AX endpoint.

Mail transports come from the suite-owned stack; the runner, broker and MCP child
are native processes sharing only this test's private HOME/state. No model runs.
"""

from __future__ import annotations

import asyncio
import subprocess
import sys
import tempfile
from contextlib import ExitStack
from pathlib import Path

import pytest

from amx.mailbox import HANDLED_KEYWORD, TAKEN_KEYWORD
from amx.testkit import read_jsonl, wait_for_message
from scenarios.support import DEV_TLS_CA, ROOT, compose, ct_hold_folder
from scenarios.test_s11_mcp_server import _result
from scenarios.test_s18_control import _outpost
from scenarios.test_s18_remote_agent import OUTPOST, _copies, _scheduler, _wait

pytestmark = pytest.mark.integration


def test_s25_native_mcp_then_ax():
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    compose("stop", "runner-ct")
    try:
        with tempfile.TemporaryDirectory(prefix="s25-") as directory, ExitStack() as cleanup:
            root = Path(directory)
            home = root / "home"
            home.mkdir(mode=0o700)
            binary = root / "ax"
            # Exactly the suite's pinned build; never an installed user's broker.
            compose("cp", "runner-ct:/usr/local/bin/ax", str(binary))
            binary.chmod(0o700)
            env = {
                "PATH": f"{root}:/usr/local/bin:/usr/bin:/bin",
                "HOME": str(home),
                "TMPDIR": str(root),
                "XDG_STATE_HOME": str(root / "state"),
                "AX_HOME": str(root / "ax-home"),
                "AMX_IMAP_PASSWORD": "dev-outpost",
                "AMX_SUBMIT_TOKEN": "dev-outpost-token",
                "OMP_NUM_THREADS": "8",
                "OPENBLAS_NUM_THREADS": "8",
            }
            args = [
                "--agent",
                OUTPOST[1],
                "--imap",
                "127.0.0.1:1432",
                "--submit",
                "smtp://127.0.0.1:2588",
                "--ca",
                str(DEV_TLS_CA),
            ]
            with (root / "children.log").open("w") as log:

                def start(command):
                    child = subprocess.Popen(
                        command, env=env, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT
                    )
                    cleanup.callback(stop, child)
                    return child

                def stop(child):
                    if child.poll() is None:
                        child.terminate()
                    try:
                        child.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=5)

                start([str(binary), "serve"])
                _wait(lambda: (root / "ax-home/broker.sock").exists(), 10, "S25 broker missing")
                runner = start(
                    [
                        sys.executable,
                        "-m",
                        "amx.runner",
                        *args,
                        "--ax",
                        "outpost-live",
                        "--ax-binary",
                        str(binary),
                        "--ax-home",
                        env["AX_HOME"],
                        "--state",
                        str(root / "runner"),
                        "--idle-seconds",
                        "0.2",
                        "--mcp-grace",
                        "1",
                        "--presence-timeout",
                        "2",
                    ]
                )
                _outpost().resume()
                server = StdioServerParameters(
                    command=sys.executable,
                    args=[
                        "-m",
                        "amx.mcp_server",
                        *args,
                        "--held-folder",
                        ct_hold_folder("outpost", "Held"),
                    ],
                    env=env,
                    cwd=str(ROOT),
                )

                async def exchange():
                    async with (
                        stdio_client(server) as (read, write),
                        ClientSession(read, write) as mcp,
                    ):
                        await mcp.initialize()
                        # Poll an empty task for longer than presence_timeout. A new
                        # SMTP request must still be admitted, not paused offline.
                        for _ in range(6):
                            await mcp.call_tool(
                                "wait_for_reply", {"task": "t_s25_empty", "timeout_seconds": 0}
                            )
                            await asyncio.sleep(0.5)
                        first = _scheduler().send(
                            to=OUTPOST[1],
                            intent="request",
                            subject="S25 MCP",
                            text="Please confirm the native MCP path.",
                        )
                        answer = _result(
                            await mcp.call_tool(
                                "wait_for_reply", {"task": first.task, "timeout_seconds": 30}
                            )
                        )
                        assert answer["status"] == "received" and answer["message"]["taken"]
                        assert not answer["message"]["seen"]
                        # Attach while MCP holds its copy: it must still finish it.
                        start(
                            [
                                sys.executable,
                                "-m",
                                "amx.examples.ax_stub",
                                "--binary",
                                str(binary),
                                "--home",
                                env["AX_HOME"],
                                "--receive",
                                "--log",
                                str(root / "ax.jsonl"),
                                "--ready-file",
                                str(root / "ready"),
                            ]
                        )
                        _wait(lambda: (root / "ready").exists(), 15, "S25 AX target missing")
                        await asyncio.sleep(2)
                        assert TAKEN_KEYWORD in _copies(first.message_id)[0][0]
                        await mcp.call_tool(
                            "reply",
                            {"message_id": first.message_id, "text": "S25 native MCP confirmed."},
                        )
                        done = _result(
                            await mcp.call_tool("done", {"message_id": first.message_id})
                        )
                        assert done["status"] == "handled"
                        second = _scheduler().send(
                            to=OUTPOST[1],
                            intent="request",
                            subject="S25 AX",
                            text="Please confirm the native AX path.",
                        )
                        _wait(
                            lambda: any(
                                HANDLED_KEYWORD in flags for flags, _ in _copies(second.message_id)
                            ),
                            30,
                            "S25 AX did not finish",
                        )
                        rows = read_jsonl(root / "ax.jsonl")
                        ids = [row.get("data", {}).get("message_id") for row in rows]
                        assert first.message_id not in ids and ids.count(second.message_id) == 1
                        flags = _copies(second.message_id)[0][0]
                        assert {"\\Seen", HANDLED_KEYWORD} <= flags and TAKEN_KEYWORD not in flags
                        assert _copies(first.message_id)[0][0] >= {TAKEN_KEYWORD, HANDLED_KEYWORD}
                        for sent in (first, second):
                            reply = wait_for_message(
                                "127.0.0.1",
                                "scheduler@agents.northwind.test",
                                "dev-scheduler",
                                lambda m, message_id=sent.message_id: (
                                    m.get("In-Reply-To") == message_id
                                ),
                                port=1431,
                            )
                            assert reply["Agent-Task"] == sent.task
                        assert runner.poll() is None
                        print(f"S25 native MCP={first.task} AX={second.task}; no duplicate custody")

                asyncio.run(exchange())
    finally:
        compose("start", "runner-ct")
        _outpost().resume()
