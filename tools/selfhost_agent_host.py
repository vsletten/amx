"""Container-only SH-26 protocol client; never an operator/production entrypoint.

The admitted parent creates these containers and exclusively owns their lifecycle.
Only the agent's CLI-written bundle and CA enter each private host. No model runs:
AX's real attach/check_inbox/reply protocol is driven like the existing ax_stub.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

from amx.adapters.ax import AxChild, AxEndpoint
from amx.credentials import read_bundle

STATE = Path("/state")
CA = "/fixture/ca.pem"


def require_host():
    """Container fixture boundary, not a substitute for the parent's X0 admission."""
    if not Path("/.dockerenv").exists() or Path(__file__).resolve() != Path(
        "/fixture/selfhost_agent_host.py"
    ):
        raise RuntimeError("requires admitted SH-26 agent-host container")
    bundle = read_bundle(STATE / "credentials.json")
    if (
        bundle["address"] not in {"ax@agents.home.arpa", "mcp@agents.home.arpa"}
        or bundle["imap"] != "imaps://mail.home.arpa:993"
        or bundle["submission"] != "smtp://gateway.home.arpa:2587"
        or os.environ.get("AX_HOME") != "/state/ax"
        or os.environ.get("XDG_STATE_HOME") != "/state/custody"
    ):
        raise RuntimeError("unexpected SH-26 host endpoints/state")
    return bundle


def unpack(call):
    if call.isError:
        raise RuntimeError("fixture MCP tool refused")
    if call.structuredContent is not None:
        value = call.structuredContent
        return value["result"] if set(value) == {"result"} else value
    return json.loads(call.content[0].text)


async def mcp_client(request=None):
    bundle = require_host()
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    env = {
        key: os.environ[key]
        for key in ("PATH", "HOME", "TMPDIR", "XDG_STATE_HOME", "AX_HOME")
        if key in os.environ
    }
    env.update(AMX_IMAP_PASSWORD=bundle["password"], AMX_SUBMIT_TOKEN=bundle["token"])
    server = StdioServerParameters(
        command="/app/.venv/bin/amx-mcp",
        args=[
            "--agent",
            bundle["address"],
            "--imap",
            bundle["imap"],
            "--submit",
            bundle["submission"],
            "--ca",
            CA,
            "--held-folder",
            "Shared Folders/holds@home.arpa/Holds/mcp/Held",
        ],
        env=env,
    )
    # Protocol/errors can contain mail; never forward the server's stderr to CI.
    with open(os.devnull, "w") as errors:
        async with (
            stdio_client(server, errlog=errors) as (read, write),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            if request is not None:
                method = request["tool"]
                if method not in {"list_inbox", "read_thread", "reply", "done", "send"}:
                    raise ValueError("unsupported fixture tool")
                return unpack(await session.call_tool(method, request["arguments"]))
            while True:
                unpack(
                    await session.call_tool(
                        "wait_for_reply", {"task": "t_sh26_empty", "timeout_seconds": 0}
                    )
                )
                (STATE / "mcp-ready").touch()
                await asyncio.sleep(1)


def target():
    require_host()
    child = AxChild("ax", STATE / "ax", STATE / "target", "fixture-session")
    stopped = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, lambda *_: stopped.set())
    try:
        child._start(["-n", "fixture-session", "-s", "sh26", "-p", "read-only"])
        subprocess.run(
            ["ax", "external", "fixture-session", "all"],
            check=True,
            capture_output=True,
            timeout=15,
        )
        endpoint = AxEndpoint(child)
        (STATE / "target-ready").touch()
        while not stopped.wait(0.2):
            message = endpoint._call("check_inbox").get("message")
            if not message:
                continue
            # Receipt carries protocol identifiers, never text, payload or raw mail.
            with (STATE / "received.jsonl").open("a") as stream:
                stream.write(
                    json.dumps({"message_id": message.get("data", {}).get("message_id")}) + "\n"
                )
            endpoint._call(
                "reply",
                message_id=message["message_id"],
                text="Private AX fixture received.",
                data={"task_state": "working"},
                client_message_id="sh26_" + message["message_id"],
            )
    finally:
        (STATE / "target-ready").unlink(missing_ok=True)
        child.close()


def serve(mode):
    require_host()
    if mode not in {"ax", "mcp"}:
        raise ValueError("invalid host mode")
    stopped = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, lambda *_: stopped.set())
    children = []
    try:

        def start(args):
            child = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            children.append(child)
            return child

        broker = start(["ax", "serve"])
        deadline = time.monotonic() + 30
        while not (STATE / "ax/broker.sock").exists():
            if broker.poll() is not None or stopped.wait(0.1) or time.monotonic() >= deadline:
                raise RuntimeError("fixture broker not ready")
        start([sys.executable, __file__, "target" if mode == "ax" else "poll"])
        ready = STATE / ("target-ready" if mode == "ax" else "mcp-ready")
        deadline = time.monotonic() + 30
        while not ready.exists():
            if any(child.poll() is not None for child in children) or stopped.wait(0.1):
                raise RuntimeError("fixture protocol client not ready")
            if time.monotonic() >= deadline:
                raise RuntimeError("fixture protocol client timed out")
        start(
            [
                "/app/.venv/bin/amx-runner",
                "--credentials=/state/credentials.json",
                "--ca=" + CA,
                "--state=/state/runner",
                "--ax=fixture-session",
                "--ax-home=/state/ax",
                "--idle-seconds=0.2",
                "--mcp-grace=10",
                "--presence-timeout=30",
            ]
        )
        while not stopped.wait(0.2):
            if any(child.poll() is not None for child in children):
                raise RuntimeError("fixture child exited")
            if ready.exists():
                (STATE / "ready.tmp").write_text(
                    json.dumps(
                        {
                            "mode": mode,
                            "runner": children[-1].pid,
                            "broker": broker.pid,
                            "session": mode == "ax",
                            "client": children[1].pid,
                        }
                    )
                )
                (STATE / "ready.tmp").replace(STATE / "ready.json")
    finally:
        (STATE / "ready.json").unlink(missing_ok=True)
        # Stop protocol clients before their broker. Bounded within Compose's grace.
        for child in reversed(children):
            if child.poll() is None:
                child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=3)


def main():
    require_host()
    action = sys.argv[1]
    if action == "serve":
        serve(sys.argv[2])
    elif action == "target":
        target()
    elif action == "poll":
        asyncio.run(mcp_client())
    elif action == "mcp":
        print(json.dumps(asyncio.run(mcp_client(json.load(sys.stdin)))))
    else:
        raise ValueError("unknown host action")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # No exception detail: upstream errors may contain credentials/private mail.
        print("SH-26 agent-host operation failed", file=sys.stderr)
        sys.exit(1)
