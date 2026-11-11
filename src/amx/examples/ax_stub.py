"""Manual attached AX endpoint for transport scenarios; no model is invoked."""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import threading
from pathlib import Path

from amx.adapters.ax import AxChild, AxEndpoint


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", default="outpost-live")
    parser.add_argument("--binary", default="ax")
    parser.add_argument("--home", type=Path, default=Path(os.environ.get("AX_HOME", "/state/ax")))
    parser.add_argument("--log", type=Path, default=Path("/state/ax-stub.jsonl"))
    parser.add_argument("--external", choices=("verified", "all", "refuse"), default="verified")
    parser.add_argument("--receive", action="store_true", help="consume mail; otherwise stay idle")
    parser.add_argument("--ready-file", type=Path)
    args = parser.parse_args()
    child = AxChild(args.binary, args.home, args.home / "stub-state", args.name)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    try:
        child._start(["-n", args.name, "-s", f"stub_{args.name}", "-p", "read-only"])
        # Owner control through the CLI, deliberately outside model tools.
        subprocess.run(
            [args.binary, "external", args.name, args.external],
            env={**os.environ, "AX_HOME": str(args.home)},
            check=True,
            capture_output=True,
        )
        endpoint = AxEndpoint(child)
        args.log.parent.mkdir(parents=True, exist_ok=True)
        if args.ready_file:
            args.ready_file.write_text(str(os.getpid()))
        while not stop.wait(0.5):
            if not args.receive:
                continue
            result = endpoint._call("check_inbox")
            message = result.get("message")
            if not message:
                continue
            with args.log.open("a") as stream:
                stream.write(json.dumps(message) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            if "[ack-only]" in message["text"]:
                endpoint.ack_message(message["message_id"])
            else:
                endpoint._call(
                    "reply",
                    message_id=message["message_id"],
                    text="AX stub: received.",
                    data={"task_state": "working"},
                    client_message_id="stub_" + message["message_id"],
                )
    finally:
        if args.ready_file:
            args.ready_file.unlink(missing_ok=True)
        child.close()


if __name__ == "__main__":
    main()
