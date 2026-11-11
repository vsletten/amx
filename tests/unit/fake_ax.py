"""Scripted ax attach child. Test configuration lives in FAKE_AX_CONFIG."""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path

CONFIG = Path(os.environ["FAKE_AX_CONFIG"])
WRITE = threading.Lock()
RELAY = "--relay" in sys.argv


def config():
    return json.loads(CONFIG.read_text())


def record(value):
    if path := config().get("log"):
        with WRITE, Path(path).open("a") as file:
            file.write(json.dumps(value) + "\n")


def emit(packet):
    with WRITE:
        print(json.dumps({"jsonrpc": "2.0", **packet}), flush=True)


record({"argv": sys.argv[1:], "home": os.environ["AX_HOME"]})
if RELAY and config().get("contract") == "interim":
    print("ax: flag provided but not defined: -relay", file=sys.stderr)
    sys.exit(1)
if failure := config().get("startup_error"):
    print(f"ax: {failure}", file=sys.stderr)
    sys.exit(1)


def agents():
    return config().get("agents", [])


def notify_changes():
    last = None
    while True:
        try:
            current = agents()
            if current != last:
                emit({"method": "notifications/ax/agents", "params": {"agents": current}})
                last = current
        except (ValueError, OSError):
            pass  # config is being rewritten
        time.sleep(0.01)


if RELAY:
    threading.Thread(target=notify_changes, daemon=True).start()


def answer(packet):
    cfg = config()
    method = packet["method"]
    if cfg.get("interleave"):
        emit(
            {
                "method": "notifications/ax/message",
                "params": {
                    "content": cfg.get("notification_text", "{}"),
                    "meta": {"kind": "message"},
                },
            }
        )
    if method == "initialize":
        result = {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "fake-ax", "version": "test"},
        }
    elif method == "tools/list":
        props = {"target": {}, "text": {}}
        if cfg.get("contract") == "v1":
            props["data"] = {}
            if RELAY and not cfg.get("broken_schema"):
                props["provenance"] = {}
        result = {"tools": [{"name": "send_message", "inputSchema": {"properties": props}}]}
    elif method == "tools/call":
        name, args = packet["params"]["name"], packet["params"]["arguments"]
        if name == cfg.get("eof_tool"):
            os._exit(1)
        if name == cfg.get("timeout_tool"):
            return
        if name == cfg.get("delay_tool"):
            time.sleep(0.15)
        if name == cfg.get("rpc_error_tool"):
            emit({"id": packet["id"], "error": {"code": -32000, "message": "broker paused"}})
            return
        value = (
            {"agents": agents(), "ax_home": os.environ["AX_HOME"], "scope": "Same-user AX_HOME"}
            if name == "list_agents"
            else {"tool": name, "arguments": args}
        )
        if name == cfg.get("error_tool"):
            value = {
                "code": "external_policy",
                "rpc_code": -32002,
                "target": "live",
                "submission": "not_submitted",
                "reason": "external policy refuse",
            }
        result = {
            "content": [{"type": "text", "text": json.dumps(value)}],
            "isError": name == cfg.get("error_tool"),
        }
        if name == cfg.get("bad_tool"):
            result = cfg["bad_result"]
    else:
        result = {}
    emit({"id": packet["id"], "result": result})


for line in sys.stdin:
    packet = json.loads(line)
    record(packet)
    if "id" in packet:
        threading.Thread(target=answer, args=(packet,), daemon=True).start()
