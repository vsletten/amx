"""Mailbox-backed echo example for ingress demonstrations."""

from __future__ import annotations

import json
import os
from email import policy
from email.parser import BytesParser
from pathlib import Path

from amx.profile import Inbound
from amx.runtime import Context


def handle(message: Inbound, context: Context) -> None:
    """Record scheduler delivery and loop only for the deliberate S07 marker."""
    context.metadata["echo"] = message.text
    output = Path(os.environ.get("AMX_HANDLER_LOG", "/data/handler.jsonl"))
    output.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "agent": context.agent,
        "intent": message.intent,
        "message_id": message.thread.message_id,
        "task": message.task,
        "task_state": message.task_state,
        "diagnostic": message.diagnostic,
        "lane": message.lane,
        "text": message.text.strip(),
        "tainted": message.tainted,
    }
    with output.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, sort_keys=True) + "\n")
    headers = BytesParser(policy=policy.default).parsebytes(message.raw, headersonly=True)
    subject = str(headers.get("Subject", ""))
    if message.lane == "agent" and message.intent != "error" and "[loop]" in subject.casefold():
        context.reply(intent="response", text="Loop reply from scheduler.", task_state="working")
