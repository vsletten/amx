"""Scripted intake agent used by the M2-M4 scenarios."""

from __future__ import annotations

import json
import os
import time
from email import policy
from email.parser import BytesParser
from pathlib import Path

from amx.profile import Inbound
from amx.runtime import Context, Refuse


def handle(message: Inbound, context: Context) -> None:
    """Record invocation evidence and provide deterministic scenario replies."""
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
        "started_at": time.time(),
        "tainted": message.tainted,
        "taint_reasons": list(message.taint_reasons),
    }
    with output.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, sort_keys=True) + "\n")
    headers = BytesParser(policy=policy.default).parsebytes(message.raw, headersonly=True)
    subject = str(headers.get("Subject", ""))
    if "[slow]" in subject.casefold():
        # S04: a deliberately slow handler so the bounded queue fills and RCPT answers 450.
        time.sleep(float(os.environ.get("AMX_SLOW_SECONDS", "1.5")))
    if message.intent != "error" and "[refuse]" in subject.casefold():
        # S18k-S18m: refused on any lane, never a bounce. In process (intake-off, sync) the LMTP
        # reply is 550 and the MTA bounces; under a runner (outpost) the gateway sends the DSN
        # from a status and reason token (PLAN §5.11), and this text stays on the agent's host.
        raise Refuse("5.7.1", "intake does not take this request", reason="policy")
    if context.reply_message is None or message.intent == "error":
        return  # e.g. a receive-only agent with no submission credentials (S17's variants)
    if message.lane == "human" and "[reply]" in subject.casefold():
        # S13: answer a person; if their mail was tainted, this reply waits in Outbox/Held.
        context.reply(intent="response", text="Thanks, intake received your note.")
        return
    if message.lane != "agent":
        return
    if "[loop]" in subject.casefold():
        context.reply(intent="response", text="Loop reply from intake.", task_state="working")
    elif message.intent == "request" and "[keep-open]" in subject.casefold():
        # S10: answer without closing the task, so S10's replay tests dedupe in an open task
        # (a retry into a closed one is S09's, docs/task-transitions.md).
        context.reply(
            intent="response", text="Intake is working on the request.", task_state="working"
        )
    elif message.intent == "request":
        context.reply(
            intent="response", text="Intake completed the request.", task_state="completed"
        )
