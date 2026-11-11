from __future__ import annotations

import uuid

import pytest

from amx.sdk import Agent
from amx.store import Store
from amx.testkit import wait_for_message
from scenarios.support import (
    CT_DB,
    DEV_TLS_CA,
    NW_HANDLER_LOG,
    mta_ct,
    mta_line_for_ct,
    trace_task,
    wait_for_handler,
    wait_for_task,
)


@pytest.mark.integration
def test_s01_full_round_trip_with_victor_cc() -> None:
    suffix = uuid.uuid4().hex[:10]
    task = f"t_s01_{suffix}"
    message_id = f"<s01-{suffix}@agents.northwind.test>"
    scheduler = Agent(
        "scheduler@agents.northwind.test",
        "smtp://127.0.0.1:2587",
        "dev-scheduler-token",
        tls_ca_file=str(DEV_TLS_CA),
    )
    sent = scheduler.send(
        to="intake@agents.contoso.test",
        cc="victor@northwind.test",
        subject=f"S01 round trip {suffix}",
        intent="request",
        task=task,
        text="Please process this round-trip request.",
    )
    message_id = sent.message_id
    matches = wait_for_handler(message_id)
    assert len(matches) == 1
    assert matches[0]["task"] == task

    delivered = wait_for_message(
        "127.0.0.1",
        "intake@agents.contoso.test",
        "dev-intake",
        lambda message: message.get("Message-ID") == message_id,
        port=1432,
    )
    assert delivered.get("Agent-Lane") == "agent"
    assert delivered.get("Agent-Trust") == "verified"
    victor_copy = wait_for_message(
        "127.0.0.1",
        "victor@northwind.test",
        "dev-victor",
        lambda message: message.get("Message-ID") == message_id,
        port=1431,
    )
    assert victor_copy.get("Cc") == "victor@northwind.test"
    responses = wait_for_task(task, path=NW_HANDLER_LOG, intent="response")
    assert len(responses) == 1

    store = Store(CT_DB)
    task_row = store.task(task)
    assert task_row is not None
    # intake's reply closed the task, and delivering the request no longer reopens it (#21).
    assert task_row["state"] == "completed"
    rows = store.rows("SELECT * FROM journal WHERE message_id = ?", (message_id,))
    assert len(rows) == 1
    trace = trace_task(task)
    assert "milter" in trace
    assert "lmtp" in trace
    assert "postfix" in trace
    assert mta_line_for_ct(trace) == mta_ct()  # contoso's own MTA handed it to the gateway
    print(
        f"S01 ROUNDTRIP: task={task} handler=intake->scheduler "
        f"journal=#{rows[0]['sequence']} sha256={str(rows[0]['raw_sha256'])[:12]}"
    )
