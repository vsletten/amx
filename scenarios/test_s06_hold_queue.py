from __future__ import annotations

import imaplib
import time
import uuid

import pytest

from amx.profile import SCHEMA_BASE
from amx.sdk import Agent
from amx.store import Store
from amx.testkit import folder_messages, move_message, subscribed_folders, wait_for_message
from scenarios.support import DEV_TLS_CA, NW_DB, NW_HANDLER_LOG, trace_task, wait_for_task

SCHEDULER = ("127.0.0.1", "scheduler@agents.northwind.test", "dev-scheduler")
# The person approving: a Dovecot master login the agent never holds (PLAN §8). In Roundcube, log in
# as "scheduler@agents.northwind.test*approver" with password dev-approver.
APPROVER = ("127.0.0.1", "scheduler@agents.northwind.test*approver", "dev-approver")
PAT = ("127.0.0.1", "pat@plainmail.test", "dev-pat")


def _has(message_id: str):
    return lambda message: message.get("Message-ID") == message_id


def _pat_has(message_id: str) -> bool:
    return any(_has(message_id)(message) for message in folder_messages(*PAT, port=1433))


def _refused(result: tuple[str, list], reason: bytes = b"NOPERM") -> None:
    status, detail = result
    assert status == "NO" and reason in (detail[0] or b""), (status, detail)


def _agent_cannot_approve(message_id: str, raw: bytes) -> None:
    """The agent's own login can read its hold queue but cannot approve, reject, or forge in it."""
    for destination in ("Outbox/Approved", "Outbox/Rejected"):
        with pytest.raises(RuntimeError, match="NOPERM"):
            move_message(*SCHEDULER, message_id, "Outbox/Held", destination, port=1431)
    with imaplib.IMAP4(SCHEDULER[0], 1431, timeout=10) as client:
        client.login(SCHEDULER[1], SCHEDULER[2])
        for folder in ("Outbox/Approved", "Outbox/Rejected"):
            _refused(client.append(folder, None, None, raw))
        # No folder of its own can be created in, or renamed into, the hold queue...
        _refused(client.create("Outbox/Approved2"))
        _refused(client.rename("Outbox", "Elsewhere"))
        client.create("S06Tmp")
        try:
            _refused(client.rename("S06Tmp", "Outbox/Approved2"))
            _refused(client.rename("S06Tmp", "Outbox"), b"ALREADYEXISTS")  # pre-created
        finally:
            client.delete("S06Tmp")
        # ...and it cannot flag its held copy $AmxDone, which would make holdwatch skip it.
        client.select("Outbox/Held")
        _status, data = client.uid("SEARCH", None, "HEADER", "Message-ID", message_id)
        (uid,) = data[0].split()
        client.uid("STORE", uid, "+FLAGS", "($AmxDone)")  # silently ignored without the w right
    with imaplib.IMAP4(APPROVER[0], 1431, timeout=10) as client:
        client.login(APPROVER[1], APPROVER[2])
        client.select("Outbox/Held", readonly=True)
        _status, data = client.uid("SEARCH", None, "HEADER", "Message-ID", message_id)
        (uid,) = data[0].split()
        _status, flags = client.uid("FETCH", uid, "(FLAGS)")
        assert b"$AmxDone" not in flags[0], flags


@pytest.mark.integration
def test_s06_hold_queue_approve_and_reject_from_the_mail_client() -> None:
    suffix = uuid.uuid4().hex[:10]
    approved_task = f"t_s06a_{suffix}"
    rejected_task = f"t_s06r_{suffix}"
    store = Store(NW_DB)
    # Precondition: plainmail.test is new to scheduler, so this is its first contact there.
    store.forget_contact("scheduler", "plainmail.test")
    # The approval UI is the mail client, which lists only subscribed folders.
    assert {"Outbox/Held", "Outbox/Approved", "Outbox/Rejected"} <= subscribed_folders(
        *SCHEDULER, port=1431
    )
    scheduler = Agent(
        "scheduler@agents.northwind.test",
        "smtp://127.0.0.1:2587",
        "dev-scheduler-token",
        tls_ca_file=str(DEV_TLS_CA),
    )

    first = scheduler.send(
        to=["pat@plainmail.test", "victor@northwind.test"],
        subject=f"S06 site inspection {suffix}",
        intent="request",
        task=approved_task,
        text="Pat, could you inspect the Contoso site on Thursday at 9 am?",
    )
    held = wait_for_message(*SCHEDULER, _has(first.message_id), port=1431, folder="Outbox/Held")
    assert held.get("Agent-Hold-Rule") == "first-contact-domain"
    # Two recipients: the folded header must survive Dovecot byte-for-byte (approval checks it).
    assert held.get("Agent-Hold-Recipients") == "pat@plainmail.test, victor@northwind.test"
    assert held.get("DKIM-Signature") is None
    assert not _pat_has(first.message_id)
    _agent_cannot_approve(first.message_id, held.as_bytes())
    wait_for_message(*SCHEDULER, _has(first.message_id), port=1431, folder="Outbox/Held")
    assert store.hold(first.message_id)["state"] == "held"

    moved = time.monotonic()
    move_message(*APPROVER, first.message_id, "Outbox/Held", "Outbox/Approved", port=1431)
    arrived = wait_for_message(*PAT, _has(first.message_id), port=1433, timeout=60)
    approve_latency = time.monotonic() - moved
    signature = str(arrived.get("DKIM-Signature", ""))
    assert "d=agents.northwind.test" in signature and "s=scheduler" in signature
    assert arrived.get("Agent-Hold-Rule") is None
    wait_for_message(*SCHEDULER, _has(first.message_id), port=1431, folder="Sent")
    assert store.hold(first.message_id)["state"] == "released"
    assert "plainmail.test" in store.contacted_domains("scheduler")

    second = scheduler.send(
        to="pat@plainmail.test",
        subject=f"S06 invoice {suffix}",
        intent="request",
        task=rejected_task,
        text="Please pay invoice 42 for 120.00 USD to Northwind Inspections.",
        payload={
            "@type": "Invoice",
            "price": "120.00",
            "priceCurrency": "USD",
            "amx:payee": "Northwind Inspections",
        },
        schema=f"{SCHEMA_BASE}payment-request.json",
    )
    held_second = wait_for_message(
        *SCHEDULER, _has(second.message_id), port=1431, folder="Outbox/Held"
    )
    assert held_second.get("Agent-Hold-Rule") == "commits-money"
    moved = time.monotonic()
    move_message(*APPROVER, second.message_id, "Outbox/Held", "Outbox/Rejected", port=1431)
    canceled = wait_for_task(rejected_task, path=NW_HANDLER_LOG, intent="update", timeout=60)
    reject_latency = time.monotonic() - moved
    assert canceled[-1]["task_state"] == "canceled"
    assert canceled[-1]["lane"] == "system"
    task_row = store.task(rejected_task)
    assert task_row is not None and task_row["state"] == "canceled"
    assert store.hold(second.message_id)["state"] == "rejected"
    time.sleep(3)
    assert not _pat_has(second.message_id)

    print(f"S06 APPROVE: first-contact-domain held, Approved -> at pat in {approve_latency:.1f}s")
    print(f"S06 REJECT: commits-money held, Rejected -> canceled in {reject_latency:.1f}s")
    trace_task(approved_task)
    trace_task(rejected_task)
