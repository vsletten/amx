from __future__ import annotations

import smtplib
import time
import uuid

import pytest

from amx.journal import Journal
from amx.profile import parse
from amx.store import Store
from amx.testkit import read_jsonl, smtp_transaction
from scenarios.support import (
    CT_DB,
    HANDLER_LOG,
    compose_exec,
    signed_request,
    wait_for_handler,
    wait_for_lmtp_duplicate,
)


@pytest.mark.integration
def test_s09_closed_task_rejected_at_rcpt() -> None:
    task = f"t_s09_{uuid.uuid4().hex[:10]}"
    setup = (
        "from amx.store import Store; "
        f"Store('/data/journal.sqlite').put_task('{task}','intake','completed')"
    )
    compose_exec("gateway-ct", "/app/.venv/bin/python", "-c", setup)
    with smtplib.SMTP("127.0.0.1", 2526, timeout=10) as client:
        assert client.mail(f"scheduler+{task}@agents.northwind.test")[0] == 250
        code, response = client.rcpt(f"intake+{task}@agents.contoso.test")
    assert code == 550
    assert b"5.1.6" in response
    assert b"task is closed" in response
    print(f"S09 REJECT {code}: {response.decode()}")

    bypass_token = f"t_s09_bypass_{uuid.uuid4().hex[:10]}"
    message_id = f"<s09-bypass-{uuid.uuid4().hex[:10]}@agents.northwind.test>"
    raw = signed_request(
        task,
        message_id,
        recipient=f"intake+{bypass_token}@agents.contoso.test",
    )
    code, response = smtp_transaction(
        "127.0.0.1",
        f"scheduler+{task}@agents.northwind.test",
        f"intake+{bypass_token}@agents.contoso.test",
        raw,
        port=2526,
    )
    assert code == 550
    assert b"Agent-Task must match" in response
    store = Store(CT_DB)
    closed_row = store.task(task)
    assert closed_row is not None
    assert closed_row["state"] == "completed"
    assert store.task(bypass_token) is None
    print(f"S09 BYPASS REJECT {code}: closed task remained completed")


@pytest.mark.integration
def test_s09_a_closed_task_refuses_new_mail_and_acknowledges_a_retry() -> None:
    """#21 on either MTA (docs/task-transitions.md): intake's own `completed` reply closes the
    task and it stays closed; the sender's retry of the delivered request is acknowledged as a
    duplicate; new mail to the task is refused at end of DATA."""
    suffix = uuid.uuid4().hex[:10]
    task = f"t_s09r_{suffix}"
    sender = f"scheduler+{task}@agents.northwind.test"
    recipient = f"intake+{task}@agents.contoso.test"
    message_id = f"<s09r-{suffix}@agents.northwind.test>"
    raw = signed_request(task, message_id)
    code, response = smtp_transaction("127.0.0.1", sender, recipient, raw, port=2526)
    assert code == 250, (code, response)
    wait_for_handler(message_id)

    # intake is queued: its reply is submitted inside the handler, before delivery completes.
    store = Store(CT_DB)
    deadline = time.monotonic() + 15
    while not store.delivered(recipient, message_id) and time.monotonic() < deadline:
        time.sleep(0.25)
    assert store.delivered(recipient, message_id)
    replies = store.rows("SELECT * FROM journal WHERE task = ? AND event = 'submission'", (task,))
    assert len(replies) == 1
    reply_raw = Journal(CT_DB.parent, store).raw_path(str(replies[0]["raw_sha256"])).read_bytes()
    assert parse(reply_raw).task_state == "completed"
    closed = store.task(task)
    assert closed is not None and closed["state"] == "completed", "LMTP no longer reopens it"

    # The sender's MTA lost the DATA reply and sends the same message again, through the MX.
    code, response = smtp_transaction("127.0.0.1", sender, recipient, raw, port=2526)
    assert code == 250, (code, response)
    receipt = wait_for_lmtp_duplicate(recipient)
    assert "duplicate already delivered" in receipt

    # New mail to the closed task: the recipient has accepted mail, so RCPT waits for the
    # Message-ID, and end of DATA refuses it.
    fresh_id = f"<s09n-{suffix}@agents.northwind.test>"
    with smtplib.SMTP("127.0.0.1", 2526, timeout=15) as client:
        assert client.mail(sender)[0] == 250
        assert client.rcpt(recipient)[0] == 250
        code, response = client.data(signed_request(task, fresh_id))
    assert code == 550, (code, response)
    assert b"5.1.6" in response
    assert b"task is closed" in response

    handled = [row["message_id"] for row in read_jsonl(HANDLER_LOG) if row["task"] == task]
    assert handled == [message_id], "the retry did not run the handler; the new mail never got in"
    assert (
        len(store.rows("SELECT * FROM journal WHERE task = ? AND event = 'submission'", (task,)))
        == 1
    )
    assert len(store.rows("SELECT * FROM journal WHERE message_id = ?", (message_id,))) == 1
    assert store.rows("SELECT * FROM journal WHERE message_id = ?", (fresh_id,)) == []
    assert store.task(task)["state"] == "completed"
    decided = store.rows(
        "SELECT stage, rule FROM policy_events WHERE task = ? AND stage = 'rcpt' ORDER BY sequence",
        (task,),
    )
    assert [row["rule"] for row in decided] == [
        "recipient-ok",
        "closed-task-at-eod",
        "closed-task-at-eod",
    ], "each RCPT decided once, on either MTA"
    ends = store.rows(
        "SELECT rule FROM policy_events WHERE task = ? AND stage = 'eod' ORDER BY sequence", (task,)
    )
    assert len(ends) == 3 and ends[-1]["rule"] == "closed-task"
    print(f"S09 RETRY: {receipt}")
    print(f"S09 NEW MAIL {code}: {response.decode()}")
