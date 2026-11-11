from __future__ import annotations

import time
import uuid

import pytest

from amx.journal import Journal
from amx.profile import parse
from amx.store import Store
from amx.tasks import TERMINAL_STATES
from amx.testkit import read_jsonl, smtp_transaction
from scenarios.support import (
    CT_DB,
    HANDLER_LOG,
    lmtp_redeliver,
    signed_request,
    wait_for_handler,
    wait_for_lmtp_duplicate,
)


@pytest.mark.integration
def test_s10_same_message_id_invokes_handler_once() -> None:
    suffix = uuid.uuid4().hex[:10]
    task = f"t_s10_{suffix}"
    message_id = f"<s10-{suffix}@agents.northwind.test>"
    sender = f"scheduler+{task}@agents.northwind.test"
    recipient = f"intake+{task}@agents.contoso.test"
    # "[keep-open]": intake answers `working`, not `completed`, so this is dedupe in an open task.
    # A retry into a task the reply closed is S09's (docs/task-transitions.md).
    raw = signed_request(task, message_id, subject=f"AMX scenario {task} [keep-open]")

    # A replayed raw send: the same signed message through contoso's MX twice.
    for _attempt in range(2):
        code, response = smtp_transaction("127.0.0.1", sender, recipient, raw, port=2526)
        assert code == 250, (code, response)

    wait_for_handler(message_id)
    store = Store(CT_DB)
    # intake runs in queued mode (M4): LMTP 250 means "queued", so completion is observed rather
    # than assumed before counting handler calls, journal rows, and deliveries.
    deadline = time.monotonic() + 15
    deliveries = []
    while not deliveries and time.monotonic() < deadline:
        deliveries = store.rows("SELECT * FROM deliveries WHERE message_id = ?", (message_id,))
        time.sleep(0.25)
    assert len(deliveries) == 1

    # Both MX submissions must have reached LMTP before counting effects. SMTP 250 alone
    # only means the MTA queued a copy; the direct retry below cannot drain that queue.
    replay_receipt = wait_for_lmtp_duplicate(recipient)

    # A forced LMTP retry: the journaled bytes again, straight to the gateway's LMTP, as an MTA
    # that lost the first 250 would send them. It passes no RCPT policy, so the task's state
    # cannot decide it, and its reply is synchronous: the duplicate is known to be answered
    # before anything is counted.
    journal = store.rows("SELECT * FROM journal WHERE message_id = ?", (message_id,))
    assert len(journal) == 1
    retry = lmtp_redeliver(str(journal[0]["raw_sha256"]), sender, recipient)
    assert retry.startswith("250 2.0.0 duplicate already delivered"), retry

    matches = [row for row in read_jsonl(HANDLER_LOG) if row["message_id"] == message_id]
    assert len(matches) == 1
    assert len(store.rows("SELECT * FROM journal WHERE message_id = ?", (message_id,))) == 1
    assert len(store.rows("SELECT * FROM deliveries WHERE message_id = ?", (message_id,))) == 1
    replies = store.rows("SELECT * FROM journal WHERE task = ? AND event = 'submission'", (task,))
    assert len(replies) == 1  # the handler's side effect, its reply, happened once
    reply_raw = Journal(CT_DB.parent, store).raw_path(str(replies[0]["raw_sha256"])).read_bytes()
    # The reply's own bytes, not the task row, say what intake emitted.
    assert parse(reply_raw).task_state == "working", "intake reply must keep task working"
    task_row = store.task(task)
    assert task_row is not None and task_row["state"] not in TERMINAL_STATES
    print(
        f"S10 DEDUPE: {message_id} sends=2 lmtp_retry='{retry}' handler_calls=1 "
        f"journal_rows=1 deliveries=1 replies=1 task_state={task_row['state']}"
    )
    print(f"S10 MX REPLAY: {replay_receipt}")
