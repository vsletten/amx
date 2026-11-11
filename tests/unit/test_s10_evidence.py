from __future__ import annotations

import json
from pathlib import Path

import pytest

from amx.journal import Journal
from amx.profile import build
from amx.store import Store


@pytest.fixture
def s10_evidence(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2]))
    from scenarios import test_s10_replay as scenario

    database = tmp_path / "journal.sqlite"
    store = Store(database)
    journal = Journal(tmp_path, store)
    handler_log = tmp_path / "handler.jsonl"
    events = []

    def run(reply_state):
        def request(task, message_id, **_kwargs):
            message = build(
                sender=f"scheduler+{task}@agents.northwind.test",
                to=f"intake+{task}@agents.contoso.test",
                subject="Request [keep-open]",
                intent="request",
                task=task,
                task_state="submitted",
                text="Request",
                message_id=message_id,
            )
            raw = message.as_bytes()
            entry = journal.append(raw, direction="inbound", task=task, message_id=message_id)
            store.mark_delivered("intake", message_id, "intake", entry.raw_sha256)
            reply = build(
                sender=f"intake+{task}@agents.contoso.test",
                to=f"scheduler+{task}@agents.northwind.test",
                subject="Reply",
                intent="response",
                in_reply_to=message_id,
                task=task,
                task_state=reply_state,
                text="Reply",
            )
            journal.append(reply.as_bytes(), direction="outbound", task=task, event="submission")
            store.put_task(task, "intake", "submitted")  # a row that disagrees with the reply
            handler_log.write_text(json.dumps({"message_id": message_id}) + "\n")
            return raw

        def receipt(_recipient):
            events.append("mx-duplicate")
            return "250 2.0.0 duplicate already queued"

        def retry(*_args):
            assert events == ["mx-duplicate"]
            events.append("direct-retry")
            return "250 2.0.0 duplicate already delivered"

        monkeypatch.setattr(scenario, "CT_DB", database)
        monkeypatch.setattr(scenario, "HANDLER_LOG", handler_log)
        monkeypatch.setattr(scenario, "signed_request", request)
        monkeypatch.setattr(
            scenario, "smtp_transaction", lambda *_args, **_kwargs: (250, b"queued")
        )
        monkeypatch.setattr(scenario, "wait_for_handler", lambda _message_id: None)
        monkeypatch.setattr(scenario, "wait_for_lmtp_duplicate", receipt)
        monkeypatch.setattr(scenario, "lmtp_redeliver", retry)
        scenario.test_s10_same_message_id_invokes_handler_once()

    return run, events


def test_s10_waits_for_the_mx_duplicate_before_direct_retry(s10_evidence):
    run, events = s10_evidence
    run("working")
    assert events == ["mx-duplicate", "direct-retry"]


def test_s10_rejects_a_closing_reply_even_when_the_task_row_is_open(s10_evidence):
    run, _events = s10_evidence
    with pytest.raises(AssertionError, match="intake reply must keep task working"):
        run("completed")
