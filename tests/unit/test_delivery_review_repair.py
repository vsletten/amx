"""Targeted PR7 regressions: delivery ownership, admission, and evidence drift."""

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from test_lmtp import FailOnceMailbox, _deliver, _handler, _queued_handler
from test_task_assignment import human

from amx.runtime import TryLater


@pytest.mark.parametrize("failure", [None, TryLater("busy"), RuntimeError("crash")])
def test_overlapping_sync_delivery_runs_once_and_releases_after_failure(tmp_path, failure):
    entered = threading.Event()
    release = threading.Event()
    seen = []

    def handle(message, context):
        seen.append(message.task)
        if len(seen) == 1:
            entered.set()
            assert release.wait(5)
            if failure is not None:
                raise failure

    handler, store, calls, mailbox = _handler(tmp_path, intake_handler=handle)
    recipient = "intake@agents.example.test"
    with ThreadPoolExecutor(max_workers=3) as pool:
        first = pool.submit(_deliver, handler, human(), [recipient])
        try:
            assert entered.wait(5)
            overlap = pool.submit(_deliver, handler, human(), [recipient]).result(timeout=2)
            assert overlap.values == ("450 4.3.0 delivery already running, retry",)
            # The same Message-ID at another agent is independent, even while intake runs.
            other = pool.submit(_deliver, handler, human(), ["echo@agents.example.test"]).result(
                timeout=2
            )
            assert other.values[0].startswith("250")
            assert len(seen) == 1
            assert len(calls) == 1
        finally:
            release.set()
        assert first.result(timeout=5).values[0].startswith("450" if failure else "250")
    retry = _deliver(handler, human(), [recipient])
    assert retry.values[0].startswith("250")
    assert len(seen) == (2 if failure else 1)
    assert len(set(seen)) == 1
    assert mailbox.addresses.count(recipient) == 1
    assert store.delivered(recipient, "<first@plainmail.test>")


def test_full_queue_refuses_before_allocating_person_correlation(tmp_path):
    release = threading.Event()
    handler, store, _, _, registry = _queued_handler(
        tmp_path, intake_handler=lambda message, context: release.wait(5), watermark=1
    )
    recipient = "intake@agents.example.test"
    try:
        first = human().replace(b"<first@plainmail.test>", b"<occupant@plainmail.test>")
        assert _deliver(handler, first, [recipient]).values[0].startswith("250")
        before = store.rows("SELECT * FROM task_assignments")
        assert len(before) == 1
        assert _deliver(handler, human(), [recipient]).values == ("450 4.2.1 agent busy, retry",)
        assert [tuple(row) for row in store.rows("SELECT * FROM task_assignments")] == [
            tuple(row) for row in before
        ]
        assert store.delivery_progress(recipient, "<first@plainmail.test>") is None
        assert len(store.rows("SELECT * FROM journal")) == 1
        release.set()
        registry.join("intake")
        assert _deliver(handler, human(), [recipient]).values[0].startswith("250")
        registry.join("intake")
    finally:
        release.set()
        registry.join("intake")
        registry.stop()


@pytest.mark.parametrize("opens", [False, True])
@pytest.mark.parametrize("drift", ["grant", "transport", "body"])
def test_pending_retry_refuses_changed_evidence_without_replaying_old_bytes(tmp_path, opens, drift):
    seen = []
    handler, store, _, _ = _handler(
        tmp_path,
        mailbox=FailOnceMailbox(),
        intake_handler=lambda message, context: seen.append(message),
    )
    recipient = "intake@agents.example.test"
    original = human(opens=opens)
    assert _deliver(handler, original, [recipient]).values[0].startswith("450")
    progress = store.delivery_progress(recipient, "<first@plainmail.test>")
    assert progress is not None
    if drift == "grant":
        changed = human(opens=not opens)
    elif drift == "transport":
        changed = b"Received: by different-mta.example.test\r\n" + original
    else:
        changed = original.replace(b"Hello", b"Different content")
    assert _deliver(handler, changed, [recipient]).values == (
        "550 5.6.0 Message-ID replay does not match the original delivery",
    )
    assert len(seen) == 1
    after = store.delivery_progress(recipient, "<first@plainmail.test>")
    assert after is not None and after["raw_sha256"] == progress["raw_sha256"]
    # Unchanged evidence still resumes the checkpoint without rerunning the handler.
    assert _deliver(handler, original, [recipient]).values[0].startswith("250")
    assert len(seen) == 1
