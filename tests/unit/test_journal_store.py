from __future__ import annotations

from amx.journal import Journal
from amx.store import Store


def test_journal_content_addressing_and_hash_chain_detect_tamper(tmp_path) -> None:
    store = Store(tmp_path / "journal.sqlite")
    journal = Journal(tmp_path, store)
    first = journal.append(
        b"Message-ID: <one@test>\r\n\r\none\r\n",
        direction="inbound",
        task="t_one",
        message_id="<one@test>",
    )
    second = journal.append(
        b"Message-ID: <two@test>\r\n\r\ntwo\r\n",
        direction="inbound",
        task="t_two",
        message_id="<two@test>",
    )

    assert second.prev_sha256 == first.entry_sha256
    assert journal.verify().valid
    first.raw_path.write_bytes(first.raw_path.read_bytes().replace(b"one", b"ONE", 1))
    verification = journal.verify()
    assert not verification.valid
    assert verification.error == "entry 1: raw content hash mismatch"


def test_store_tracks_closed_tasks_and_successful_delivery_once(tmp_path) -> None:
    store = Store(tmp_path / "store.sqlite")
    store.put_task("t_done", "intake", "completed")
    store.put_task("t_open", "intake", "working")
    assert store.closed_tasks() == frozenset({("intake", "t_done")})
    assert store.mark_delivered("intake+t_one@agents.test", "<once@test>", "intake", "abc")
    assert not store.mark_delivered("intake+t_one@agents.test", "<once@test>", "intake", "abc")
    assert store.mark_delivered("echo+t_one@agents.test", "<once@test>", "echo", "abc")
    assert store.delivered("intake+t_one@agents.test", "<once@test>")
    assert store.delivered("echo+t_one@agents.test", "<once@test>")


def test_a_closed_task_never_reopens_and_a_later_outcome_replaces_it(tmp_path) -> None:
    """docs/task-transitions.md T2 and T3, for every writer (put_task)."""
    store = Store(tmp_path / "store.sqlite")
    assert store.put_task("t_1", "intake", "submitted")
    assert store.put_task("t_1", "intake", "completed")
    for reopening in ("submitted", "working", "input-required"):
        assert not store.put_task("t_1", "intake", reopening)
        assert store.task("t_1")["state"] == "completed"
    assert store.put_task("t_1", "intake", "canceled"), "a rejected hold cancels a completed task"
    assert store.put_task("t_1", "intake", "failed"), "a bounce fails it"
    assert store.task("t_1")["revision"] == 3, "one per write that happened"
    assert store.closed_tasks() == frozenset({("intake", "t_1")})


def test_a_delivered_state_is_recorded_only_if_the_task_did_not_change_meanwhile(tmp_path) -> None:
    """T1: LMTP read ``revision`` before the handler ran; a write since then stands."""
    store = Store(tmp_path / "store.sqlite")
    assert store.put_task_unless_changed("t_new", "intake", "submitted", None)
    assert not store.put_task_unless_changed("t_new", "intake", "working", None), "now exists"
    assert store.task("t_new")["state"] == "submitted"

    store.put_task("t_1", "intake", "submitted")
    before = int(store.task("t_1")["revision"])
    store.put_task("t_1", "intake", "working")  # the handler's reply
    assert not store.put_task_unless_changed("t_1", "intake", "submitted", before)
    assert store.task("t_1")["state"] == "working"
    now = int(store.task("t_1")["revision"])
    assert store.put_task_unless_changed("t_1", "intake", "input-required", now)
    assert store.task("t_1")["state"] == "input-required"

    store.put_task("t_2", "intake", "completed")
    closed = int(store.task("t_2")["revision"])
    assert not store.put_task_unless_changed("t_2", "intake", "submitted", closed), "T2"
    assert store.put_task_unless_changed("t_2", "intake", "failed", closed), "T3: a DSN"
    assert store.task("t_2")["state"] == "failed"


def test_accepted_deliveries_are_what_a_retry_could_repeat(tmp_path) -> None:
    """D1-D3: handled, completed, or queued (250 queued); never refused or merely deferred."""
    journal = Journal(tmp_path, Store(tmp_path / "journal.sqlite"))
    store = journal.store
    recipient = "intake+t_1@agents.test"

    def journaled(message_id: str) -> None:
        journal.append_delivery(
            f"Message-ID: {message_id}\r\n\r\nbody\r\n".encode(),
            recipient=recipient,
            agent="intake",
            identity=None,
            task="t_1",
            message_id=message_id,
        )

    assert not store.accepted_delivery(recipient)
    journaled("<deferred@test>")  # a sync handler said TryLater: LMTP answered 450
    journaled("<refused@test>")
    store.mark_delivery_refused(recipient, "<refused@test>", "550 5.7.1 no")
    assert not store.accepted_delivery(recipient), "a sender's retry of these is not a duplicate"

    journaled("<queued@test>")
    store.mark_delivery_accepted(recipient, "<queued@test>")
    journaled("<handled@test>")
    store.mark_handler_completed(recipient, "<handled@test>")
    journaled("<completed@test>")
    store.mark_handler_completed(recipient, "<completed@test>")
    store.complete_delivery(recipient, "<completed@test>", "intake", "sha")
    for message_id in ("<queued@test>", "<handled@test>", "<completed@test>"):
        assert store.accepted_delivery(recipient, message_id), message_id
    for message_id in ("<deferred@test>", "<refused@test>", "<unknown@test>"):
        assert not store.accepted_delivery(recipient, message_id), message_id
    assert store.accepted_delivery(recipient)
    assert not store.accepted_delivery("echo+t_1@agents.test"), "per recipient address"


def test_a_store_from_before_the_revision_column_gains_it(tmp_path) -> None:
    import sqlite3

    path = tmp_path / "old.sqlite"
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE tasks (token TEXT PRIMARY KEY, agent TEXT NOT NULL, state TEXT NOT NULL,"
        " created_at TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL DEFAULT '')"
    )
    connection.execute(
        "INSERT INTO tasks(token, agent, state) VALUES ('t_old', 'intake', 'working')"
    )
    connection.commit()
    connection.close()
    store = Store(path)
    assert (store.task("t_old")["state"], store.task("t_old")["revision"]) == ("working", 0)
    assert store.put_task_unless_changed("t_old", "intake", "input-required", 0)


def test_legacy_completed_markers_are_accepted_without_progress_rows(tmp_path) -> None:
    import sqlite3

    path = tmp_path / "legacy.sqlite"
    recipient, message_id = "intake+t_old@agents.test", "<old@test>"
    # An actual pre-progress database, not a new store with an artificially missing row.
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE deliveries (message_id TEXT NOT NULL, recipient TEXT NOT NULL, "
            "agent TEXT NOT NULL, raw_sha256 TEXT NOT NULL, delivered_at TEXT NOT NULL DEFAULT '', "
            "PRIMARY KEY (recipient, message_id))"
        )
        connection.execute(
            "INSERT INTO deliveries(message_id, recipient, agent, raw_sha256) VALUES (?, ?, ?, ?)",
            (message_id, recipient, "intake", "sha"),
        )
    store = Store(path)
    assert store.delivery_progress(recipient, message_id) is None
    assert store.accepted_delivery(recipient)
    assert store.accepted_delivery(recipient, message_id)
    assert not store.accepted_delivery(recipient, "<new@test>")
    assert not store.accepted_delivery("echo+t_old@agents.test", message_id)


def test_concurrent_journal_appends_keep_a_single_valid_chain(tmp_path) -> None:
    import threading

    journal = Journal(tmp_path, Store(tmp_path / "journal.sqlite"))
    barrier = threading.Barrier(8)
    errors: list[BaseException] = []

    def append(index: int) -> None:
        barrier.wait()
        try:
            for step in range(10):
                journal.append(
                    f"Message-ID: <{index}-{step}@test>\r\n\r\nbody\r\n".encode(),
                    direction="outbound",
                    message_id=f"<{index}-{step}@test>",
                )
        except BaseException as error:  # pragma: no cover - reported below
            errors.append(error)

    threads = [threading.Thread(target=append, args=(index,)) for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    verification = journal.verify()
    assert verification.valid, verification.error
    assert verification.entries == 80


def test_store_contacts_and_external_send_counts(tmp_path) -> None:
    store = Store(tmp_path / "store.sqlite")
    store.remember_contact("scheduler", "PlainMail.test")
    store.remember_contact("scheduler", "plainmail.test")
    assert store.contacted_domains("scheduler") == frozenset({"plainmail.test"})
    assert store.contacted_domains("intake") == frozenset()
    store.forget_contact("scheduler", "plainmail.test")
    assert store.contacted_domains("scheduler") == frozenset()
    store.record_send("scheduler", "<a@test>", external_recipients=3)
    store.record_send("scheduler", "<b@test>", external_recipients=0)
    with store.connection() as connection:
        connection.execute(
            "INSERT INTO outbound_sends(agent, message_id, external_recipients, created_at) "
            "VALUES ('scheduler', '<old@test>', 5, '2020-01-01T00:00:00.000Z')"
        )
    assert store.external_sends_last_day("scheduler") == 3
    assert store.external_sends_last_day("intake") == 0


def test_store_adds_the_accepted_column_to_an_m3_delivery_progress_table(tmp_path) -> None:
    import sqlite3

    path = tmp_path / "m3.sqlite"
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TABLE delivery_progress (
                message_id TEXT NOT NULL, recipient TEXT NOT NULL, agent TEXT NOT NULL,
                raw_sha256 TEXT NOT NULL, journal_sequence INTEGER NOT NULL,
                state TEXT NOT NULL, response TEXT,
                updated_at TEXT NOT NULL DEFAULT 'x', PRIMARY KEY (recipient, message_id)
            )
            """
        )
        connection.execute(
            "INSERT INTO delivery_progress VALUES "
            "('<m@t>', 'r', 'a', 'h', 1, 'journaled', NULL, 'x')"
        )
    store = Store(path)
    assert store.delivery_progress("r", "<m@t>")["task_revision"] is None
    assert store.pending_deliveries() == [], "an M3 row was never answered 250 queued"
    store.mark_delivery_accepted("r", "<m@t>")
    assert [row["message_id"] for row in store.pending_deliveries()] == ["<m@t>"]
