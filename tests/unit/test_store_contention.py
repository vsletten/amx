"""Store writes under contention: a writer that stalls must not hold SQLite's write lock."""

from __future__ import annotations

import re
import sqlite3
import threading

from amx import store as store_module
from amx.journal import Journal
from amx.store import Store

_WRITE = re.compile(r"^\s*(?:INSERT(?:\s+OR\s+\w+)?\s+INTO|UPDATE|DELETE\s+FROM)\s+(\w+)")


def _connect_with(monkeypatch, factory: type[sqlite3.Connection]) -> None:
    connect = sqlite3.connect
    monkeypatch.setattr(
        store_module.sqlite3,
        "connect",
        lambda *args, **kwargs: connect(*args, **kwargs, factory=factory),
    )


def test_a_writer_stalled_after_its_insert_holds_up_no_one(tmp_path, monkeypatch) -> None:
    """The gateway's stress run: 16 parallel Stalwart sessions, and a record_policy that waited
    out the 10 s busy timeout. A writer that had its INSERT back had to get the GIL again to
    commit, holding the write lock while every other writer's timeout ran down. Here one writer
    stops right after its INSERT until everyone else is done. Their 5 s is only for their own
    synced writes, one fsync each: the stalled writer never lets go of a lock it holds."""
    store = Store(tmp_path / "journal.sqlite")
    stalled, release = threading.Event(), threading.Event()

    class Stalling(sqlite3.Connection):
        def execute(self, sql: str, parameters=(), /) -> sqlite3.Cursor:  # type: ignore[override]
            cursor = super().execute(sql, parameters)
            if threading.current_thread().name == "stalled" and _WRITE.match(sql):
                stalled.set()
                release.wait(10)
            return cursor

    _connect_with(monkeypatch, Stalling)
    monkeypatch.setattr(store_module, "_BUSY_TIMEOUT", 5.0)
    writer = threading.Thread(
        target=store.record_policy,
        args=("mail", "stalled", "accept", None, None, ""),
        name="stalled",
    )
    writer.start()
    errors: list[Exception] = []

    def work(n: int) -> None:
        try:
            store.record_policy("rcpt", f"rule-{n}", "accept", None, f"t_{n}", "")
            store.put_task(f"t_{n}", "intake", "working")
            store.rows("SELECT * FROM policy_events")
            store.closed_tasks()
        except sqlite3.OperationalError as error:
            errors.append(error)

    try:
        assert stalled.wait(5)
        # Already committed, though its thread has not come back from the INSERT.
        assert store.rows("SELECT 1 FROM policy_events WHERE rule = 'stalled'")
        workers = [threading.Thread(target=work, args=(n,)) for n in range(8)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()
    finally:
        release.set()
        writer.join()
    assert errors == []
    rules = {row["rule"] for row in store.rows("SELECT rule FROM policy_events")}
    assert rules == {"stalled", *(f"rule-{n}" for n in range(8))}
    assert len(store.rows("SELECT token FROM tasks")) == 8


def test_only_policy_trace_rows_commit_without_an_fsync(tmp_path, monkeypatch) -> None:
    """The milter writes a policy row per SMTP stage, so those skip the fsync; the journal,
    deliveries, tasks, and send counts are the gateway's promises and stay synced (FULL)."""
    store = Store(tmp_path / "journal.sqlite")
    journal = Journal(tmp_path, store)
    synchronous: dict[str, set[int]] = {}

    class Recording(sqlite3.Connection):
        def execute(self, sql: str, parameters=(), /) -> sqlite3.Cursor:  # type: ignore[override]
            if match := _WRITE.match(sql):
                level = super().execute("PRAGMA synchronous").fetchone()[0]
                synchronous.setdefault(match.group(1), set()).add(level)
            return super().execute(sql, parameters)

    _connect_with(monkeypatch, Recording)
    store.record_policy("connect", "client-ok", "accept", None, None, "")
    store.put_task("t_1", "intake", "working")
    store.taint_task("intake", "t_1", ("directs-recipient",))
    store.record_send("intake", "<a@test>", external_recipients=1)
    store.put_hold(
        message_id="<held@test>",
        agent="intake",
        task="t_1",
        rule="tainted-input",
        envelope_from="intake@agents.example.test",
        recipients=("pat@people.test",),
        raw_sha256="0" * 64,
        held_sha256="0" * 64,
    )
    assert store.transition_hold("<held@test>", "releasing")  # an UPDATE
    journal.append(b"Message-ID: <a@test>\r\n\r\nhi\r\n", direction="inbound", task="t_1")
    assert synchronous.pop("policy_events") == {1}  # NORMAL
    assert set(synchronous) == {"tasks", "tainted_tasks", "outbound_sends", "holds", "journal"}
    assert all(levels == {2} for levels in synchronous.values()), synchronous  # FULL
