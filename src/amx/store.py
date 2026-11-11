"""SQLite persistence for gateway agents, tasks, deliveries, and journal entries."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

# Closed task states (docs/task-transitions.md): a task in one never reopens.
TERMINAL_STATES = frozenset({"completed", "failed", "canceled"})
# A handled delivery can snapshot a task that did not exist before its handler ran.
ABSENT_TASK_REVISION = -1
_TERMINAL_PARAMETERS = tuple(sorted(TERMINAL_STATES))
# How long a statement waits for another connection's write transaction before it fails with
# "database is locked".
_BUSY_TIMEOUT = 10.0

_PUT_TASK_SQL = """
INSERT INTO tasks(token, agent, state) VALUES (?, ?, ?)
ON CONFLICT(agent, token) DO UPDATE SET
    state=excluded.state,
    updated_at=strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
    revision=tasks.revision + 1
WHERE tasks.state NOT IN (?, ?, ?) OR excluded.state IN (?, ?, ?)
"""

_SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
    name TEXT PRIMARY KEY,
    address TEXT NOT NULL UNIQUE,
    handler TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE TABLE IF NOT EXISTS tasks (
    token TEXT NOT NULL,
    agent TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    revision INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (agent, token)
);
CREATE TABLE IF NOT EXISTS task_assignments (
    recipient TEXT NOT NULL,
    message_id TEXT NOT NULL,
    token TEXT NOT NULL UNIQUE,
    PRIMARY KEY (recipient, message_id)
);
CREATE TABLE IF NOT EXISTS deliveries (
    message_id TEXT NOT NULL,
    recipient TEXT NOT NULL,
    agent TEXT NOT NULL,
    raw_sha256 TEXT NOT NULL,
    delivered_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (recipient, message_id)
);
CREATE TABLE IF NOT EXISTS journal (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    direction TEXT NOT NULL,
    raw_sha256 TEXT NOT NULL,
    prev_sha256 TEXT NOT NULL,
    entry_sha256 TEXT NOT NULL UNIQUE,
    identity TEXT,
    task TEXT,
    message_id TEXT,
    event TEXT NOT NULL,
    detail TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS delivery_progress (
    message_id TEXT NOT NULL,
    recipient TEXT NOT NULL,
    agent TEXT NOT NULL,
    raw_sha256 TEXT NOT NULL,
    journal_sequence INTEGER NOT NULL REFERENCES journal(sequence),
    state TEXT NOT NULL CHECK (state IN ('journaled', 'handled', 'refused', 'completed')),
    response TEXT,
    task_revision INTEGER,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (recipient, message_id)
);
CREATE TABLE IF NOT EXISTS holds (
    message_id TEXT PRIMARY KEY,
    agent TEXT NOT NULL,
    task TEXT NOT NULL,
    rule TEXT NOT NULL,
    envelope_from TEXT NOT NULL,
    recipients TEXT NOT NULL,
    raw_sha256 TEXT NOT NULL,
    held_sha256 TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('held', 'releasing', 'released', 'rejected')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE TABLE IF NOT EXISTS contacts (
    agent TEXT NOT NULL,
    domain TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (agent, domain)
);
CREATE TABLE IF NOT EXISTS named_recipients (
    agent TEXT NOT NULL,
    task TEXT NOT NULL,
    address TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (agent, task, address)
);
CREATE TABLE IF NOT EXISTS outbound_sends (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    agent TEXT NOT NULL,
    message_id TEXT NOT NULL,
    external_recipients INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE TABLE IF NOT EXISTS outbound_progress (
    agent TEXT NOT NULL,
    message_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    input_sha256 TEXT NOT NULL,
    raw_sha256 TEXT NOT NULL,
    groups TEXT NOT NULL,
    accepted TEXT NOT NULL DEFAULT '[]',
    completed INTEGER NOT NULL DEFAULT 0,
    claim TEXT,
    claimed_epoch REAL,
    PRIMARY KEY (agent, message_id, kind)
);
CREATE TABLE IF NOT EXISTS tainted_tasks (
    agent TEXT NOT NULL,
    task TEXT NOT NULL,
    reasons TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (agent, task)
);
CREATE TABLE IF NOT EXISTS policy_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    stage TEXT NOT NULL,
    rule TEXT NOT NULL,
    action TEXT NOT NULL,
    code TEXT,
    task TEXT,
    detail TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_controls (
    agent TEXT PRIMARY KEY,
    command TEXT NOT NULL CHECK (command IN ('pause', 'capacity')),
    max INTEGER CHECK (command != 'capacity' OR (max IS NOT NULL AND max >= 1)),
    reason TEXT,
    declared_epoch REAL NOT NULL,
    expires_at REAL NOT NULL,
    message_id TEXT NOT NULL,
    journal_sequence INTEGER REFERENCES journal(sequence),
    declared_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE TABLE IF NOT EXISTS refusals (
    recipient TEXT NOT NULL,
    message_id TEXT NOT NULL,
    agent TEXT NOT NULL,
    task TEXT,
    status TEXT NOT NULL,
    reason TEXT NOT NULL,
    envelope_from TEXT,
    dsn TEXT NOT NULL CHECK (dsn IN ('pending', 'sent', 'dropped')),
    why TEXT NOT NULL,
    dsn_message_id TEXT,
    claimed_epoch REAL,
    journal_sequence INTEGER REFERENCES journal(sequence),
    refused_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (recipient, message_id)
);
"""


class Store:
    """Small thread-safe-by-connection SQLite store."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as connection:
            # Stored in the file: every later connection opens it in WAL mode.
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(_SCHEMA)
            progress_columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(delivery_progress)").fetchall()
            }
            if "accepted" not in progress_columns:
                # M4: set once LMTP answered "250 queued"; restart recovery requeues only these.
                connection.execute(
                    "ALTER TABLE delivery_progress ADD COLUMN accepted INTEGER NOT NULL DEFAULT 0"
                )
            if "task_revision" not in progress_columns:
                connection.execute("ALTER TABLE delivery_progress ADD COLUMN task_revision INTEGER")
            if "envelope_from" not in progress_columns:
                # PLAN §5.11: where a remote agent's refusal sends its DSN. NULL on older rows,
                # whose refusals are then recorded without one.
                connection.execute("ALTER TABLE delivery_progress ADD COLUMN envelope_from TEXT")
            task_columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(tasks)").fetchall()
            }
            if "revision" not in task_columns:
                # #21: counts writes, so LMTP can tell whether a handler wrote its task.
                connection.execute(
                    "ALTER TABLE tasks ADD COLUMN revision INTEGER NOT NULL DEFAULT 0"
                )
            # SH-02: both ends of a sibling conversation share a token, not a lifecycle.
            # DDL and copy are one transaction; retain timestamps and revision snapshots.
            task_key = [
                row["name"]
                for row in sorted(
                    connection.execute("PRAGMA table_info(tasks)"), key=lambda row: row["pk"]
                )
                if row["pk"]
            ]
            if task_key == ["token"]:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute("ALTER TABLE tasks RENAME TO tasks_legacy")
                connection.execute(
                    """CREATE TABLE tasks (
                        token TEXT NOT NULL, agent TEXT NOT NULL, state TEXT NOT NULL,
                        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                        updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                        revision INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (agent, token)
                    )"""
                )
                connection.execute(
                    "INSERT INTO tasks SELECT token, agent, state, created_at, "
                    "updated_at, revision "
                    "FROM tasks_legacy"
                )
                connection.execute("DROP TABLE tasks_legacy")
                connection.commit()
            policy_columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(policy_events)").fetchall()
            }
            if "agent" not in policy_columns:
                # PLAN §5.10: which agent an RCPT or control decision was about, for trace.
                connection.execute("ALTER TABLE policy_events ADD COLUMN agent TEXT")
            columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(deliveries)").fetchall()
            }
            if "recipient" not in columns:
                connection.executescript(
                    """
                    ALTER TABLE deliveries RENAME TO deliveries_legacy;
                    CREATE TABLE deliveries (
                        message_id TEXT NOT NULL,
                        recipient TEXT NOT NULL,
                        agent TEXT NOT NULL,
                        raw_sha256 TEXT NOT NULL,
                        delivered_at TEXT NOT NULL DEFAULT (
                            strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                        ),
                        PRIMARY KEY (recipient, message_id)
                    );
                    INSERT INTO deliveries(message_id, recipient, agent, raw_sha256, delivered_at)
                    SELECT message_id, agent, agent, raw_sha256, delivered_at
                    FROM deliveries_legacy;
                    DROP TABLE deliveries_legacy;
                    """
                )

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        """Yield a fresh connection for the current thread; its transaction commits on success.

        Its first INSERT, UPDATE, or DELETE opens a transaction that holds SQLite's write lock
        until the commit, while this thread runs Python. Use ``_write`` for a single statement.
        """
        connection = sqlite3.connect(self.path, timeout=_BUSY_TIMEOUT)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        try:
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _write(self, sql: str, parameters: tuple[Any, ...], *, sync: bool = True) -> int:
        """Run one write statement as its own transaction; return how many rows it changed.

        With no transaction open around it, SQLite takes the write lock, writes, commits, and
        lets go inside one call that runs without the GIL. In a ``connection()`` block the lock
        is held from the statement to the commit, including while this thread waits for the
        GIL, and every other writer's busy timeout runs down meanwhile. ``sync=False`` commits
        without an fsync (``synchronous=NORMAL``): the row survives a gateway crash, but an OS
        crash or power loss can drop it until a later synced commit or a checkpoint.
        """
        connection = sqlite3.connect(self.path, timeout=_BUSY_TIMEOUT, isolation_level=None)
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            if not sync:
                connection.execute("PRAGMA synchronous=NORMAL")
            return connection.execute(sql, parameters).rowcount
        finally:
            connection.close()

    def add_agent(self, name: str, address: str, handler: str, *, enabled: bool = True) -> None:
        """Create or update one agent registration."""
        self._write(
            """
            INSERT INTO agents(name, address, handler, enabled) VALUES (?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                address=excluded.address, handler=excluded.handler, enabled=excluded.enabled
            """,
            (name, address, handler, int(enabled)),
        )

    def agent(self, name: str) -> sqlite3.Row | None:
        """Return one agent row."""
        with self.connection() as connection:
            return connection.execute("SELECT * FROM agents WHERE name = ?", (name,)).fetchone()

    def assigned_task(self, recipient: str, message_id: str, candidate: str) -> str:
        """Persist correlation once per delivery, without opening a task.

        A retry, concurrent delivery or restart takes the first random token written.
        The additive table also upgrades existing stores without changing task keys.
        """
        self._write(
            """
            INSERT INTO task_assignments(recipient, message_id, token) VALUES (?, ?, ?)
            ON CONFLICT(recipient, message_id) DO NOTHING
            """,
            (recipient, message_id, candidate),
        )
        with self.connection() as connection:
            row = connection.execute(
                "SELECT token FROM task_assignments WHERE recipient = ? AND message_id = ?",
                (recipient, message_id),
            ).fetchone()
        assert row is not None
        return str(row["token"])

    def put_task(self, token: str, agent: str, state: str) -> bool:
        """Create or update a task state; return whether it was written.

        A closed task never reopens: an open state for a task in a terminal state is ignored.
        A terminal state replaces another, so the later outcome is kept (a rejected hold cancels
        a task its held reply completed). See docs/task-transitions.md, T2 and T3.
        """
        changed = self._write(
            _PUT_TASK_SQL,
            (token, agent, state, *_TERMINAL_PARAMETERS, *_TERMINAL_PARAMETERS),
        )
        return changed == 1

    def put_task_unless_changed(
        self, token: str, agent: str, state: str, revision: int | None
    ) -> bool:
        """Record a delivered message's state unless its task was written since ``revision``.

        ``revision`` is the task's revision read before the handler ran (``None``: no row yet).
        Anything written while the handler ran, its own reply above all, is newer than the
        message it answered, so it stands (docs/task-transitions.md, T1). A closed task never
        reopens (T2). Returns whether the state was written.
        """
        if revision is None:
            changed = self._write(
                """
                INSERT INTO tasks(token, agent, state) VALUES (?, ?, ?)
                ON CONFLICT(agent, token) DO NOTHING
                """,
                (token, agent, state),
            )
        else:
            changed = self._write(
                """
                UPDATE tasks SET
                    state = ?,
                    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                    revision = revision + 1
                WHERE token = ? AND agent = ? AND revision = ?
                    AND (state NOT IN (?, ?, ?) OR ? IN (?, ?, ?))
                """,
                (
                    state,
                    token,
                    agent,
                    revision,
                    *_TERMINAL_PARAMETERS,
                    state,
                    *_TERMINAL_PARAMETERS,
                ),
            )
        return changed == 1

    def task(self, token: str, agent: str | None = None) -> sqlite3.Row | None:
        """Return an agent's task. Legacy unscoped reads fail on ambiguous tokens."""
        with self.connection() as connection:
            if agent is None:
                rows = connection.execute(
                    "SELECT * FROM tasks WHERE token = ?", (token,)
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM tasks WHERE token = ? AND agent = ?", (token, agent)
                ).fetchall()
        if len(rows) > 1:
            raise ValueError("task token is ambiguous; specify agent")
        return rows[0] if rows else None

    def task_keys(self, *, closed: bool = False) -> frozenset[tuple[str, str]]:
        """Return agent-scoped task keys for ingress policy."""
        with self.connection() as connection:
            if closed:
                rows = connection.execute(
                    "SELECT agent, token FROM tasks WHERE state IN (?, ?, ?)",
                    _TERMINAL_PARAMETERS,
                ).fetchall()
            else:
                rows = connection.execute("SELECT agent, token FROM tasks").fetchall()
        return frozenset((str(row["agent"]), str(row["token"])) for row in rows)

    def closed_tasks(self) -> frozenset[tuple[str, str]]:
        """Return terminal (agent, token) pairs; never union participants by token."""
        return self.task_keys(closed=True)

    def delivered(self, recipient: str, message_id: str) -> bool:
        """Return whether a message was successfully dispatched to this recipient."""
        with self.connection() as connection:
            row = connection.execute(
                "SELECT 1 FROM deliveries WHERE recipient = ? AND message_id = ?",
                (recipient, message_id),
            ).fetchone()
        return row is not None

    def accepted_delivery(self, recipient: str, message_id: str | None = None) -> bool:
        """Return whether LMTP took responsibility for mail to this recipient (this Message-ID).

        Accepted: a completed delivery marker (including pre-progress stores), the handler ran
        (``handled``, ``completed``), or a queued agent's LMTP answered
        ``250 queued``. LMTP answers a replay of such a delivery without running the handler
        again. A refused or deferred delivery is not accepted. With no ``message_id``: whether
        the recipient has any accepted delivery, i.e. whether a message to it could be a retry
        (docs/task-transitions.md, D1-D3).
        """
        # LMTP's completed-marker lookup wins even when an older store has no progress row.
        with self.connection() as connection:
            if message_id is None:
                row = connection.execute(
                    """
                    SELECT 1 FROM deliveries WHERE recipient = ?
                    UNION ALL
                    SELECT 1 FROM delivery_progress WHERE recipient = ?
                        AND (state IN ('handled', 'completed')
                             OR (state = 'journaled' AND accepted = 1))
                    LIMIT 1
                    """,
                    (recipient, recipient),
                ).fetchone()
            else:
                row = connection.execute(
                    """
                    SELECT 1 FROM deliveries WHERE recipient = ? AND message_id = ?
                    UNION ALL
                    SELECT 1 FROM delivery_progress WHERE recipient = ? AND message_id = ?
                        AND (state IN ('handled', 'completed')
                             OR (state = 'journaled' AND accepted = 1))
                    LIMIT 1
                    """,
                    (recipient, message_id, recipient, message_id),
                ).fetchone()
        return row is not None

    def delivery_progress(self, recipient: str, message_id: str) -> sqlite3.Row | None:
        """Return the durable LMTP state for one recipient and message."""
        with self.connection() as connection:
            return connection.execute(
                "SELECT * FROM delivery_progress WHERE recipient = ? AND message_id = ?",
                (recipient, message_id),
            ).fetchone()

    def mark_handler_completed(
        self, recipient: str, message_id: str, *, task_revision: int | None = None
    ) -> None:
        """Checkpoint the handler and its pre-handler task revision in one durable write.

        A task write can then fail and resume without running the handler again. ``None`` means
        no task write is pending; ``ABSENT_TASK_REVISION`` means the task did not yet exist.
        """
        changed = self._write(
            """
            UPDATE delivery_progress
            SET state = 'handled', task_revision = ?,
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE recipient = ? AND message_id = ? AND state = 'journaled'
            """,
            (task_revision, recipient, message_id),
        )
        if changed != 1:
            raise RuntimeError("delivery is not awaiting handler completion")

    def mark_delivery_refused(self, recipient: str, message_id: str, response: str) -> None:
        """Persist a handler's permanent refusal so a replay returns the same status."""
        changed = self._write(
            """
            UPDATE delivery_progress
            SET state = 'refused', response = ?,
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE recipient = ? AND message_id = ? AND state = 'journaled'
            """,
            (response, recipient, message_id),
        )
        if changed != 1:
            raise RuntimeError("delivery is not awaiting a handler outcome")

    def complete_delivery(
        self, recipient: str, message_id: str, agent: str, raw_sha256: str
    ) -> None:
        """Atomically record mailbox completion and the public deduplication marker."""
        with self.connection() as connection:
            cursor = connection.execute(
                """
                UPDATE delivery_progress
                SET state = 'completed', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                WHERE recipient = ? AND message_id = ? AND state = 'handled'
                """,
                (recipient, message_id),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("delivery is not awaiting mailbox completion")
            connection.execute(
                """
                INSERT INTO deliveries(message_id, recipient, agent, raw_sha256)
                VALUES (?, ?, ?, ?)
                """,
                (message_id, recipient, agent, raw_sha256),
            )

    def mark_delivered(self, recipient: str, message_id: str, agent: str, raw_sha256: str) -> bool:
        """Record successful dispatch; return false when already recorded."""
        changed = self._write(
            """
            INSERT OR IGNORE INTO deliveries(message_id, recipient, agent, raw_sha256)
            VALUES (?, ?, ?, ?)
            """,
            (message_id, recipient, agent, raw_sha256),
        )
        return changed == 1

    def mark_delivery_accepted(self, recipient: str, message_id: str) -> None:
        """Record that LMTP answered 250 for a queued delivery, so the MTA will not retry it."""
        self._write(
            "UPDATE delivery_progress SET accepted = 1 WHERE recipient = ? AND message_id = ?",
            (recipient, message_id),
        )

    def pending_deliveries(self) -> list[sqlite3.Row]:
        """Return accepted deliveries journaled or handled but not completed, oldest first.

        Deliveries LMTP answered with a 4xx are excluded: the sending MTA still owns those (and
        may already have bounced them).
        """
        with self.connection() as connection:
            return list(
                connection.execute(
                    """
                    SELECT * FROM delivery_progress
                    WHERE state IN ('journaled', 'handled') AND accepted = 1
                    ORDER BY journal_sequence
                    """
                ).fetchall()
            )

    def put_hold(
        self,
        *,
        message_id: str,
        agent: str,
        task: str,
        rule: str,
        envelope_from: str,
        recipients: tuple[str, ...],
        raw_sha256: str,
        held_sha256: str,
    ) -> None:
        """Record an outbound message about to be filed in the agent's Outbox/Held.

        ``raw_sha256`` names the journaled copy that release signs and sends; ``held_sha256`` is
        the exact IMAP copy a person sees, which an approval must match.
        """
        self._write(
            """
            INSERT INTO holds(
                message_id, agent, task, rule, envelope_from, recipients, raw_sha256,
                held_sha256, state
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'held')
            """,
            (
                message_id,
                agent,
                task,
                rule,
                envelope_from,
                json.dumps(list(recipients)),
                raw_sha256,
                held_sha256,
            ),
        )

    def delete_hold(self, message_id: str) -> None:
        """Remove a hold whose Outbox/Held copy could not be filed (submission compensation)."""
        self._write("DELETE FROM holds WHERE message_id = ? AND state = 'held'", (message_id,))

    def hold(self, message_id: str) -> sqlite3.Row | None:
        """Return one hold record by Message-ID."""
        with self.connection() as connection:
            return connection.execute(
                "SELECT * FROM holds WHERE message_id = ?", (message_id,)
            ).fetchone()

    def transition_hold(self, message_id: str, state: str, *, from_state: str = "held") -> bool:
        """Move a hold from ``from_state`` to ``state`` atomically; false if it was not there."""
        changed = self._write(
            """
            UPDATE holds
            SET state = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE message_id = ? AND state = ?
            """,
            (state, message_id, from_state),
        )
        return changed == 1

    def remember_contact(self, agent: str, domain: str) -> None:
        """Record that an agent has sent mail to a domain."""
        self._write(
            "INSERT OR IGNORE INTO contacts(agent, domain) VALUES (?, ?)",
            (agent, domain.casefold()),
        )

    def forget_contact(self, agent: str, domain: str) -> None:
        """Make the agent's next message to a domain a first contact again."""
        self._write(
            "DELETE FROM contacts WHERE agent = ? AND domain = ?", (agent, domain.casefold())
        )

    def contacted_domains(self, agent: str) -> frozenset[str]:
        """Return every domain the agent has already sent mail to."""
        with self.connection() as connection:
            rows = connection.execute(
                "SELECT domain FROM contacts WHERE agent = ?", (agent,)
            ).fetchall()
        return frozenset(str(row["domain"]) for row in rows)

    def name_recipients(self, agent: str, task: str, addresses: tuple[str, ...]) -> None:
        """Record the addresses an agent's owner named in a task (SH-46)."""
        if not addresses:
            return
        self._write(
            "INSERT OR IGNORE INTO named_recipients(agent, task, address) VALUES "
            + ", ".join("(?, ?, ?)" for _address in addresses),
            tuple(value for address in addresses for value in (agent, task, address.casefold())),
        )

    def named_recipients(self, agent: str, task: str, *, open_only: bool = True) -> frozenset[str]:
        """Return the addresses the agent's owner named in a task: the agent may write to them.

        A closed task names nobody for new mail: what the owner approved ends with the task.
        ``open_only=False`` is for a message submitted while the task was open (a hold being
        released), which keeps the approval it was submitted under.
        """
        with self.connection() as connection:
            rows = connection.execute(
                """
                SELECT address FROM named_recipients WHERE agent = ? AND task = ?
                AND (? OR NOT EXISTS (
                    SELECT 1 FROM tasks
                    WHERE tasks.agent = ? AND tasks.token = ? AND tasks.state IN (?, ?, ?)
                ))
                """,
                (agent, task, not open_only, agent, task, *_TERMINAL_PARAMETERS),
            ).fetchall()
        return frozenset(str(row["address"]) for row in rows)

    def outbound_progress(self, agent: str, message_id: str, kind: str) -> sqlite3.Row | None:
        """The canonical signed copy and accepted SMTP groups for this sender's retry."""
        with self.connection() as connection:
            return connection.execute(
                "SELECT * FROM outbound_progress WHERE agent = ? AND message_id = ? AND kind = ?",
                (agent, message_id, kind),
            ).fetchone()

    def prepare_outbound(
        self,
        agent: str,
        message_id: str,
        kind: str,
        input_sha256: str,
        raw_sha256: str,
        groups: str,
    ) -> None:
        """First writer fixes the signed bytes and envelope groups before any SMTP DATA."""
        self._write(
            """INSERT OR IGNORE INTO outbound_progress
                (agent, message_id, kind, input_sha256, raw_sha256, groups)
                VALUES (?, ?, ?, ?, ?, ?)""",
            (agent, message_id, kind, input_sha256, raw_sha256, groups),
        )

    def claim_outbound(
        self,
        agent: str,
        message_id: str,
        kind: str,
        claim: str,
        now: float,
    ) -> bool:
        """Serialize attempts; reclaim after a crashed sender's five-minute lease."""
        return (
            self._write(
                """UPDATE outbound_progress SET claim = ?, claimed_epoch = ?
                WHERE agent = ? AND message_id = ? AND kind = ?
                    AND (claim IS NULL OR claimed_epoch < ?)""",
                (claim, now, agent, message_id, kind, now - 300),
            )
            == 1
        )

    def checkpoint_outbound(
        self,
        agent: str,
        message_id: str,
        kind: str,
        claim: str,
        accepted: str,
    ) -> None:
        """Durably record a positive DATA receipt before attempting another group."""
        if (
            self._write(
                """UPDATE outbound_progress SET accepted = ?
                WHERE agent = ? AND message_id = ? AND kind = ? AND claim = ?""",
                (accepted, agent, message_id, kind, claim),
            )
            != 1
        ):
            raise RuntimeError("outbound claim was lost")

    def release_outbound(self, agent: str, message_id: str, kind: str, claim: str) -> None:
        """Release only this attempt's lease, including after a temporary SMTP failure."""
        self._write(
            """UPDATE outbound_progress SET claim = NULL, claimed_epoch = NULL
                WHERE agent = ? AND message_id = ? AND kind = ? AND claim = ?""",
            (agent, message_id, kind, claim),
        )

    def finish_outbound(
        self,
        agent: str,
        message_id: str,
        kind: str,
        claim: str,
        *,
        task: str,
        task_state: str,
        external_recipients: int,
        domains: frozenset[str],
    ) -> None:
        """Commit send accounting, lifecycle and completion together, once per retry identity."""
        with self.connection() as connection:
            changed = connection.execute(
                """UPDATE outbound_progress SET completed = 1
                    WHERE agent = ? AND message_id = ? AND kind = ? AND claim = ?
                        AND completed = 0""",
                (agent, message_id, kind, claim),
            ).rowcount
            if not changed:
                raise RuntimeError("outbound claim was lost before completion")
            connection.execute(
                """INSERT INTO outbound_sends(agent, message_id, external_recipients)
                    VALUES (?, ?, ?)""",
                (agent, message_id, external_recipients),
            )
            for domain in domains:
                connection.execute(
                    "INSERT OR IGNORE INTO contacts(agent, domain) VALUES (?, ?)", (agent, domain)
                )
            if kind == "submission":
                connection.execute(
                    _PUT_TASK_SQL,
                    (task, agent, task_state, *_TERMINAL_PARAMETERS, *_TERMINAL_PARAMETERS),
                )
            else:
                connection.execute(
                    """UPDATE holds SET state = 'released',
                        updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                        WHERE agent = ? AND message_id = ? AND state = 'releasing'""",
                    (agent, message_id),
                )

    def record_send(self, agent: str, message_id: str, *, external_recipients: int) -> None:
        """Record one message that left the gateway and how many outside recipients it had."""
        self._write(
            """
            INSERT INTO outbound_sends(agent, message_id, external_recipients)
            VALUES (?, ?, ?)
            """,
            (agent, message_id, external_recipients),
        )

    def external_sends_last_day(self, agent: str) -> int:
        """Return how many external recipients the agent sent to in the trailing 24 hours."""
        with self.connection() as connection:
            row = connection.execute(
                """
                SELECT COALESCE(SUM(external_recipients), 0) AS sent FROM outbound_sends
                WHERE agent = ?
                  AND created_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-1 day')
                """,
                (agent,),
            ).fetchone()
        return int(row["sent"])

    def taint_task(self, agent: str, task: str, reasons: tuple[str, ...]) -> None:
        """Mark a task tainted for an agent: everything it sends in that task is held."""
        self._write(
            """
            INSERT INTO tainted_tasks(agent, task, reasons) VALUES (?, ?, ?)
            ON CONFLICT(agent, task) DO UPDATE SET reasons = excluded.reasons
            """,
            (agent, task, ", ".join(reasons) or "tainted-input"),
        )

    def task_taint(self, agent: str, task: str) -> str | None:
        """Return the taint reasons for an agent's task, or ``None`` if it is not tainted."""
        with self.connection() as connection:
            row = connection.execute(
                "SELECT reasons FROM tainted_tasks WHERE agent = ? AND task = ?", (agent, task)
            ).fetchone()
        return None if row is None else str(row["reasons"])

    def declare_control(
        self,
        agent: str,
        command: str,
        *,
        declared_epoch: float,
        expires_at: float,
        message_id: str,
        journal_sequence: int | None,
        maximum: int | None = None,
        reason: str | None = None,
    ) -> None:
        """Record an agent's declaration, replacing its last one (PLAN §5.10).

        An agent has at most one: the latest pause or capacity stands until it expires or the
        agent declares again. Both times are epoch seconds on the gateway's clock.
        """
        self._write(
            """
            INSERT INTO agent_controls(
                agent, command, max, reason, declared_epoch, expires_at, message_id,
                journal_sequence
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(agent) DO UPDATE SET
                command = excluded.command, max = excluded.max, reason = excluded.reason,
                declared_epoch = excluded.declared_epoch, expires_at = excluded.expires_at,
                message_id = excluded.message_id, journal_sequence = excluded.journal_sequence,
                declared_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            """,
            (
                agent,
                command,
                maximum,
                reason,
                declared_epoch,
                expires_at,
                message_id,
                journal_sequence,
            ),
        )

    def clear_control(self, agent: str) -> bool:
        """Drop an agent's declaration (``resume``); return whether it had one."""
        return self._write("DELETE FROM agent_controls WHERE agent = ?", (agent,)) == 1

    def controls(self, now: float, max_ttl: float) -> dict[str, sqlite3.Row]:
        """Every agent's declaration in force at ``now`` (epoch seconds), by agent.

        In force means from its declaration until its own end, and never more than ``max_ttl``
        (the maximum configured now) after it was declared: lowering the maximum shortens what
        was already declared, and each row's ``ends_at`` says when it stops counting. A clock
        stepped back before the declaration ignores it until the clock catches up. Each bound
        can only release the agent, never hold it longer. A lapsed row is ignored, not deleted:
        reading stays a read, and the next declaration replaces it.
        """
        with self.connection() as connection:
            rows = connection.execute(
                """
                SELECT *, MIN(expires_at, declared_epoch + ?) AS ends_at FROM agent_controls
                WHERE declared_epoch <= ? AND ? < MIN(expires_at, declared_epoch + ?)
                """,
                (max_ttl, now, now, max_ttl),
            ).fetchall()
        return {str(row["agent"]): row for row in rows}

    def refusal(self, recipient: str, message_id: str) -> sqlite3.Row | None:
        """Return a remote agent's recorded refusal of one filed message (PLAN §5.11)."""
        with self.connection() as connection:
            return connection.execute(
                "SELECT * FROM refusals WHERE recipient = ? AND message_id = ?",
                (recipient, message_id),
            ).fetchone()

    def record_refusal(
        self,
        recipient: str,
        message_id: str,
        *,
        agent: str,
        task: str | None,
        status: str,
        reason: str,
        envelope_from: str | None,
        dsn: str,
        why: str,
        dsn_message_id: str | None,
        journal_sequence: int,
    ) -> bool:
        """Record a refusal once; return false when this message was already refused.

        ``dsn`` is ``pending`` when a DSN is to be sent (``finish_refusal_dsn`` marks it sent) and
        ``dropped`` when none may be; ``why`` says which rule decided.
        """
        changed = self._write(
            """
            INSERT OR IGNORE INTO refusals(
                recipient, message_id, agent, task, status, reason, envelope_from, dsn, why,
                dsn_message_id, journal_sequence
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                recipient,
                message_id,
                agent,
                task,
                status,
                reason,
                envelope_from,
                dsn,
                why,
                dsn_message_id,
                journal_sequence,
            ),
        )
        return changed == 1

    def claim_refusal_dsn(
        self, recipient: str, message_id: str, *, now: float, lease: float = 60.0
    ) -> bool:
        """Claim a pending DSN for sending; false when it is not pending or another claim holds.

        A claim older than ``lease`` seconds belongs to a sender that crashed or hung between
        claiming and finishing, and may be taken over. Its DSN may then go out twice, with one
        Message-ID, which the receiving gateway's LMTP deduplicates.
        """
        changed = self._write(
            """
            UPDATE refusals SET claimed_epoch = ?,
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE recipient = ? AND message_id = ? AND dsn = 'pending'
                AND (claimed_epoch IS NULL OR claimed_epoch < ?)
            """,
            (now, recipient, message_id, now - lease),
        )
        return changed == 1

    def finish_refusal_dsn(
        self,
        recipient: str,
        message_id: str,
        *,
        claimed: float,
        outcome: str,
        why: str | None = None,
    ) -> None:
        """Settle a claimed DSN: ``sent``, ``dropped`` (with the rule that dropped it), or
        ``pending`` again, which releases the claim for a retry. Only the claim's holder can."""
        if outcome not in {"pending", "sent", "dropped"} or (outcome == "dropped") != bool(why):
            raise ValueError(f"not a DSN outcome: {outcome} {why}")
        self._write(
            """
            UPDATE refusals SET dsn = ?, why = COALESCE(?, why), claimed_epoch = NULL,
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            WHERE recipient = ? AND message_id = ? AND dsn = 'pending' AND claimed_epoch = ?
            """,
            (outcome, why, recipient, message_id, claimed),
        )

    def record_policy(
        self,
        stage: str,
        rule: str,
        action: str,
        code: str | None,
        task: str | None,
        detail: str,
        *,
        agent: str | None = None,
    ) -> None:
        """Append a policy decision for trace output.

        Not synced: the milter writes one row per SMTP stage, and an fsync each would cap every
        MTA's sessions at the disk's fsync rate. An OS crash or power loss can drop the latest
        rows (a gateway crash cannot). The MTA logged each reply, and the synced journal keeps
        the messages themselves. ``agent`` names the agent an RCPT or control decision was
        about, so trace can show that agent's declarations beside it.
        """
        self._write(
            """
            INSERT INTO policy_events(stage, rule, action, code, task, detail, agent)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (stage, rule, action, code, task, detail, agent),
            sync=False,
        )

    def rows(self, query: str, parameters: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        """Run a read-only query and return all rows."""
        if not query.lstrip().upper().startswith("SELECT"):
            raise ValueError("rows() accepts SELECT queries only")
        with self.connection() as connection:
            return list(connection.execute(query, parameters).fetchall())
