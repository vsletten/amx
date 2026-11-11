"""Content-addressed raw message storage with a SQLite hash chain."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from amx.store import Store

GENESIS = "0" * 64


@dataclass(frozen=True, slots=True)
class JournalEntry:
    """One committed journal entry."""

    sequence: int
    raw_sha256: str
    prev_sha256: str
    entry_sha256: str
    raw_path: Path


@dataclass(frozen=True, slots=True)
class Verification:
    """Result of complete journal verification."""

    valid: bool
    entries: int
    error: str | None = None


def _entry_hash(
    prev_sha256: str,
    raw_sha256: str,
    direction: str,
    identity: str | None,
    task: str | None,
    message_id: str | None,
    event: str,
    detail: str,
) -> str:
    canonical = json.dumps(
        {
            "detail": detail,
            "direction": direction,
            "event": event,
            "identity": identity,
            "message_id": message_id,
            "prev_sha256": prev_sha256,
            "raw_sha256": raw_sha256,
            "task": task,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(canonical).hexdigest()


class Journal:
    """Append and verify messages in a content-addressed hash chain."""

    def __init__(self, root: str | Path, store: Store) -> None:
        self.root = Path(root)
        self.raw_root = self.root / "raw"
        self.raw_root.mkdir(parents=True, exist_ok=True)
        self.store = store

    def raw_path(self, digest: str) -> Path:
        """Return the deterministic path for a raw-message digest."""
        return self.raw_root / digest[:2] / f"{digest}.eml"

    def store_raw(self, raw: bytes) -> tuple[str, Path]:
        """Write raw bytes to their content address once; return the digest and path.

        Each writer uses its own temporary name, so concurrent writers of identical bytes cannot
        replace each other's temporary file; the final rename is atomic and idempotent.
        """
        raw_sha256 = hashlib.sha256(raw).hexdigest()
        path = self.raw_path(raw_sha256)
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            temporary = path.with_name(f"{path.name}.{uuid.uuid4().hex}.tmp")
            temporary.write_bytes(raw)
            temporary.replace(path)
        return raw_sha256, path

    def append(
        self,
        raw: bytes,
        *,
        direction: str,
        identity: str | None = None,
        task: str | None = None,
        message_id: str | None = None,
        event: str = "accepted",
        detail: str = "",
    ) -> JournalEntry:
        """Store raw bytes once and atomically append their metadata to the chain."""
        raw_sha256, path = self.store_raw(raw)

        with self.store.connection() as connection:
            # Submission, workers, and hold watchers append concurrently; take the write lock
            # before reading the chain head so two appends can never share a predecessor.
            connection.execute("BEGIN IMMEDIATE")
            previous = connection.execute(
                "SELECT entry_sha256 FROM journal ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            prev_sha256 = str(previous["entry_sha256"]) if previous else GENESIS
            entry_sha256 = _entry_hash(
                prev_sha256,
                raw_sha256,
                direction,
                identity,
                task,
                message_id,
                event,
                detail,
            )
            cursor = connection.execute(
                """
                INSERT INTO journal(
                    direction, raw_sha256, prev_sha256, entry_sha256,
                    identity, task, message_id, event, detail
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    direction,
                    raw_sha256,
                    prev_sha256,
                    entry_sha256,
                    identity,
                    task,
                    message_id,
                    event,
                    detail,
                ),
            )
            if cursor.lastrowid is None:
                raise RuntimeError("journal insert returned no sequence")
            sequence = cursor.lastrowid
        return JournalEntry(sequence, raw_sha256, prev_sha256, entry_sha256, path)

    def append_delivery(
        self,
        raw: bytes,
        *,
        recipient: str,
        agent: str,
        identity: str | None,
        task: str | None,
        message_id: str,
        note: str | None = None,
        envelope_from: str | None = None,
    ) -> JournalEntry:
        """Journal one recipient delivery and durably establish its initial state once.

        ``note`` (e.g. the content judgment's probabilities and taint) is appended to the entry's
        detail, so the hash chain covers it. ``envelope_from`` is the MTA's MAIL FROM (``""`` for a
        null sender): it is kept on the delivery, and in the detail, because a remote agent's
        refusal sends its DSN there (PLAN §5.11).
        """
        raw_sha256, path = self.store_raw(raw)

        with self.store.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            progress = connection.execute(
                "SELECT * FROM delivery_progress WHERE recipient = ? AND message_id = ?",
                (recipient, message_id),
            ).fetchone()
            if progress is not None:
                if progress["agent"] != agent or progress["raw_sha256"] != raw_sha256:
                    raise ValueError("Message-ID replay does not match the original delivery")
                row = connection.execute(
                    "SELECT * FROM journal WHERE sequence = ?",
                    (progress["journal_sequence"],),
                ).fetchone()
                if row is None:
                    raise RuntimeError("delivery progress references a missing journal entry")
                return JournalEntry(
                    int(row["sequence"]),
                    str(row["raw_sha256"]),
                    str(row["prev_sha256"]),
                    str(row["entry_sha256"]),
                    self.raw_path(str(row["raw_sha256"])),
                )

            previous = connection.execute(
                "SELECT entry_sha256 FROM journal ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            prev_sha256 = str(previous["entry_sha256"]) if previous else GENESIS
            detail = f"recipient={recipient} agent={agent}"
            if envelope_from is not None:
                detail += f" from=<{envelope_from}>"
            if note:
                detail += f" {note}"
            entry_sha256 = _entry_hash(
                prev_sha256,
                raw_sha256,
                "inbound",
                identity,
                task,
                message_id,
                "lmtp-received",
                detail,
            )
            cursor = connection.execute(
                """
                INSERT INTO journal(
                    direction, raw_sha256, prev_sha256, entry_sha256,
                    identity, task, message_id, event, detail
                ) VALUES ('inbound', ?, ?, ?, ?, ?, ?, 'lmtp-received', ?)
                """,
                (
                    raw_sha256,
                    prev_sha256,
                    entry_sha256,
                    identity,
                    task,
                    message_id,
                    detail,
                ),
            )
            if cursor.lastrowid is None:
                raise RuntimeError("journal insert returned no sequence")
            sequence = cursor.lastrowid
            connection.execute(
                """
                INSERT INTO delivery_progress(
                    message_id, recipient, agent, raw_sha256, journal_sequence, state,
                    envelope_from
                ) VALUES (?, ?, ?, ?, ?, 'journaled', ?)
                """,
                (message_id, recipient, agent, raw_sha256, sequence, envelope_from),
            )
        return JournalEntry(sequence, raw_sha256, prev_sha256, entry_sha256, path)

    def verify(self) -> Verification:
        """Verify the raw content hashes and every link in sequence order."""
        rows = self.store.rows("SELECT * FROM journal ORDER BY sequence")
        previous = GENESIS
        for index, row in enumerate(rows, start=1):
            sequence = int(row["sequence"])
            if sequence != index:
                return Verification(
                    False, index - 1, f"sequence gap at {sequence}, expected {index}"
                )
            if row["prev_sha256"] != previous:
                return Verification(False, index - 1, f"entry {sequence}: previous hash mismatch")
            path = self.raw_path(str(row["raw_sha256"]))
            if not path.is_file():
                return Verification(False, index - 1, f"entry {sequence}: raw message missing")
            actual_raw_hash = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual_raw_hash != row["raw_sha256"]:
                return Verification(
                    False, index - 1, f"entry {sequence}: raw content hash mismatch"
                )
            expected = _entry_hash(
                previous,
                str(row["raw_sha256"]),
                str(row["direction"]),
                row["identity"],
                row["task"],
                row["message_id"],
                str(row["event"]),
                str(row["detail"]),
            )
            if expected != row["entry_sha256"]:
                return Verification(False, index - 1, f"entry {sequence}: entry hash mismatch")
            previous = expected
        return Verification(True, len(rows))

    def events(self, task: str | None = None) -> list[dict[str, Any]]:
        """Return journal rows as dictionaries for trace rendering."""
        if task is None:
            rows = self.store.rows("SELECT * FROM journal ORDER BY sequence")
        else:
            rows = self.store.rows(
                "SELECT * FROM journal WHERE task = ? ORDER BY sequence", (task,)
            )
        return [dict(row) for row in rows]
