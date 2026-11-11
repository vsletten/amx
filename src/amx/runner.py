"""A remote agent's runner: an ordinary mail client on the agent's own host (PLAN §5.9).

    AMX_IMAP_PASSWORD=dev-outpost AMX_SUBMIT_TOKEN=dev-outpost-token amx-runner \\
        --agent outpost@agents.contoso.test --imap edge-ct:143 \\
        --submit smtp://edge-ct:2587 --ca dev-ca.pem --handler amx.examples.intake:handle

Against a live host (``deploy/live``), IMAP is implicit TLS on 993: ``--imap imaps://mail.host``,
verified like the submission port (the system's trust store, or ``--ca`` for a self-signed one).

The gateway files a remote agent's mail in its INBOX (``mode: remote``) and runs nothing for it.
The runner connects out, with the agent's own IMAP login, IDLEs on INBOX, and hands each message
it has not finished to the same ``handle(msg, ctx)`` an in-process handler gets. ``ctx.reply`` and
``ctx.send`` submit through the gateway with the agent's token, so signing, grants, rate limits,
hold rules, and taint apply exactly as for any agent. Nothing ever connects to the runner.

Each message moves through the remote form of LMTP's journaled → handled → completed:

1. **Take:** set ``\\Seen``. From here a tainted message holds whatever the agent submits, because
   the gateway can see it (``MailboxAppender.tainted_in_progress``).
2. **Run** the handler. ``TryLater`` or a crash un-takes the message (clears ``\\Seen``), and the
   next pass retries it, up to four attempts in all, as queued mode; then it is finished as
   refused. ``Refuse`` finishes it as refused, once the gateway has taken the refusal (below).
3. **Record** the outcome in the runner's own state file, keyed like the gateway's dedupe
   (recipient, Message-ID). A connection lost before step 4 then never runs the handler twice.
4. **Finish:** set ``$AmxHandled`` (and ``$AmxRefused``). The gateway's RCPT watermark counts
   every INBOX message without it.

A refused message was accepted with 250 when the gateway filed it, so no SMTP reply can carry the
refusal. Before finishing one, the runner sends the gateway a ``refuse`` command naming it
(PLAN §5.11): its ``Delivered-To`` and Message-ID, a status (``5.7.1``, ``5.6.0``, or ``5.3.0`` for
a handler that kept failing), and a reason token. The gateway bounces it to the sender, once, if
it verified the sender at ingress. ``$AmxRefused`` is still set, beside ``$AmxHandled``, as the
local record of the refusal, and only once the gateway has settled the command: taken it, refused
it for good (``550 5.7.1 refusal rejected: …``), or it could not be built. Any other answer
(none, a ``4xx``, another ``5xx``, or an unmarked ``550 5.7.1`` from a gateway older than the
command) leaves the message unfinished and untaken, and the command is sent again, backing off
from 5 s to 5 minutes: the gateway answers a repeat without bouncing twice.

The other direction runs over the same submission path (PLAN §5.10). The agent tells its gateway
its own state by mailing the control address: a handler calls ``ctx.declare``, and from the
agent's host, with only the token:

    AMX_SUBMIT_TOKEN=dev-outpost-token amx-runner --agent outpost@agents.contoso.test \\
        --submit smtp://edge-ct:2587 --ca dev-ca.pem control pause --seconds 300

``pause`` makes each RCPT to the agent answer 450 until then, ``capacity --max N --ttl-seconds T``
lowers the watermark for a while, and ``resume`` clears either. Each lapses on its own.
"""

from __future__ import annotations

import argparse
import hashlib
import imaplib
import json
import logging
import os
import signal
import smtplib
import sqlite3
import sys
import threading
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, replace
from email import policy
from email.parser import BytesParser
from pathlib import Path

from amx.adapters.ax import AxChild, AxPresence, OfflinePolicy, Presence, address_name
from amx.control import REASONS, REFUSAL_REJECTED, refusal_reason, refusal_status
from amx.credentials import read_bundle
from amx.custody import Custody
from amx.mailbox import HANDLED_KEYWORD, TAKEN_KEYWORD, ImapEndpoint, idle, taint_reasons
from amx.policy import TASK_TAINT_HEADER
from amx.profile import Inbound, Thread, parse
from amx.runtime import Context, Handler, Refuse, TryLater, load_handler
from amx.sdk import Agent, Received
from amx.transport import bind_transport

LOG = logging.getLogger(__name__)

REFUSED_KEYWORD = "$AmxRefused"
SYSTEM_LANE = "system"


@dataclass(frozen=True, slots=True)
class ImapLogin:
    """The agent's own IMAP login: never the gateway's master user."""

    host: str
    port: int
    username: str
    password: str
    tls: bool = False  # implicit TLS (imaps://), the live bundle's port 993
    ca_file: str | None = None

    def connect(self) -> imaplib.IMAP4:
        """Open the IMAP connection (TLS verified when ``tls``)."""
        endpoint = ImapEndpoint(self.host, self.port, self.tls)
        return endpoint.connect(ca_file=self.ca_file, timeout=30)


MAX_ATTEMPTS = 4  # as queued mode's in-place retries (PLAN §5.4)


@dataclass(frozen=True, slots=True)
class Refusal:
    """What the runner tells the gateway about a message it refused (PLAN §5.11)."""

    recipient: str
    message_id: str
    status: str
    reason: str
    due: float = 0.0  # when to send it again after an attempt that got no final answer


# Resends of a refusal the gateway has not settled back off from 5 s, doubling, to this.
REPORT_BACKOFF_MAX = 300.0


class HandledLog:
    """What this runner has finished, in its own SQLite file (never the gateway's store)."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS handled ("
                "key TEXT PRIMARY KEY, outcome TEXT NOT NULL, "
                "at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')))"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS attempts ("
                "key TEXT PRIMARY KEY, failed INTEGER NOT NULL)"
            )
            # A refusal the gateway has yet to acknowledge has no answer (PLAN §5.11).
            connection.execute(
                "CREATE TABLE IF NOT EXISTS refusals ("
                "key TEXT PRIMARY KEY, recipient TEXT NOT NULL, message_id TEXT NOT NULL, "
                "status TEXT NOT NULL, reason TEXT NOT NULL, answer TEXT, "
                "attempts INTEGER NOT NULL DEFAULT 0, due REAL NOT NULL DEFAULT 0)"
            )

            for table, columns in (
                ("ax_deliveries", "key TEXT PRIMARY KEY, data TEXT NOT NULL"),
                ("ax_outgoing", "message_id TEXT PRIMARY KEY, key TEXT NOT NULL"),
                ("ax_threads", "task TEXT PRIMARY KEY, message_id TEXT NOT NULL"),
                ("ax_replies", "message_id TEXT PRIMARY KEY, data TEXT NOT NULL"),
            ):
                connection.execute(f"CREATE TABLE IF NOT EXISTS {table} ({columns})")

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=10.0)
        try:
            with connection:  # commits, or rolls back on error
                yield connection
        finally:
            connection.close()

    def ax_records(self) -> list[dict]:
        with self._connection() as connection:
            rows = connection.execute("SELECT data FROM ax_deliveries ORDER BY rowid").fetchall()
        return [json.loads(row[0]) for row in rows]

    def ax_record(self, key: str) -> dict | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT data FROM ax_deliveries WHERE key=?", (key,)
            ).fetchone()
        return json.loads(row[0]) if row else None

    def ax_save(self, record: dict, *, thread: bool = False) -> None:
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO ax_deliveries(key,data) VALUES (?,?) "
                "ON CONFLICT(key) DO UPDATE SET data=excluded.data",
                (record["key"], json.dumps(record)),
            )
            for message_id in record.get("ids", []):
                connection.execute(
                    "INSERT OR IGNORE INTO ax_outgoing(message_id,key) VALUES (?,?)",
                    (message_id, record["key"]),
                )

            if thread and record.get("task") is not None:
                connection.execute(
                    "INSERT INTO ax_threads(task,message_id) VALUES (?,?) "
                    "ON CONFLICT(task) DO UPDATE SET message_id=excluded.message_id",
                    (record["task"], record["message_id"]),
                )

    def ax_lookup(self, message_id: str) -> dict | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT key FROM ax_outgoing WHERE message_id=?", (message_id,)
            ).fetchone()
        return self.ax_record(row[0]) if row else None

    def ax_parent(self, task: str | None) -> str | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT message_id FROM ax_threads WHERE task=?", (task,)
            ).fetchone()
        return row[0] if row else None

    def ax_reply(self, message_id: str) -> dict | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT data FROM ax_replies WHERE message_id=?", (message_id,)
            ).fetchone()
        return json.loads(row[0]) if row else None

    def ax_save_reply(self, record: dict) -> None:
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO ax_replies(message_id,data) VALUES (?,?) "
                "ON CONFLICT(message_id) DO UPDATE SET data=excluded.data",
                (record["message_id"], json.dumps(record)),
            )

    def ax_replies(self) -> list[dict]:
        with self._connection() as connection:
            rows = connection.execute("SELECT data FROM ax_replies").fetchall()
        return [json.loads(row[0]) for row in rows]

    def outcome(self, key: str) -> str | None:
        """Return the recorded outcome for a delivery, or ``None`` if it was never finished."""
        with self._connection() as connection:
            row = connection.execute("SELECT outcome FROM handled WHERE key = ?", (key,)).fetchone()
        return None if row is None else str(row[0])

    def failed(self, key: str) -> int:
        """Count one more failed attempt at a delivery; return how many there have been."""
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO attempts(key, failed) VALUES (?, 1) "
                "ON CONFLICT(key) DO UPDATE SET failed = failed + 1",
                (key,),
            )
            row = connection.execute("SELECT failed FROM attempts WHERE key = ?", (key,)).fetchone()
        return int(row[0])

    def record(self, key: str, outcome: str, refusal: Refusal | None = None) -> None:
        """Record a finished handler's outcome, and the refusal to report, in one write."""
        with self._connection() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO handled(key, outcome) VALUES (?, ?)", (key, outcome)
            )
            if refusal is not None:
                connection.execute(
                    "INSERT OR IGNORE INTO refusals(key, recipient, message_id, status, reason) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (key, refusal.recipient, refusal.message_id, refusal.status, refusal.reason),
                )

    def unanswered_refusal(self, key: str) -> Refusal | None:
        """The refusal of a delivery the gateway has not yet acknowledged, if any."""
        with self._connection() as connection:
            row = connection.execute(
                "SELECT recipient, message_id, status, reason, due FROM refusals "
                "WHERE key = ? AND answer IS NULL",
                (key,),
            ).fetchone()
        if row is None:
            return None
        return Refusal(str(row[0]), str(row[1]), str(row[2]), str(row[3]), float(row[4]))

    def defer(self, key: str, now: float) -> float:
        """Count one more unsettled attempt at reporting a refusal; return when to try again."""
        with self._connection() as connection:
            row = connection.execute(
                "SELECT attempts FROM refusals WHERE key = ?", (key,)
            ).fetchone()
            attempts = (int(row[0]) if row else 0) + 1
            due = now + min(REPORT_BACKOFF_MAX, 5.0 * 2 ** min(attempts - 1, 6))
            connection.execute(
                "UPDATE refusals SET attempts = ?, due = ? WHERE key = ?", (attempts, due, key)
            )
        return due

    def answer(self, key: str, answer: str) -> None:
        """Keep the gateway's final answer to a refusal; it is then never sent again."""
        with self._connection() as connection:
            connection.execute("UPDATE refusals SET answer = ? WHERE key = ?", (answer, key))


def delivered_to(raw: bytes) -> str:
    """The envelope recipient the gateway filed this copy for (its ``Delivered-To`` stamp)."""
    headers = BytesParser(policy=policy.default).parsebytes(raw, headersonly=True)
    delivered = headers.get_all("Delivered-To", [])
    return str(delivered[0]).strip().casefold() if delivered else ""


def delivery_key(raw: bytes) -> str:
    """The gateway's dedupe key for this INBOX copy: its recipient and its Message-ID."""
    headers = BytesParser(policy=policy.default).parsebytes(raw, headersonly=True)
    message_id = str(headers.get("Message-ID", "")).strip()
    if not message_id:
        message_id = f"<sha256-{hashlib.sha256(raw).hexdigest()}@amx.invalid>"
    return f"{delivered_to(raw)} {message_id}"


def bind(raw: bytes) -> Inbound:
    """Read an INBOX copy as LMTP reads a delivery, with the gateway's verdicts bound to it.

    The receiving milter and the gateway's filing wrote them. No sender can supply them (the
    milter refuses any message that carries one), and the agent's own login cannot insert into
    its INBOX (the mailhost's ACL; not on Stalwart, PLAN §8). ``Agent-Lane: system`` marks a
    gateway event, such as a person rejecting a held message, which reaches the handler on the
    ``system`` lane as it does in-process, threaded on the held message. ``Agent-Task-Taint``
    carries the task's taint, which an in-process handler's context would carry.
    """
    headers = BytesParser(policy=policy.default).parsebytes(raw, headersonly=True)
    lanes = [str(value).strip().casefold() for value in headers.get_all("Agent-Lane", [])]
    if lanes == [SYSTEM_LANE]:
        event = parse(raw)
        held = Thread(message_id=event.thread.in_reply_to, in_reply_to=None, references=())
        inbound = replace(event, lane=SYSTEM_LANE, trust=None, sender=None, thread=held)
    else:
        inbound = bind_transport(raw, headers, set())
    task_taint = taint_reasons(headers.get_all(TASK_TAINT_HEADER, []))
    if not task_taint:
        return inbound
    reasons = tuple(dict.fromkeys((*inbound.taint_reasons, *task_taint)))
    return replace(inbound, tainted=True, taint_reasons=reasons)


class Runner:
    """Pull an agent's INBOX over IMAP IDLE and run its handler on each unfinished message."""

    def __init__(
        self,
        agent: Agent,
        login: ImapLogin,
        handler: Handler | None,
        handled: HandledLog,
        *,
        idle_seconds: float = 20.0,
        retry_seconds: float = 5.0,
        connect: Callable[[], imaplib.IMAP4] | None = None,
        max_attempts: int = MAX_ATTEMPTS,
        clock: Callable[[], float] = time.time,
        custody: Custody | None = None,
    ) -> None:
        self.agent = agent
        self.login = login
        self.handler = handler
        self.handled = handled
        self.idle_seconds = idle_seconds
        self.retry_seconds = retry_seconds
        self.max_attempts = max_attempts
        self.clock = clock
        self.custody = custody or Custody(agent.address)
        self.ax_delivery = None
        self.busy = False  # between taking a message and finishing it (see main's SIGTERM)
        self._exists = 0  # the INBOX size the server last announced on this connection
        self._connect = connect or self.login.connect

    def run(self, stop: threading.Event) -> None:
        """Connect, drain, IDLE, repeat; reconnect after any failure until ``stop`` is set."""
        while not stop.is_set():
            try:
                with self._connect() as client:
                    client.login(self.login.username, self.login.password)
                    status, detail = client.select("INBOX")
                    if status != "OK":
                        raise imaplib.IMAP4.error(f"cannot select INBOX: {detail!r}")
                    self._exists = int(detail[0] or 0)
                    LOG.info("runner %s: watching INBOX", self.agent.address)
                    while not stop.is_set():
                        failed = self.drain(client, stop)
                        if stop.is_set():
                            continue
                        # Stalwart announces mail filed during the pass only at the next NOOP,
                        # never when IDLE starts; Dovecot may announce it in any response.
                        client.noop()
                        if self._arrived(client):
                            continue
                        # A failed handler is retried sooner than a quiet mailbox is re-scanned.
                        idle(client, self.retry_seconds if failed else self.idle_seconds)
            except (OSError, imaplib.IMAP4.error) as error:
                LOG.warning("runner %s: %s", self.agent.address, error)
                stop.wait(self.retry_seconds)
            except Exception:  # Never let an unexpected error end the agent's intake.
                LOG.exception("runner %s crashed; reconnecting", self.agent.address)
                stop.wait(self.retry_seconds)

    def _arrived(self, client: imaplib.IMAP4) -> bool:
        """Whether the server announced more INBOX mail (EXISTS grew) since the last check.

        imaplib keeps such untagged responses aside, and no server repeats them in IDLE, so without
        this check a message filed mid-pass waits for the next re-scan (S18b on Stalwart, 20 s).
        Only growth counts: a server may repeat an unchanged EXISTS on every NOOP.
        """
        expunged = client.untagged_responses.pop("EXPUNGE", None)
        if expunged:  # each EXPUNGE shrinks the mailbox by one before any later EXISTS
            self._exists = max(0, self._exists - len(expunged))
        announced = client.untagged_responses.pop("EXISTS", None)
        client.untagged_responses.pop("RECENT", None)
        if not announced:
            return False
        count = int(announced[-1])
        grew, self._exists = count > self._exists, count
        return grew

    def drain(self, client: imaplib.IMAP4, stop: threading.Event | None = None) -> int:
        """Handle every INBOX message not yet finished, oldest first; return how many failed."""
        if self.handler is None and self.ax_delivery is None:
            # A presence-only worker leaves copies untouched.
            return 0
        status, data = client.uid("SEARCH", None, "UNDELETED", "UNKEYWORD", HANDLED_KEYWORD)
        if status != "OK":
            raise imaplib.IMAP4.error(f"SEARCH failed: {data!r}")
        failed = 0
        for uid in sorted((data[0] or b"").split(), key=int):
            if stop is not None and stop.is_set():
                break
            status, fetched = client.uid("FETCH", uid, "(BODY.PEEK[])")
            raw = next((item[1] for item in fetched if isinstance(item, tuple)), None)
            if status != "OK" or raw is None:
                continue
            self.busy = True
            try:
                if not self.handle(client, uid.decode(), raw):
                    failed += 1
            finally:
                self.busy = False
        return failed

    def handle(self, client: imaplib.IMAP4, uid: str, raw: bytes) -> bool:
        """Take, run, record, and finish one message; return false to retry it later."""
        key = delivery_key(raw)
        with self.custody.locked() as state:
            status, fetched = client.uid("FETCH", uid, "(FLAGS)")
            if status != "OK":
                raise imaplib.IMAP4.error("cannot check message custody")
            flags = {
                flag.lower()
                for item in fetched
                if isinstance(item, (bytes, tuple))
                for flag in imaplib.ParseFlags(item[0] if isinstance(item, tuple) else item)
            }
            if HANDLED_KEYWORD.lower().encode() in flags:
                return True
            if TAKEN_KEYWORD.lower().encode() in flags or state["claims"].get(key) == "mcp":
                return True
            existing = self.handled.ax_record(key)
            if (
                self.ax_delivery is not None
                and (existing is None or existing["state"] in {"expired", "rejected"})
                and self.handled.outcome(key) is None
                and (not self.ax_delivery.connected or self.ax_delivery.worker.presence._offline())
            ):
                return True  # --handler is not an absent-AX fallback.
            if self.handler is None and self.ax_delivery is None:
                return False
            state["claims"][key] = "runner"
        if self.ax_delivery is not None and self.handled.outcome(key) is None:
            offered = self.ax_delivery.offer(client, uid, raw)
            if offered is not None:
                return offered
        if self.handler is None and self.handled.outcome(key) is None:
            return False
        outcome = self.handled.outcome(key)
        if outcome is None:
            self._flag(client, uid, "\\Seen")
            result = self._run(uid, raw)
            if result is None:
                failed = self.handled.failed(key)
                if failed < self.max_attempts:
                    # Not running any more, so no longer taken: a tainted message waiting for a
                    # retry must not hold what the runner sends for other messages meanwhile.
                    self._flag(client, uid, "\\Seen", add=False)
                    return False
                # A handler that always fails (and may reply each time) is not retried forever.
                result = (f"refused after {failed} failed attempts", "5.3.0", "handler-failed")
            outcome, status, reason = result
            self.handled.record(key, outcome, self._refusal(raw, status, reason))
        elif (pending := self.handled.unanswered_refusal(key)) is not None:
            now = self.clock()
            # A due far in the future means the clock stepped back: report now, not after that.
            if now < pending.due <= now + REPORT_BACKOFF_MAX:
                # Backing off, and not taken meanwhile: a reconnect after the pass that deferred
                # it may have lost that pass's un-take, so make sure again.
                self._untake(client, uid)
                return False
            self._flag(client, uid, "\\Seen")  # taken again while its refusal is reported
        try:
            reported = self._report_refusal(key)
        except Exception:  # its own state file, say: never leave the copy taken for this
            LOG.exception("runner %s: refusal of %s not reported", self.agent.address, key)
            reported = False
        if not reported:
            # The handler is done, so the message is not taken while the report waits: a tainted
            # one must not hold the agent's other sends, and it stays unfinished (counted).
            self._untake(client, uid)
            return False
        refused = outcome.startswith("refused")
        self._flag(
            client, uid, f"{HANDLED_KEYWORD} {REFUSED_KEYWORD}" if refused else HANDLED_KEYWORD
        )
        LOG.info("runner %s: %s %s", self.agent.address, outcome, key)
        return True

    def _untake(self, client: imaplib.IMAP4, uid: str) -> None:
        """Clear ``\\Seen``; a failure is left to the next pass, which clears it again."""
        try:
            self._flag(client, uid, "\\Seen", add=False)
        except (OSError, imaplib.IMAP4.error) as error:
            LOG.warning("runner %s: cannot un-take UID %s: %s", self.agent.address, uid, error)

    @staticmethod
    def _refusal(raw: bytes, status: str | None, reason: str | None) -> Refusal | None:
        """The refusal to report for a filed copy; none for a success or a gateway event.

        A gateway event (``Agent-Lane: system``, such as a rejected hold) has no envelope, so
        nothing names it at the gateway and it has no sender to tell.
        """
        recipient = delivered_to(raw)
        if status is None or reason is None or not recipient:
            return None
        headers = BytesParser(policy=policy.default).parsebytes(raw, headersonly=True)
        message_id = str(headers.get("Message-ID", "")).strip()
        if not message_id:
            return None
        return Refusal(recipient, message_id, status, reason)

    def _report_refusal(self, key: str) -> bool:
        """Send the gateway the refusal it has not settled; false to try again later.

        Two answers are final: ``250`` (bounced, dropped, or already known), and the gateway's
        ``550 5.7.1 refusal rejected: …`` (it will never take this command: the mail was not
        filed for this agent, say). Anything else is retried, backing off from 5 s to 5 min, and
        the gateway takes the same command again without a second bounce: no answer, a ``4xx``
        (the copy is not recorded as filed yet, say), and any other ``5xx``, which is not about
        this refusal (a token refused for now, an error inside the gateway, or a gateway too old
        to know the command, whose ``550 5.7.1`` lacks the marker).
        """
        refusal = self.handled.unanswered_refusal(key)
        if refusal is None:
            return True
        try:
            declared = self.agent.refuse(
                refusal.recipient,
                refusal.message_id,
                status=refusal.status,
                reason=refusal.reason,
            )
        except smtplib.SMTPResponseException as error:
            return self._answered(key, [(error.smtp_code, error.smtp_error)], error)
        except smtplib.SMTPRecipientsRefused as error:
            return self._answered(key, list(error.recipients.values()), error)
        except (OSError, smtplib.SMTPException) as error:  # before ValueError: TLS errors are both
            return self._unsettled(key, error)
        except ValueError as error:  # the SDK found the payload outside the control schema
            LOG.error(
                "runner %s: refusal of %s not expressible: %s", self.agent.address, key, error
            )
            self.handled.answer(key, f"not sent: {error}")
            return True
        except Exception as error:  # never escape with the copy taken
            return self._unsettled(key, error)
        self.handled.answer(key, declared.applied)
        return True

    def _answered(
        self, key: str, answers: Sequence[tuple[int, bytes | str]], error: Exception
    ) -> bool:
        """Settle a refusal the gateway rejected for good; back off from any other answer."""
        marker = f"5.7.1 {REFUSAL_REJECTED}"
        final = bool(answers) and all(
            code == 550
            and (text.decode(errors="replace") if isinstance(text, bytes) else text).startswith(
                marker
            )
            for code, text in answers
        )
        if not final:
            return self._unsettled(key, error)
        LOG.error("runner %s: refusal of %s rejected: %s", self.agent.address, key, error)
        self.handled.answer(key, f"rejected: {error}")
        return True

    def _unsettled(self, key: str, error: Exception) -> bool:
        due = self.handled.defer(key, self.clock())
        LOG.warning(
            "runner %s: refusal of %s not settled (%s); again in %.0f s",
            self.agent.address,
            key,
            error,
            due - self.clock(),
        )
        return False

    def _run(self, uid: str, raw: bytes) -> tuple[str, str | None, str | None] | None:
        """Run the handler; return its outcome with a refusal's status and reason, or ``None``
        for a temporary failure."""
        try:
            inbound = bind(raw)
        except Exception as error:  # ProfileError mostly; never let one copy wedge the runner
            # The gateway filed it, so this is a fault here, not the sender's; keep it visible.
            LOG.error("runner %s: cannot read UID %s: %s", self.agent.address, uid, error)
            return f"refused unreadable: {error}", "5.3.0", "unreadable"
        context = Context(
            agent=self.agent.name,
            metadata={"remote": True, "uid": uid, "recipient": delivered_to(raw)},
            send_message=self.agent.send,
            reply_message=Received(self.agent, inbound).reply,
            declare_state=self.agent.declare,
        )
        try:
            assert self.handler is not None
            self.handler(inbound, context)
        except Refuse as error:
            status = refusal_status(error.code)
            return (
                f"refused {error.code} {error.text}",
                status,
                refusal_reason(status, error.reason),
            )
        except TryLater as error:
            LOG.warning("runner %s: UID %s later: %s", self.agent.address, uid, error)
            return None
        except Exception:  # A crashed handler is a temporary failure, as in queued mode.
            LOG.exception("runner %s: handler failed on UID %s", self.agent.address, uid)
            return None
        return "handled", None, None

    @staticmethod
    def _flag(client: imaplib.IMAP4, uid: str, flags: str, *, add: bool = True) -> None:
        status, detail = client.uid("STORE", uid, "+FLAGS" if add else "-FLAGS", f"({flags})")
        if status != "OK":
            raise imaplib.IMAP4.error(f"cannot set {flags} on UID {uid}: {detail!r}")


def declare(agent: Agent, args: argparse.Namespace) -> int:
    """``amx-runner ... control <command>``: declare the agent's state and exit (PLAN §5.10).

    It uses the same submission path and token the runner sends with, from the agent's own host;
    the gateway applies the declaration to the login's agent and relays nothing.
    """
    try:
        if args.command == "pause":
            declared = agent.pause(seconds=args.seconds, reason=args.reason)
        elif args.command == "resume":
            declared = agent.resume()
        else:
            declared = agent.capacity(args.max, ttl_seconds=args.ttl_seconds)
    except (OSError, smtplib.SMTPException, ValueError) as error:
        print(f"amx-runner: {agent.address}: not declared: {error}", file=sys.stderr)
        return 1
    print(f"{agent.address} declared {declared.applied} (task {declared.task})")
    return 0


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="amx-runner",
        description="Run one remote AMX agent: IMAP IDLE in, authenticated submission out.",
        epilog=(
            "Credentials come from --credentials (the bundle `amx agent add --live` wrote), or "
            "from AMX_IMAP_PASSWORD and AMX_SUBMIT_TOKEN with --agent, --imap, and --submit. "
            "'amx-runner --agent A --submit URL control pause --seconds 300' declares the "
            "agent's state to its gateway instead, and needs only the token."
        ),
    )
    parser.add_argument("--credentials", type=Path, help="the operator's credentials bundle")
    parser.add_argument("--agent", help="the agent address, e.g. outpost@...")
    parser.add_argument(
        "--imap",
        help="the agent's IMAP server, to run it: host:port (plain text), or imaps://host[:port]",
    )
    parser.add_argument("--submit", help="smtp://host:port of the gateway")
    parser.add_argument("--ca", help="CA file for the submission and IMAPS certificates")
    parser.add_argument("--handler", help="module:function, as in gateway YAML (to run)")
    parser.add_argument("--state", default="runner-state", help="directory for the runner's log")
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=int(os.environ.get("AMX_MAX_BYTES", 10485760)),
        help="lane limits.max_bytes, including encoded MIME overhead",
    )
    parser.add_argument("--ax", metavar="TARGET", help="deliver to an AX target")
    parser.add_argument(
        "--ax-home", type=Path, help="AX_HOME shared with the target (default ~/.ax)"
    )
    parser.add_argument("--ax-binary", default="ax", help="AX executable (default ax on PATH)")
    parser.add_argument("--ax-name", help="AX endpoint name (default amx-<full-address digest>)")
    parser.add_argument(
        "--ax-ttl-seconds",
        type=int,
        default=3600,
        help="AX delivery TTL (seconds)",
    )
    parser.add_argument("--idle-seconds", type=float, default=20.0)
    parser.add_argument("--mcp-grace", type=float, default=60.0)
    parser.add_argument("--presence-timeout", type=float, default=30.0)
    parser.add_argument(
        "--offline",
        type=OfflinePolicy,
        choices=OfflinePolicy,
        default=OfflinePolicy.PAUSE,
        help=(
            "absent AX target policy: hold keeps mail in INBOX; pause asks senders to retry "
            "(default: pause for standalone compatibility)"
        ),
    )
    parser.add_argument(
        "--control-address", help="the gateway's control address (default control@<domain>)"
    )
    actions = parser.add_subparsers(dest="action")
    control = actions.add_parser("control", help="declare this agent's state, then exit")
    commands = control.add_subparsers(dest="command", required=True)
    pause = commands.add_parser("pause", help="each RCPT to this agent gets 450 for a while")
    pause.add_argument("--seconds", type=float, required=True)
    pause.add_argument("--reason", default="maintenance", choices=REASONS)
    commands.add_parser("resume", help="clear the declaration: the configuration governs")
    capacity = commands.add_parser("capacity", help="take fewer messages at once for a while")
    capacity.add_argument("--max", type=int, required=True)
    capacity.add_argument("--ttl-seconds", type=int, required=True)
    args = parser.parse_args(argv)
    token = os.environ.get("AMX_SUBMIT_TOKEN")
    password = os.environ.get("AMX_IMAP_PASSWORD")
    if args.credentials is not None:
        try:
            bundle = read_bundle(args.credentials)
        except (OSError, ValueError) as error:
            parser.error(str(error))
        password, token = str(bundle["password"]), str(bundle["token"])
        args.agent = args.agent or str(bundle["address"])
        args.imap = args.imap or str(bundle["imap"])
        args.submit = args.submit or str(bundle["submission"])
    if not (args.agent and args.submit):
        parser.error("pass --credentials, or --agent and --submit")
    if not token:
        parser.error(
            "pass --credentials, or set AMX_SUBMIT_TOKEN (and AMX_IMAP_PASSWORD to run the agent)"
        )
    agent = Agent(
        args.agent,
        args.submit,
        token,
        tls_ca_file=args.ca,
        control_address=args.control_address,
        max_bytes=args.max_bytes,
    )
    if args.action == "control":
        sys.exit(declare(agent, args))
    if not password:
        parser.error("pass --credentials, or set AMX_IMAP_PASSWORD and AMX_SUBMIT_TOKEN")
    if not args.imap or not (args.handler or args.ax):
        parser.error("--imap and at least one of --handler or --ax are required to run the agent")
    if not 1 <= args.ax_ttl_seconds <= 604800:
        parser.error("--ax-ttl-seconds must be between 1 and 604800")
    if not (0 < args.mcp_grace < float("inf") and 0 < args.presence_timeout < float("inf")):
        parser.error("--mcp-grace and --presence-timeout must be positive finite seconds")
    try:
        imap = ImapEndpoint.parse(args.imap)
    except ValueError as error:
        parser.error(str(error))
    logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(message)s")
    logging.getLogger("amx").setLevel(logging.INFO)
    runner = Runner(
        agent,
        ImapLogin(imap.host, imap.port, args.agent, password, imap.tls, args.ca),
        load_handler(args.handler) if args.handler else None,
        HandledLog(Path(args.state) / "runner.sqlite"),
        idle_seconds=args.idle_seconds,
    )
    stop = threading.Event()
    ax = None
    ax_thread = None
    if args.ax:
        state = Path(args.state)
        try:
            ax = AxPresence(
                AxChild(
                    args.ax_binary,
                    args.ax_home or Path.home() / ".ax",
                    state,
                    args.ax_name or address_name(agent.address),
                ),
                Presence(
                    agent,
                    args.ax,
                    custody=runner.custody,
                    mcp_grace=args.mcp_grace,
                    presence_timeout=args.presence_timeout,
                    offline=args.offline,
                ),
            )
        except ValueError as error:
            parser.error(str(error))
        from amx.ax_delivery import AxDelivery

        runner.ax_delivery = AxDelivery(
            runner,
            ax,
            ttl_seconds=args.ax_ttl_seconds,
            credential_directories=(args.credentials.parent, args.credentials.resolve())
            if args.credentials
            else (),
        )
        ax.delivery = runner.ax_delivery
        ax_thread = threading.Thread(target=ax.run, args=(stop,), name="amx-ax")

    def terminate(_signal: int, _frame: object) -> None:
        # As PID 1 in a container, Python ignores SIGTERM, so handle it. With a message in hand,
        # finish it (flags included) before leaving: cut short, its handler would run again on
        # restart and could send a second reply. A refusal's report can take longer than the
        # stop grace period (SMTP timeouts are 15 s); if it is cut short, the restarted runner
        # reports it again, which the gateway takes without a second bounce. Otherwise exit at
        # once, since a clean IMAP logout from inside IDLE fails and the reconnect loop would
        # catch that failure.
        if ax is not None:
            stop.set()
            if not runner.busy:
                raise SystemExit(0)  # run the AX cleanup even when interrupted inside IMAP IDLE
        elif runner.busy:
            stop.set()
        else:
            os._exit(0)

    signal.signal(signal.SIGTERM, terminate)
    try:
        if ax_thread is not None:
            ax_thread.start()
        runner.run(stop)
    finally:
        stop.set()
        if ax is not None:
            # Wake a pending MCP request before waiting for the worker to release its socket.
            process = ax.child.process
            if process is not None and process.poll() is None:
                process.terminate()
        if ax_thread is not None:
            ax_thread.join()


if __name__ == "__main__":
    main()
