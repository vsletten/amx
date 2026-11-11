"""IMAP IDLE watchers that turn folder moves in a hold queue into hold-queue decisions.

A person approves a held message by moving it from ``Outbox/Held`` to ``Outbox/Approved`` in any
mail client, and cancels it by moving it to ``Outbox/Rejected``. One thread per agent and folder
IDLEs on that folder. The folder move is only a signal carrying the Message-ID: what gets signed
and sent is the gateway's own journaled copy, and only for a message that agent has in ``held``.

The queue is in the agent's own mailbox by default. ``mailbox.hold_owner`` moves it to a mailbox
the agent does not own, as ``<hold_prefix>Held`` and so on (Stalwart, PLAN §5.8); the watchers
then open that mailbox, and the agent's own folders are never watched.
"""

from __future__ import annotations

import hashlib
import imaplib
import logging
import threading
from collections.abc import Callable
from email import policy
from email.parser import BytesParser

from amx.adapters.submission import SubmissionService
from amx.config import GatewayConfig, MailboxConfig
from amx.holds import SENT_FOLDER, hold_queue
from amx.mailbox import connect_mailbox, idle, quote_mailbox
from amx.profile import Inbound, Thread
from amx.store import Store

LOG = logging.getLogger(__name__)

DONE_KEYWORD = "$AmxDone"

# Returns the folder to move the processed message to, or None to flag it done in place.
MessageAction = Callable[[bytes], str | None]


def _message_id(raw: bytes) -> str | None:
    headers = BytesParser(policy=policy.default).parsebytes(raw, headersonly=True)
    return str(headers.get("Message-ID", "")).strip() or None


class HoldService:
    """Apply approve and reject decisions for one gateway."""

    def __init__(
        self,
        submission: SubmissionService,
        store: Store,
        deliver_local: Callable[[str, Inbound], None],
    ) -> None:
        self.submission = submission
        self.store = store
        self.deliver_local = deliver_local

    def approve(self, agent: str, raw: bytes) -> str | None:
        """Release the held message a person moved to Approved; file it in the agent's Sent.

        Returns the folder to move the copy to: ``Sent`` once released, the queue's Held folder
        when the release is refused for now, or ``None`` (flag it done in place) for anything
        else. When the queue is in another mailbox, that mailbox's Sent is not the agent's: the
        signed copy is filed in the agent's Sent instead, and the approved copy is flagged done.

        The moved copy must be byte-identical to the copy the gateway filed in Held, so a
        substitute carrying the same Message-ID (different text shown to the approver) is ignored.
        """
        queue = hold_queue(self.submission.config, agent)
        message_id = _message_id(raw)
        hold = self.store.hold(message_id) if message_id else None
        if hold is None or hashlib.sha256(raw).hexdigest() != hold["held_sha256"]:
            self._ignored(agent, queue.approved, message_id, "is not an unaltered pending hold")
            return None
        released = self.submission.release(agent, str(message_id))
        if released is None:
            pending = self.store.hold(message_id)
            if pending is not None and pending["state"] == "held" and pending["agent"] == agent:
                # Refused for now (agent disabled or grant narrowed; release() recorded why).
                # Put the copy back, unflagged, so a person can approve or reject it later.
                return queue.held
            misfiled = self._misfiled(agent, queue.approved, raw)
            if misfiled is not None:
                return misfiled
            self._ignored(agent, queue.approved, message_id)
            return None
        if queue.own:
            return SENT_FOLDER
        self.submission.file_sent(agent, str(message_id), released.raw)
        return None

    def reject(self, agent: str, raw: bytes) -> str | None:
        """Cancel the held message a person moved to Rejected and tell the agent."""
        rejected = hold_queue(self.submission.config, agent).rejected
        message_id = _message_id(raw)
        hold = self.submission.reject(agent, message_id) if message_id else None
        if hold is None:
            misfiled = self._misfiled(agent, rejected, raw)
            if misfiled is not None:
                return misfiled
            self._ignored(agent, rejected, message_id)
            return None
        held_raw = self.submission.journal.raw_path(str(hold["raw_sha256"])).read_bytes()
        self.deliver_local(
            agent,
            Inbound(
                intent="update",
                task=str(hold["task"]),
                task_state="canceled",
                schema=None,
                payload=None,
                text=(
                    f"A person rejected held message {message_id} (hold rule {hold['rule']}). "
                    "It was not sent."
                ),
                sender=None,
                lane="system",
                trust=None,
                thread=Thread(message_id=message_id, in_reply_to=None, references=()),
                raw=held_raw,
            ),
        )
        return None

    def _misfiled(self, agent: str, folder: str, raw: bytes) -> str | None:
        """Send another agent's pending hold back to that agent's Held; None if it is not one.

        With every agent's queue in one mailbox (Stalwart), the approver can drag agent A's held
        copy into agent B's Approved or Rejected. B must not decide it, and flagging it done there
        would hide it from A's watcher for good, because the keyword moves with the message.
        """
        message_id = _message_id(raw)
        hold = self.store.hold(message_id) if message_id else None
        if (
            hold is None
            or hold["state"] != "held"
            or hold["agent"] == agent
            or hashlib.sha256(raw).hexdigest() != hold["held_sha256"]
        ):
            return None
        home = hold_queue(self.submission.config, str(hold["agent"]))
        if home.mailbox != hold_queue(self.submission.config, agent).mailbox:
            return None  # another agent's own mailbox (Dovecot): it cannot have been moved here
        self.store.record_policy(
            "hold",
            "hold-misfiled",
            "move",
            None,
            str(hold["task"]),
            f"{agent} {folder}: {message_id} is {hold['agent']}'s hold; back to {home.held}",
        )
        return home.held

    def _ignored(
        self,
        agent: str,
        folder: str,
        message_id: str | None,
        reason: str = "is not a pending hold",
    ) -> None:
        hold = self.store.hold(message_id) if message_id else None
        self.store.record_policy(
            "hold",
            "hold-not-pending",
            "ignore",
            None,
            str(hold["task"]) if hold is not None else None,
            f"{agent} {folder}: {message_id or 'no Message-ID'} {reason}",
        )


class FolderWatcher(threading.Thread):
    """IDLE on one folder of one mailbox and hand each new message to an action."""

    def __init__(
        self,
        config: MailboxConfig,
        address: str,
        folder: str,
        action: MessageAction,
        *,
        idle_seconds: float = 20.0,
        retry_seconds: float = 2.0,
    ) -> None:
        super().__init__(name=f"holdwatch-{address}-{folder}", daemon=True)
        self.config = config
        self.address = address
        self.folder = folder
        self.action = action
        self.idle_seconds = idle_seconds
        self.retry_seconds = retry_seconds
        self._stopped = threading.Event()

    def stop(self) -> None:
        """Ask the watcher to exit after its current IDLE cycle."""
        self._stopped.set()

    def run(self) -> None:
        while not self._stopped.is_set():
            try:
                with connect_mailbox(self.config, timeout=30) as client:
                    client.login(self.config.login_for(self.address), self.config.master_password)
                    status, detail = client.select(quote_mailbox(self.folder))
                    if status != "OK":
                        raise imaplib.IMAP4.error(f"cannot select {self.folder}: {detail!r}")
                    while not self._stopped.is_set():
                        self.drain(client)
                        idle(client, self.idle_seconds)
            except (OSError, imaplib.IMAP4.error) as error:
                LOG.warning("holdwatch %s %s: %s", self.address, self.folder, error)
                self._stopped.wait(self.retry_seconds)
            except Exception:  # Never let an unexpected error end this agent's approvals.
                LOG.exception("holdwatch %s %s crashed; restarting", self.address, self.folder)
                self._stopped.wait(self.retry_seconds)

    def drain(self, client: imaplib.IMAP4) -> int:
        """Process every message in the folder not yet marked done; return how many."""
        status, data = client.uid("SEARCH", None, "UNKEYWORD", DONE_KEYWORD)
        if status != "OK":
            raise imaplib.IMAP4.error(f"SEARCH failed in {self.folder}")
        processed = 0
        for uid in (data[0] or b"").split():
            status, fetched = client.uid("FETCH", uid, "(BODY.PEEK[])")
            raw = next((item[1] for item in fetched if isinstance(item, tuple)), None)
            if status != "OK" or raw is None:
                continue
            try:
                destination = self.action(raw)
            except Exception:  # Leave it unmarked; the next cycle retries.
                LOG.exception("holdwatch %s %s: action failed", self.address, self.folder)
                continue
            if destination is not None:
                status, _ = client.uid("MOVE", uid, quote_mailbox(destination))
                if status == "OK":
                    processed += 1
                    continue
            client.uid("STORE", uid, "+FLAGS", f"({DONE_KEYWORD})")
            processed += 1
        return processed


def watchers_for(
    config: GatewayConfig, agents: list[str], service: HoldService
) -> list[FolderWatcher]:
    """An Approved and a Rejected watcher on each agent's hold queue, wherever it lives."""
    watchers: list[FolderWatcher] = []
    for agent in agents:
        queue = hold_queue(config, agent)
        watchers.append(
            FolderWatcher(
                config.mailbox,
                queue.mailbox,
                queue.approved,
                lambda raw, name=agent: service.approve(name, raw),
            )
        )
        watchers.append(
            FolderWatcher(
                config.mailbox,
                queue.mailbox,
                queue.rejected,
                lambda raw, name=agent: service.reject(name, raw),
            )
        )
    return watchers


def start_watchers(
    config: GatewayConfig, agents: list[str], service: HoldService
) -> list[FolderWatcher]:
    """Start Approved and Rejected watchers for every agent that can submit mail."""
    watchers = watchers_for(config, agents, service)
    for watcher in watchers:
        watcher.start()
    return watchers
