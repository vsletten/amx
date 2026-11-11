"""LMTP delivery adapter: journal, mailbox append, and synchronous handler dispatch."""

from __future__ import annotations

import hashlib
import logging
import sqlite3
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from email import errors as email_errors
from email import policy
from email.message import Message
from email.parser import BytesParser
from typing import Any

from aiosmtpd.controller import Controller
from aiosmtpd.lmtp import LMTP

from amx.config import GatewayConfig
from amx.journal import Journal
from amx.mailbox import MailboxAppender, taint_reasons
from amx.policy import TAINT_HEADER, TASK_TAINT_HEADER
from amx.profile import Inbound, ProfileError, build, named_addresses
from amx.runtime import Admission, Context, HandlerRegistry, Refuse, TryLater
from amx.sdk import Agent, Received
from amx.store import ABSENT_TASK_REVISION, Store
from amx.tasks import mint_token, valid_token
from amx.transport import TransportMetadata, bind_transport, transport_metadata

LOG = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class RecipientStatuses:
    """One final LMTP status for each accepted envelope recipient."""

    values: tuple[str, ...]


def _journal_note(metadata: TransportMetadata) -> str | None:
    parts = []
    if metadata.judgment:
        parts.append(f"judgment=[{metadata.judgment}]")
    if metadata.taint:
        parts.append(f"taint={','.join(metadata.taint)}")
    return " ".join(parts) or None


def _recipient(value: object, agent_domain: str) -> tuple[str, str | None, str | None]:
    recipient = str(value).strip().strip("<>").casefold()
    local_part, separator, domain = recipient.partition("@")
    if not separator or domain != agent_domain:
        return recipient, None, None
    agent, plus, token_value = local_part.partition("+")
    token = token_value if plus and token_value else None
    return recipient, agent, token


def _mail_from(envelope: Any) -> str | None:
    """The MTA's MAIL FROM, ``""`` for a null sender (a bounce); ``None`` when not given."""
    value = getattr(envelope, "mail_from", None)
    if value is None:
        return None
    return str(value).strip().strip("<>").strip()


def _status(code: str, error: object) -> str:
    detail = " ".join(str(error).splitlines()).strip()
    return f"{code} {detail}"


@dataclass(frozen=True, slots=True)
class _Delivery:
    """One journaled recipient delivery, enough to run or resume it on any thread."""

    recipient: str
    agent: str
    message_id: str
    inbound: Inbound
    sequence: int
    raw_sha256: str


def system_event(
    address: str, agent_domain: str, inbound: Inbound, task_taint: str | None = None
) -> bytes:
    """A gateway task event (a person rejected a hold) as a message in a remote agent's INBOX.

    ``Agent-Lane`` and ``Agent-Task-Taint`` are reserved: the milter refuses any message that
    carries one, submission strips them, and an agent's own login cannot insert into its INBOX
    (the mailhost's ACL), so only the gateway's own append can have put them there. The runner
    turns the event back into the ``system``-lane Inbound an in-process handler gets, tainted
    when its task is.
    """
    assert inbound.task is not None and inbound.task_state is not None
    held = inbound.thread.message_id
    message = build(
        sender=f"postmaster@{agent_domain}",
        to=address,
        subject=f"AMX task {inbound.task}: {inbound.task_state}",
        intent=inbound.intent,
        task=inbound.task,
        task_state=inbound.task_state,
        text=inbound.text,
        in_reply_to=held,
        references=(held,) if held else (),
    )
    stamps = "Agent-Lane: system\r\n"
    if task_taint:
        stamps += f"{TASK_TAINT_HEADER}: {task_taint}\r\n"
    return stamps.encode() + message.as_bytes(policy=policy.SMTP)


def _message_id(headers: Message, raw: bytes) -> str:
    message_id = str(headers.get("Message-ID", "")).strip()
    return message_id or f"<sha256-{hashlib.sha256(raw).hexdigest()}@amx.invalid>"


class LmtpHandler:
    """aiosmtpd handler implementing AMX delivery semantics.

    In ``sync`` mode the LMTP reply means the handler ran. In ``queued`` mode it means the message
    is journaled and in the agent's bounded work queue; a worker runs the handler, appends to the
    mailbox, and completes the delivery. A full queue answers ``450 4.2.1`` so the MTA retries.
    """

    def __init__(
        self,
        config: GatewayConfig,
        store: Store,
        journal: Journal,
        registry: HandlerRegistry,
        mailbox: MailboxAppender,
        outbound_agents: dict[str, Agent] | None = None,
        *,
        retry_delays: tuple[float, ...] = (1.0, 5.0, 15.0),
    ) -> None:
        self.config = config
        self.store = store
        self.journal = journal
        self.registry = registry
        self.mailbox = mailbox
        self.outbound_agents = outbound_agents or {}
        self.retry_delays = retry_delays
        self._inflight: set[tuple[str, str]] = set()
        self._inflight_lock = threading.Lock()
        self._delivering: set[tuple[str, str]] = set()

    def _context(self, agent: str, inbound: Inbound, metadata: dict[str, Any]) -> Context:
        outbound = self.outbound_agents.get(agent)
        received = Received(outbound, inbound) if outbound is not None else None
        send_message = outbound.send if outbound is not None else None
        reasons = inbound.taint_reasons if inbound.tainted else ()
        if not reasons and inbound.task:
            stored = self.store.task_taint(agent, inbound.task)
            # A clean message (or a local event such as `canceled`) in an already tainted task
            # keeps the taint: a new task opened from it must be held too.
            reasons = tuple(item.strip() for item in (stored or "").split(",") if item.strip())
        if send_message is not None and reasons:
            send_message = self._tainted_send(agent, reasons, send_message)

        def declare_state(command: str, **fields: Any) -> Any:
            # A declaration goes nowhere and can only lower the agent's own capacity, so taint
            # does not wrap it (PLAN §5.10).
            assert outbound is not None
            return outbound.declare(command, **fields)

        return Context(
            agent=agent,
            metadata=metadata,
            send_message=send_message,
            reply_message=received.reply if received is not None else None,
            declare_state=declare_state if outbound is not None else None,
        )

    def _tainted_send(
        self, agent: str, reasons: tuple[str, ...], send: Callable[..., Any]
    ) -> Callable[..., Any]:
        """Wrap ctx.send so a task a tainted handler opens is tainted before it is submitted."""

        def send_tainted(**message: Any) -> Any:
            task = message.get("task") or mint_token()
            self.store.taint_task(agent, task, reasons)
            return send(**{**message, "task": task})

        return send_tainted

    def _run_handler(self, delivery: _Delivery, admission: Admission | None = None) -> str | None:
        """Run the handler for a journaled delivery; return a final status unless it succeeded.

        On success the delivered message's task state is recorded, unless something wrote the
        task while the handler ran: its own reply answers this message, so it stands. A remote
        agent's handler runs later, on its own host, so there this records the state before the
        message is filed. A refused or failed delivery records nothing (docs/task-transitions.md).
        """
        inbound = delivery.inbound
        if inbound.tainted and inbound.task:
            # Anything the handler sends in this task now waits in Outbox/Held (tainted-input).
            self.store.taint_task(delivery.agent, inbound.task, inbound.taint_reasons)
        try:
            before = (
                self.store.task(inbound.task, delivery.agent)
                if inbound.task and inbound.task_state
                else None
            )
            self.registry.dispatch(
                delivery.agent,
                delivery.inbound,
                self._context(
                    delivery.agent,
                    delivery.inbound,
                    {"journal_sequence": delivery.sequence, "recipient": delivery.recipient},
                ),
                admission=admission,
            )
        except TryLater as error:
            return _status("450 4.3.0", error)
        except Refuse as error:
            response = _status(f"550 {error.code}", error.text)
            self.store.mark_delivery_refused(delivery.recipient, delivery.message_id, response)
            return response
        except Exception as error:  # Handler crashes are temporary delivery failures.
            return _status("450 4.3.0 handler error:", error)
        revision = None
        if inbound.task and inbound.task_state:
            revision = int(before["revision"]) if before is not None else ABSENT_TASK_REVISION
        self.store.mark_handler_completed(
            delivery.recipient, delivery.message_id, task_revision=revision
        )
        return None

    def _filed_copy(self, delivery: _Delivery) -> bytes:
        """A remote agent's INBOX copy: the delivered bytes under the stamps its runner reads.

        ``Delivered-To`` names the envelope recipient, as an MDA writes it, so the runner sees the
        task token a person's reply was delivered to. ``Agent-Taint`` is added when only the
        ``unjudged`` backstop tainted the message (the milter writes it otherwise), and only on
        mail the milter saw: a bounce the mailhost generated has no transport headers, and a lone
        ``Agent-Taint`` would make it unreadable (``amx.transport``). ``Agent-Task-Taint`` carries
        the task's taint on every copy, bounces included: an in-process handler's context carries
        that taint, and the runner has no other way to learn it.
        """
        inbound = delivery.inbound
        stamps = [f"Delivered-To: {delivery.recipient}"]
        headers = BytesParser(policy=policy.default).parsebytes(inbound.raw, headersonly=True)
        judged = inbound.lane in {"agent", "human"}
        if judged and inbound.tainted and not headers.get_all(TAINT_HEADER):
            stamps.append(f"{TAINT_HEADER}: {', '.join(inbound.taint_reasons)}")
        task_taint = self.store.task_taint(delivery.agent, inbound.task) if inbound.task else None
        if task_taint:
            stamps.append(f"{TASK_TAINT_HEADER}: {', '.join(taint_reasons([task_taint]))}")
        return "".join(f"{stamp}\r\n" for stamp in stamps).encode() + inbound.raw

    def _finish(self, delivery: _Delivery, admission: Admission | None = None) -> str:
        """Append a handled delivery to the agent mailbox and complete it.

        Handler completion and its pre-handler task revision are already durable. Record the
        task state with that revision before filing: a failed task write resumes here without
        rerunning the handler, and a handler's own reply still wins (#21).

        A remote agent's INBOX is its queue, so for one the append and the settling of the RCPT
        admission happen under the milter's admission lock: its depth read (admissions, then the
        mailbox) then counts the message exactly once, never twice.
        """
        inbound = delivery.inbound
        address = f"{delivery.agent}@{self.config.agent_domain}"
        if inbound.task and inbound.task_state:
            try:
                progress = self.store.delivery_progress(delivery.recipient, delivery.message_id)
                revision = progress["task_revision"] if progress is not None else None
                # Old handled rows have no snapshot: preserve their task state rather than
                # guessing whether a handler replied before the upgrade.
                if revision is not None and not self.store.put_task_unless_changed(
                    inbound.task,
                    delivery.agent,
                    inbound.task_state,
                    None if revision == ABSENT_TASK_REVISION else int(revision),
                ):
                    LOG.info(
                        "task %s keeps its state: written while %s's handler ran, or closed",
                        inbound.task,
                        delivery.agent,
                    )
            except Exception as error:
                LOG.warning(
                    "task state for %s could not be recorded: %s",
                    inbound.task,
                    error,
                    extra={
                        "event": "task-state-deferred",
                        "task": inbound.task,
                        "recipient": delivery.recipient,
                        "error_kind": type(error).__name__,
                    },
                )
                return _status("450 4.3.0 task state error:", error)
        try:
            if self.registry.mode(delivery.agent) == "remote":
                filed = self._filed_copy(delivery)
                with self.registry.admission:
                    self.mailbox.append(address, filed)
                    if admission is not None:
                        self.registry.settle(admission)
            else:
                self.mailbox.append(address, inbound.raw)
        except Exception as error:
            return _status("450 4.3.0 mailbox error:", error)
        self.store.complete_delivery(
            delivery.recipient, delivery.message_id, delivery.agent, delivery.raw_sha256
        )
        return f"250 2.0.0 delivered journal={delivery.sequence} sha256={delivery.raw_sha256[:12]}"

    def _enqueue(
        self, delivery: _Delivery, *, force: bool = False, admission: Admission | None = None
    ) -> str:
        key = (delivery.recipient, delivery.message_id)
        with self._inflight_lock:
            in_flight = key in self._inflight
            self._inflight.add(key)
        if in_flight:
            return self._duplicate_queued(*key)
        try:
            submitted = self.registry.submit(
                delivery.agent, lambda: self._work(delivery), force=force, admission=admission
            )
        except ValueError:
            # A config reload made the agent something other than queued (or removed it) since
            # this delivery read its mode: nothing is queued, so the MTA retries into the new one.
            with self._inflight_lock:
                self._inflight.discard(key)
            return "451 4.3.0 agent changed while delivering, retry"
        if not submitted:
            with self._inflight_lock:
                self._inflight.discard(key)
            return "450 4.2.1 agent busy, retry"
        # From here the MTA considers the message delivered; only restart recovery may resume it.
        self.store.mark_delivery_accepted(delivery.recipient, delivery.message_id)
        return f"250 2.0.0 queued journal={delivery.sequence} sha256={delivery.raw_sha256[:12]}"

    def _duplicate_queued(self, recipient: str, message_id: str) -> str:
        """Answer an MTA retry of a delivery that is still in its agent's queue.

        The first attempt can have queued it and then failed to record that it was accepted (and
        answered 451). This 250 is what hands the message over, so the acceptance is recorded
        first: otherwise restart recovery would not requeue it, and the MTA would not resend it.
        """
        self.store.mark_delivery_accepted(recipient, message_id)
        return "250 2.0.0 duplicate already queued"

    def _work(self, delivery: _Delivery) -> None:
        """Run one queued delivery to completion, retrying temporary failures in place."""
        try:
            for delay in (0.0, *self.retry_delays):
                if delay:
                    time.sleep(delay)
                progress = self.store.delivery_progress(delivery.recipient, delivery.message_id)
                if progress is None or str(progress["state"]) in {"completed", "refused"}:
                    return
                if str(progress["state"]) == "journaled":
                    failure = self._run_handler(delivery)
                    if failure is not None and failure.startswith("550"):
                        return
                    if failure is not None:
                        LOG.warning("queued handler for %s: %s", delivery.agent, failure)
                        continue
                status = self._finish(delivery)
                if status.startswith("250"):
                    return
                LOG.warning("queued delivery for %s: %s", delivery.agent, status)
            LOG.error(
                "queued delivery %s for %s stays pending until restart recovery",
                delivery.message_id,
                delivery.recipient,
            )
        finally:
            with self._inflight_lock:
                self._inflight.discard((delivery.recipient, delivery.message_id))

    def _deliver(
        self,
        raw: bytes,
        recipient: str,
        agent: str,
        message_id: str,
        inbound: Inbound,
        metadata: TransportMetadata,
        admission: Admission,
        mail_from: str | None = None,
    ) -> str:
        # Claim the whole delivery, including journaling and mailbox completion. A
        # concurrent sync retry must not run the handler or file a second copy. Do
        # not wait on user code; the MTA retains overlapping attempts for retry.
        # Queued ownership remains separate: _inflight outlives this LMTP call.
        key = (recipient, message_id)
        with self._inflight_lock:
            if key in self._delivering:
                return "450 4.3.0 delivery already running, retry"
            self._delivering.add(key)
        try:
            return self._deliver_claimed(
                raw, recipient, agent, message_id, inbound, metadata, admission, mail_from
            )
        finally:
            with self._inflight_lock:
                self._delivering.discard(key)

    def _deliver_claimed(
        self,
        raw: bytes,
        recipient: str,
        agent: str,
        message_id: str,
        inbound: Inbound,
        metadata: TransportMetadata,
        admission: Admission,
        mail_from: str | None = None,
    ) -> str:
        if self.store.delivered(recipient, message_id):
            return "250 2.0.0 duplicate already delivered"
        queued = self.registry.mode(agent) == "queued"
        if queued:
            with self._inflight_lock:
                in_flight = (recipient, message_id) in self._inflight
            if in_flight:
                return self._duplicate_queued(recipient, message_id)
            # Avoid allocating correlation for a clear capacity refusal. This is
            # only a precheck: submit still atomically checks capacity after the
            # journal write, and a racing refusal retains journaled retry state.
            if self.registry.full(agent):
                return "450 4.2.1 agent busy, retry"
        headers = BytesParser(policy=policy.default).parsebytes(raw, headersonly=True)
        if (
            inbound.lane == "human"
            and inbound.report is None
            and inbound.task is None
            and "+" not in recipient.partition("@")[0]
            and str(headers.get("Agent-Grant-Can-Open-Tasks", "")).strip() == "true"
        ):
            task = self.store.assigned_task(recipient, message_id, mint_token())
            # Journal the per-recipient stamped copy so queue recovery sees the same
            # correlation. No state is recorded until authenticated agent submission.
            raw = f"Agent-Task-Assigned: {task}\r\n".encode() + raw
            inbound = replace(inbound, task=task, raw=raw)
        try:
            entry = self.journal.append_delivery(
                raw,
                recipient=recipient,
                agent=agent,
                identity=metadata.verified_domain,
                task=inbound.task,
                message_id=message_id,
                note=_journal_note(metadata),
                envelope_from=mail_from,
            )
        except ValueError as error:
            return _status("550 5.6.0", error)

        progress = self.store.delivery_progress(recipient, message_id)
        if progress is None:
            raise RuntimeError("journaled delivery is missing progress state")
        state = str(progress["state"])
        if state == "completed":
            return "250 2.0.0 duplicate already delivered"
        if state == "refused":
            return str(progress["response"])
        if inbound.lane == "human" and metadata.trust == "high" and inbound.task:
            # SH-46: the owner's verified From, To, and Cc (DKIM over-signs them, SH-40; a
            # signed-in person's came through submission) name who the agent may write to here.
            # Only once the delivery is journaled: a refused one names nobody, and a crash before
            # this point is retried by the MTA through the same path.
            self.store.name_recipients(agent, inbound.task, named_addresses(headers))

        delivery = _Delivery(
            recipient, agent, message_id, inbound, entry.sequence, entry.raw_sha256
        )
        if queued:
            return self._enqueue(delivery, admission=admission)
        if state == "journaled":
            failure = self._run_handler(delivery, admission)
            if failure is not None:
                return failure
        return self._finish(delivery, admission)

    def _backstop(
        self,
        metadata: TransportMetadata,
        inbound: Inbound,
        recipients: list[tuple[str, str | None, str | None]],
    ) -> tuple[TransportMetadata, Inbound]:
        """Taint mail that should have been judged but carries no judgment (``unjudged``).

        The milter judges whenever the recipients' mode is not off; a delivery without a judgment
        means a path the milter did not map (e.g. an unrecognised recipient form). Applied on
        live delivery and again when restart recovery rebuilds a queued delivery.
        """
        if not self._unjudged(metadata, recipients):
            return metadata, inbound
        metadata = replace(metadata, taint=(*metadata.taint, "unjudged"))
        inbound = replace(inbound, tainted=True, taint_reasons=(*inbound.taint_reasons, "unjudged"))
        return metadata, inbound

    def _unjudged(
        self, metadata: TransportMetadata, recipients: list[tuple[str, str | None, str | None]]
    ) -> bool:
        if metadata.lane not in {"agent", "human"} or metadata.judgment is not None:
            return False
        config = self.config  # one configuration: a reload may replace it at any moment
        modes = [
            config.agents[agent].content_judge_mode
            for _recipient, agent, _token in recipients
            if agent is not None and agent in config.agents
        ]
        return config.content_judge.mode_for(metadata.lane, modes) != "off"

    def recover(self) -> int:
        """Requeue accepted deliveries for queued agents that a stop or crash interrupted.

        Only deliveries LMTP answered ``250 queued`` for: the MTA will not retry those, so the
        journal and delivery progress rows are the durable queue. Deliveries answered with a 4xx
        still belong to the sending MTA.
        """
        recovered = 0
        for row in self.store.pending_deliveries():
            agent = str(row["agent"])
            if self.registry.mode(agent) != "queued":
                continue
            recipient = str(row["recipient"])
            _address, _agent, token = _recipient(recipient, self.config.agent_domain)
            try:
                raw = self.journal.raw_path(str(row["raw_sha256"])).read_bytes()
                headers = BytesParser(policy=policy.default).parsebytes(raw, headersonly=True)
                inbound = bind_transport(raw, headers, {token} if token else set())
                metadata = transport_metadata(headers) or TransportMetadata(
                    "system", "system", None, None
                )
                _metadata, inbound = self._backstop(metadata, inbound, [(recipient, agent, token)])
            except (OSError, ProfileError) as error:
                LOG.error("cannot recover %s for %s: %s", row["message_id"], recipient, error)
                continue
            delivery = _Delivery(
                recipient,
                agent,
                str(row["message_id"]),
                inbound,
                int(row["journal_sequence"]),
                str(row["raw_sha256"]),
            )
            if self._enqueue(delivery, force=True).startswith("250 2.0.0 queued"):
                recovered += 1
        return recovered

    def deliver_local(self, agent: str, inbound: Inbound, *, again: bool = True) -> None:
        """Hand a gateway-originated task event (no SMTP transaction) to an agent's handler.

        A remote agent's handler is not here, so the event is filed in its INBOX instead.
        """
        if self.registry.mode(agent) == "remote":
            address = f"{agent}@{self.config.agent_domain}"
            try:
                stored = self.store.task_taint(agent, inbound.task) if inbound.task else None
                task_taint = ", ".join(taint_reasons([stored])) if stored else None
                event = system_event(address, self.config.agent_domain, inbound, task_taint)
                self.mailbox.append(address, event)
            except Exception:
                LOG.exception("local event for %s could not be filed", agent)
            return
        context = self._context(agent, inbound, {"local": True})

        def run() -> None:
            try:
                self.registry.dispatch(agent, inbound, context)
            except Exception:
                LOG.exception("local event for %s failed", agent)

        if self.registry.mode(agent) == "queued":
            try:
                self.registry.submit(agent, run, force=True)
                return
            except ValueError:
                # A reload rebuilt the agent in between: deliver by its new mode (once).
                if again:
                    self.deliver_local(agent, inbound, again=False)
                    return
        run()

    async def handle_DATA(
        self, _server: Any, _session: Any, envelope: Any
    ) -> RecipientStatuses:  # aiosmtpd hook is necessarily async
        """Deliver each LMTP recipient and return one final status per recipient."""
        raw = bytes(envelope.original_content)
        recipients = [_recipient(value, self.config.agent_domain) for value in envelope.rcpt_tos]
        parsed_headers = BytesParser(policy=policy.default).parsebytes(raw, headersonly=True)
        header_message_id = str(parsed_headers.get("Message-ID", "")).strip() or None
        # Each agent recipient settles the admission the milter counted for it: moved into the
        # queue or the running handler when dispatched, dropped on every other outcome.
        admissions = [
            Admission(agent, header_message_id) if agent is not None else None
            for _recipient_value, agent, _token in recipients
        ]
        try:
            return self._handle(
                raw, recipients, parsed_headers, admissions, mail_from=_mail_from(envelope)
            )
        finally:
            for admission in admissions:
                if admission is not None:
                    self.registry.settle(admission)

    def _handle(
        self,
        raw: bytes,
        recipients: list[tuple[str, str | None, str | None]],
        parsed_headers: Message,
        admissions: list[Admission | None],
        *,
        mail_from: str | None = None,
    ) -> RecipientStatuses:
        if any(
            isinstance(defect, email_errors.MissingHeaderBodySeparatorDefect)
            for defect in parsed_headers.defects
        ):
            # A malformed header line would end the header block early and hide the milter's
            # transport headers (lane, judgment, taint) in the body: refuse rather than guess.
            status = "550 5.6.0 malformed header block"
            return RecipientStatuses(tuple(status for _recipient_value in recipients))
        try:
            recipient_tokens = {token for _recipient, _agent, token in recipients if token}
            inbound = bind_transport(raw, parsed_headers, recipient_tokens)
        except ProfileError as error:
            status = _status("550 5.6.0", error)
            return RecipientStatuses(tuple(status for _recipient_value in recipients))

        message_id = _message_id(parsed_headers, raw)
        metadata = transport_metadata(parsed_headers) or TransportMetadata(
            "system", "system", None, None
        )
        metadata, inbound = self._backstop(metadata, inbound, recipients)

        preflight: list[str | None] = []
        for _recipient_value, agent, token in recipients:
            if agent is None or agent not in self.config.agents:
                preflight.append("550 5.1.1 unknown agent")
            elif token is not None and not valid_token(token):
                preflight.append("550 5.1.3 invalid task token in sub-address")
            elif (
                inbound.task != token
                and (inbound.task is not None or token is not None)
                and not (inbound.lane == "agent" and token is None)
            ):
                preflight.append("550 5.7.1 Agent-Task does not match recipient subaddress token")
            else:
                preflight.append(None)
        if any(status is not None for status in preflight):
            return RecipientStatuses(
                tuple(
                    status or "450 4.3.0 another recipient failed transaction preflight"
                    for status in preflight
                )
            )

        statuses: list[str] = []
        for (recipient, agent, _token), admission in zip(recipients, admissions, strict=True):
            if agent is None or admission is None:
                continue
            try:
                status = self._deliver(
                    raw, recipient, agent, message_id, inbound, metadata, admission, mail_from
                )
            except sqlite3.OperationalError as error:
                # The store could not be written (locked past its busy timeout, say). Raised,
                # aiosmtpd would answer 500 and the MTA would bounce the message. The MTA's retry
                # resumes it as after a crash at the same point: a handler that ran but was not
                # checkpointed runs again, and a copy filed but not completed is filed again.
                LOG.exception("delivery of %s to %s was not recorded", message_id, recipient)
                status = _status("451 4.3.0 gateway store unavailable:", error)
            statuses.append(status)
        return RecipientStatuses(tuple(statuses))


class LmtpProtocol(LMTP):
    """LMTP protocol extension that emits every per-recipient final status."""

    async def push(self, status: Any) -> None:
        if isinstance(status, RecipientStatuses):
            for value in status.values:
                await super().push(value)
            return
        await super().push(status)


class LmtpController(Controller):
    """Controller that instantiates the per-recipient LMTP protocol."""

    def factory(self) -> LMTP:
        """Create the protocol implementation for each connection."""
        return LmtpProtocol(self.handler, **self.SMTP_kwargs)


def controller(handler: LmtpHandler, config: GatewayConfig) -> LmtpController:
    """Internal delivery gets the same signing/rendering headroom as Postfix cleanup."""
    return LmtpController(
        handler,
        hostname=config.lmtp_host,
        port=config.lmtp_port,
        decode_data=False,
        enable_SMTPUTF8=True,
        data_size_limit=3 * config.limits.max_bytes,
    )
