"""Small synchronous client SDK for authenticated AMX submission."""

from __future__ import annotations

import contextlib
import re
import smtplib
import ssl
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from types import MappingProxyType
from typing import Any
from urllib.parse import urlparse

from amx.attachments import (
    DEFAULT_MAX_BYTES,
    EXECUTABLE_TYPES,
    Attachment,
    security_parts,
    sniff_type,
)
from amx.control import CONTROL_INTENT, CONTROL_SCHEMA
from amx.profile import Inbound, Intent, TaskState, build
from amx.profile import parse as parse_profile
from amx.tasks import mint_token, valid_token

_HELD = re.compile(r"\bheld rule=(\S+)")


@dataclass(frozen=True, slots=True)
class PreparedSubmission:
    """An exact SMTP envelope and wire message, persistable before the first send."""

    sender: str
    recipients: tuple[str, ...]
    raw: bytes


@dataclass(frozen=True, slots=True)
class Sent:
    """Identifiers assigned to a successfully submitted message."""

    task: str
    message_id: str
    # The hold rule when the gateway parked the message in Outbox/Held for a person's approval.
    held: str | None = None


@dataclass(frozen=True, slots=True)
class Declared:
    """A declaration the gateway applied (PLAN §5.10): ``applied`` is its 250 reply's account,
    e.g. ``pause until=2026-09-27T12:10:00Z reason=maintenance``. ``task`` names the journal
    entry, so ``amx trace <task>`` shows it."""

    task: str
    message_id: str
    applied: str


def _reset(client: smtplib.SMTP) -> None:
    """RSET after a refusal, as ``sendmail`` does, without hiding the refusal on a disconnect."""
    with contextlib.suppress(smtplib.SMTPServerDisconnected):
        client.rset()


def _submit(client: smtplib.SMTP, sender: str, recipients: Sequence[str], raw: bytes) -> str:
    """Run MAIL/RCPT/DATA like ``sendmail`` but keep the final reply, which reports a hold."""
    code, detail = client.mail(sender)
    if code != 250:
        _reset(client)
        raise smtplib.SMTPSenderRefused(code, detail, sender)
    refused = {}
    for recipient in recipients:
        code, detail = client.rcpt(recipient)
        if code not in (250, 251):
            refused[recipient] = (code, detail)
    if len(refused) == len(recipients):
        _reset(client)
        raise smtplib.SMTPRecipientsRefused(refused)
    code, detail = client.data(raw)
    if code != 250:
        _reset(client)
        raise smtplib.SMTPDataError(code, detail)
    return detail.decode("utf-8", "replace")


class Received:
    """An inbound value bound to the agent that can reply to it."""

    def __init__(self, agent: Agent, inbound: Inbound) -> None:
        self._agent = agent
        self._inbound = inbound

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inbound, name)

    def reply(
        self,
        *,
        intent: Intent = "response",
        payload: Mapping[str, Any] | None = None,
        schema: str | None = None,
        text: str,
        task_state: TaskState = "working",
        subject: str | None = None,
        cc: str | Sequence[str] | None = None,
        prepare: Callable[[PreparedSubmission], None] | None = None,
        attachments: Sequence[Attachment] = (),
    ) -> Sent:
        """Reply in the current task and RFC 5322 thread."""
        if self._inbound.task is None:
            raise ValueError("cannot reply without a correlated task token")
        if self._inbound.sender is None:
            raise ValueError("cannot reply without a sender address")
        message = BytesParser(policy=policy.default).parsebytes(self._inbound.raw, headersonly=True)
        original_subject = str(message.get("Subject", "AMX response"))
        reply_subject = subject or (
            original_subject
            if original_subject.casefold().startswith("re:")
            else f"Re: {original_subject}"
        )
        message_id = self._inbound.thread.message_id
        if message_id is None:
            raise ValueError("cannot reply without a Message-ID")
        references = (*self._inbound.thread.references, message_id)
        return self._agent.send(
            to=self._inbound.sender.address,
            subject=reply_subject,
            intent=intent,
            task=self._inbound.task,
            task_state=task_state,
            payload=payload,
            schema=schema,
            text=text,
            cc=cc,
            in_reply_to=message_id,
            references=references,
            prepare=prepare,
            attachments=attachments,
        )


Handler = Callable[[Received], None]


class Agent:
    """Synchronous AMX agent submission and parsing client."""

    def __init__(
        self,
        address: str,
        submit_url: str,
        token: str,
        *,
        tls_ca_file: str | None = None,
        control_address: str | None = None,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ) -> None:
        parsed_address = parseaddr(address)[1]
        local, separator, domain = parsed_address.rpartition("@")
        if not separator or not local or not domain:
            raise ValueError("agent address must be an addr-spec")
        endpoint = urlparse(submit_url)
        if endpoint.scheme != "smtp" or endpoint.hostname is None:
            raise ValueError("submit_url must use smtp://host[:port]")
        self.address = parsed_address
        self.name = local.split("+", 1)[0]
        self.domain = domain
        self.submit_host = endpoint.hostname
        self.submit_port = endpoint.port or 2587
        self.token = token
        self.tls_ca_file = tls_ca_file
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        self.max_bytes = max_bytes
        # Where this agent's gateway takes its declarations: control@<its domain> unless the
        # gateway's control.address says otherwise.
        self.control_address = control_address or f"control@{domain}"
        self._handlers: dict[str, Handler] = {}
        self._task_states: dict[str, str] = {}

    @property
    def handlers(self) -> Mapping[str, Handler]:
        """Return the registered intent handlers."""
        return MappingProxyType(self._handlers)

    def on(self, intent: str) -> Callable[[Handler], Handler]:
        """Register a synchronous handler for an inbound intent."""

        def register(handler: Handler) -> Handler:
            self._handlers[intent] = handler
            return handler

        return register

    @staticmethod
    def _correlate(addresses: str | Sequence[str] | None, task: str) -> str | Sequence[str] | None:
        if addresses is None:
            return None
        values = [addresses] if isinstance(addresses, str) else list(addresses)
        correlated: list[str] = []
        for display, address in getaddresses(values):
            local, separator, domain = address.rpartition("@")
            if separator and domain.casefold().startswith("agents.") and "+" not in local:
                address = f"{local}+{task}@{domain}"
            correlated.append(f"{display} <{address}>" if display else address)
        if isinstance(addresses, str):
            return ", ".join(correlated)
        return correlated

    def send(
        self,
        *,
        to: str | Sequence[str],
        subject: str,
        intent: Intent,
        text: str,
        task: str | None = None,
        task_state: TaskState = "submitted",
        payload: Mapping[str, Any] | None = None,
        schema: str | None = None,
        cc: str | Sequence[str] | None = None,
        in_reply_to: str | None = None,
        references: Sequence[str] = (),
        prepare: Callable[[PreparedSubmission], None] | None = None,
        attachments: Sequence[Attachment] = (),
    ) -> Sent:
        """Build and submit one profile message over authenticated SMTP."""
        for attachment in attachments:
            if sniff_type(attachment.content, attachment.filename) in EXECUTABLE_TYPES:
                raise ValueError("executable attachments are refused")
        task_token = task or mint_token()
        if not valid_token(task_token):
            raise ValueError("task must be lower-case letters, digits, '_' or '-' (at most 64)")
        message = build(
            sender=self.address,
            to=self._correlate(to, task_token) or to,
            subject=subject,
            intent=intent,
            task=task_token,
            task_state=task_state,
            text=text,
            payload=payload,
            schema=schema,
            cc=self._correlate(cc, task_token),
            in_reply_to=in_reply_to,
            references=references,
            attachments=attachments,
        )
        raw = message.as_bytes(policy=policy.SMTP)
        self._check_size(raw)
        if any(part.type in EXECUTABLE_TYPES for part in security_parts(message)):
            raise ValueError("executable attachments are refused")
        recipients = [
            address
            for _display, address in getaddresses(
                [str(value) for name in ("To", "Cc") for value in message.get_all(name, [])]
            )
            if address
        ]
        envelope_from = f"{self.name}+{task_token}@{self.domain}"
        prepared = PreparedSubmission(envelope_from, tuple(recipients), raw)
        if prepare is not None:
            prepare(prepared)
        reply = self.submit_prepared(prepared)
        self._task_states[task_token] = task_state
        held = _HELD.search(reply)
        return Sent(task_token, str(message["Message-ID"]), held.group(1) if held else None)

    def submit_prepared(self, prepared: PreparedSubmission) -> str:
        """Replay persisted bytes and identifiers without generating new mail.

        This is stable client replay, not SMTP exactly-once acceptance. A lost DATA
        response is uncertain; recipient-side Message-ID dedupe is still required.
        """
        self._check_size(prepared.raw)
        message = BytesParser(policy=policy.default).parsebytes(prepared.raw)
        if any(part.type in EXECUTABLE_TYPES for part in security_parts(message)):
            raise ValueError("executable attachments are refused")
        return self._transmit(prepared.sender, prepared.recipients, prepared.raw)

    def _check_size(self, raw: bytes) -> None:
        if len(raw) > self.max_bytes:
            raise ValueError(f"encoded message exceeds limits.max_bytes={self.max_bytes}")

    def _transmit(self, envelope_from: str, recipients: Sequence[str], raw: bytes) -> str:
        """Submit over STARTTLS with this agent's token; return the final reply's text."""
        with smtplib.SMTP(self.submit_host, self.submit_port, timeout=15) as client:
            tls_context = ssl.create_default_context(cafile=self.tls_ca_file)
            client.starttls(context=tls_context)
            client.login(self.name, self.token)
            return _submit(client, envelope_from, recipients, raw)

    def declare(self, command: str, **fields: Any) -> Declared:
        """Declare this agent's own state to its gateway (PLAN §5.10), or refuse a message (§5.11).

        The message goes to the control address alone, from this agent, and the gateway applies
        it and relays nothing. ``command`` is ``pause`` (``until``: RFC 3339, ``reason``),
        ``resume``, ``capacity`` (``max``, ``ttl_seconds``), or ``refuse`` (see ``refuse``). The
        payload is validated against the control schema here first, so a malformed declaration
        never leaves the client.
        Raises the SMTP error the gateway answered, e.g. an ``until`` beyond its maximum.
        """
        task = mint_token()
        message = build(
            sender=self.address,
            to=self.control_address,
            subject=f"AMX control: {command}",
            intent=CONTROL_INTENT,
            task=task,
            task_state="completed",
            text=f"A control declaration for this agent's gateway: {command}.",
            payload={"command": command, **fields},
            schema=CONTROL_SCHEMA,
        )
        raw = message.as_bytes(policy=policy.SMTP)
        self._check_size(raw)
        reply = self._transmit(
            f"{self.name}@{self.domain}",
            [self.control_address],
            raw,
        )
        applied = reply.removeprefix("2.0.0 ").removeprefix("declared ")
        return Declared(task, str(message["Message-ID"]), applied)

    def pause(
        self,
        *,
        seconds: float | None = None,
        until: datetime | None = None,
        reason: str = "maintenance",
    ) -> Declared:
        """Pause: each RCPT to this agent gets ``450`` until ``until``, or for ``seconds`` from now
        on this host's clock. The gateway refuses a pause longer than its maximum (1 h in the
        dev stack), so a pause right at the maximum can fail by this host's clock skew."""
        if (seconds is None) == (until is None):
            raise ValueError("pass seconds or until")
        end = until if until is not None else datetime.now(UTC) + timedelta(seconds=seconds or 0)
        if end.tzinfo is None:
            raise ValueError("until must be timezone-aware")
        stamp = end.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
        return self.declare("pause", until=stamp, reason=reason)

    def resume(self) -> Declared:
        """Clear this agent's declaration: its configured watermark governs again."""
        return self.declare("resume")

    def capacity(self, maximum: int, *, ttl_seconds: int) -> Declared:
        """Take at most ``maximum`` messages at once for ``ttl_seconds`` (never more than the
        configured watermark, whatever ``maximum`` says)."""
        return self.declare("capacity", max=maximum, ttl_seconds=ttl_seconds)

    def refuse(
        self, recipient: str, message_id: str, *, status: str = "5.7.1", reason: str = "policy"
    ) -> Declared:
        """Tell the gateway this agent refuses a message it filed here (PLAN §5.11).

        ``recipient`` is the envelope recipient the gateway filed the copy for (its
        ``Delivered-To``), and ``message_id`` its Message-ID. ``status`` is ``5.7.1`` (policy),
        ``5.6.0`` (content), or ``5.3.0`` (the handler failed), and ``reason`` a token from
        ``amx.control.REFUSAL_REASONS``. The gateway bounces the message to its sender once, if
        it verified that sender, and answers a repeat without bouncing again; ``applied`` says
        which (``dsn=sent``, ``dsn=dropped why=…``, ``again``). Raises the SMTP error the gateway
        answered, e.g. ``550`` for a message it never delivered to this agent.
        """
        return self.declare(
            "refuse", recipient=recipient, message_id=message_id, status=status, reason=reason
        )

    def parse(self, raw: bytes) -> Received:
        """Parse and bind an inbound message, recording DSN/task state."""
        inbound = parse_profile(raw)
        if inbound.task is not None and inbound.task_state is not None:
            self._task_states[inbound.task] = inbound.task_state
        return Received(self, inbound)

    def dispatch(self, raw: bytes) -> Received:
        """Parse and synchronously call the handler registered for its intent."""
        received = self.parse(raw)
        handler = self._handlers.get(received.intent)
        if handler is not None:
            handler(received)
        return received

    def task_state(self, task: str) -> str | None:
        """Return the last observed local state for a task."""
        return self._task_states.get(task)


def parse(raw: bytes) -> Inbound:
    """Parse raw bytes, including DSNs mapped to failed task state."""
    return parse_profile(raw)
