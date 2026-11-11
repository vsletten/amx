"""Authenticated agent submission, profile completion, signing, and reinjection."""

from __future__ import annotations

import hashlib
import hmac
import imaplib
import json
import logging
import smtplib
import sqlite3
import ssl
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from email import policy
from email.message import EmailMessage, Message
from email.parser import BytesParser
from email.utils import format_datetime, getaddresses, make_msgid
from typing import Any

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult, LoginPassword

from amx.attachments import security_parts
from amx.config import GatewayConfig
from amx.control import (
    CONTROL_INTENT,
    CONTROL_SCHEMA,
    REFUSAL_REJECTED,
    ControlError,
    Declaration,
    declaration,
)
from amx.credentials import new_secret, verify_token
from amx.dsn import BounceVerdict, bounce_verdict, build_dsn, dsn_message_id
from amx.holds import (
    HOLD_HEADER,
    HOLD_RECIPIENTS_HEADER,
    SENT_FOLDER,
    TAINTED_RULE,
    hold_queue,
    match_hold_rule,
    recipient_domain,
)
from amx.identity import sign
from amx.journal import Journal
from amx.mailbox import MailboxAppender
from amx.policy import Verdict, household_refusal, is_reserved_transport_header
from amx.profile import PROTOCOL, ProfileError, machine_payload, parse
from amx.tasks import valid_token

LOG = logging.getLogger(__name__)


class AuthenticationError(ValueError):
    """Submission credentials do not identify an enabled local agent."""


class SubmissionError(ValueError):
    """A submitted message cannot be completed safely."""


class SizeOrAttachmentRefused(SubmissionError):
    """The encoded input exceeds the lane limit or carries a blocked true type."""


class RateLimited(RuntimeError):
    """The agent reached its external-recipient ceiling for the trailing day."""


class HoldUnavailable(RuntimeError):
    """A hold rule matched but the message could not be filed in the hold queue."""


class ControlRefused(SubmissionError):
    """A message to the control address (or in its schema) that the gateway will not apply."""


class RefusalRejected(ControlRefused):
    """A well-formed ``refuse`` the gateway will never take: its text is marked, so the runner
    stops resending it and finishes the message without a bounce (PLAN §5.11)."""

    def __init__(self, text: str) -> None:
        super().__init__(f"{REFUSAL_REJECTED} {text}")


class RefusalDeferred(RuntimeError):
    """A ``refuse`` command the gateway cannot settle yet: the named copy's filing or its DSN is
    still in progress, or the agent's INBOX cannot be read (451, and the runner retries)."""


def _permanent(error: Exception) -> bool:
    """Whether the MTA refused a reinjection for good (every answer 5xx), not just for now."""
    if isinstance(error, smtplib.SMTPRecipientsRefused):
        return all(code >= 500 for code, _text in error.recipients.values())
    return isinstance(error, smtplib.SMTPResponseException) and error.smtp_code >= 500


def _transient(error: Exception) -> bool:
    """Whether a reinjection failure can pass: no connection, or an answer that is not 5xx."""
    return isinstance(error, (OSError, smtplib.SMTPException)) and not _permanent(error)


def _rfc5322(stamp: str) -> str:
    """A journal timestamp (UTC ISO 8601) as a DSN's ``Arrival-Date``."""
    return format_datetime(datetime.fromisoformat(stamp).astimezone(UTC))


@dataclass(frozen=True, slots=True)
class SubmissionResult:
    """The message and SMTP envelope passed to Postfix, or filed in the hold queue.

    ``declared`` is set instead for a control declaration, which went nowhere: what the gateway
    applied (PLAN §5.10).
    """

    raw: bytes
    envelope_from: str
    recipients: tuple[str, ...]
    held: str | None = None
    declared: str | None = None


Reinject = Callable[[str, tuple[str, ...], bytes], None]


def _permanent(error: Exception) -> bool:
    """Whether the MTA refused the reinjection for good (5xx), not for now."""
    if isinstance(error, smtplib.SMTPResponseException):
        return error.smtp_code >= 500
    if isinstance(error, smtplib.SMTPRecipientsRefused) and error.recipients:
        # The whole transaction is aborted on any refusal, so one 5xx recipient fails every retry.
        return any(code >= 500 for code, _text in error.recipients.values())
    return False


def _replace(message: Message, name: str, value: str) -> None:
    if message.get_all(name):
        del message[name]
    message[name] = value


def _machine_text(message: Message) -> str:
    for part in message.walk():
        if part.get_content_type() != "application/ld+json":
            continue
        raw = part.get_payload(decode=True)
        if raw is None:
            continue
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)
    return "Automated agent message."


def _has_plain(message: Message) -> bool:
    return any(part.get_content_type() == "text/plain" for part in message.walk())


def _header_recipients(message: Message) -> tuple[str, ...]:
    return tuple(
        address
        for _display, address in getaddresses(
            [str(value) for name in ("To", "Cc", "Bcc") for value in message.get_all(name, [])]
        )
        if address
    )


def _add_plain(message: EmailMessage, text: str) -> None:
    plain = EmailMessage(policy=policy.SMTP)
    plain.set_content(text, charset="utf-8")
    if message.is_multipart():
        payload = message.get_payload()
        assert isinstance(payload, list)
        message.set_payload([plain, *payload])
        return
    message.make_mixed()
    payload = message.get_payload()
    assert isinstance(payload, list)
    message.set_payload([plain, *payload])


class SubmissionService:
    """Complete and sign authenticated agent messages, then reinject them."""

    def __init__(
        self,
        config: GatewayConfig,
        journal: Journal,
        *,
        reinject: Reinject | None = None,
        mailbox: MailboxAppender | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        # Replaced whole when the gateway reloads its configuration (amx.reload).
        self.config = config
        self.journal = journal
        self.store = journal.store
        self.mailbox = mailbox
        self._custom_reinject = reinject
        # The injected transport hook covers both kinds for offline/testkit callers.
        # Production chooses system routing by call site, never by submitted headers or sender.
        self._reinject_system = reinject or self._smtp_reinject_system
        self.clock = clock
        # The gateway's own in-process handlers submit as their agent with a token only this
        # process knows: a registered agent's config holds a hash, not a token to hand them.
        self._internal_tokens: dict[str, str] = {}

    def _external_domains(self, recipients: tuple[str, ...]) -> frozenset[str]:
        own = {self.config.domain.casefold(), self.config.agent_domain.casefold()}
        return frozenset(
            domain
            for domain in (recipient_domain(address) for address in recipients)
            if domain and domain not in own
        )

    def _seen_domains(self, agent: str) -> frozenset[str]:
        return (
            frozenset({self.config.domain.casefold(), self.config.agent_domain.casefold()})
            | (frozenset({self.config.people_domain}) if self.config.people_domain else frozenset())
            | self.config.known_domains
            | self.store.contacted_domains(agent)
        )

    def _external_recipients(self, recipients: tuple[str, ...]) -> int:
        own = {self.config.domain.casefold(), self.config.agent_domain.casefold()}
        return sum(1 for address in recipients if recipient_domain(address) not in own | {""})

    def _not_allowlisted(
        self, agent: str, recipients: tuple[str, ...], named: frozenset[str] = frozenset()
    ) -> list[str]:
        """The outside recipients the outbound allowlist refuses (PLAN §11).

        ``named`` are the addresses the agent's owner named in this task (SH-46).
        """
        own = {self.config.domain.casefold(), self.config.agent_domain.casefold()}
        return [
            address
            for address in recipients
            if recipient_domain(address) not in own
            and not self.config.outbound_allowed(
                address, agent=agent, named=address.casefold() in named
            )
        ]

    def _household_refusal(self, agent: str, recipients: tuple[str, ...]) -> Verdict | None:
        """Normalize the same local recipient forms as sibling routing, then compare (SH-47)."""
        own_agents = []
        for address in recipients:
            local, _, domain = address.strip().strip("<>").casefold().rpartition("@")
            name = local.strip('"').partition("+")[0]
            if (
                domain.rstrip(".") == self.config.agent_domain.casefold()
                and name in self.config.agents
            ):
                own_agents.append(name)
        return household_refusal(
            agent,
            tuple(own_agents),
            {name: configured.household for name, configured in self.config.agents.items()},
        )

    def _check_households(
        self, agent: str, recipients: tuple[str, ...], task: str, *, stage: str = "submission"
    ) -> None:
        refused = self._household_refusal(agent, recipients)
        if refused is not None:
            self.store.record_policy(
                stage, refused.rule, refused.action, refused.code, task, refused.text, agent=agent
            )
            raise SubmissionError(f"{refused.rule}: {refused.text}")

    def _record_sent(self, agent: str, message_id: str, recipients: tuple[str, ...]) -> None:
        self.store.record_send(
            agent, message_id, external_recipients=self._external_recipients(recipients)
        )
        for domain in self._external_domains(recipients):
            self.store.remember_contact(agent, domain)

    def _taint_in_progress(self, agent: str) -> str | None:
        """The taint a remote agent is sending under, if any (PLAN §5.9).

        An in-process handler's ``ctx.send`` taints whatever task it sends in while it handles
        tainted mail. A remote agent sends from its own host, so the gateway reads the same fact
        from the agent's INBOX: a tainted message it has taken and not finished. A mailbox that
        cannot be read is a temporary failure (451), so the runner retries rather than sends.
        """
        configured = self.config.agents.get(agent)
        if configured is None or configured.mode != "remote":
            return None
        if self.mailbox is None:
            raise HoldUnavailable(f"no mailbox to read {agent}'s INBOX for tainted work")
        try:
            return self.mailbox.tainted_in_progress(
                f"{agent}@{self.config.agent_domain}",
                lambda task: self.store.task_taint(agent, task),
            )
        except Exception as error:
            raise HoldUnavailable(
                f"cannot read {agent}'s INBOX for tainted work: {error}"
            ) from error

    def _authorized(self, agent: str, intent: str | None, schema: str | None) -> bool:
        """Return whether the agent is enabled and its current grant covers intent and schema."""
        configured = self.config.agents.get(agent)
        grant = self.config.grant_for(self.config.agent_domain, agent, "agent")
        return bool(configured and configured.enabled and grant and grant.permits(intent, schema))

    def _identity(self, agent: str) -> str:
        return f"{self.config.agent_domain}/{agent}"

    def _sign(self, agent: str, raw: bytes) -> tuple[bytes, str]:
        """Sign with the agent's current selector's key; return the bytes and the selector."""
        config = self.config
        selector = config.selector_for(agent)
        signed = sign(
            raw,
            selector=selector,
            domain=config.agent_domain,
            private_key=config.keys_dir / f"{selector}.private.pem",
        )
        return signed, selector

    def internal_token(self, agent: str) -> str:
        """The token the gateway's own handler for ``agent`` submits with (never persisted)."""
        return self._internal_tokens.setdefault(agent, new_secret())

    def authenticate(self, agent: str, token: str) -> bool:
        """Return whether a token belongs to an enabled local agent.

        The configured token (dev agents), the token whose hash a registered agent's config
        holds, or, for an agent whose handler runs in this process, its internal token.
        """
        configured = self.config.agents.get(agent)
        if configured is None or not configured.enabled or not token:
            return False
        # Bytes: compare_digest refuses a non-ASCII str, and AUTH may carry one.
        presented = token.encode("utf-8", "surrogateescape")
        if configured.submit_token and hmac.compare_digest(
            configured.submit_token.encode(), presented
        ):
            return True
        if configured.submit_token_hash and verify_token(token, configured.submit_token_hash):
            return True
        internal = self._internal_tokens.get(agent)
        return bool(
            internal is not None
            and configured.mode != "remote"
            and hmac.compare_digest(internal.encode(), presented)
        )

    def _smtp_reinject(self, sender: str, recipients: tuple[str, ...], raw: bytes) -> None:
        for port, group in self._smtp_groups(recipients):
            self._smtp_send(sender, group, raw, port)

    def _smtp_groups(self, recipients: tuple[str, ...]) -> tuple[tuple[int, tuple[str, ...]], ...]:
        # The sibling copy must pass ingress policy before LMTP. Outside/role mail keeps
        # the ordinary unfiltered route. Split envelopes only: signed headers stay intact.
        sibling: list[str] = []
        ordinary: list[str] = []
        for recipient in recipients:
            local, _, domain = recipient.strip().strip("<>").casefold().rpartition("@")
            target = (
                sibling
                if self.config.sibling_port
                and domain.rstrip(".") == self.config.agent_domain.casefold()
                and local.strip('"').partition("+")[0] not in self.config.role_addresses
                else ordinary
            )
            target.append(recipient)
        return tuple(
            (port, tuple(group))
            for port, group in (
                (self.config.sibling_port, sibling),
                (self.config.postfix_port, ordinary),
            )
            if group
        )

    @staticmethod
    def _retry_digest(raw: bytes) -> str:
        # Transport traces and wire line endings change between authenticated retries.
        # Everything else, including all recipients (Bcc), task and payload, must match.
        message = BytesParser(policy=policy.SMTP).parsebytes(raw)
        while message.get_all("Received"):
            del message["Received"]
        return hashlib.sha256(message.as_bytes(policy=policy.SMTP)).hexdigest()

    def _outbound(
        self,
        agent: str,
        message_id: str,
        kind: str,
        input_sha256: str,
        unsigned: bytes,
        sender: str,
        recipients: tuple[str, ...],
        task: str,
        task_state: str,
        detail: str,
    ) -> bytes:
        """Resume only unacknowledged groups, using the first journaled signed bytes.

        Positive DATA receipts are checkpointed before the next group. A disconnect before
        receipt (or a crash before checkpoint) is ambiguous and remains at-least-once.
        """
        row = self.store.outbound_progress(agent, message_id, kind)
        if row is None:
            self._check_households(
                agent, recipients, task, stage="submission" if kind == "submission" else "hold"
            )
            signed, selector = self._sign(agent, unsigned)
            entry = self.journal.append(
                signed,
                direction="outbound",
                identity=self._identity(agent),
                task=task,
                message_id=message_id,
                event=kind,
                detail=f"{detail}signed d={self.config.agent_domain} s={selector}",
            )
            groups = ((0, recipients),) if self._custom_reinject else self._smtp_groups(recipients)
            self.store.prepare_outbound(
                agent, message_id, kind, input_sha256, entry.raw_sha256, json.dumps(groups)
            )
        row = self.store.outbound_progress(agent, message_id, kind)
        assert row is not None
        if row["input_sha256"] != input_sha256:
            raise SubmissionError("Message-ID replay does not match the original submission")
        signed = self.journal.raw_path(str(row["raw_sha256"])).read_bytes()
        claim = uuid.uuid4().hex
        if not self.store.claim_outbound(agent, message_id, kind, claim, self.clock()):
            raise HoldUnavailable("this submission is being sent; retry")
        try:
            row = self.store.outbound_progress(agent, message_id, kind)
            assert row is not None
            if row["completed"]:
                return signed
            # A held message was checked while its task was open; holding it may have closed it.
            named = self.store.named_recipients(agent, task, open_only=kind == "submission")
            accepted = json.loads(str(row["accepted"]))
            for index, (port, group) in enumerate(json.loads(str(row["groups"]))):
                if index in accepted:
                    continue
                # Reload may have tightened policy since submit/approval checked it.
                # Check only unsent groups; positive receipts keep their retry custody.
                self._check_households(
                    agent,
                    tuple(group),
                    task,
                    stage="submission" if kind == "submission" else "hold",
                )
                refused = self._not_allowlisted(agent, tuple(group), named)
                if refused:
                    self.store.record_policy(
                        "submission" if kind == "submission" else "hold",
                        "outbound-not-allowlisted",
                        "reject",
                        "550 5.7.1",
                        task,
                        f"{agent} to {', '.join(refused)}",
                        agent=agent,
                    )
                    raise SubmissionError(
                        f"recipient not on this gateway's outbound allowlist: {', '.join(refused)}"
                    )
                if self._custom_reinject:
                    self._custom_reinject(sender, tuple(group), signed)
                else:
                    self._smtp_send(sender, tuple(group), signed, port)
                accepted.append(index)
                self.store.checkpoint_outbound(agent, message_id, kind, claim, json.dumps(accepted))
            self.store.finish_outbound(
                agent,
                message_id,
                kind,
                claim,
                task=task,
                task_state=task_state,
                external_recipients=self._external_recipients(recipients),
                # Writing to a person the owner named (SH-46) approves that address in that task,
                # never their whole domain for every later first contact.
                domains=self._external_domains(
                    tuple(
                        address
                        for address in recipients
                        if address.casefold() not in named
                        and not self.config.own_sender_listed(agent, address)
                    )
                ),
            )
            if kind == "submission":
                self.file_sent(agent, message_id, signed)
            return signed
        finally:
            self.store.release_outbound(agent, message_id, kind, claim)

    def _smtp_reinject_system(self, sender: str, recipients: tuple[str, ...], raw: bytes) -> None:
        # Gateway-created reports already have trusted provenance. Sibling ingress would
        # reject their closed tasks or auto-replied From, preventing LMTP's system event.
        self._smtp_send(sender, recipients, raw, self.config.postfix_port)

    def _smtp_send(self, sender: str, recipients: tuple[str, ...], raw: bytes, port: int) -> None:
        accepted = False
        try:
            with smtplib.SMTP(self.config.postfix_host, port, timeout=15) as client:
                # RFC 5321 greets before MAIL; the live mailhost enforces it.
                client.ehlo_or_helo_if_needed()
                code, response = client.mail(sender)
                if not 200 <= code < 300:
                    raise smtplib.SMTPSenderRefused(code, response, sender)
                refused: dict[str, tuple[int, bytes]] = {}
                for recipient in recipients:
                    code, response = client.rcpt(recipient)
                    if not 200 <= code < 300:
                        refused[recipient] = (code, response)
                if refused:
                    client.rset()
                    raise smtplib.SMTPRecipientsRefused(refused)
                code, response = client.data(raw)
                if not 200 <= code < 300:
                    raise smtplib.SMTPDataError(code, response)
                accepted = True
        except (OSError, smtplib.SMTPException):
            # A QUIT/close failure cannot revoke the positive DATA queue receipt.
            if not accepted:
                raise

    def _is_control_address(self, address: str) -> bool:
        """Whether an address is the control address in any spelling the MTA would deliver to
        it: sub-addressed, its local part quoted, or its domain ending in a dot (PLAN §5.10).
        Such a spelling is then refused, since only the plain address is a declaration."""
        local, at, domain = address.strip().strip("<>").casefold().rpartition("@")
        return (
            bool(at)
            and domain.rstrip(".") == self.config.agent_domain.casefold()
            and local.strip('"').partition("+")[0] == self.config.control.address
        )

    def _is_control(self, parsed: Message, envelope_recipients: tuple[str, ...]) -> bool:
        """Whether a submission is a declaration: it names the control address anywhere, or it
        uses the control schema. Either way it must then pass as one or be refused. It never
        takes the ordinary path, so a control payload cannot reach a counterparty, and a message
        to the control address cannot carry mail to anyone else."""
        if str(parsed.get("Agent-Schema", "")).strip() == CONTROL_SCHEMA:
            return True
        addresses = (*_header_recipients(parsed), *envelope_recipients)
        return any(self._is_control_address(address) for address in addresses)

    def _declare(
        self,
        agent: str,
        raw: bytes,
        parsed: Message,
        envelope_from: str | None,
        envelope_recipients: tuple[str, ...],
    ) -> SubmissionResult:
        """Apply an agent's declaration of its own state (PLAN §5.10); relay and deliver nothing.

        The declaration skips hold rules, taint, rate limits, signing, and grants, and no content
        judge reads it. For a declaration of state none of them has anything to protect: nothing
        leaves the gateway, and the only effect is on the declaring agent's own admission at
        RCPT, which it can only lower, for at most ``control.max_ttl_seconds``. Every field of
        its machine part is an enum, an integer, or a timestamp, so no text of the agent's
        reaches anyone. The one value a sender ever sees, a pause's end, reaches it rounded to
        the minute. ``refuse`` is the exception: it sends a DSN, to the verified sender of one
        message filed for the agent and still unfinished, once, in the gateway's words (§5.11).
        Journaled first, then applied: a store failure after the journal answers 451, and the
        agent's retry journals it again.
        """
        now = self.clock()
        try:
            declared, task, message_id = self._read_declaration(
                agent, raw, parsed, envelope_from, envelope_recipients, now
            )
            delivery = (
                self._refused_delivery(agent, declared) if declared.command == "refuse" else None
            )
        except ControlRefused as error:
            task_header = str(parsed.get("Agent-Task", "")).strip()
            self.store.record_policy(
                "control",
                "control-refused",
                "reject",
                "550 5.7.1",
                task_header if valid_token(task_header) else None,
                str(error),
                agent=agent,
            )
            raise
        if delivery is not None:
            return self._refuse(agent, raw, declared, delivery, now)
        entry = self.journal.append(
            raw,
            direction="control",
            identity=self._identity(agent),
            task=task,
            message_id=message_id,
            event=f"control-{declared.command}",
            detail=f"agent={agent} {declared.summary()}",
        )
        if declared.command == "resume":
            self.store.clear_control(agent)
        else:
            assert declared.expires_at is not None
            self.store.declare_control(
                agent,
                declared.command,
                declared_epoch=now,
                expires_at=declared.expires_at,
                message_id=message_id,
                journal_sequence=entry.sequence,
                maximum=declared.max,
                reason=declared.reason,
            )
        summary = declared.summary()
        if declared.max is not None:
            # A declaration can lower the configured watermark, never raise it (the milter takes
            # the minimum on every RCPT); the reply says what it amounts to now.
            summary += f" effective={min(self.config.agents[agent].watermark, declared.max)}"
        own = f"{agent}@{self.config.agent_domain}"
        return SubmissionResult(raw, own, (self.config.control_address,), declared=summary)

    def _refused_delivery(self, agent: str, declared: Declaration) -> sqlite3.Row:
        """The delivery a ``refuse`` names, which must be mail filed for this remote agent (§5.11).

        The recipient is the login's agent's address (any task sub-address), and the gateway's
        own delivery record for that recipient and Message-ID is the agent's. An in-process agent
        refuses with its LMTP reply instead, and the MTA writes that bounce. Whether the copy is
        still unfinished is checked in ``_refuse``, once a repeat has been recognized.
        """
        assert declared.recipient is not None and declared.message_id is not None
        configured = self.config.agents.get(agent)
        if configured is None or configured.mode != "remote":
            raise RefusalRejected(
                "refuse is for mail filed for a remote agent; "
                "an in-process handler refuses with its LMTP reply"
            )
        local, _at, domain = declared.recipient.rpartition("@")
        if domain != self.config.agent_domain.casefold() or local.partition("+")[0] != agent:
            raise RefusalRejected(f"{declared.recipient} is not an address of {agent}")
        delivery = self.store.delivery_progress(declared.recipient, declared.message_id)
        if delivery is None or delivery["agent"] != agent or delivery["state"] == "refused":
            raise RefusalRejected(
                f"no message {declared.message_id} was delivered to {declared.recipient}"
            )
        return delivery

    def _unfinished(self, agent: str, declared: Declaration, delivery: sqlite3.Row) -> None:
        """Refuse a command unless the named copy is filed and its agent has not finished it.

        The runner reports a refusal before it sets ``$AmxHandled``, so the copy it names is still
        unfinished in the INBOX. That keeps a runner mistake or a stale replay from refusing mail
        finished long ago, whose sender's task may have completed since. (A hostile agent's own
        login can clear the flag; it could also fail that task by replying ``failed``.) LMTP
        files the copy before it records the delivery ``completed``, and a runner woken by the
        append can be faster than that write, so a delivery not yet ``completed`` whose copy is
        not in the INBOX yet answers 451.
        """
        assert declared.recipient is not None and declared.message_id is not None
        if self.mailbox is None:
            raise RefusalDeferred(f"no mailbox to read {agent}'s INBOX")
        try:
            unfinished = self.mailbox.unfinished(
                f"{agent}@{self.config.agent_domain}", declared.recipient, declared.message_id
            )
        except (OSError, imaplib.IMAP4.error, RuntimeError) as error:
            raise RefusalDeferred(f"cannot read {agent}'s INBOX: {error}") from error
        if unfinished:
            return
        if delivery["state"] != "completed":
            raise RefusalDeferred(f"{declared.message_id} is not filed yet; retry")
        raise RefusalRejected(f"{declared.message_id} is not waiting in {agent}'s INBOX")

    def _refuse(
        self,
        agent: str,
        raw: bytes,
        declared: Declaration,
        delivery: sqlite3.Row,
        now: float,
    ) -> SubmissionResult:
        """Record a remote agent's refusal of a filed message, and bounce it once (PLAN §5.11).

        The first command for a message checks that its copy is still unfinished, decides with
        ``amx.dsn.bounce_verdict`` whether its sender gets a DSN, and records the refusal. A
        repeated command (the runner's retry after a lost reply) changes nothing: the recorded
        refusal stands, and a DSN already sent or dropped is not sent again. A DSN whose
        reinjection failed for now stays pending, and the next command sends it. Both are
        journaled under the refused message's task, so ``amx trace`` shows them in its timeline.
        No task state is written, as for an in-process refusal (docs/task-transitions.md): the
        DSN fails the sender's task at the sender.
        """
        assert declared.recipient is not None and declared.message_id is not None
        assert declared.status is not None and declared.reason is not None
        recipient, refused = declared.recipient, declared.message_id
        summary = f"agent={agent} {declared.summary()}"
        existing = self.store.refusal(recipient, refused)
        again = existing is not None
        if existing is None:
            try:
                self._unfinished(agent, declared, delivery)
            except ControlRefused as error:
                self.store.record_policy(
                    "control",
                    "control-refused",
                    "reject",
                    "550 5.7.1",
                    None,
                    str(error),
                    agent=agent,
                )
                raise
            try:
                original = self.journal.raw_path(str(delivery["raw_sha256"])).read_bytes()
            except FileNotFoundError:  # the journal lost it: nothing to verify, or to return
                verdict = BounceVerdict(False, "original-unreadable")
            except OSError as error:  # EMFILE, EIO: it may read next time
                raise RefusalDeferred(f"cannot read the refused message now: {error}") from error
            else:
                verdict = bounce_verdict(
                    original,
                    delivery["envelope_from"],
                    lambda domain, selector: self.config.grant_for(domain, selector, "agent"),
                )
            dsn = "pending" if verdict.send else "dropped"
            task = self._delivered_task(delivery)
            entry = self.journal.append(
                raw,
                direction="control",
                identity=self._identity(agent),
                task=task,
                message_id=refused,
                event="control-refuse",
                detail=f"{summary} dsn={dsn} why={verdict.why}",
            )
            again = not self.store.record_refusal(
                recipient,
                refused,
                agent=agent,
                task=task,
                status=declared.status,
                reason=declared.reason,
                envelope_from=delivery["envelope_from"],
                dsn=dsn,
                why=verdict.why,
                dsn_message_id=(
                    dsn_message_id(recipient, refused, self.config.agent_domain)
                    if verdict.send
                    else None
                ),
                journal_sequence=entry.sequence,
            )
        elif existing["dsn"] != "pending":
            # A repeat of a settled refusal (its reply was lost). A repeat that retries a pending
            # DSN is journaled by that attempt instead, so an outage adds one row per attempt.
            self.journal.append(
                raw,
                direction="control",
                identity=self._identity(agent),
                task=existing["task"],
                message_id=refused,
                event="control-refuse",
                detail=f"{summary} again dsn={existing['dsn']}",
            )
        row = self.store.refusal(recipient, refused)
        assert row is not None
        if row["dsn"] == "pending":
            self._send_dsn(row, delivery, now)
            row = self.store.refusal(recipient, refused)
            assert row is not None
            if row["dsn"] == "pending":  # a 250 is final to the runner, so never with this
                raise RefusalDeferred("the DSN for this refusal is still pending; retry")
        # Kept short: a reply line carries at most 512 octets, and the recipient and Message-ID
        # (up to 254 and 250) are in the journal.
        applied = (
            f"refuse status={row['status']} reason={row['reason']} dsn={row['dsn']} "
            f"why={row['why']}{' again' if again else ''}"
        )
        own = f"{agent}@{self.config.agent_domain}"
        return SubmissionResult(raw, own, (self.config.control_address,), declared=applied)

    def _delivered_task(self, delivery: sqlite3.Row) -> str | None:
        """The task of a delivery, from its journal entry."""
        origin = self.store.rows(
            "SELECT task FROM journal WHERE sequence = ?", (delivery["journal_sequence"],)
        )
        return str(origin[0]["task"]) if origin and origin[0]["task"] else None

    def _send_dsn(self, refusal: sqlite3.Row, delivery: sqlite3.Row, now: float) -> None:
        """Send a pending refusal's DSN through the ordinary outbound path, exactly once.

        The claim makes one command the sender; one that finds a live claim answers 451, and its
        retry finds the DSN sent. The gateway-created DSN uses ordinary trusted reinjection,
        not sibling ingress, with a null envelope sender and unsigned, as the MTAs' own
        bounces are. Its bytes are the same on every attempt (dated when the refusal was
        recorded), so the journal stores them once.
        Each attempt is journaled when it ends: ``dsn`` when it was sent, ``dsn-failed`` when
        not. Only a failure that can pass (no connection, a ``4xx``) leaves the DSN pending for
        the runner's retry, with a 451. One that cannot is final, and drops the DSN with a
        ``250``: a ``5xx`` from the MTA (``reinject-refused``), or a report that cannot be built
        or sent at all (``dsn-error``). Retrying either would hold the agent's copy, and a
        watermark slot, forever.
        """
        recipient, refused = str(refusal["recipient"]), str(refusal["message_id"])
        if not self.store.claim_refusal_dsn(recipient, refused, now=now):
            current = self.store.refusal(recipient, refused)
            if current is not None and current["dsn"] == "pending":
                raise RefusalDeferred("the DSN for this refusal is being sent; retry")
            return
        outcome, why = "pending", None
        detail = (
            f"refused recipient={recipient} message_id={refused} status={refusal['status']} "
            f"reason={refusal['reason']} to=<{refusal['envelope_from']}>"
        )

        def journal(report: bytes, event: str, note: str = "") -> None:
            """Journal the attempt once it has ended. Best effort: the outcome is decided and
            settled either way, so a store that cannot take the entry never makes a DSN that
            was sent go out again."""
            try:
                self.journal.append(
                    report,
                    direction="outbound",
                    task=refusal["task"],
                    message_id=str(refusal["dsn_message_id"]),
                    event=event,
                    detail=f"{detail}{note}",
                )
            except Exception:
                LOG.exception(
                    "the %s entry for %s to %s was not journaled", event, refused, recipient
                )

        try:
            if not self.config.outbound_allowed(str(refusal["envelope_from"])):
                outcome, why = "dropped", "not-allowlisted"
                journal(detail.encode(), "dsn-failed", " sender not on the outbound allowlist")
                return
            try:
                report = self._dsn_report(refusal, delivery)
            except FileNotFoundError as error:  # the journaled original is gone for good
                outcome, why = "dropped", "original-unreadable"
                journal(detail.encode(), "dsn-failed", f" original missing, DSN dropped: {error}")
                return
            except (OSError, sqlite3.OperationalError) as error:  # may pass: stays pending
                raise RefusalDeferred(f"cannot build the DSN now: {error}") from error
            except Exception as error:  # a report that cannot be built at all
                LOG.exception("the DSN for %s to %s cannot be built", refused, recipient)
                outcome, why = "dropped", "dsn-error"
                journal(detail.encode(), "dsn-failed", f" not built, DSN dropped: {error}")
                return
            try:
                self._reinject_system("", (str(refusal["envelope_from"]),), report)
            except Exception as error:
                if _transient(error):
                    journal(report, "dsn-failed", f" reinjection failed, DSN pending: {error}")
                    raise
                outcome = "dropped"
                why = "reinject-refused" if _permanent(error) else "dsn-error"
                journal(report, "dsn-failed", f" reinjection refused, DSN dropped: {error}")
            else:
                outcome = "sent"
                journal(report, "dsn")
        finally:
            self.store.finish_refusal_dsn(recipient, refused, claimed=now, outcome=outcome, why=why)

    def _dsn_report(self, refusal: sqlite3.Row, delivery: sqlite3.Row) -> bytes:
        original = self.journal.raw_path(str(delivery["raw_sha256"])).read_bytes()
        arrival = self.store.rows(
            "SELECT created_at FROM journal WHERE sequence = ?", (delivery["journal_sequence"],)
        )
        return build_dsn(
            original=original,
            envelope_from=str(refusal["envelope_from"]),
            recipient=str(refusal["recipient"]),
            status=str(refusal["status"]),
            reason=str(refusal["reason"]),
            domain=self.config.domain,
            reporting_mta=self.config.agent_domain,
            message_id=str(refusal["dsn_message_id"]),
            arrival=_rfc5322(str(arrival[0]["created_at"])) if arrival else None,
            date=_rfc5322(str(refusal["refused_at"])),
        )

    def _read_declaration(
        self,
        agent: str,
        raw: bytes,
        parsed: Message,
        envelope_from: str | None,
        envelope_recipients: tuple[str, ...],
        now: float,
    ) -> tuple[Declaration, str, str]:
        """Check a control message strictly; return the declaration, its task, and Message-ID.

        It goes to the control address and nowhere else, comes from the authenticated agent
        itself (the declaration always applies to the login, never to a name in the message), and
        is a profile ``event`` whose machine part validates against the control schema.
        """
        control = self.config.control_address.casefold()
        addressed = {
            address.strip().strip("<>").casefold()
            for address in (*_header_recipients(parsed), *envelope_recipients)
        }
        if addressed != {control}:
            raise ControlRefused(f"a control declaration goes to {control} and nowhere else")
        own = f"{agent}@{self.config.agent_domain}".casefold()
        senders = [
            address for _display, address in getaddresses(map(str, parsed.get_all("From", [])))
        ]
        if envelope_from is not None:
            senders.append(envelope_from.strip().strip("<>"))
        if len(parsed.get_all("From", [])) != 1 or any(
            local.partition("+")[0] + at + domain != own
            for local, at, domain in (sender.casefold().rpartition("@") for sender in senders)
        ):
            raise ControlRefused(f"a control declaration must come from the login's agent, {own}")
        try:
            inbound = parse(raw)
        except ProfileError as error:
            raise ControlRefused(f"invalid control declaration: {error}") from error
        if inbound.protocol != PROTOCOL:
            raise ControlRefused("a control declaration must be an AMX profile message")
        if inbound.intent != CONTROL_INTENT:
            raise ControlRefused(f"a control declaration has Agent-Intent: {CONTROL_INTENT}")
        if inbound.schema != CONTROL_SCHEMA or inbound.payload is None:
            raise ControlRefused(f"a control declaration carries a {CONTROL_SCHEMA} machine part")
        if inbound.task is None or not valid_token(inbound.task):
            raise ControlRefused("Agent-Task must be a valid task token")
        assert inbound.thread.message_id is not None  # the profile requires one
        try:
            declared = declaration(
                inbound.payload, now=now, max_ttl=self.config.control.max_ttl_seconds
            )
        except ControlError as error:
            raise ControlRefused(str(error)) from error
        return declared, inbound.task, inbound.thread.message_id

    def submit(
        self,
        agent: str,
        token: str,
        raw: bytes,
        *,
        envelope_from: str | None = None,
        envelope_recipients: tuple[str, ...] = (),
    ) -> SubmissionResult:
        """Authenticate, fill the profile, sign, journal, and send one message.

        A message to the control address, or in the control schema, is a declaration instead:
        it is applied here and goes nowhere (PLAN §5.10). The envelope is read only to find one.
        """
        if not self.authenticate(agent, token):
            raise AuthenticationError("invalid per-agent submission credentials")
        if len(raw) > self.config.limits.max_bytes:
            raise SizeOrAttachmentRefused(
                f"size-or-attachment limits.max_bytes={self.config.limits.max_bytes}"
            )
        parsed = BytesParser(policy=policy.SMTP).parsebytes(raw)
        if any(
            part.type in self.config.limits.blocked_attachment_types
            for part in security_parts(parsed)
        ):
            raise SizeOrAttachmentRefused("size-or-attachment blocked attachment true type")
        if not isinstance(parsed, EmailMessage):
            raise SubmissionError("submission must be an email message")
        if self._is_control(parsed, envelope_recipients):
            return self._declare(agent, raw, parsed, envelope_from, envelope_recipients)
        input_sha256 = self._retry_digest(raw)
        task = str(parsed.get("Agent-Task", "")).strip()
        if not task:
            raise SubmissionError("submission requires Agent-Task")
        if not valid_token(task):
            raise SubmissionError(
                "Agent-Task must be lower-case letters, digits, '_' or '-' (at most 64)"
            )
        intent = str(parsed.get("Agent-Intent", "")).strip() or None
        schema = str(parsed.get("Agent-Schema", "")).strip() or None
        grant = self.config.grant_for(self.config.agent_domain, agent, "agent")
        if grant is None or not grant.permits(intent, schema):
            raise SubmissionError("intent or schema is not granted for this local agent")
        if not grant.can_open_tasks and self.journal.store.task(task, agent) is None:
            raise SubmissionError("local agent is not allowed to open tasks")
        address = f"{agent}+{task}@{self.config.agent_domain}"
        _replace(parsed, "From", address)
        _replace(parsed, "Reply-To", address)
        _replace(parsed, "Auto-Submitted", "auto-generated")
        _replace(parsed, "Agent-Protocol", PROTOCOL)
        if parsed.get("Date") is None:
            parsed["Date"] = format_datetime(datetime.now().astimezone())
        if parsed.get("Message-ID") is None:
            parsed["Message-ID"] = make_msgid(domain=self.config.agent_domain)
        if not _has_plain(parsed):
            _add_plain(parsed, _machine_text(parsed))
        try:
            machine_payload(parsed)
        except ProfileError as error:
            raise SubmissionError(f"invalid machine part: {error}") from error

        recipients = _header_recipients(parsed)
        if not recipients:
            raise SubmissionError("submission requires a To, Cc, or Bcc recipient")
        for recipient in recipients:
            # Holds and limits judge the domain after the last "@". Refuse every form Postfix
            # could route elsewhere: a bare local part (qualified or percent-hacked), user%host,
            # host!user, and a quoted "@" in the local part.
            local, at, domain = recipient.rpartition("@")
            if (
                not at
                or not local
                or not domain
                or any(c in recipient for c in "%!")
                or "@" in local
            ):
                raise SubmissionError(f"unsupported recipient address: {recipient}")
        if parsed.get_all("Bcc"):
            del parsed["Bcc"]
        # The :10025 reinjection path has no milter, so nothing downstream strips headers that
        # only the receiving transport may write (lane, trust, verified identity, judgment,
        # taint); an agent must never be able to supply them.
        stripped = {name for name in parsed if is_reserved_transport_header(name)}
        for name in stripped | {HOLD_HEADER, HOLD_RECIPIENTS_HEADER}:
            while parsed.get_all(name):
                del parsed[name]
        message_id = str(parsed["Message-ID"])
        unsigned = parsed.as_bytes(policy=policy.SMTP)

        # A retry of a message already sent, or already waiting for a person, is answered as it
        # was the first time, before any policy that may have changed since (a reload, or the
        # task that very message closed, SH-46): nothing goes out or waits twice, and the sender
        # is not told it was refused.
        progress = self.store.outbound_progress(agent, message_id, "submission")
        if progress is not None:
            if progress["input_sha256"] != input_sha256:
                raise SubmissionError("Message-ID replay does not match the original submission")
            if progress["completed"]:
                signed = self.journal.raw_path(str(progress["raw_sha256"])).read_bytes()
                return SubmissionResult(signed, address, recipients)
        held = self.store.hold(message_id)
        if (
            held is not None
            and held["agent"] == agent
            and held["raw_sha256"] == hashlib.sha256(unsigned).hexdigest()
            # Bcc is not in the unsigned copy: the envelope must be the held one too.
            and json.loads(str(held["recipients"])) == list(recipients)
        ):
            return SubmissionResult(unsigned, address, recipients, held=str(held["rule"]))
        # The people the agent's owner put on this task's thread (SH-46): no allowlist entry and
        # no first-contact hold stands between the agent and them.
        self._check_households(agent, recipients, task)
        named = self.store.named_recipients(agent, task)
        refused = self._not_allowlisted(agent, recipients, named)
        if refused:
            self.store.record_policy(
                "submission",
                "outbound-not-allowlisted",
                "reject",
                "550 5.7.1",
                task,
                f"{agent} to {', '.join(refused)}",
                agent=agent,
            )
            # Before holds and limits: nothing waits for an approval that could not send it.
            raise SubmissionError(
                f"recipient not on this gateway's outbound allowlist: {', '.join(refused)}"
            )
        task_state = str(parsed.get("Agent-Task-State", "submitted")).strip() or "submitted"

        external = self._external_recipients(recipients)
        ceiling = self.config.external_per_day(agent)
        if external > ceiling:
            raise SubmissionError(
                f"{external} external recipients exceed the {ceiling} per day ceiling"
            )
        if external and self.store.external_sends_last_day(agent) + external > ceiling:
            raise RateLimited(f"external rate limit reached: {ceiling} recipients per day")

        if not self.store.task_taint(agent, task):
            in_progress = self._taint_in_progress(agent)
            if in_progress:
                self.store.taint_task(agent, task, (in_progress,))
        # Produced while handling tainted content: a person approves it, whatever the rules say.
        rule = (
            TAINTED_RULE
            if self.store.task_taint(agent, task)
            else match_hold_rule(
                self.config.hold_rules,
                agent=agent,
                intent=intent,
                schema=schema,
                recipient_domains=frozenset(
                    recipient_domain(address)
                    for address in recipients
                    if address.casefold() not in named
                    and not self.config.own_sender_listed(agent, address)
                ),
                seen_domains=self._seen_domains(agent),
            )
        )
        if rule is not None:
            if progress is not None:
                raise HoldUnavailable(
                    "pending submission now requires a hold; remaining groups not sent"
                )
            return self._hold(
                agent, task, task_state, rule, address, recipients, unsigned, message_id
            )

        signed = self._outbound(
            agent,
            message_id,
            "submission",
            input_sha256,
            unsigned,
            address,
            recipients,
            task,
            task_state,
            "",
        )
        return SubmissionResult(signed, address, recipients)

    def file_sent(self, agent: str, message_id: str, signed: bytes) -> None:
        """File the sent copy in the agent's Sent folder, as a mail client would.

        Best effort: the message is already on its way, so a failed append is only logged. A held
        message reaches Sent when it is released: holdwatch moves the approved copy there, or,
        when the hold queue is in another mailbox, files the signed copy through here.
        """
        if self.mailbox is None:
            return
        try:
            self.mailbox.append(f"{agent}@{self.config.agent_domain}", signed, folder=SENT_FOLDER)
        except Exception as error:
            LOG.warning("sent %s but could not file it in %s: %s", message_id, SENT_FOLDER, error)

    def _hold(
        self,
        agent: str,
        task: str,
        task_state: str,
        rule: str,
        envelope_from: str,
        recipients: tuple[str, ...],
        unsigned: bytes,
        message_id: str,
    ) -> SubmissionResult:
        """File an unsigned message in the agent's hold queue instead of sending it.

        The queue is the agent's Outbox/Held unless ``mailbox.hold_owner`` puts it in another
        mailbox (PLAN §5.8). The Held copy names every envelope recipient (Bcc included), because
        the person approving it must see exactly who it goes to. The hold is committed before the
        copy is exposed in IMAP, and removed again if the copy cannot be filed.
        """
        if self.mailbox is None:
            raise SubmissionError(f"hold rule {rule} matched but no hold queue is configured")
        if self.store.hold(message_id) is not None:
            raise SubmissionError(f"Message-ID is already in the hold queue: {message_id}")
        held_copy = (
            f"{HOLD_HEADER}: {rule}\r\n{HOLD_RECIPIENTS_HEADER}: {',\r\n '.join(recipients)}\r\n"
        ).encode() + unsigned
        queue = hold_queue(self.config, agent)
        entry = self.journal.append(
            unsigned,
            direction="outbound",
            identity=self._identity(agent),
            task=task,
            message_id=message_id,
            event="held",
            detail=f"rule={rule} folder={queue.held} recipients={len(recipients)}",
        )
        self.store.put_hold(
            message_id=message_id,
            agent=agent,
            task=task,
            rule=rule,
            envelope_from=envelope_from,
            recipients=recipients,
            raw_sha256=entry.raw_sha256,
            held_sha256=hashlib.sha256(held_copy).hexdigest(),
        )
        try:
            self.mailbox.append(queue.mailbox, held_copy, folder=queue.held)
        except Exception as error:
            self.store.delete_hold(message_id)
            self.journal.append(
                unsigned,
                direction="outbound",
                identity=self._identity(agent),
                task=task,
                message_id=message_id,
                event="hold-aborted",
                detail=f"rule={rule} could not be filed in {queue.held}: {error}",
            )
            raise HoldUnavailable(f"cannot file in {queue.held}: {error}") from error
        self.store.put_task(task, agent, task_state)
        return SubmissionResult(unsigned, envelope_from, recipients, held=rule)

    def _return_hold(self, agent: str, message_id: str) -> None:
        # Once any group is accepted, rejection must not claim that nothing was sent.
        progress = self.store.outbound_progress(agent, message_id, "released")
        if progress is None or (
            not progress["claim"] and not json.loads(str(progress["accepted"]))
        ):
            self.store.transition_hold(message_id, "held", from_state="releasing")

    def release(self, agent: str, message_id: str) -> SubmissionResult | None:
        """Claim a held message, sign it now, journal it, reinject it, and mark it released.

        The bytes sent are the gateway's journaled copy, never the IMAP copy the person moved:
        the folder move is only the approval signal. The claim (``held`` → ``releasing``) is
        atomic, so a concurrent rejection cannot also succeed. Failure before any accepted group
        returns to ``held``; a partial send stays ``releasing`` and retries only remaining groups.
        A crashed send with no receipt/checkpoint remains ambiguous (at-least-once).
        Returns ``None`` for a message this agent has no pending hold for, or when the agent's
        current configuration no longer authorizes it. The approval overrides the rate ceiling.
        """
        hold = self.store.hold(message_id)
        if hold is None or hold["agent"] != agent:
            return None
        if hold["state"] == "held":
            if not self.store.transition_hold(message_id, "releasing"):
                return None
        elif hold["state"] != "releasing":
            return None
        try:
            prepared = self._prepare_release(agent, message_id, hold)
        except Exception:
            self._return_hold(agent, message_id)
            raise
        if prepared is None:
            pending = self.store.hold(message_id)
            if pending is not None and pending["state"] == "releasing":
                raise HoldUnavailable(
                    "partially sent approval is no longer authorized; retry later"
                )
            return None
        unsigned, envelope_from, recipients = prepared
        try:
            signed = self._outbound(
                agent,
                message_id,
                "released",
                str(hold["raw_sha256"]),
                unsigned,
                envelope_from,
                recipients,
                str(hold["task"]),
                "",
                f"rule={hold['rule']} approved; ",
            )
        except Exception as error:
            self._return_hold(agent, message_id)
            self.journal.append(
                unsigned,
                direction="outbound",
                identity=self._identity(agent),
                task=str(hold["task"]),
                message_id=message_id,
                event="release-failed",
                detail=f"reinjection failed, release pending: {error}",
            )
            raise
        # Sent. From here a failure must leave the hold "releasing" (a rejection would then
        # tell the agent a sent message was not sent); the Approved scan redrives it.
        return SubmissionResult(signed, envelope_from, recipients)

    def _prepare_release(
        self, agent: str, message_id: str, hold: sqlite3.Row
    ) -> tuple[bytes, str, tuple[str, ...]] | None:
        """Re-check authority and read the approved, immutable journaled copy."""
        unsigned = self.journal.raw_path(str(hold["raw_sha256"])).read_bytes()
        headers = BytesParser(policy=policy.default).parsebytes(unsigned, headersonly=True)
        intent = str(headers.get("Agent-Intent", "")).strip() or None
        schema = str(headers.get("Agent-Schema", "")).strip() or None
        if not self._authorized(agent, intent, schema):
            self._return_hold(agent, message_id)
            self.store.record_policy(
                "hold",
                "hold-release-denied",
                "ignore",
                None,
                str(hold["task"]),
                f"{agent} is disabled or no longer granted {intent} {schema or ''}".rstrip(),
            )
            return None
        recipients = tuple(str(value) for value in json.loads(str(hold["recipients"])))
        household = self._household_refusal(agent, recipients)
        if household is not None:
            self._return_hold(agent, message_id)
            self.store.record_policy(
                "hold",
                household.rule,
                "ignore",
                household.code,
                str(hold["task"]),
                household.text,
                agent=agent,
            )
            return None
        refused = self._not_allowlisted(
            agent,
            recipients,
            # Holding the message may have closed its task (its own Agent-Task-State); the
            # owner's naming it was submitted under still stands.
            self.store.named_recipients(agent, str(hold["task"]), open_only=False),
        )
        if refused:  # the allowlist changed while the message waited
            self._return_hold(agent, message_id)
            self.store.record_policy(
                "hold",
                "hold-release-denied",
                "ignore",
                None,
                str(hold["task"]),
                f"not on the outbound allowlist: {', '.join(refused)}",
            )
            return None
        return unsigned, str(hold["envelope_from"]), recipients

    def reject(self, agent: str, message_id: str) -> sqlite3.Row | None:
        """Mark a held message rejected and its task canceled; return the hold row once."""
        hold = self.store.hold(message_id)
        if hold is None or hold["agent"] != agent:
            return None
        if not self.store.transition_hold(message_id, "rejected"):
            return None
        task = str(hold["task"])
        self.store.put_task(task, agent, "canceled")
        unsigned = self.journal.raw_path(str(hold["raw_sha256"])).read_bytes()
        self.journal.append(
            unsigned,
            direction="outbound",
            identity=self._identity(agent),
            task=task,
            message_id=message_id,
            event="hold-rejected",
            detail=f"rule={hold['rule']} rejected; task_state=canceled",
        )
        return hold


class SubmissionHandler:
    """aiosmtpd hooks for one authenticated submission endpoint."""

    def __init__(self, service: SubmissionService) -> None:
        self.service = service

    def authenticator(
        self,
        _server: Any,
        _session: Any,
        _envelope: Any,
        mechanism: str,
        auth_data: Any,
    ) -> AuthResult:
        """Validate AUTH PLAIN/LOGIN against the static per-agent token."""
        if mechanism not in {"PLAIN", "LOGIN"} or not isinstance(auth_data, LoginPassword):
            return AuthResult(success=False, handled=False)
        agent = auth_data.login.decode("utf-8", errors="replace")
        token = auth_data.password.decode("utf-8", errors="replace")
        if not self.service.authenticate(agent, token):
            return AuthResult(success=False, handled=False)
        return AuthResult(success=True, auth_data=(agent, token))

    async def handle_DATA(self, _server: Any, session: Any, envelope: Any) -> str:
        """Process one fully authenticated SMTP transaction."""
        credentials = session.auth_data
        if not isinstance(credentials, tuple) or len(credentials) != 2:
            return "530 5.7.0 authentication required"
        agent, token = credentials
        try:
            result = self.service.submit(
                agent,
                token,
                bytes(envelope.original_content),
                envelope_from=getattr(envelope, "mail_from", None),
                envelope_recipients=tuple(getattr(envelope, "rcpt_tos", ()) or ()),
            )
        except SizeOrAttachmentRefused as error:
            return f"552 5.3.4 {error}"
        except (AuthenticationError, SubmissionError) as error:
            return f"550 5.7.1 {error}"
        except RateLimited as error:
            return f"450 4.7.1 {error}"
        except (HoldUnavailable, RefusalDeferred) as error:
            return f"451 4.3.0 {error}"
        except sqlite3.OperationalError as error:
            # Locked past its busy timeout, full, read-only: retryable, as at LMTP (PLAN §8).
            return f"451 4.3.0 gateway store unavailable: {error}"
        except (OSError, smtplib.SMTPException) as error:
            if _permanent(error):
                # e.g. 552 message too large after signing: a retry would fail the same way.
                return f"554 5.3.0 reinjection refused: {error}"
            return f"451 4.3.0 reinjection failed: {error}"
        if result.declared is not None:
            return f"250 2.0.0 declared {result.declared}"
        if result.held is not None:
            queue = hold_queue(self.service.config, agent)
            where = "" if queue.own else f" mailbox={queue.mailbox}"
            return f"250 2.0.0 held rule={result.held} folder={queue.held}{where}"
        return "250 2.0.0 submitted"


def controller(
    service: SubmissionService, *, tls_context: ssl.SSLContext | None = None
) -> Controller:
    """Build the independently threaded submission controller."""
    cert = service.config.submission_tls_cert
    key = service.config.submission_tls_key
    if cert is None or key is None:
        raise ValueError("submission TLS certificate and key are required")
    if tls_context is None:
        tls_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        tls_context.load_cert_chain(cert, key)
    handler = SubmissionHandler(service)
    return Controller(
        handler,
        hostname=service.config.submission_host,
        port=service.config.submission_port,
        decode_data=False,
        enable_SMTPUTF8=True,
        # The ingress limit, not aiosmtpd's 32 MiB: larger mail would fail at reinjection.
        data_size_limit=service.config.limits.max_bytes,
        auth_required=True,
        auth_require_tls=True,
        require_starttls=True,
        tls_context=tls_context,
        authenticator=handler.authenticator,
    )
