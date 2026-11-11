"""Build and parse the AMX 0.1 email profile without performing I/O."""

from __future__ import annotations

import codecs
import json
import re
from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import asdict, dataclass
from datetime import datetime
from email import policy
from email.message import EmailMessage, Message
from email.parser import BytesParser
from email.utils import format_datetime, getaddresses, make_msgid, parseaddr, parsedate_to_datetime
from importlib import resources
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal, cast
from urllib.parse import urlparse

from jsonschema import Draft202012Validator, FormatChecker

from amx.attachments import (
    Attachment,
    ReceivedAttachment,
    received_attachments,
    safe_filename,
    sniff_type,
)
from amx.tasks import valid_token

PROTOCOL = "amx/0.1"
DEFAULT_CONTEXT = "https://schema.org"
SCHEMA_BASE = "https://evtmail.ai/schema/0.1/"

type Intent = Literal["request", "response", "update", "ack", "error", "event"]
type TaskState = Literal[
    "submitted", "working", "input-required", "completed", "failed", "canceled"
]
type Lane = Literal["agent", "human", "system"]

INTENTS: frozenset[str] = frozenset({"request", "response", "update", "ack", "error", "event"})
TASK_STATES: frozenset[str] = frozenset(
    {"submitted", "working", "input-required", "completed", "failed", "canceled"}
)

_SCHEMA_DIRECTORY = Path(__file__).resolve().parents[2] / "spec" / "schemas"
_MESSAGE_ID_RE = re.compile(r"<[^<>\s]+>")
_PLAIN_ADDRESS_RE = re.compile(r"[a-z0-9#$&'*+/=?^_`{|}~.-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+")
_PROFILE_REQUIRED = (
    "Message-ID",
    "Date",
    "From",
    "To",
    "Subject",
    "Agent-Protocol",
    "Agent-Intent",
    "Agent-Task",
    "Agent-Task-State",
)
_PROFILE_SINGULAR = (
    *_PROFILE_REQUIRED,
    "Auto-Submitted",
    "Agent-Schema",
    "Agent-Card",
    "Agent-Reply-By",
    "Agent-Idempotency-Key",
)


class ProfileError(ValueError):
    """The message does not conform to the AMX profile."""


class MachinePartError(ProfileError):
    """The machine-readable MIME part is malformed."""


class UnknownSchemaError(ProfileError):
    """The schema URI is not in the local registry."""


class SchemaValidationError(ProfileError):
    """The machine payload does not satisfy its declared schema."""


@dataclass(frozen=True, slots=True)
class Identity:
    """Address information asserted by the message, not a verified transport identity."""

    address: str
    display_name: str | None = None
    dkim_domain: str | None = None
    dkim_selector: str | None = None


@dataclass(frozen=True, slots=True)
class Thread:
    """RFC 5322 thread identifiers."""

    message_id: str | None
    in_reply_to: str | None
    references: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DeliveryReport:
    """The per-recipient fields of a delivery status notification."""

    action: str | None
    status: str | None
    recipient: str | None
    diagnostic: str | None


@dataclass(frozen=True, slots=True)
class DispositionReport:
    """The useful fields of a message disposition notification."""

    recipient: str | None
    original_message_id: str | None
    disposition: str | None


type Report = DeliveryReport | DispositionReport


@dataclass(frozen=True, slots=True)
class Inbound:
    """Normalized input delivered to an AMX handler."""

    intent: Intent
    task: str | None
    task_state: TaskState | None
    schema: str | None
    payload: dict[str, Any] | None
    text: str
    sender: Identity | None
    lane: Lane
    trust: str | None
    thread: Thread
    raw: bytes
    report: Report | None = None
    protocol: str | None = None
    card: str | None = None
    reply_by: str | None = None
    idempotency_key: str | None = None
    # Set by the receiving gateway's content judgment (PLAN §5.7), never by the message itself.
    tainted: bool = False
    taint_reasons: tuple[str, ...] = ()

    @property
    def attachments(self) -> tuple[ReceivedAttachment, ...]:
        """Files in MIME order, with bytes decoded on demand; not the machine payload."""
        return received_attachments(BytesParser(policy=policy.default).parsebytes(self.raw))

    @property
    def status(self) -> str | None:
        """Return a DSN enhanced status code, when this is a DSN."""
        return self.report.status if isinstance(self.report, DeliveryReport) else None

    @property
    def diagnostic(self) -> str | None:
        """Return a DSN diagnostic, when this is a DSN."""
        return self.report.diagnostic if isinstance(self.report, DeliveryReport) else None

    def as_dict(self) -> dict[str, Any]:
        """Return the stable JSON-compatible form used by the conformance corpus."""
        value = asdict(self)
        value.pop("raw")
        # Taint is a transport verdict about this delivery, not part of the message profile.
        value.pop("tainted")
        value.pop("taint_reasons")
        thread = cast(dict[str, Any], value["thread"])
        thread["references"] = list(thread["references"])
        if self.attachments:
            value["attachments"] = [part.metadata() for part in self.attachments]
        return value


def _load_schema_registry() -> Mapping[str, Mapping[str, Any]]:
    schemas: dict[str, Mapping[str, Any]] = {}
    directory = (
        _SCHEMA_DIRECTORY
        if _SCHEMA_DIRECTORY.is_dir()
        else resources.files("amx").joinpath("schemas")
    )
    paths = sorted(
        (path for path in directory.iterdir() if path.name.endswith(".json")),
        key=lambda path: path.name,
    )
    if not paths:
        raise RuntimeError(f"no local schemas found in {directory}")
    for path in paths:
        schema = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(schema, dict) or not isinstance(schema.get("$id"), str):
            raise RuntimeError(f"schema has no string $id: {path}")
        Draft202012Validator.check_schema(schema)
        schemas[schema["$id"]] = schema
    return MappingProxyType(schemas)


SCHEMA_REGISTRY = _load_schema_registry()


def _validate_payload(payload: Mapping[str, Any], schema_uri: str) -> dict[str, Any]:
    schema = SCHEMA_REGISTRY.get(schema_uri)
    if schema is None:
        raise UnknownSchemaError(f"schema {schema_uri!r} is not in the local registry")
    normalized = deepcopy(dict(payload))
    normalized.setdefault("@context", DEFAULT_CONTEXT)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(normalized), key=lambda error: list(error.absolute_path))
    if errors:
        error = errors[0]
        location = "$"
        if error.absolute_path:
            location += "".join(
                f"[{item}]" if isinstance(item, int) else f".{item}" for item in error.absolute_path
            )
        raise SchemaValidationError(f"schema validation failed at {location}: {error.message}")
    return normalized


def _checked_header(value: str, name: str) -> str:
    if "\r" in value or "\n" in value:
        raise ValueError(f"{name} must not contain a newline")
    if not value.strip():
        raise ValueError(f"{name} must not be empty")
    return value


def _address_header(value: str | Sequence[str], name: str) -> str:
    if isinstance(value, str):
        return _checked_header(value, name)
    if not value:
        raise ValueError(f"{name} must not be empty")
    return ", ".join(_checked_header(item, name) for item in value)


def _uri_header(value: str, name: str, *, http_only: bool = False) -> str:
    checked = _checked_header(value, name)
    parsed = urlparse(checked)
    if not parsed.scheme or (
        http_only and (parsed.scheme not in {"http", "https"} or not parsed.netloc)
    ):
        kind = "HTTP(S) " if http_only else ""
        raise ValueError(f"{name} must be an absolute {kind}URI")
    return checked


def _date_header(value: str, name: str) -> str:
    checked = _checked_header(value, name)
    try:
        parsedate_to_datetime(checked)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{name} must be an RFC 5322 date-time") from error
    return checked


def build(
    *,
    sender: str,
    to: str | Sequence[str],
    subject: str,
    intent: Intent,
    task: str,
    task_state: TaskState,
    text: str,
    payload: Mapping[str, Any] | None = None,
    schema: str | None = None,
    cc: str | Sequence[str] | None = None,
    reply_to: str | None = None,
    in_reply_to: str | None = None,
    references: Sequence[str] = (),
    card: str | None = None,
    reply_by: datetime | str | None = None,
    idempotency_key: str | None = None,
    message_id: str | None = None,
    date: datetime | None = None,
    attachments: Sequence[Attachment] = (),
) -> EmailMessage:
    """Build and validate an AMX 0.1 profile message.

    The function has no network or filesystem side effects. Schemas are selected only from
    :data:`SCHEMA_REGISTRY`, which is loaded from ``spec/schemas``.
    """
    if intent not in INTENTS:
        raise ValueError(f"unsupported intent: {intent}")
    if task_state not in TASK_STATES:
        raise ValueError(f"unsupported task state: {task_state}")
    sender = _checked_header(sender, "sender")
    task = _checked_header(task, "task")
    subject = _checked_header(subject, "subject")
    if not text.strip():
        raise ValueError("text must not be empty")
    if payload is None and schema is not None:
        raise ValueError("schema requires a payload")
    if payload is not None and schema is None:
        raise ValueError("payload requires a schema")
    if intent == "response" and in_reply_to is None:
        raise ValueError("response messages require in_reply_to")

    normalized_payload: dict[str, Any] | None = None
    if payload is not None:
        assert schema is not None
        normalized_payload = _validate_payload(payload, schema)

    message = EmailMessage(policy=policy.SMTP)
    message["From"] = sender
    message["To"] = _address_header(to, "to")
    if cc is not None:
        message["Cc"] = _address_header(cc, "cc")
    if reply_to is not None:
        message["Reply-To"] = _checked_header(reply_to, "reply_to")
    message["Subject"] = subject
    message["Date"] = (
        format_datetime(date) if date is not None else format_datetime(datetime.now().astimezone())
    )
    sender_domain = parseaddr(sender)[1].partition("@")[2] or None
    message["Message-ID"] = _checked_header(
        message_id if message_id is not None else make_msgid(domain=sender_domain), "message_id"
    )
    message["Auto-Submitted"] = "auto-generated"
    message["Agent-Protocol"] = PROTOCOL
    message["Agent-Intent"] = intent
    message["Agent-Task"] = task
    message["Agent-Task-State"] = task_state
    if schema is not None:
        message["Agent-Schema"] = _uri_header(schema, "schema")
    if card is not None:
        message["Agent-Card"] = _uri_header(card, "card", http_only=True)
    if reply_by is not None:
        message["Agent-Reply-By"] = (
            format_datetime(reply_by)
            if isinstance(reply_by, datetime)
            else _date_header(reply_by, "reply_by")
        )
    if idempotency_key is not None:
        message["Agent-Idempotency-Key"] = _checked_header(idempotency_key, "idempotency_key")
    if in_reply_to is not None:
        message["In-Reply-To"] = _checked_header(in_reply_to, "in_reply_to")
    if references:
        message["References"] = " ".join(
            _checked_header(reference, "references") for reference in references
        )

    message.set_content(text, charset="utf-8")
    if normalized_payload is not None:
        encoded = json.dumps(
            normalized_payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode()
        message.add_attachment(
            encoded,
            maintype="application",
            subtype="ld+json",
            disposition="inline",
            filename="payload.json",
        )
        machine = cast(Message, message.get_payload()[-1])
        machine["Content-Purpose"] = "Machine-readable"
    for attachment in attachments:
        filename = safe_filename(attachment.filename)
        declared = attachment.declared_type or sniff_type(attachment.content, filename)
        if not re.fullmatch(r"[\w!#$&^.+-]+/[\w!#$&^.+-]+", declared, flags=re.ASCII):
            raise ValueError("attachment declared_type must be a MIME type")
        maintype, subtype = declared.split("/", 1)
        if maintype.casefold() == "message" and subtype.casefold() == "rfc822":
            # RFC 2046: encapsulated mail is structured, not a base64 scalar payload.
            forwarded = BytesParser(policy=policy.SMTP).parsebytes(attachment.content)
            message.add_attachment(forwarded, filename=filename, disposition="attachment")
            continue
        if maintype.casefold() in {"message", "multipart"}:
            raise ValueError(f"unsupported structured attachment: {declared}")
        message.add_attachment(
            attachment.content,
            maintype=maintype,
            subtype=subtype,
            filename=filename,
            disposition="attachment",
            cte="base64",
        )
    return message


def _single_header(message: Message, name: str, *, required: bool = False) -> str | None:
    values = message.get_all(name, [])
    if len(values) > 1:
        raise ProfileError(f"{name} must occur at most once")
    if not values:
        if required:
            raise ProfileError(f"missing required header: {name}")
        return None
    value = str(values[0]).strip()
    if required and not value:
        raise ProfileError(f"empty required header: {name}")
    return value


def _identity(message: Message) -> Identity | None:
    sender = _single_header(message, "From")
    if sender is None:
        return None
    display_name, address = parseaddr(sender)
    if not address:
        return None
    return Identity(address=address, display_name=display_name or None)


def _message_ids(value: str | None) -> tuple[str, ...]:
    if value is None:
        return ()
    ids = tuple(_MESSAGE_ID_RE.findall(value))
    return ids or tuple(value.split())


def _thread(message: Message) -> Thread:
    message_id = _single_header(message, "Message-ID")
    in_reply_to = _single_header(message, "In-Reply-To")
    in_reply_ids = _message_ids(in_reply_to)
    return Thread(
        message_id=message_id,
        in_reply_to=in_reply_ids[-1] if in_reply_ids else in_reply_to,
        references=_message_ids(_single_header(message, "References")),
    )


def _task_from_recipients(message: Message) -> str | None:
    for header in ("To", "Delivered-To"):
        values = [str(value) for value in message.get_all(header, [])]
        for _display_name, address in getaddresses(values):
            local_part = address.rpartition("@")[0]
            _mailbox, separator, token = local_part.partition("+")
            if separator and token:
                return token
    return None


def named_addresses(
    message: Message, fields: Sequence[str] = ("From", "To", "Cc")
) -> tuple[str, ...]:
    """The lower-cased addresses ``message`` names in ``fields``, once each and in order (SH-46).

    ``message`` is parsed with the default policy. Only a dot-atom ``local@domain`` counts: a
    quoted local part, ``%``, or ``!`` is left out (submission refuses the last two, and the first
    would not compare equal). A header with a defect, or one the standard library cannot parse,
    names nobody at all, because callers grant these addresses authority to receive mail; SH-40
    already refuses a listed sender's mail whose To or Cc has one.
    """
    named: dict[str, None] = {}
    try:
        for field_name in fields:
            for header in message.get_all(field_name, []):
                if getattr(header, "defects", None):
                    return ()
                addresses = getattr(header, "addresses", None)
                specs = (
                    [address.addr_spec for address in addresses]
                    if addresses is not None
                    else [spec for _name, spec in getaddresses([str(header)])]
                )
                for spec in specs:
                    if _PLAIN_ADDRESS_RE.fullmatch(spec.casefold()):
                        named[spec.casefold()] = None
    except Exception:  # the stdlib header parser raises on some malformed input
        return ()
    return tuple(named)


def _normalize_text(value: str) -> str:
    return value.replace("\r\n", "\n").replace("\r", "\n")


def _body_parts(message: Message, *, include_files: bool = False) -> list[Message]:
    """Return outer body parts without descending into ordinary attachments."""
    parts: list[Message] = []
    pending = [message]
    while pending:
        part = pending.pop()
        if part is not message and part.get_content_disposition() == "attachment":
            continue
        if part.get_filename() and not include_files:
            continue
        if part.get_content_maintype() == "message":
            continue
        payload = part.get_payload()
        if part.is_multipart() and isinstance(payload, list):
            pending.extend(reversed([child for child in payload if isinstance(child, Message)]))
        else:
            parts.append(part)
    return parts


def _text_part(message: Message) -> str:
    for part in _body_parts(message):
        if part.get_content_type() != "text/plain":
            continue
        try:
            content = part.get_content()
        except (LookupError, UnicodeError) as error:
            raise ProfileError("text/plain part has an invalid charset or encoding") from error
        return _normalize_text(content if isinstance(content, str) else content.decode("utf-8"))
    return ""


def _machine_candidates(message: Message) -> list[Message]:
    candidates = []
    schema_uri = _single_header(message, "Agent-Schema")
    for part in _body_parts(message, include_files=True):
        if part.get_content_type() != "application/ld+json":
            continue
        if part.get_filename() not in {None, "payload.json"}:
            # A user file cannot appoint itself as the protocol payload with headers.
            # Retain compatibility with valid machine parts using noncanonical names,
            # including the duplicate-valid-payload refusal gate.
            if schema_uri is None:
                continue
            try:
                _decode_machine_part(part, schema_uri)
            except ProfileError:
                continue
        candidates.append(part)
    return candidates


def validated_machine_part(message: Message) -> Message | None:
    """Return only the actual locally schema-validated AMX payload entity, by identity."""
    if str(message.get("Agent-Protocol", "")) != PROTOCOL:
        return None
    if machine_payload(message) is None:
        return None
    return next(
        part
        for part in _machine_candidates(message)
        if str(part.get("Content-Purpose", "")).casefold() == "machine-readable"
    )


def _machine_payload(message: Message, schema_uri: str | None) -> dict[str, Any] | None:
    marked: list[Message] = []
    unmarked_ld_json = False
    for part in _machine_candidates(message):
        if part.get_content_type() != "application/ld+json":
            continue
        purpose = str(part.get("Content-Purpose", ""))
        if purpose.casefold() == "machine-readable":
            marked.append(part)
        else:
            unmarked_ld_json = True
    if len(marked) > 1:
        raise MachinePartError("a message may contain at most one machine-readable part")
    if not marked:
        if schema_uri is not None and unmarked_ld_json:
            raise MachinePartError("application/ld+json machine part lacks Content-Purpose")
        if schema_uri is not None:
            raise MachinePartError("Agent-Schema requires a machine-readable part")
        return None
    if schema_uri is None:
        raise MachinePartError("a machine-readable part requires Agent-Schema")
    return _decode_machine_part(marked[0], schema_uri)


def _decode_machine_part(part: Message, schema_uri: str) -> dict[str, Any]:
    raw_content = part.get_payload(decode=True)
    if raw_content is None:
        raise MachinePartError("machine-readable part has no decodable body")
    declared_charset = part.get_content_charset() or "utf-8"
    try:
        normalized_charset = codecs.lookup(declared_charset).name
    except LookupError as error:
        raise MachinePartError("machine-readable part must be UTF-8") from error
    if normalized_charset != "utf-8":
        raise MachinePartError("machine-readable part must be UTF-8")
    try:
        decoded = raw_content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise MachinePartError("machine-readable part must be UTF-8") from error
    try:
        payload = json.loads(decoded)
    except json.JSONDecodeError as error:
        raise MachinePartError("machine-readable part is not valid JSON") from error
    if not isinstance(payload, dict):
        raise MachinePartError("machine-readable part must be a JSON object")
    return _validate_payload(payload, schema_uri)


def machine_payload(message: Message) -> dict[str, Any] | None:
    """Validate a message's machine part against its declared ``Agent-Schema`` and return it.

    Raises a :class:`ProfileError` subclass for an unknown schema, a missing or malformed machine
    part, or a payload that fails validation. Only the local registry is consulted.
    """
    return _machine_payload(message, _single_header(message, "Agent-Schema"))


def _report_blocks(part: Message) -> list[Message]:
    payload = part.get_payload()
    if isinstance(payload, list):
        return [block for block in payload if isinstance(block, Message)]
    return []


def _report_address(value: str | None) -> str | None:
    if value is None:
        return None
    _kind, separator, address = value.partition(";")
    return address.strip() if separator else value.strip()


def _parse_dsn(message: Message) -> DeliveryReport:
    for part in message.walk():
        if part.get_content_type() != "message/delivery-status":
            continue
        blocks = _report_blocks(part)
        recipient_blocks = [block for block in blocks if block.get("Final-Recipient")]
        block = recipient_blocks[0] if recipient_blocks else (blocks[-1] if blocks else None)
        if block is not None:
            return DeliveryReport(
                action=_single_header(block, "Action"),
                status=_single_header(block, "Status"),
                recipient=_report_address(
                    _single_header(block, "Final-Recipient")
                    or _single_header(block, "Original-Recipient")
                ),
                diagnostic=_single_header(block, "Diagnostic-Code"),
            )
    return DeliveryReport(action=None, status=None, recipient=None, diagnostic=None)


def _parse_mdn(message: Message) -> DispositionReport:
    for part in message.walk():
        if part.get_content_type() != "message/disposition-notification":
            continue
        blocks = _report_blocks(part)
        block = blocks[0] if blocks else None
        if block is not None:
            return DispositionReport(
                recipient=_report_address(
                    _single_header(block, "Final-Recipient")
                    or _single_header(block, "Original-Recipient")
                ),
                original_message_id=_single_header(block, "Original-Message-ID"),
                disposition=_single_header(block, "Disposition"),
            )
    return DispositionReport(recipient=None, original_message_id=None, disposition=None)


def _report_type(message: Message) -> str | None:
    if message.get_content_type() != "multipart/report":
        return None
    value = message.get_param("report-type", header="Content-Type")
    return str(value).casefold() if value is not None else None


def parse(raw: bytes) -> Inbound:
    """Parse raw RFC 5322 bytes into a normalized :class:`Inbound` value."""
    if not isinstance(raw, bytes):
        raise TypeError("raw message must be bytes")
    message = BytesParser(policy=policy.default).parsebytes(raw)
    thread = _thread(message)
    sender = _identity(message)
    task_from_address = _task_from_recipients(message)
    report_type = _report_type(message)
    protocol = _single_header(message, "Agent-Protocol")

    if protocol is None and report_type == "delivery-status":
        return Inbound(
            intent="error",
            task=task_from_address,
            task_state="failed",
            schema=None,
            payload=None,
            text=_text_part(message),
            sender=sender,
            lane="system",
            trust=None,
            thread=thread,
            raw=raw,
            report=_parse_dsn(message),
        )
    if protocol is None and report_type == "disposition-notification":
        return Inbound(
            intent="ack",
            task=task_from_address,
            task_state=None,
            schema=None,
            payload=None,
            text=_text_part(message),
            sender=sender,
            lane="system",
            trust=None,
            thread=thread,
            raw=raw,
            report=_parse_mdn(message),
        )

    if protocol is None:
        assigned = _single_header(message, "Agent-Task-Assigned")
        if assigned is not None and (not valid_token(assigned) or task_from_address is not None):
            raise ProfileError("invalid or conflicting Agent-Task-Assigned")
        return Inbound(
            intent="response",
            task=assigned or task_from_address,
            task_state=None,
            schema=None,
            payload=None,
            text=_text_part(message),
            sender=sender,
            lane="human",
            trust=None,
            thread=thread,
            raw=raw,
        )
    for header in _PROFILE_SINGULAR:
        _single_header(message, header)
    for header in _PROFILE_REQUIRED:
        _single_header(message, header, required=True)
    if protocol != PROTOCOL:
        raise ProfileError(f"unsupported Agent-Protocol: {protocol}")
    auto_submitted = _single_header(message, "Auto-Submitted", required=True)
    if auto_submitted.casefold() != "auto-generated":
        raise ProfileError("Auto-Submitted must be auto-generated")
    intent_value = cast(str, _single_header(message, "Agent-Intent", required=True))
    if intent_value not in INTENTS:
        raise ProfileError(f"invalid Agent-Intent: {intent_value}")
    if intent_value == "response" and thread.in_reply_to is None:
        raise ProfileError("response messages require In-Reply-To")
    state_value = cast(str, _single_header(message, "Agent-Task-State", required=True))
    if state_value not in TASK_STATES:
        raise ProfileError(f"invalid Agent-Task-State: {state_value}")
    task = _single_header(message, "Agent-Task", required=True)
    schema_uri = _single_header(message, "Agent-Schema")
    card = _single_header(message, "Agent-Card")
    reply_by = _single_header(message, "Agent-Reply-By")
    try:
        if card is not None:
            card = _uri_header(card, "Agent-Card", http_only=True)
        if reply_by is not None:
            reply_by = _date_header(reply_by, "Agent-Reply-By")
    except ValueError as error:
        raise ProfileError(str(error)) from error
    text = _text_part(message)
    if not text:
        raise ProfileError("profile message requires a text/plain part")
    payload = _machine_payload(message, schema_uri)
    return Inbound(
        intent=cast(Intent, intent_value),
        task=task,
        task_state=cast(TaskState, state_value),
        schema=schema_uri,
        payload=payload,
        text=text,
        sender=sender,
        lane="agent",
        trust=None,
        thread=thread,
        raw=raw,
        protocol=protocol,
        card=card,
        reply_by=reply_by,
        idempotency_key=_single_header(message, "Agent-Idempotency-Key"),
    )
