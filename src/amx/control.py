"""An agent's declarations of its own state to its own gateway (PLAN §5.10). Pure; no I/O.

The gateway tells a remote agent about its tasks with ``Agent-Lane: system`` mail in its INBOX
(PLAN §5.9). This is the other direction: the agent tells the gateway it is paused, or can take
fewer messages at once, by mailing the reserved control address over the submission path it
already has. Submission applies the declaration and answers 250; nothing is relayed or delivered.

A declaration can only take capacity away, and it lapses on its own. The RCPT watermark becomes
``min(configured, declared)``, a pause answers ``450`` at RCPT, and every declaration expires
within the gateway's ``control.max_ttl_seconds``, so a crashed agent's last word does not outlive
it. Per-message acknowledgment stays an IMAP flag (§5.9): this is for agent-wide state, which no
single message can carry.

One command is about a single message instead (PLAN §5.11). ``refuse`` names mail the gateway
filed for the agent, by its envelope recipient and Message-ID, with a status from a short list
and a reason token, and the gateway turns it into the DSN an in-process refusal's ``550`` would
have produced. It is not agent state and never expires; ``amx.dsn`` builds the report.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from amx.profile import SCHEMA_BASE, SCHEMA_REGISTRY

CONTROL_SCHEMA = f"{SCHEMA_BASE}control.json"
# A declaration is the agent informing its gateway; it asks nobody to do work.
CONTROL_INTENT = "event"
_PROPERTIES = SCHEMA_REGISTRY[CONTROL_SCHEMA]["properties"]
COMMANDS: tuple[str, ...] = tuple(_PROPERTIES["command"]["enum"])


def _branch(command: str) -> Mapping[str, Any]:
    for branch in SCHEMA_REGISTRY[CONTROL_SCHEMA]["allOf"]:
        if branch["if"]["properties"]["command"]["const"] == command:
            return branch["then"]["properties"]
    raise KeyError(command)


# A pause's reason is one of these, never text: it shows in trace, and nowhere else.
REASONS: tuple[str, ...] = tuple(_branch("pause")["reason"]["enum"])
# A refusal's reason and status, which reach the refused message's sender in a DSN (§5.11).
REFUSAL_REASONS: tuple[str, ...] = tuple(_branch("refuse")["reason"]["enum"])
REFUSAL_STATUSES: tuple[str, ...] = tuple(_PROPERTIES["status"]["enum"])
# Starts the text of every refusal the gateway will never take (``550 5.7.1 refusal rejected:
# …``), so a runner can tell it from any other 550 5.7.1, such as a gateway too old to know the
# command, which it must keep retrying.
REFUSAL_REJECTED = "refusal rejected:"
# What each status means when a handler gives no reason of its own.
DEFAULT_REFUSAL_REASON = {"5.7.1": "policy", "5.6.0": "content", "5.3.0": "handler-failed"}


class ControlError(ValueError):
    """A control message the gateway will not apply."""


@dataclass(frozen=True, slots=True)
class Declaration:
    """One validated declaration, with its expiry on the gateway's clock (epoch seconds)."""

    command: str
    # None for resume, which clears the agent's state, and refuse, which is not agent state.
    expires_at: float | None = None
    max: int | None = None
    reason: str | None = None
    # refuse only: the filed message it names, and the status its DSN carries.
    recipient: str | None = None
    message_id: str | None = None
    status: str | None = None

    def summary(self) -> str:
        """What the gateway applied, for its 250 reply, the journal, and trace."""
        parts = [self.command]
        if self.recipient is not None:
            parts.append(f"recipient={self.recipient} message_id={self.message_id}")
        if self.status is not None:
            parts.append(f"status={self.status}")
        if self.max is not None:
            parts.append(f"max={self.max}")
        if self.expires_at is not None:
            parts.append(f"until={iso(self.expires_at)}")
        if self.reason is not None:
            parts.append(f"reason={self.reason}")
        return " ".join(parts)


def iso(epoch: float) -> str:
    """An instant as UTC ISO 8601 to the second, as trace and replies print it."""
    return datetime.fromtimestamp(epoch, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def retry_after(epoch: float) -> str:
    """The retry hint a paused agent's RCPT refusal gives any sender: the pause's end, rounded
    up to the minute, so the agent-chosen instant carries no more than minutes to a sender."""
    minute = math.ceil(epoch / 60) * 60
    return datetime.fromtimestamp(minute, UTC).strftime("%Y-%m-%dT%H:%MZ")


def _instant(value: object) -> float:
    """An RFC 3339 timestamp with its offset (the schema's pattern) as epoch seconds.

    Anything the platform cannot represent (a year 9999 instant pushed past 9999 by its offset,
    say) is a refusal like any other, never an exception that escapes the SMTP handler.
    """
    try:
        parsed = datetime.fromisoformat(str(value))
        epoch = parsed.timestamp() if parsed.tzinfo is not None else None
    except (ValueError, OverflowError, OSError) as error:
        raise ControlError(f"until is not a usable RFC 3339 timestamp: {value!r}") from error
    if epoch is None:
        raise ControlError("until must carry its UTC offset")
    return epoch


def declaration(payload: Mapping[str, Any], *, now: float, max_ttl: int) -> Declaration:
    """Turn a schema-valid control payload into what the gateway applies.

    The schema already fixed each command's fields and their types. This adds what needs the
    gateway's clock and configuration: a pause must end in the future and no later than
    ``max_ttl`` seconds from now, and a capacity must not be declared for longer. A declaration
    beyond the bound is refused, not shortened, so the agent learns it was not taken as stated.
    """
    command = str(payload.get("command"))
    if command == "resume":
        return Declaration("resume")
    if command == "refuse":
        # Whether the named message was delivered to this agent is the gateway's lookup, not
        # the payload's to say (PLAN §5.11).
        return Declaration(
            "refuse",
            reason=str(payload["reason"]),
            recipient=str(payload["recipient"]),
            message_id=str(payload["message_id"]),
            status=str(payload["status"]),
        )
    if command == "pause":
        until = _instant(payload["until"])
        # The agent's own string in the refusal: formatting an instant this far out can fail.
        if until <= now:
            raise ControlError(f"until {payload['until']} is not in the future")
        if until - now > max_ttl:
            raise ControlError(f"until {payload['until']} is more than {max_ttl} s ahead")
        return Declaration("pause", until, reason=str(payload["reason"]))
    if command == "capacity":
        ttl = int(payload["ttl_seconds"])
        if ttl > max_ttl:
            raise ControlError(f"ttl_seconds {ttl} is more than the {max_ttl} s maximum")
        return Declaration("capacity", now + ttl, max=int(payload["max"]))
    raise ControlError(f"unknown control command: {command!r}")


def refusal_status(code: str) -> str:
    """The DSN status for a handler's ``Refuse`` code: the code itself when it is one a refusal
    may carry, ``5.6.0`` for any other content code (``5.6.x``), and ``5.7.1`` otherwise. The
    short list keeps what an agent tells a sender to a few well-understood meanings."""
    if code in REFUSAL_STATUSES:
        return code
    return "5.6.0" if code.startswith("5.6.") else "5.7.1"


def refusal_reason(status: str, reason: str | None) -> str:
    """A refusal's reason token: the handler's own when it is on the list, else the status's."""
    return reason if reason in REFUSAL_REASONS else DEFAULT_REFUSAL_REASON[status]
