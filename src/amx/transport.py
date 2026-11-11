"""The trust boundary between the milter and whatever hands a message to an agent's handler.

The milter writes its verdicts (lane, trust, verified identity, judgment, taint) as reserved
headers that no sender can supply. LMTP binds them to the parsed message before an in-process
handler runs; a remote agent's runner reads the same headers from its INBOX copy (PLAN §5.9).
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from email.message import Message

from amx.policy import JUDGMENT_HEADER, TAINT_HEADER
from amx.profile import Identity, Inbound, ProfileError, parse


@dataclass(frozen=True, slots=True)
class TransportMetadata:
    """Milter-owned identity metadata required at the trust boundary."""

    lane: str
    trust: str
    verified_domain: str | None
    verified_selector: str | None
    taint: tuple[str, ...] = ()
    judgment: str | None = None


def _single_header(message: Message, name: str, *, required: bool) -> str | None:
    values = message.get_all(name, [])
    if len(values) > 1:
        raise ProfileError(f"{name} must occur exactly once")
    if not values:
        if required:
            raise ProfileError(f"missing transport result header: {name}")
        return None
    value = str(values[0]).strip()
    if not value:
        raise ProfileError(f"empty transport result header: {name}")
    return value


def transport_metadata(message: Message) -> TransportMetadata | None:
    """Read and check the milter's verdict headers; ``None`` when a message carries none."""
    if not message.get_all("Agent-Lane", []) and not message.get_all("Agent-Trust", []):
        reserved = [
            name
            for name in message
            if name.casefold().startswith(("agent-verified-", "agent-grant-"))
            or name.casefold() in {TAINT_HEADER.casefold(), JUDGMENT_HEADER.casefold()}
        ]
        if reserved:
            raise ProfileError("incomplete transport result metadata")
        return None
    lane = _single_header(message, "Agent-Lane", required=True)
    trust = _single_header(message, "Agent-Trust", required=True)
    assert lane is not None and trust is not None
    lane = lane.casefold()
    trust = trust.casefold()

    verified_domain = _single_header(message, "Agent-Verified-Domain", required=False)
    verified_selector = _single_header(message, "Agent-Verified-Selector", required=False)
    grant_names = [name for name in message if name.casefold().startswith("agent-grant-")]
    normalized_grants = [name.casefold() for name in grant_names]
    if len(normalized_grants) != len(set(normalized_grants)):
        raise ProfileError("Agent-Grant-* transport headers must not be duplicated")

    if lane == "agent":
        if trust != "verified" or verified_domain is None or verified_selector is None:
            raise ProfileError("agent lane requires verified trust, domain, and selector")
        if grant_names:
            raise ProfileError("agent lane must not carry human Agent-Grant-* results")
    elif lane == "human":
        if trust not in {"low", "domain", "high"}:
            raise ProfileError("human lane trust must be low, domain or high")
        if trust == "high" and (
            _single_header(message, "Agent-Grant-Role", required=True) != "owner"
            or _single_header(message, "Agent-Grant-Can-Open-Tasks", required=True) != "true"
        ):
            raise ProfileError("high human trust requires the owner task grant")
        if verified_domain is not None or verified_selector is not None:
            raise ProfileError("human lane must not carry verified agent identity")
    else:
        raise ProfileError(f"invalid Agent-Lane transport result: {lane}")
    taint_value = _single_header(message, TAINT_HEADER, required=False)
    taint = tuple(item.strip() for item in (taint_value or "").split(",") if item.strip())
    judgment = _single_header(message, JUDGMENT_HEADER, required=False)
    return TransportMetadata(
        lane, trust, verified_domain, verified_selector, taint=taint, judgment=judgment
    )


def bind_transport(raw: bytes, headers: Message, recipient_tokens: set[str]) -> Inbound:
    """Parse a delivered message and bind the milter's transport results to it.

    ``recipient_tokens`` are the envelope recipients' task tokens: a person's message with no task
    of its own takes the one token it was delivered to.
    """
    inbound = parse(raw)
    metadata = transport_metadata(headers)
    if metadata is None and inbound.lane != "system":
        raise ProfileError("missing transport result metadata")
    if metadata is None:
        metadata = TransportMetadata("system", "system", None, None)
    elif metadata.lane == "agent" and inbound.protocol is None:
        raise ProfileError("agent transport lane requires an AMX profile")
    elif metadata.lane == "human" and inbound.protocol is not None:
        raise ProfileError("AMX profile requires the agent transport lane")

    if inbound.lane == "human" and inbound.task is None and len(recipient_tokens) == 1:
        inbound = replace(inbound, task=next(iter(recipient_tokens)))
    sender = inbound.sender
    if sender is not None and metadata.verified_domain:
        sender = Identity(
            address=sender.address,
            display_name=sender.display_name,
            dkim_domain=metadata.verified_domain,
            dkim_selector=metadata.verified_selector,
        )
    return replace(
        inbound,
        lane=metadata.lane,  # type: ignore[arg-type]
        trust=metadata.trust,
        sender=sender,
        tainted=bool(metadata.taint),
        taint_reasons=metadata.taint,
    )
