"""Pure ingress policy evaluation, independent from Postfix and milter APIs."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from email import policy as email_policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses
from enum import StrEnum
from typing import Literal

from amx.address_lists import address_listed
from amx.config import JUDGE_ACTIONS, ContentJudgeConfig, JudgeStep, LimitsConfig, TrustGrant
from amx.control import CONTROL_SCHEMA, retry_after
from amx.judge import Judgment
from amx.profile import MachinePartError, ProfileError, SchemaValidationError, parse
from amx.registry import selector_agent
from amx.tasks import valid_token

# Version of State's Python constructor contract, not the wire profile or package release.
STATE_API_VERSION = 2

RESERVED_TRANSPORT_HEADERS = frozenset(
    {
        "agent-lane",
        "agent-trust",
        "agent-verified-domain",
        "agent-verified-selector",
        "agent-content-judgment",
        "agent-taint",
        "agent-task-taint",
        "agent-task-assigned",
    }
)
JUDGMENT_HEADER = "Agent-Content-Judgment"
TAINT_HEADER = "Agent-Taint"
# PLAN §5.9: the task's taint, stamped on a remote agent's INBOX copy when the gateway files it.
TASK_TAINT_HEADER = "Agent-Task-Taint"


def is_reserved_transport_header(name: str) -> bool:
    """Return whether a header is owned exclusively by the receiving transport."""
    normalized = name.casefold()
    return normalized in RESERVED_TRANSPORT_HEADERS or normalized.startswith("agent-grant-")


class Stage(StrEnum):
    """SMTP transaction stages where AMX makes decisions."""

    CONNECT = "connect"
    MAIL = "mail"
    RCPT = "rcpt"
    EOD = "eod"


@dataclass(frozen=True, slots=True)
class Verdict:
    """A transport-neutral policy result."""

    action: Literal["accept", "tempfail", "reject"]
    rule: str
    code: str | None = None
    text: str = ""
    headers: tuple[tuple[str, str], ...] = ()
    quarantine: str | None = None

    @property
    def accepted(self) -> bool:
        """Return true for an accepted transaction."""
        return self.action == "accept"


@dataclass(frozen=True, slots=True)
class AgentState:
    """Dynamic state relevant to one recipient agent.

    ``paused_until`` and ``declared_max`` are the agent's own declaration in force (PLAN §5.10),
    read at capture time, so a lapsed one is already absent. ``oldest_untaken`` is how long the
    oldest INBOX message a remote agent's runner has not taken has waited, when the milter read
    the backlog: a liveness signal for trace, which no rule acts on.
    """

    enabled: bool = True
    depth: int = 0
    watermark: int = 2
    paused_until: float | None = None
    declared_max: int | None = None
    oldest_untaken: float | None = None

    @property
    def limit(self) -> int:
        """The effective watermark: a declaration can lower the configured one, never raise it."""
        if self.declared_max is None:
            return self.watermark
        return min(self.watermark, self.declared_max)


@dataclass(frozen=True, slots=True)
class State:
    """Read-only policy state; API v2 requires (agent, token) task pairs (SH-02)."""

    agent_domain: str
    agents: dict[str, AgentState] = field(default_factory=dict)
    known_tasks: frozenset[tuple[str, str]] = field(default_factory=frozenset)
    closed_tasks: frozenset[tuple[str, str]] = field(default_factory=frozenset)
    blocklist: frozenset[str] = field(default_factory=frozenset)
    grants: tuple[TrustGrant, ...] = ()
    limits: LimitsConfig = field(default_factory=LimitsConfig)
    greylisting: bool = False
    known_domains: frozenset[str] = field(default_factory=frozenset)
    # The control address's local part in the agent domain (PLAN §5.10); nothing from outside
    # may reach it.
    control_agent: str | None = None
    people_domain: str | None = None
    # SH-40: per agent, the senders it takes people's mail from (addresses and domains). An
    # agent missing here takes anyone's.
    accept_from: dict[str, frozenset[str]] = field(default_factory=dict)
    # SH-47: explicit None labels are the default household; missing entries fail closed for
    # own-agent mail. Built by the adapter, no I/O here.
    households: dict[str, str | None] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("known_tasks", "closed_tasks"):
            values = getattr(self, name)
            if not isinstance(values, (set, frozenset)) or any(
                not isinstance(key, tuple)
                or len(key) != 2
                or any(not isinstance(value, str) or not value for value in key)
                for key in values
            ):
                raise TypeError(
                    f"State.{name} API v2 requires a set of (agent, token) string pairs"
                )

    def grant_for(self, domain: str | None, selector: str | None, lane: str) -> TrustGrant | None:
        """Resolve a grant using only verified transport identity and lane."""
        for grant in self.grants:
            if grant.lane != lane:
                continue
            if lane == "agent" and (grant.d == "*" or grant.s == "*"):
                continue
            if not grant.names(domain, selector):  # exactly the verified agent's name (SH-44)
                continue
            return grant
        return None


@dataclass(frozen=True, slots=True)
class TxnContext:
    """Facts collected by an SMTP adapter for one policy stage."""

    client_ip: str | None = None
    connection_rate_exceeded: bool = False
    mail_from: str | None = None
    sender_domain: str | None = None
    recipient: str | None = None
    recipient_agent: str | None = None
    task_token: str | None = None
    # The sub-address token of each *agent* recipient in the transaction (a person's mailbox has
    # none and is not compared). None means the caller supplied only ``task_token``.
    recipient_task_tokens: tuple[str | None, ...] | None = None
    recipient_agents: tuple[str, ...] | None = None
    # Set by the trusted SMTP listener, never from headers or signing identity.
    sibling: bool = False
    submission: bool = False
    auth_authen: str | None = None
    # RCPT: the recipient has mail LMTP accepted, so a message to it could be a sender's retry.
    recipient_accepted_mail: bool = False
    # EOD, aligned with the agent recipients' tokens: LMTP already accepted this Message-ID for
    # that recipient (a retry). A missing entry means no.
    message_accepted: tuple[bool, ...] = ()
    raw: bytes = b""
    dkim_verified: bool = False
    dkim_domain: str | None = None
    dkim_selector: str | None = None
    identity_error: str | None = None
    # SH-40: the DKIM-verified, aligned From address of any message (people's mail included),
    # read by one strict parse (amx.identity.from_identity). None: not verified.
    sender_verified: str | None = None
    # SH-47: the own-domain agent named by a verified signature's From, even on the human
    # lane. Unlike a person's owner assertion, household isolation needs no over-signed To/Cc.
    own_agent_verified: str | None = None
    from_domain: str | None = None
    size: int = 0
    attachment_types: frozenset[str] = field(default_factory=frozenset)


def _reject(rule: str, code: str, text: str) -> Verdict:
    return Verdict("reject", rule, code, text)


def _tempfail(rule: str, code: str, text: str) -> Verdict:
    return Verdict("tempfail", rule, code, text)


def _domain_from_address(address: str | None) -> str | None:
    if not address or "@" not in address:
        return None
    return address.rpartition("@")[2].rstrip("> ").casefold()


def _addressed_agents(
    message: EmailMessage, agent_domain: str, fields: tuple[str, ...]
) -> frozenset[tuple[str, str | None]]:
    """``(agent, task token or None)`` for each agent address in ``fields``; for a malformed
    header, a sentinel that matches no recipient and names a task (so both checks refuse)."""
    names: set[tuple[str, str | None]] = set()
    domain = agent_domain.casefold()
    malformed = frozenset({("", "malformed")})
    try:
        for field_name in fields:
            for header in message.get_all(field_name, []):
                if getattr(header, "defects", None):
                    return malformed
                # Delivered-To and X-Original-To parse as unstructured text: read their
                # addresses the same way for every field.
                addresses = getattr(header, "addresses", None)
                specs = (
                    [address.addr_spec for address in addresses]
                    if addresses is not None
                    else [spec for _name, spec in getaddresses([str(header)])]
                )
                for spec in specs:
                    local, at, at_domain = spec.rpartition("@")
                    if at and local and at_domain.casefold() == domain:
                        agent, plus, token = local.partition("+")
                        names.add((agent.casefold(), token.casefold() if plus and token else None))
    except Exception:  # the stdlib header parser raises on some malformed input
        return malformed
    return frozenset(names)


def household_refusal(
    sender: str, recipients: tuple[str, ...], households: dict[str, str | None]
) -> Verdict | None:
    """Own agents need explicit, matching households, irrespective of grants or task owners."""
    if any(
        sender not in households
        or recipient not in households
        or households[sender] != households[recipient]
        for recipient in recipients
    ):
        return _reject(
            "agent-household",
            "550 5.7.1",
            "this agent takes agent mail only from its own household",
        )
    return None


def evaluate(stage: Stage, ctx: TxnContext, state: State) -> Verdict:
    """Evaluate one SMTP stage without I/O or mutation.

    Rule order follows PLAN §5.2. Adapters capture mutable database and DNS facts first and pass
    those facts in as :class:`State` and :class:`TxnContext` values.
    """
    if stage is Stage.CONNECT:
        if ctx.connection_rate_exceeded:
            return _tempfail("connect-rate", "421 4.7.0", "connection rate exceeded")
        return Verdict("accept", "connect-ok")

    if stage is Stage.MAIL:
        sender_domain = (ctx.sender_domain or _domain_from_address(ctx.mail_from) or "").casefold()
        if sender_domain in state.blocklist:
            return _reject("blocked-domain", "550 5.7.1", "sender domain blocked by policy")
        return Verdict("accept", "mail-ok")

    if stage is Stage.RCPT:
        if ctx.recipient_agent is None:
            return Verdict("accept", "non-agent-recipient")
        if state.control_agent is not None and ctx.recipient_agent == state.control_agent:
            # Only an agent's authenticated submission reaches the control address (§5.10).
            return _reject(
                "control-address", "550 5.7.1", "control address accepts only agent submission"
            )
        agent = state.agents.get(ctx.recipient_agent)
        if agent is None or not agent.enabled:
            return _reject("agent-unknown", "550 5.1.1", "unknown or disabled agent")
        if ctx.task_token is not None and not valid_token(ctx.task_token):
            # Tokens name files and rows downstream; only the minted shape is accepted (M5).
            return _reject("invalid-task-token", "550 5.1.3", "invalid task token in sub-address")
        closed = (
            ctx.task_token is not None
            and (ctx.recipient_agent, ctx.task_token) in state.closed_tasks
        )
        if closed and not ctx.recipient_accepted_mail:
            # Nothing it could be a retry of (docs/task-transitions.md D1).
            return _reject("closed-task", "550 5.1.6", "task is closed")
        if agent.paused_until is not None:
            # The agent's own pause (§5.10): no backlog to read, and the sender learns when.
            return _tempfail(
                "agent-paused",
                "450 4.2.1",
                f"agent paused, retry after {retry_after(agent.paused_until)}",
            )
        if agent.depth >= agent.limit:
            # A declared capacity binds only below the configured watermark.
            rule = "agent-watermark" if agent.depth >= agent.watermark else "agent-capacity"
            return _tempfail(rule, "450 4.2.1", "agent busy, retry")
        if closed:
            # Possibly a retry of accepted mail: end of DATA decides with the Message-ID (D2).
            return Verdict("accept", "closed-task-at-eod")
        return Verdict("accept", "recipient-ok")

    if stage is not Stage.EOD:
        raise ValueError(f"unsupported policy stage: {stage}")

    message = BytesParser(policy=email_policy.default).parsebytes(ctx.raw)
    supplied_transport_headers = [name for name in message if is_reserved_transport_header(name)]
    if supplied_transport_headers:
        return _reject(
            "reserved-transport-header",
            "550 5.7.1",
            f"sender supplied reserved transport header: {supplied_transport_headers[0]}",
        )
    is_agent_lane = message.get("Agent-Protocol") is not None
    lane = "agent" if is_agent_lane else "human"
    added_headers: list[tuple[str, str]] = [("Agent-Lane", lane)]

    owner = False
    if ctx.submission and ctx.auth_authen:
        # Compare one unambiguous parsed mailbox, never display names or a last-@ substring.
        from_headers = message.get_all("From", [])
        from_header = from_headers[0] if len(from_headers) == 1 else None
        addresses = getattr(from_header, "addresses", ())
        login = ctx.auth_authen.casefold()
        if (
            from_header is None
            or from_header.defects
            or len(addresses) != 1
            or addresses[0].addr_spec.casefold() != login
            or (ctx.mail_from or "").casefold() != login
        ):
            return _reject(
                "submission-sender-mismatch", "550 5.7.1", "From and envelope must match login"
            )
        owner = bool(
            not is_agent_lane
            and state.people_domain
            and login.rpartition("@")[2] == state.people_domain.casefold()
        )

    recipients = ctx.recipient_agents or ((ctx.recipient_agent,) if ctx.recipient_agent else ())
    if is_agent_lane:
        aligned = bool(
            ctx.dkim_verified
            and ctx.dkim_domain
            and ctx.from_domain
            and ctx.dkim_domain.casefold() == ctx.from_domain.casefold()
        )
        if not aligned:
            return _reject(
                "agent-identity",
                "550 5.7.1",
                ctx.identity_error or "agent DKIM verification or From alignment failed",
            )
        if ctx.dkim_domain and ctx.dkim_domain.casefold() == state.agent_domain.casefold():
            own = state.agents.get(selector_agent(ctx.dkim_selector or ""))
            if not ctx.sibling or own is None or not own.enabled:
                return _reject(
                    "own-agent-ingress",
                    "550 5.7.1",
                    "own agents require trusted sibling submission",
                )
            refused = household_refusal(ctx.dkim_selector or "", recipients, state.households)
            if refused is not None:
                return refused
        added_headers.extend(
            (
                ("Agent-Trust", "verified"),
                ("Agent-Verified-Domain", ctx.dkim_domain or ""),
                ("Agent-Verified-Selector", ctx.dkim_selector or ""),
            )
        )
    else:
        # SH-47 also covers own agents omitting Agent-Protocol. This address was verified by
        # the adapter's strict From parse, never by an envelope or a supplied transport header.
        sender_local, _, sender_domain = (ctx.sender_verified or "").casefold().rpartition("@")
        sender_agent = ctx.own_agent_verified or (
            sender_local.partition("+")[0] if sender_domain == state.agent_domain.casefold() else ""
        )
        if sender_agent in state.agents:
            refused = household_refusal(sender_agent, recipients, state.households)
            if refused is not None:
                return refused
        listed = [state.accept_from[a] for a in recipients if a in state.accept_from]
        # A genuine delivery or read report: an MTA's or mail client's, from the null sender.
        report = (
            message.get_content_type() == "multipart/report"
            and str(message.get_param("report-type", "", header="Content-Type")).casefold()
            in {"delivery-status", "disposition-notification"}
            and (ctx.mail_from or "").strip("<> ") == ""
        )
        if listed and report:
            # Delivery and read reports skip the list, at low trust: they reach the mailbox, and a
            # session that takes only verified external mail refuses them. Never as the owner.
            owner = False
        if listed and not report:
            # A person an agent works for (SH-40): their verified address, or a signed-in local
            # person's login, which submission already checked against From.
            signed_in = ctx.auth_authen if owner else None
            sender = (ctx.sender_verified or signed_in or "").casefold()
            if not sender or not all(address_listed(sender, entries) for entries in listed):
                return _reject(
                    "sender-not-accepted",
                    "550 5.7.1",
                    "this agent takes mail only from its listed senders, verified by DKIM",
                )
            if not signed_in:
                # The signed To/Cc must name the agent with the very task token it is delivered
                # under, and no unsigned header may name another task: a signed message cannot be
                # re-sent to an agent, or into a task, it was not written to.
                tokens = ctx.recipient_task_tokens or (ctx.task_token,)
                addressed = _addressed_agents(message, state.agent_domain, ("To", "Cc"))
                unsigned = _addressed_agents(
                    message, state.agent_domain, ("Delivered-To", "X-Original-To")
                )
                if any(
                    agent in state.accept_from
                    and (
                        (agent, token.casefold() if token else None) not in addressed
                        or any(t for _a, t in unsigned)
                    )
                    for agent, token in zip(
                        recipients, (*tokens, *([None] * len(recipients))), strict=False
                    )
                ):
                    return _reject(
                        "sender-not-accepted",
                        "550 5.7.1",
                        "a listed sender's mail must name this agent and task in its signed To/Cc",
                    )
            # The owner only of agents that all list this sender: one agent's list must not
            # make the sender the owner of a co-recipient that takes anyone's mail.
            owner = len(listed) == len(recipients)
        added_headers.append(
            ("Agent-Trust", "high" if owner else ("domain" if ctx.dkim_verified else "low"))
        )
        if owner:
            added_headers.append(("Agent-Grant-Role", "owner"))

    references = str(message.get("References", "")).split()
    received_depth = len(message.get_all("Received", []))
    from_domain = ctx.from_domain or _domain_from_address(str(message.get("From", "")))
    from_is_agent = bool(from_domain and from_domain.startswith("agents."))
    auto_submitted = str(message.get("Auto-Submitted", "")).casefold()
    if (
        len(references) > state.limits.references_depth
        or received_depth > state.limits.received_depth
        or (from_is_agent and auto_submitted != "auto-generated")
    ):
        return _reject("loop-guard", "550 5.4.6", "message loop guard exceeded")

    try:
        inbound = parse(ctx.raw)
    except (MachinePartError, SchemaValidationError, ProfileError) as error:
        return _reject("invalid-machine-part", "550 5.6.0", str(error))
    if is_agent_lane and inbound.task is not None and not valid_token(inbound.task):
        return _reject("invalid-task-token", "550 5.6.0", "Agent-Task is not a valid task token")
    if inbound.schema == CONTROL_SCHEMA:
        # A declaration is for the sender's own gateway, by submission (§5.10); no other agent
        # should ever receive one.
        return _reject("control-schema", "550 5.7.1", "control declarations are not mail")

    recipient_tokens = (
        ctx.recipient_task_tokens if ctx.recipient_task_tokens is not None else (ctx.task_token,)
    )
    if any(
        inbound.task != token
        and (inbound.task is not None or token is not None)
        and not (is_agent_lane and token is None)
        for token in recipient_tokens
    ):
        return _reject(
            "task-token-mismatch",
            "550 5.7.1",
            "Agent-Task must match every recipient subaddress token",
        )
    recipient_tokens = tuple(
        token or (inbound.task if is_agent_lane else None) for token in recipient_tokens
    )
    recipient_agents = ctx.recipient_agents or tuple(
        ctx.recipient_agent for _token in recipient_tokens
    )
    accepted = (*ctx.message_accepted, *(False for _token in recipient_tokens))
    if any(
        token is not None and (agent, token) in state.closed_tasks and not retry
        for agent, token, retry in zip(recipient_agents, recipient_tokens, accepted, strict=False)
    ):
        # New mail for a closed task. A retry of a message every recipient accepted goes on to
        # LMTP, which answers it as a duplicate (docs/task-transitions.md D3, D4).
        return _reject("closed-task", "550 5.1.6", "task is closed")

    grant = state.grant_for(ctx.dkim_domain, ctx.dkim_selector, lane)
    if is_agent_lane and (grant is None or not grant.permits(inbound.intent, inbound.schema)):
        return _reject("grant", "550 5.7.1", "intent or schema is not granted")
    if (
        is_agent_lane
        and grant is not None
        and not grant.can_open_tasks
        and any((agent, inbound.task) not in state.known_tasks for agent in recipient_agents)
    ):
        return _reject("grant", "550 5.7.1", "identity is not allowed to open tasks")
    if not is_agent_lane and grant is not None:
        added_headers.append(
            ("Agent-Grant-Can-Open-Tasks", str(owner or grant.can_open_tasks).lower())
        )
    elif owner:
        added_headers.append(("Agent-Grant-Can-Open-Tasks", "true"))

    message_size = ctx.size or len(ctx.raw)
    blocked_types = ctx.attachment_types & state.limits.blocked_attachment_types
    # Only the gateway-owned sibling path carries already size-checked submissions plus
    # signing, trace headers and a rendered text part. Match Postfix's internal headroom.
    size_limit = (3 if ctx.sibling else 1) * state.limits.max_bytes
    if message_size > size_limit or blocked_types:
        return _reject("size-or-attachment", "552 5.3.4", "message size or attachment type denied")

    sender_domain = (ctx.sender_domain or _domain_from_address(ctx.mail_from) or "").casefold()
    if (
        state.greylisting
        and sender_domain
        and sender_domain not in state.known_domains | {state.people_domain}
    ):
        return _tempfail("first-contact-greylist", "451 4.7.1", "first contact, retry later")

    return Verdict("accept", "eod-ok", headers=tuple(added_headers))


# Refusal texts name the signal so the bounce tells the sending operator what their agent emitted.
# Only content that asks the recipient to act can escalate past a grant; a judged ack, update, or
# error from a sender granted fewer intents is not smuggling anything (S15 is about requests).
ESCALATING_INTENTS = frozenset({"request"})

_JUDGE_REFUSALS = {
    "directs-recipient": ("550 5.7.1", "content directs the recipient agent"),
    "truncated": ("550 5.3.4", "message too long to check"),
    "parts-disagree": ("550 5.6.0", "text and machine parts disagree"),
    "intent-not-granted": ("550 5.7.1", "intent not granted"),
    "judge-unavailable": ("550 5.7.0", "content check unavailable"),
}
_JUDGE_DEFERRALS = {
    "judge-unavailable": ("451 4.7.0", "content check unavailable"),
}


def judgment_header(mode: str, judgment: Judgment | None, error: str | None) -> str:
    """Render every probability for the ``Agent-Content-Judgment`` header (and the journal)."""
    parts = [f"mode={mode}"]
    if judgment is not None:
        parts.append(f"model={judgment.model}")
        if judgment.directs_recipient is not None:
            parts.append(f"directs_recipient={judgment.directs_recipient:.3f}")
        if judgment.parts_agree is not None:
            parts.append(f"parts_agree={judgment.parts_agree:.3f}")
        if judgment.content_intent is not None:
            intent = judgment.content_intent
            parts.append(f"content_intent={intent.label}/{intent.confidence:.3f}")
            spread = ",".join(
                f"{label}:{probability:.3f}"
                for label, probability in sorted(intent.distribution.items())
            )
            parts.append(f"content_intent_distribution={spread}")
        parts.append(f"truncated={'yes' if judgment.truncated else 'no'}")
        parts.append(f"latency_ms={judgment.latency_ms:.0f}")
    if error is not None:
        parts.append(f"error={' '.join(error.split())[:120]}")
    return "; ".join(parts)


def judged_actions(
    judgment: Judgment | None,
    error: str | None,
    *,
    lane: str,
    grant: TrustGrant | None,
    config: ContentJudgeConfig,
) -> list[tuple[str, str]]:
    """Map each signal to its own action on this lane's ladder; return (action, reason) pairs.

    Signals are never combined: each one that crosses its own threshold contributes its action.
    """
    rules = config.rules[lane]
    if judgment is None:
        return [(rules.judge_error, "judge-unavailable")]

    def severest(steps: list[JudgeStep]) -> str | None:
        # The most severe matching step wins, whatever order the configuration lists them in.
        if not steps:
            return None
        return max((step.action for step in steps), key=JUDGE_ACTIONS.index)

    actions: list[tuple[str, str]] = []
    if judgment.directs_recipient is not None:
        action = severest(
            [
                step
                for step in rules.directs_recipient
                if judgment.directs_recipient >= step.threshold
            ]
        )
        if action is not None:
            actions.append((action, "directs-recipient"))
    if judgment.parts_agree is not None:
        action = severest(
            [step for step in rules.parts_agree if judgment.parts_agree < step.threshold]
        )
        if action is not None:
            actions.append((action, "parts-disagree"))
    intent = judgment.content_intent
    if (
        intent is not None
        and grant is not None
        and intent.label in ESCALATING_INTENTS
        and intent.confidence >= config.intent_min_confidence
        and "*" not in grant.intents
        and intent.label not in grant.intents
    ):
        actions.append((rules.intent_not_granted, "intent-not-granted"))
    if judgment.truncated:
        actions.append((rules.truncated, "truncated"))
    return [(action, reason) for action, reason in actions if action != "none"]


def apply_judgment(
    identity: Verdict,
    judgment: Judgment | None,
    error: str | None,
    *,
    mode: str,
    lane: str,
    grant: TrustGrant | None,
    config: ContentJudgeConfig,
) -> Verdict:
    """Combine the identity-only verdict with a content judgment (PLAN §5.7).

    Monotone by construction: a refused or deferred identity verdict is returned unchanged, and an
    accepted one can only gain the judgment header, gain taint, be quarantined, be deferred, or be
    refused. Nothing here can accept what identity refused, drop a header identity added, open a
    task, widen a grant, or release a hold.
    """
    if not identity.accepted or mode == "off":
        return identity
    headers = (*identity.headers, (JUDGMENT_HEADER, judgment_header(mode, judgment, error)))
    if mode == "observe":
        return replace(identity, headers=headers)
    actions = judged_actions(judgment, error, lane=lane, grant=grant, config=config)
    if not actions:
        return replace(identity, headers=headers)
    severest = max(JUDGE_ACTIONS.index(action) for action, _reason in actions)
    action = JUDGE_ACTIONS[severest]
    reasons = [reason for item, reason in actions if item == action]
    if action == "reject":
        code, text = _JUDGE_REFUSALS[reasons[0]]
        return Verdict("reject", f"content-{reasons[0]}", code, text)
    if action == "tempfail":
        code, text = _JUDGE_DEFERRALS.get(
            reasons[0], ("451 4.7.1", f"{_JUDGE_REFUSALS[reasons[0]][1]}, retry later")
        )
        return Verdict("tempfail", f"content-{reasons[0]}", code, text)
    taint = ", ".join(dict.fromkeys(reason for _item, reason in actions))
    tainted = replace(
        identity, rule=f"content-taint-{reasons[0]}", headers=(*headers, (TAINT_HEADER, taint))
    )
    if action == "quarantine":
        return replace(tainted, rule=f"content-quarantine-{reasons[0]}", quarantine=taint)
    return tainted
