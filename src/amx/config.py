"""Typed YAML configuration for an AMX gateway."""

from __future__ import annotations

import os
import re
import string
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml

from amx import domain_dkim
from amx.address_lists import address_listed, parse_outbound_allowlist
from amx.attachments import DEFAULT_BLOCKED_TYPES
from amx.credentials import is_token_hash
from amx.judge import CHECKS, DEFAULT_MODEL, JudgeBackendConfig
from amx.registry import check_household, check_selector, read_grants, read_registrations

# sync: LMTP's 250 means the handler ran; queued: it is in the gateway's work queue; remote: it
# is filed in the agent's INBOX, and a runner on the agent's own host takes it from there (§5.9).
HANDLER_MODES = frozenset({"sync", "queued", "remote"})
JUDGE_MODES = ("off", "observe", "enforce")  # ordered from least to most strict
JUDGE_ACTIONS = ("none", "taint", "quarantine", "tempfail", "reject")  # least to most severe
LANES = ("agent", "human")


@dataclass(frozen=True, slots=True)
class AgentConfig:
    """Configuration for one agent: hosted in the gateway, or remote (its handler elsewhere)."""

    handler: str
    mode: Literal["sync", "queued", "remote"] = "sync"
    watermark: int = 2
    workers: int = 1
    enabled: bool = True
    # The dev agents carry a plaintext token; a registered agent only its hash (PLAN §5.2).
    submit_token: str | None = None
    submit_token_hash: str | None = None
    external_per_day: int | None = None
    content_judge_mode: str | None = None
    # The DKIM selector the gateway signs with: the agent's name, or "<name>.k<N>" once
    # `amx agent rotate --activate` moved it to a new key. None means the name.
    selector: str | None = None
    # Registry revocation/rotation remains authoritative for registered agents;
    # YAML agents instead publish exactly their configured selector locally.
    registered: bool = False
    # SH-40: whose people's mail this agent takes (addresses and domains). None: the gateway's
    # ``accept_from``; an empty set: anyone's, as before SH-40.
    accept_from: frozenset[str] | None = None
    household: str | None = None
    outbound_allowlist: frozenset[str] | None = None

    def __post_init__(self) -> None:
        check_household(self.household, self.accept_from)


@dataclass(frozen=True, slots=True)
class TrustGrant:
    """Capabilities granted to a verified identity or the human lane."""

    d: str = "*"
    s: str = "*"
    lane: Literal["agent", "human"] = "agent"
    intents: frozenset[str] = field(default_factory=frozenset)
    schemas: frozenset[str] = field(default_factory=frozenset)
    can_open_tasks: bool = False
    trust: str = "verified"

    def names(self, domain: str | None, agent: str | None) -> bool:
        """Whether this grant's ``(d, s)`` covers a verified identity.

        Since SH-44 the identity is the agent's name, the signed From address's local part
        (:func:`amx.identity.verify`), and ``s`` names it exactly. A key rotation, the domain's
        or an agent's own, never changes it, so no counterparty needs a new grant. No suffix is
        stripped here: a local part such as ``planner.k2`` is chosen by the sender, not by the
        domain's DNS, and must not stand for ``planner``.
        """
        domain_matches = self.d == "*" or self.d == domain
        return domain_matches and (self.s == "*" or (agent is not None and self.s == agent))

    def permits(self, intent: str | None, schema: str | None) -> bool:
        """Return whether the intent and schema are within this grant."""
        intent_allowed = intent is not None and ("*" in self.intents or intent in self.intents)
        schema_allowed = schema is None or "*" in self.schemas or schema in self.schemas
        return intent_allowed and schema_allowed


@dataclass(frozen=True, slots=True)
class LimitsConfig:
    """Ingress limits used by the pure policy evaluator."""

    references_depth: int = 100
    received_depth: int = 25
    max_bytes: int = 10 * 1024 * 1024
    external_per_day: int = 10
    blocked_attachment_types: frozenset[str] = field(default_factory=lambda: DEFAULT_BLOCKED_TYPES)

    def __post_init__(self) -> None:
        # Older shipped YAML names PE files x-msdownload. Keep that configuration
        # effective against the canonical byte-sniffed type, never the declaration.
        if "application/x-msdownload" in self.blocked_attachment_types:
            object.__setattr__(
                self,
                "blocked_attachment_types",
                self.blocked_attachment_types | {"application/vnd.microsoft.portable-executable"},
            )


@dataclass(frozen=True, slots=True)
class HoldRule:
    """One outbound hold rule; every condition present in ``when`` must match."""

    name: str
    recipient_domain_seen: bool | None = None
    schema_regex: str | None = None
    intents: frozenset[str] = field(default_factory=frozenset)
    agents: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True, slots=True)
class JudgeStep:
    """One rung of a signal's ladder: act when the probability crosses ``threshold``."""

    threshold: float
    action: str


@dataclass(frozen=True, slots=True)
class LaneRules:
    """How each judged signal maps to an action on one lane (PLAN §5.7 verdict ladder).

    Each signal has its own ladder; the gateway takes the most severe resulting action. Signals
    are never combined into a conjunction.
    """

    directs_recipient: tuple[JudgeStep, ...]  # act when the probability is >= threshold
    parts_agree: tuple[JudgeStep, ...]  # act when the probability is < threshold
    intent_not_granted: str  # when the content asks for something the sender's grant lacks
    judge_error: str  # when the judge is unavailable
    truncated: str = "taint"  # when part of the message was cut before judging (unseen content)


DEFAULT_LANE_RULES = {
    # Fitted on the live jev-1.13.0 dev split in production request shape (PLAN §5.7 records the
    # data): injections scored 0.68-0.99, ordinary and firm legitimate requests 0.02-0.04.
    # Refusal at even odds, taint near the log-odds midpoint. parts_agree, rechecked after M5 on
    # production-shaped agent messages and a real S11 rerun: agreeing 0.70-0.96, disagreeing
    # 0.01-0.12 except the identifier-versus-label miss documented in PLAN §5.7. The 0.2 line
    # separates the remaining cases. A tainted message still has every reply held.
    "agent": LaneRules(
        directs_recipient=(JudgeStep(0.5, "reject"), JudgeStep(0.2, "taint")),
        parts_agree=(JudgeStep(0.2, "reject"),),
        intent_not_granted="reject",
        judge_error="tempfail",
        truncated="taint",
    ),
    # People may write odd mail: they are never bounced or hidden by default. Taint lets the
    # agent read and answer, and every answer waits in Outbox/Held for a person (S13).
    "human": LaneRules(
        directs_recipient=(JudgeStep(0.2, "taint"),),
        parts_agree=(JudgeStep(0.2, "taint"),),
        intent_not_granted="taint",
        judge_error="taint",
        truncated="taint",
    ),
}


@dataclass(frozen=True, slots=True)
class ContentJudgeConfig:
    """PLAN §5.3 ``content_judge``: off by default; agent overrides lane overrides gateway."""

    backend: JudgeBackendConfig = field(default_factory=JudgeBackendConfig)
    mode: str = "off"
    lane_modes: dict[str, str] = field(default_factory=dict)
    checks: frozenset[str] = frozenset(CHECKS)
    intent_min_confidence: float = 0.8
    rules: dict[str, LaneRules] = field(default_factory=lambda: dict(DEFAULT_LANE_RULES))

    def mode_for(self, lane: str, agent_modes: list[str | None]) -> str:
        """Resolve the mode for one message: the strictest over its agent recipients."""
        lane_mode = self.lane_modes.get(lane, self.mode)
        modes = [agent_mode or lane_mode for agent_mode in agent_modes]
        if not modes:
            return "off"
        return max(modes, key=JUDGE_MODES.index)


@dataclass(frozen=True, slots=True)
class MailboxConfig:
    """IMAP master-user connection to the mailhost (Dovecot, or Stalwart in M6)."""

    host: str
    port: int = 143
    master_user: str = "gateway"
    master_password: str = "dev-gateway"
    # How the mailhost spells "log in to {user}'s mailbox as {master}": Dovecot's
    # auth_master_user_separator is "*"; Stalwart uses "{user}%{master}@<domain>" (M6).
    master_login: str = "{user}*{master}"
    # Where each agent's hold queue lives (PLAN §5.8). By default it is in the agent's own
    # mailbox, under Outbox/, where Dovecot's ACL denies the agent every write. Stalwart cannot
    # deny an owner anything, so there the queues live in a mailbox the agent does not own
    # (hold_owner), one folder tree per agent (hold_prefix names it with {agent}).
    hold_owner: str | None = None
    hold_prefix: str = "Outbox/"
    tls: bool = False
    tls_ca_file: str | None = None
    tls_server_name: str | None = None

    def login_for(self, address: str) -> str:
        """The master login that opens ``address``'s mailbox."""
        return self.master_login.format(user=address, master=self.master_user)


@dataclass(frozen=True, slots=True)
class ControlConfig:
    """PLAN §5.10: the reserved address an agent declares its own state to, and the bound on
    how long any declaration lasts. The address is ``<address>@<agent_domain>``; no agent may
    have that name, and the milter refuses it from outside."""

    address: str = "control"
    max_ttl_seconds: int = 3600


@dataclass(frozen=True, slots=True)
class GatewayConfig:
    """Complete configuration for one gateway process."""

    domain: str
    agent_domain: str
    data_dir: Path
    agents: dict[str, AgentConfig]
    trust: tuple[TrustGrant, ...]
    limits: LimitsConfig
    mailbox: MailboxConfig
    blocklist: frozenset[str] = field(default_factory=frozenset)
    hold_rules: tuple[HoldRule, ...] = ()
    content_judge: ContentJudgeConfig = field(default_factory=ContentJudgeConfig)
    greylisting: bool = False
    known_domains: frozenset[str] = field(default_factory=frozenset)
    # Explicit opt-in: authenticated accounts in this domain may open human tasks.
    people_domain: str | None = None
    people_milter_port: int = 0
    # Empty: any outside recipient. Otherwise only these addresses and domains (PLAN §11).
    outbound_allowlist: frozenset[str] = field(default_factory=frozenset)
    # SH-40: people's mail to an agent only from these addresses and domains, matched against a
    # DKIM-verified, aligned From; empty: anyone's. An agent's own ``accept_from`` overrides it.
    accept_from: frozenset[str] = field(default_factory=frozenset)
    # Independent ceiling: an allowlist can narrow, never widen local-only.
    outbound: str = "unrestricted"
    local_domains: frozenset[str] = field(default_factory=frozenset)
    milter_host: str = "0.0.0.0"
    milter_port: int = 8890
    sibling_milter_port: int = 0  # Stalwart's listener-bound second milter endpoint
    lmtp_host: str = "0.0.0.0"
    lmtp_port: int = 2424
    submission_host: str = "0.0.0.0"
    submission_port: int = 2587
    postfix_host: str = "127.0.0.1"
    postfix_port: int = 10025
    # Opt in only where the MTA has a trusted, filtered sibling reinjection loop.
    sibling_port: int = 0
    keys_dir: Path = Path("keys")
    # SH-44: the domain key every agent signs with (``<registry_dir>/dkim.yaml``'s active
    # selector). None: a lane from before SH-44, whose agents sign with their own keys.
    domain_selector: str | None = None
    dns_server: str | None = None
    # The DNS zone the agent domain's records are published in (default: ``domain``). The live
    # bundle's ``domain`` is the agent domain itself (only it is "own"), and its records go in
    # the organization's zone, so `amx agent` uses zone-relative names for DNS hosts' forms.
    dns_zone: str | None = None
    # The size of the DKIM keys `amx agent` makes for this gateway: 2048, or 1024 where the DNS
    # editor cannot hold the longer record (the live bundle writes its tls.dkim_bits here).
    dkim_bits: int = 2048
    submission_tls_cert: Path | None = None
    submission_tls_key: Path | None = None
    submission_tls_ca: Path | None = None
    control: ControlConfig = field(default_factory=ControlConfig)

    @property
    def zone(self) -> str:
        """The zone DNS records are named relative to (``dns_zone``, else ``domain``)."""
        return self.dns_zone or self.domain

    @property
    def control_address(self) -> str:
        """The address an agent sends its declarations to (PLAN §5.10)."""
        return f"{self.control.address}@{self.agent_domain}"

    # How the gateway's in-process agents reach its own submission listener. It must be a name
    # the listener's certificate carries: the live bundle maps the MX host name to 127.0.0.1.
    submission_client_host: str = "127.0.0.1"
    # Local parts in the agent domain that are not agents (postmaster, abuse). The MTA delivers
    # them elsewhere, and the milter treats them as it treats a person's address.
    role_addresses: frozenset[str] = field(default_factory=frozenset)
    # PLAN §5.2: what `amx agent add --live` and `amx trust add` write (merged above, and
    # reloaded while the gateway runs), and the mailhost's accounts file they record logins in.
    registry_dir: Path | None = None
    accounts_file: Path | None = None

    def grant_for(self, domain: str | None, selector: str | None, lane: str) -> TrustGrant | None:
        """Resolve the first matching trust grant without consulting message content."""
        for grant in self.trust:
            if grant.lane != lane:
                continue
            if lane == "agent" and (grant.d == "*" or grant.s == "*"):
                continue
            if grant.names(domain, selector):
                return grant
        return None

    def accept_from_for(self, agent: str) -> frozenset[str]:
        """The senders ``agent`` takes people's mail from (SH-40); empty means anyone."""
        configured = self.agents.get(agent)
        if configured is not None and configured.accept_from is not None:
            return configured.accept_from
        return self.accept_from

    def outbound_allowlist_for(self, agent: str | None) -> frozenset[str]:
        """An agent's override, its household's owner list, or the default lane list (SH-47)."""
        configured = self.agents.get(agent) if agent is not None else None
        if configured is not None:
            if configured.outbound_allowlist is not None:
                return configured.outbound_allowlist
            if configured.household is not None:
                return configured.accept_from or frozenset()
        return self.outbound_allowlist

    def own_sender_listed(self, agent: str, address: str) -> bool:
        """An agent's effective accept_from exempts an address from first contact (SH-47)."""
        configured = self.agents.get(agent)
        return bool(configured and address_listed(address, self.accept_from_for(agent)))

    def selector_for(self, agent: str) -> str:
        """The DKIM selector ``agent``'s mail is signed with now: the domain's, once it has one."""
        configured = self.agents.get(agent)
        # Registered agents sign with the domain's key; an agent the operator configured in the
        # YAML keeps the selector the YAML gives it (or its name), published by the operator.
        if self.domain_selector is not None and (configured is None or configured.registered):
            return self.domain_selector
        return (configured.selector if configured else None) or agent

    def outbound_allowed(
        self, address: str, *, agent: str | None = None, named: bool = False
    ) -> bool:
        """Apply the local-only ceiling before the optional recipient allowlist.

        ``named``: the agent's owner named this address in the task (SH-46), which stands in for
        the allowlist but not for the ceiling.
        """
        address = address.strip().strip("<>").casefold()
        local = self.local_domains | {self.domain.casefold(), self.agent_domain.casefold()}
        if self.outbound == "local-only" and address.rpartition("@")[2] not in local:
            return False
        entries = self.outbound_allowlist_for(agent)
        if named or not entries:
            return True
        return address_listed(address, entries)

    def external_per_day(self, agent: str) -> int:
        """Return the agent's external send ceiling, falling back to the gateway limit."""
        configured = self.agents.get(agent)
        if configured is not None and configured.external_per_day is not None:
            return configured.external_per_day
        return self.limits.external_per_day


_HOLD_CONDITIONS = frozenset({"recipient_domain_seen", "schema_regex", "intents", "agents"})


def _string_list(value: object, field_name: str) -> frozenset[str]:
    if value is None:
        return frozenset()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{field_name} must be a list of strings")
    return frozenset(value)


def _hold_rule(value: object, index: int) -> HoldRule:
    field_name = f"hold_rules[{index}]"
    rule = _mapping(value, field_name)
    name = rule.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ValueError(f"{field_name} requires a name")
    when = _mapping(rule.get("when"), f"{field_name}.when")
    unknown = sorted(set(when) - _HOLD_CONDITIONS)
    if unknown:
        raise ValueError(f"{field_name} has unknown conditions: {', '.join(unknown)}")
    if not when:
        raise ValueError(f"{field_name} requires at least one condition")
    # A mistyped condition must fail config load, never silently match nothing or everything.
    seen = when.get("recipient_domain_seen")
    if seen is not None and not isinstance(seen, bool):
        raise ValueError(f"{field_name}.when.recipient_domain_seen must be true or false")
    schema_regex = when.get("schema_regex")
    if schema_regex is not None:
        if not isinstance(schema_regex, str) or not schema_regex:
            raise ValueError(f"{field_name}.when.schema_regex must be a non-empty string")
        re.compile(schema_regex)
    return HoldRule(
        name=name.strip(),
        recipient_domain_seen=seen,
        schema_regex=schema_regex,
        intents=_string_list(when.get("intents"), f"{field_name}.when.intents"),
        agents=_string_list(when.get("agents"), f"{field_name}.when.agents"),
    )


def _choice(value: object, allowed: tuple[str, ...], field_name: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise ValueError(f"{field_name} must be one of: {', '.join(allowed)}")
    return value


def _probability(value: object, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float) or not 0 <= value <= 1:
        raise ValueError(f"{field_name} must be a number between 0 and 1")
    return float(value)


def _steps(value: object, key: str, field_name: str) -> tuple[JudgeStep, ...]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{field_name} must be a non-empty list of steps")
    steps = []
    for index, item in enumerate(value):
        step = _mapping(item, f"{field_name}[{index}]")
        if set(step) != {key, "action"}:
            raise ValueError(f"{field_name}[{index}] must have exactly {key} and action")
        steps.append(
            JudgeStep(
                _probability(step[key], f"{field_name}[{index}].{key}"),
                _choice(step["action"], JUDGE_ACTIONS, f"{field_name}[{index}].action"),
            )
        )
    return tuple(steps)


def _content_judge(value: object, data_dir: Path) -> ContentJudgeConfig:
    raw = _mapping(value, "content_judge")
    known = {
        "backend",
        "base_url",
        "model",
        "api_key_env",
        "timeout_seconds",
        "stub_down_file",
        "mode",
        "lanes",
        "checks",
        "intent_min_confidence",
        "rules",
        "on_judge_error",
    }
    unknown = sorted(set(raw) - known)
    if unknown:
        raise ValueError(f"content_judge has unknown keys: {', '.join(unknown)}")
    backend_name = os.environ.get("AMX_CONTENT_JUDGE_BACKEND") or raw.get("backend", "stub")
    down_file = raw.get("stub_down_file")
    backend = JudgeBackendConfig(
        backend=_choice(backend_name, ("stub", "jev", "laya"), "content_judge.backend"),
        base_url=os.environ.get("AMX_CONTENT_JUDGE_BASE_URL") or raw.get("base_url"),
        model=str(raw.get("model", DEFAULT_MODEL)),
        api_key_env=str(raw.get("api_key_env", "TYPESAFE_API_KEY")),
        timeout_seconds=float(raw.get("timeout_seconds", 10.0)),
        stub_down_file=(data_dir / str(down_file)) if down_file else None,
    )
    lane_modes: dict[str, str] = {}
    for lane, item in _mapping(raw.get("lanes"), "content_judge.lanes").items():
        _choice(lane, LANES, "content_judge.lanes key")
        lane_raw = _mapping(item, f"content_judge.lanes.{lane}")
        if set(lane_raw) - {"mode"}:
            raise ValueError(f"content_judge.lanes.{lane} accepts only mode")
        lane_modes[lane] = _choice(lane_raw.get("mode"), JUDGE_MODES, f"lanes.{lane}.mode")
    checks = set(CHECKS)
    for name, enabled in _mapping(raw.get("checks"), "content_judge.checks").items():
        _choice(name, CHECKS, "content_judge.checks key")
        if not isinstance(enabled, bool):
            raise ValueError(f"content_judge.checks.{name} must be true or false")
        if not enabled:
            checks.discard(name)
    rules = dict(DEFAULT_LANE_RULES)
    errors = _mapping(raw.get("on_judge_error"), "content_judge.on_judge_error")
    rules_raw = _mapping(raw.get("rules"), "content_judge.rules")
    for lane in set(errors) | set(rules_raw):
        _choice(lane, LANES, "content_judge lane key")
    for lane in LANES:
        base = rules[lane]
        lane_raw = _mapping(rules_raw.get(lane), f"content_judge.rules.{lane}")
        extra = sorted(
            set(lane_raw) - {"directs_recipient", "parts_agree", "content_intent", "truncated"}
        )
        if extra:
            raise ValueError(f"content_judge.rules.{lane} has unknown keys: {', '.join(extra)}")
        rules[lane] = LaneRules(
            directs_recipient=(
                _steps(lane_raw["directs_recipient"], "at_least", f"rules.{lane}.directs_recipient")
                if "directs_recipient" in lane_raw
                else base.directs_recipient
            ),
            parts_agree=(
                _steps(lane_raw["parts_agree"], "below", f"rules.{lane}.parts_agree")
                if "parts_agree" in lane_raw
                else base.parts_agree
            ),
            intent_not_granted=(
                _choice(lane_raw["content_intent"], JUDGE_ACTIONS, f"rules.{lane}.content_intent")
                if "content_intent" in lane_raw
                else base.intent_not_granted
            ),
            judge_error=(
                _choice(errors[lane], JUDGE_ACTIONS, f"on_judge_error.{lane}")
                if lane in errors
                else base.judge_error
            ),
            truncated=(
                _choice(lane_raw["truncated"], JUDGE_ACTIONS, f"rules.{lane}.truncated")
                if "truncated" in lane_raw
                else base.truncated
            ),
        )
    return ContentJudgeConfig(
        backend=backend,
        mode=_choice(raw.get("mode", "off"), JUDGE_MODES, "content_judge.mode"),
        lane_modes=lane_modes,
        checks=frozenset(checks),
        intent_min_confidence=_probability(
            raw.get("intent_min_confidence", 0.8), "content_judge.intent_min_confidence"
        ),
        rules=rules,
    )


def _mapping(value: object, field_name: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{field_name} must be a mapping")
    return {str(key): item for key, item in value.items()}


def _check_master_login(template: str) -> None:
    """Only bare {user} and {master}: a stray placeholder fails at startup, not at an append."""
    bad = ValueError(f"mailbox.master_login: bad template {template!r}")
    try:
        fields = [part[1:] for part in string.Formatter().parse(template) if part[1] is not None]
    except ValueError as error:  # an unbalanced brace
        raise bad from error
    if "user" not in {name for name, _spec, _conversion in fields}:
        raise ValueError("mailbox.master_login must contain {user}")
    for name, spec, conversion in fields:
        if name not in ("user", "master") or spec or conversion:
            raise bad


def _check_hold_location(owner: str | None, prefix: str, agent_domain: str) -> None:
    """Only a layout some mailhost can protect from the agent (PLAN §5.8).

    Without an owner the queue is the agent's own Outbox/*, the four names Dovecot's ACL and the
    mailhost entrypoint cover; any other folder in its own mailbox the agent could create and
    fill itself. With an owner, it must not be an agent (a Stalwart owner may do anything in its
    own folders), and each agent needs its own tree.
    """
    bad = ValueError(f"mailbox.hold_prefix: bad template {prefix!r}")
    try:
        fields = [part[1:] for part in string.Formatter().parse(prefix) if part[1] is not None]
    except ValueError as error:  # an unbalanced brace
        raise bad from error
    if any(name != "agent" or spec or conversion for name, spec, conversion in fields):
        raise bad
    if not prefix.endswith("/") or prefix.startswith("/") or "//" in prefix:
        raise ValueError(f"mailbox.hold_prefix must be a folder path ending in '/': {prefix!r}")
    if owner is None:
        if prefix != "Outbox/":
            raise ValueError("mailbox.hold_prefix other than 'Outbox/' needs a mailbox.hold_owner")
        return
    local, at, domain = owner.rpartition("@")
    if not (local and at and domain):
        raise ValueError(f"mailbox.hold_owner must be an address: {owner!r}")
    if domain == agent_domain.casefold():
        raise ValueError(f"mailbox.hold_owner must not be in the agent domain: {owner!r}")
    # Otherwise every agent's watcher would see, and flag done, the others' decisions.
    if not fields:
        raise ValueError("mailbox.hold_prefix must contain {agent} when hold_owner is set")


_CONTROL_LOCAL_PART = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
# Longer than a day is no longer a declaration of current state; the schema has the same cap.
_CONTROL_TTL_CEILING = 86400


def _control(value: object, agents: dict[str, AgentConfig]) -> ControlConfig:
    raw = _mapping(value, "control")
    unknown = sorted(set(raw) - {"address", "max_ttl_seconds"})
    if unknown:
        raise ValueError(f"control has unknown keys: {', '.join(unknown)}")
    defaults = ControlConfig()
    address = str(raw.get("address", defaults.address))
    if not _CONTROL_LOCAL_PART.fullmatch(address):
        raise ValueError(
            "control.address must be a local part of lower-case letters, digits, and '-'"
        )
    if address in agents:
        raise ValueError(f"control.address {address!r} is also an agent's name")
    ttl = raw.get("max_ttl_seconds", defaults.max_ttl_seconds)
    if isinstance(ttl, bool) or not isinstance(ttl, int) or not 1 <= ttl <= _CONTROL_TTL_CEILING:
        raise ValueError(
            f"control.max_ttl_seconds must be an integer from 1 to {_CONTROL_TTL_CEILING}"
        )
    return ControlConfig(address=address, max_ttl_seconds=ttl)


def _merge_registry(
    registry_dir: Path,
    agent_domain: str,
    agents: dict[str, AgentConfig],
    grants: list[TrustGrant],
) -> None:
    """Add the registered agents, their own grants, and ``amx trust`` grants (PLAN §5.2).

    A registered agent must not shadow one the operator configured in the YAML. Its own grant
    (``d`` = the agent domain, ``s`` = its name) and the trust files' grants go after the YAML's,
    so for the same ``(d, s)`` the YAML's grant wins.
    """
    for name, registration in read_registrations(registry_dir).items():
        if name in agents:
            raise ValueError(f"registered agent {name} is also configured in the gateway YAML")
        agents[name] = AgentConfig(
            handler=registration.handler,
            mode=registration.mode,  # type: ignore[arg-type]
            watermark=registration.watermark,
            workers=registration.workers,
            enabled=registration.enabled,
            submit_token_hash=registration.submit_token_hash,
            external_per_day=registration.external_per_day,
            selector=registration.selector,
            registered=True,
            household=registration.household,
            accept_from=registration.accept_from,
            outbound_allowlist=registration.outbound_allowlist,
        )
        if not is_token_hash(registration.submit_token_hash):
            raise ValueError(f"registered agent {name}: submit_token_hash is not an amx hash")
        grants.append(
            TrustGrant(
                d=agent_domain,
                s=name,
                intents=frozenset(registration.intents),
                schemas=frozenset(registration.schemas),
                can_open_tasks=registration.can_open_tasks,
            )
        )
    for grant in read_grants(registry_dir):
        grants.append(
            TrustGrant(
                d=grant.d,
                s=grant.s,
                intents=frozenset(grant.intents),
                schemas=frozenset(grant.schemas),
                can_open_tasks=grant.can_open_tasks,
            )
        )


def load_config(path: str | Path, *, registry_dir: Path | None = None) -> GatewayConfig:
    """Load a gateway YAML file into immutable typed configuration.

    ``registry_dir`` stands in for the YAML's: the registration commands run on the host, where
    the YAML names the gateway container's path, and check their result this way (PLAN §5.2).
    """
    config_path = Path(path)
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    values = _mapping(raw, "config")
    domain = str(values["domain"])
    agent_domain = str(values.get("agent_domain", f"agents.{domain}"))

    agents: dict[str, AgentConfig] = {}
    for name, item in _mapping(values.get("agents"), "agents").items():
        agent = _mapping(item, f"agents.{name}")
        mode = str(agent.get("mode", "sync"))
        if mode not in HANDLER_MODES:
            raise ValueError(f"agents.{name}.mode must be sync, queued, or remote")
        handler = str(agent.get("handler", "mailbox-only"))
        if mode == "remote" and handler != "mailbox-only":
            raise ValueError(
                f"agents.{name}: a remote agent's handler runs on its own host; omit handler"
            )
        watermark = int(agent.get("watermark", 2))
        workers = int(agent.get("workers", 1))
        if watermark < 1 or workers < 1:
            raise ValueError(f"agents.{name} watermark and workers must be at least 1")
        external_per_day = agent.get("external_per_day")
        judge_raw = _mapping(agent.get("content_judge"), f"agents.{name}.content_judge")
        if set(judge_raw) - {"mode"}:
            raise ValueError(f"agents.{name}.content_judge accepts only mode")
        judge_mode = (
            _choice(judge_raw["mode"], JUDGE_MODES, f"agents.{name}.content_judge.mode")
            if "mode" in judge_raw
            else None
        )
        token_hash = agent.get("submit_token_hash")
        if token_hash is not None and not (
            isinstance(token_hash, str) and is_token_hash(token_hash)
        ):
            raise ValueError(f"agents.{name}.submit_token_hash is not an amx token hash")
        selector = agent.get("selector")
        if selector is not None:
            check_selector(name, str(selector))
        accept_from = (
            parse_outbound_allowlist(agent["accept_from"], f"agents.{name}.accept_from")
            if agent.get("accept_from") is not None
            else None
        )
        agents[name] = AgentConfig(
            handler=handler,
            mode=mode,  # type: ignore[arg-type]
            watermark=watermark,
            workers=workers,
            enabled=bool(agent.get("enabled", True)),
            submit_token=str(agent["submit_token"]) if agent.get("submit_token") else None,
            submit_token_hash=token_hash,
            external_per_day=None if external_per_day is None else int(external_per_day),
            content_judge_mode=judge_mode,
            selector=None if selector is None else str(selector),
            accept_from=accept_from,
            household=agent.get("household"),
            outbound_allowlist=(
                parse_outbound_allowlist(
                    agent["outbound_allowlist"], f"agents.{name}.outbound_allowlist"
                )
                if agent.get("outbound_allowlist") is not None
                else None
            ),
        )

    grants: list[TrustGrant] = []
    trust_value = values.get("trust", [])
    if not isinstance(trust_value, list):
        raise ValueError("trust must be a list")
    for index, item in enumerate(trust_value):
        grant = _mapping(item, f"trust[{index}]")
        grants.append(
            TrustGrant(
                d=str(grant.get("d", "*")),
                s=str(grant.get("s", "*")),
                lane=str(grant.get("lane", "agent")),  # type: ignore[arg-type]
                intents=frozenset(str(value) for value in grant.get("intents", [])),
                schemas=frozenset(str(value) for value in grant.get("schemas", [])),
                can_open_tasks=bool(grant.get("can_open_tasks", False)),
                trust=str(grant.get("trust", "verified")),
            )
        )

    registry_value = values.get("registry_dir")
    if registry_dir is None and registry_value:
        registry_dir = (config_path.parent / str(registry_value)).resolve()
    domain_selector = None
    if registry_dir is not None:
        _merge_registry(registry_dir, agent_domain, agents, grants)
        domain_state = domain_dkim.read(registry_dir)
        domain_selector = domain_state.active if domain_state else None

    limits_raw = _mapping(values.get("limits"), "limits")
    limits = LimitsConfig(
        references_depth=int(limits_raw.get("references_depth", 100)),
        received_depth=int(limits_raw.get("received_depth", 25)),
        max_bytes=int(limits_raw.get("max_bytes", 10 * 1024 * 1024)),
        external_per_day=int(limits_raw.get("external_per_day", 10)),
        blocked_attachment_types=frozenset(
            str(value)
            for value in limits_raw.get("blocked_attachment_types", DEFAULT_BLOCKED_TYPES)
        ),
    )
    hold_value = values.get("hold_rules", [])
    if not isinstance(hold_value, list):
        raise ValueError("hold_rules must be a list")
    hold_rules = tuple(_hold_rule(item, index) for index, item in enumerate(hold_value))
    for index, rule in enumerate(hold_rules):
        unknown_agents = sorted(rule.agents - set(agents))
        if unknown_agents:
            raise ValueError(
                f"hold_rules[{index}].when.agents names unknown agents: {', '.join(unknown_agents)}"
            )
    data_dir = (config_path.parent / str(values.get("data_dir", "data"))).resolve()
    content_judge = _content_judge(values.get("content_judge"), data_dir)
    mailbox_raw = _mapping(values.get("mailbox"), "mailbox")
    # AMX_MAILBOX_MASTER_LOGIN lets one gateway YAML serve either mailhost (compose.stalwart.yaml).
    master_login = os.environ.get("AMX_MAILBOX_MASTER_LOGIN") or str(
        mailbox_raw.get("master_login", "{user}*{master}")
    )
    _check_master_login(master_login)
    # The same for the hold queue's location: compose.stalwart.yaml moves it off the agent.
    hold_owner = os.environ.get("AMX_MAILBOX_HOLD_OWNER") or mailbox_raw.get("hold_owner")
    hold_owner = str(hold_owner).casefold() if hold_owner else None
    hold_prefix = os.environ.get("AMX_MAILBOX_HOLD_PREFIX") or str(
        mailbox_raw.get("hold_prefix", "Outbox/")
    )
    _check_hold_location(hold_owner, hold_prefix, agent_domain)
    mailbox = MailboxConfig(
        host=str(mailbox_raw.get("host", f"mail.{domain}")),
        port=int(mailbox_raw.get("port", 143)),
        master_user=str(mailbox_raw.get("master_user", "gateway")),
        master_password=str(mailbox_raw.get("master_password", "dev-gateway")),
        master_login=master_login,
        hold_owner=hold_owner,
        hold_prefix=hold_prefix,
        tls=bool(mailbox_raw.get("tls", False)),
        tls_ca_file=mailbox_raw.get("tls_ca_file"),
        tls_server_name=mailbox_raw.get("tls_server_name"),
    )
    listeners = _mapping(values.get("listeners"), "listeners")
    role_addresses = _string_list(values.get("role_addresses"), "role_addresses")
    role_addresses = frozenset(name.casefold() for name in role_addresses)
    clashing = sorted(role_addresses & {name.casefold() for name in agents})
    if clashing:
        raise ValueError(f"role_addresses name agents: {', '.join(clashing)}")
    if any("@" in name or "+" in name or not name for name in role_addresses):
        raise ValueError("role_addresses must be bare local parts, such as postmaster")
    control = _control(values.get("control"), agents)
    if control.address in role_addresses:
        raise ValueError(f"control.address {control.address!r} is also a role address")
    dns_zone = str(values["dns_zone"]).casefold().rstrip(".") if values.get("dns_zone") else None
    dkim_bits = values.get("dkim_bits", 2048)
    if dkim_bits not in (1024, 2048):
        raise ValueError("dkim_bits must be 2048, or 1024 where DNS cannot hold the record")
    if dns_zone and agent_domain != dns_zone and not agent_domain.endswith(f".{dns_zone}"):
        raise ValueError(f"agent_domain {agent_domain} is not inside dns_zone {dns_zone}")
    return GatewayConfig(
        domain=domain,
        agent_domain=agent_domain,
        data_dir=data_dir,
        agents=agents,
        trust=tuple(grants),
        limits=limits,
        mailbox=mailbox,
        blocklist=frozenset(str(value).casefold() for value in values.get("blocklist", [])),
        hold_rules=hold_rules,
        content_judge=content_judge,
        greylisting=bool(values.get("greylisting", False)),
        known_domains=frozenset(str(value).casefold() for value in values.get("known_domains", [])),
        people_domain=(
            str(os.environ.get("AMX_PEOPLE_DOMAIN") or values.get("people_domain") or "").casefold()
            or None
        ),
        people_milter_port=int(
            os.environ.get("AMX_PEOPLE_MILTER_PORT", listeners.get("people_milter_port", 0))
        ),
        outbound_allowlist=parse_outbound_allowlist(values.get("outbound_allowlist")),
        accept_from=parse_outbound_allowlist(values.get("accept_from"), "accept_from"),
        outbound=_choice(
            values.get("outbound", "unrestricted"), ("unrestricted", "local-only"), "outbound"
        ),
        local_domains=frozenset(
            value.casefold() for value in _string_list(values.get("local_domains"), "local_domains")
        ),
        milter_host=str(listeners.get("milter_host", "0.0.0.0")),
        milter_port=int(listeners.get("milter_port", 8890)),
        sibling_milter_port=int(
            os.environ.get("AMX_SIBLING_MILTER_PORT", str(listeners.get("sibling_milter_port", 0)))
        ),
        lmtp_host=str(listeners.get("lmtp_host", "0.0.0.0")),
        lmtp_port=int(listeners.get("lmtp_port", 2424)),
        submission_host=str(listeners.get("submission_host", "0.0.0.0")),
        submission_port=int(listeners.get("submission_port", 2587)),
        submission_client_host=str(listeners.get("submission_client_host", "127.0.0.1")),
        role_addresses=role_addresses,
        postfix_host=str(values.get("postfix_host", "127.0.0.1")),
        postfix_port=int(values.get("postfix_port", 10025)),
        sibling_port=int(
            os.environ.get(
                "AMX_SIBLING_PORT",
                os.environ.get(
                    "AMX_POSTFIX_SIBLING_PORT",
                    values.get("sibling_port", values.get("postfix_sibling_port", 0)),
                ),
            )
        ),
        keys_dir=(config_path.parent / str(values.get("keys_dir", "keys"))).resolve(),
        dns_server=str(values["dns_server"]) if values.get("dns_server") else None,
        dns_zone=dns_zone,
        dkim_bits=dkim_bits,
        submission_tls_cert=(
            (config_path.parent / str(values["submission_tls_cert"])).resolve()
            if values.get("submission_tls_cert")
            else None
        ),
        submission_tls_key=(
            (config_path.parent / str(values["submission_tls_key"])).resolve()
            if values.get("submission_tls_key")
            else None
        ),
        submission_tls_ca=(
            (config_path.parent / str(values["submission_tls_ca"])).resolve()
            if values.get("submission_tls_ca")
            else None
        ),
        control=control,
        registry_dir=registry_dir,
        domain_selector=domain_selector,
        accounts_file=(
            (config_path.parent / str(values["accounts_file"])).resolve()
            if values.get("accounts_file")
            else None
        ),
    )
