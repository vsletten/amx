"""Pure outbound hold-rule matching (PLAN §5.3 ``hold_rules``) and where holds are filed."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from amx.config import GatewayConfig, HoldRule

HOLD_HEADER = "Agent-Hold-Rule"
HOLD_RECIPIENTS_HEADER = "Agent-Hold-Recipients"
TAINTED_RULE = "tainted-input"  # PLAN §5.7: replies to tainted content always wait for a person
# The default hold queue, in the agent's own mailbox (Dovecot; mailbox.hold_prefix "Outbox/").
HELD_FOLDER = "Outbox/Held"
APPROVED_FOLDER = "Outbox/Approved"
REJECTED_FOLDER = "Outbox/Rejected"
SENT_FOLDER = "Sent"


@dataclass(frozen=True, slots=True)
class HoldQueue:
    """Where one agent's held mail waits: the mailbox, as the gateway opens it, and its folders."""

    mailbox: str
    held: str
    approved: str
    rejected: str
    # True when the queue is the agent's own Outbox (so released copies can move to Sent).
    own: bool


def hold_queue(config: GatewayConfig, agent: str) -> HoldQueue:
    """Resolve ``mailbox.hold_owner`` and ``mailbox.hold_prefix`` for one agent (PLAN §5.8)."""
    owner = config.mailbox.hold_owner
    prefix = config.mailbox.hold_prefix.format(agent=agent)
    return HoldQueue(
        mailbox=owner or f"{agent}@{config.agent_domain}",
        held=f"{prefix}Held",
        approved=f"{prefix}Approved",
        rejected=f"{prefix}Rejected",
        own=owner is None,  # config refuses an owner in the agent domain
    )


def recipient_domain(address: str) -> str:
    """Return the casefolded domain of an address, or an empty string when it has none."""
    _local, at, domain = address.rpartition("@")
    return domain.strip().rstrip(">").casefold() if at else ""


def match_hold_rule(
    rules: Iterable[HoldRule],
    *,
    agent: str,
    intent: str | None,
    schema: str | None,
    recipient_domains: frozenset[str],
    seen_domains: frozenset[str],
) -> str | None:
    """Return the name of the first rule whose every condition matches, or ``None``.

    ``recipient_domain_seen: false`` matches when any recipient domain is outside
    ``seen_domains`` (the gateway's own domains, configured known domains, and domains this agent
    already sent to). ``schema_regex`` searches the declared ``Agent-Schema`` case-insensitively;
    submission has already validated the machine part against that schema. Conditions inside
    one rule are combined with AND; rules are tried in order.
    """
    for rule in rules:
        if rule.agents and agent not in rule.agents:
            continue
        if rule.intents and intent not in rule.intents:
            continue
        if rule.schema_regex is not None and (
            schema is None or re.search(rule.schema_regex, schema, re.IGNORECASE) is None
        ):
            continue
        if rule.recipient_domain_seen is not None:
            any_unseen = bool(recipient_domains - seen_domains)
            if rule.recipient_domain_seen == any_unseen:
                continue
        return rule.name
    return None
