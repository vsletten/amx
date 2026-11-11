from __future__ import annotations

import pytest

from amx.config import HoldRule, load_config
from amx.holds import match_hold_rule, recipient_domain

RULES = (
    HoldRule(name="first-contact-domain", recipient_domain_seen=False),
    HoldRule(name="commits-money", schema_regex="(order|payment|invoice)"),
)


def _match(rules=RULES, **facts):
    values = {
        "agent": "scheduler",
        "intent": "request",
        "schema": None,
        "recipient_domains": frozenset({"agents.contoso.test"}),
        "seen_domains": frozenset({"agents.contoso.test"}),
    }
    values.update(facts)
    return match_hold_rule(rules, **values)


def test_first_contact_matches_any_unseen_recipient_domain() -> None:
    assert _match() is None
    assert (
        _match(recipient_domains=frozenset({"agents.contoso.test", "plainmail.test"}))
        == "first-contact-domain"
    )


def test_schema_regex_matches_and_rules_are_tried_in_order() -> None:
    money = "https://evtmail.ai/schema/0.1/payment-request.json"
    assert _match(schema=money) == "commits-money"
    assert _match(schema=money, recipient_domains=frozenset({"new.test"})) == (
        "first-contact-domain"
    )
    assert _match(schema="https://evtmail.ai/schema/0.1/request.json") is None


def test_agent_and_intent_scopes_and_seen_true() -> None:
    scoped = (HoldRule(name="only-intake", intents=frozenset({"response"}), agents={"intake"}),)
    assert _match(scoped) is None
    assert _match(scoped, agent="intake") is None
    assert _match(scoped, agent="intake", intent="response") == "only-intake"
    known_only = (HoldRule(name="known", recipient_domain_seen=True),)
    assert _match(known_only) == "known"
    assert _match(known_only, recipient_domains=frozenset({"new.test"})) is None


def test_recipient_domain_casefolds() -> None:
    assert recipient_domain("Pat <pat@PlainMail.TEST>") == "plainmail.test"
    assert recipient_domain("no-at-sign") == ""


def _write(tmp_path, body: str):
    path = tmp_path / "gateway.yaml"
    path.write_text(
        "domain: example.test\nmailbox: {host: mail.example.test}\n" + body, encoding="utf-8"
    )
    return path


def test_config_parses_hold_rules_modes_and_rate_limits(tmp_path) -> None:
    config = load_config(
        _write(
            tmp_path,
            """
agents:
  intake: {handler: mailbox-only, mode: queued, watermark: 3, workers: 2, external_per_day: 50}
  other: {handler: mailbox-only}
hold_rules:
  - {name: first-contact-domain, when: {recipient_domain_seen: false}}
  - {name: commits-money, when: {schema_regex: "(order|payment|invoice)", intents: [request]}}
limits: {external_per_day: 7}
""",
        )
    )
    assert config.agents["intake"].mode == "queued"
    assert config.agents["intake"].workers == 2
    assert config.external_per_day("intake") == 50
    assert config.external_per_day("other") == 7
    assert config.hold_rules == (
        HoldRule(name="first-contact-domain", recipient_domain_seen=False),
        HoldRule(
            name="commits-money",
            schema_regex="(order|payment|invoice)",
            intents=frozenset({"request"}),
        ),
    )


def test_config_defaults_to_ten_external_messages_per_day(tmp_path) -> None:
    config = load_config(_write(tmp_path, "agents: {a: {handler: mailbox-only}}\n"))
    assert config.external_per_day("a") == 10
    assert config.hold_rules == ()


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("agents: {a: {mode: batch}}\n", "must be sync, queued, or remote"),
        ("agents: {a: {mode: remote, handler: 'amx.examples.echo:handle'}}\n", "on its own host"),
        ("agents: {a: {watermark: 0}}\n", "at least 1"),
        ("hold_rules: {}\n", "hold_rules must be a list"),
        ("hold_rules: [{when: {schema_regex: x}}]\n", "requires a name"),
        ("hold_rules: [{name: r, when: {}}]\n", "at least one condition"),
        ("hold_rules: [{name: r, when: {recipent_domain_seen: false}}]\n", "unknown conditions"),
        ("hold_rules: [{name: r, when: {schema_regex: '('}}]\n", "missing"),
        ("hold_rules: [{name: 5, when: {intents: [request]}}]\n", "requires a name"),
        ("hold_rules: [{name: r, when: {intents: request}}]\n", "list of strings"),
        ("hold_rules: [{name: r, when: {agents: [1]}}]\n", "list of strings"),
        ("hold_rules: [{name: r, when: {recipient_domain_seen: 'false'}}]\n", "true or false"),
        ("hold_rules: [{name: r, when: {schema_regex: 5}}]\n", "non-empty string"),
        ("hold_rules: [{name: r, when: {agents: [ghost]}}]\n", "unknown agents: ghost"),
    ],
)
def test_config_fails_closed_on_bad_hold_and_mode_settings(tmp_path, body, message) -> None:
    with pytest.raises(Exception, match=message):
        load_config(_write(tmp_path, body))
