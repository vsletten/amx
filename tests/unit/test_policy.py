from __future__ import annotations

from dataclasses import replace
from email import policy as email_policy
from email.message import EmailMessage
from pathlib import Path

import pytest

from amx.config import LimitsConfig, TrustGrant
from amx.policy import AgentState, Stage, State, TxnContext, evaluate
from amx.profile import SCHEMA_BASE, build


def _raw() -> bytes:
    return build(
        sender="scheduler@agents.northwind.test",
        to="intake@agents.contoso.test",
        subject="M2 policy fixture",
        intent="request",
        task="t_policy",
        task_state="submitted",
        text="Please intake this request.",
        payload={"action": "intake"},
        schema=f"{SCHEMA_BASE}request.json",
        message_id="<policy@agents.northwind.test>",
    ).as_bytes(policy=email_policy.SMTP)


def _human_raw() -> bytes:
    message = EmailMessage(policy=email_policy.SMTP)
    message["From"] = "pat@plainmail.test"
    message["To"] = "intake@agents.contoso.test"
    message["Subject"] = "Hello"
    message["Message-ID"] = "<human@plainmail.test>"
    message.set_content("Ordinary human mail")
    return message.as_bytes()


def _state(**changes: object) -> State:
    state = State(
        agent_domain="agents.contoso.test",
        agents={"intake": AgentState(enabled=True, depth=0, watermark=2)},
        grants=(
            TrustGrant(
                d="agents.northwind.test",
                s="scheduler",
                intents=frozenset({"request", "response"}),
                schemas=frozenset({"*"}),
                can_open_tasks=True,
            ),
            TrustGrant(
                lane="human",
                intents=frozenset({"request", "response"}),
                schemas=frozenset({"*"}),
                can_open_tasks=False,
                trust="low",
            ),
        ),
    )
    return replace(state, **changes)


def _eod(**changes: object) -> TxnContext:
    context = TxnContext(
        raw=_raw(),
        mail_from="scheduler@agents.northwind.test",
        sender_domain="agents.northwind.test",
        dkim_verified=True,
        dkim_domain="agents.northwind.test",
        dkim_selector="scheduler",
        from_domain="agents.northwind.test",
        task_token="t_policy",
        recipient_agent="intake",
    )
    return replace(context, **changes)


@pytest.mark.parametrize(
    ("stage", "context", "state", "rule", "action", "code"),
    [
        (
            Stage.CONNECT,
            TxnContext(connection_rate_exceeded=True),
            _state(),
            "connect-rate",
            "tempfail",
            "421 4.7.0",
        ),
        (
            Stage.MAIL,
            TxnContext(mail_from="bot@blocked.test", sender_domain="blocked.test"),
            _state(blocklist=frozenset({"blocked.test"})),
            "blocked-domain",
            "reject",
            "550 5.7.1",
        ),
        (
            Stage.RCPT,
            TxnContext(recipient_agent="missing"),
            _state(),
            "agent-unknown",
            "reject",
            "550 5.1.1",
        ),
        (
            Stage.RCPT,
            TxnContext(recipient_agent="intake", task_token="/data/llm/intake/t_victim"),
            _state(),
            "invalid-task-token",
            "reject",
            "550 5.1.3",
        ),
        (
            Stage.RCPT,
            TxnContext(recipient_agent="intake", task_token="t_closed"),
            _state(closed_tasks=frozenset({("intake", "t_closed")})),
            "closed-task",
            "reject",
            "550 5.1.6",
        ),
        (
            Stage.RCPT,
            TxnContext(
                recipient_agent="intake", task_token="t_closed", recipient_accepted_mail=True
            ),
            _state(closed_tasks=frozenset({("intake", "t_closed")})),
            "closed-task-at-eod",
            "accept",
            None,
        ),
        (
            Stage.RCPT,
            TxnContext(recipient_agent="intake"),
            _state(agents={"intake": AgentState(depth=2, watermark=2)}),
            "agent-watermark",
            "tempfail",
            "450 4.2.1",
        ),
        (
            Stage.EOD,
            _eod(dkim_verified=False, dkim_domain=None),
            _state(),
            "agent-identity",
            "reject",
            "550 5.7.1",
        ),
        (
            Stage.EOD,
            TxnContext(
                raw=_human_raw(),
                mail_from="pat@plainmail.test",
                sender_domain="plainmail.test",
                from_domain="plainmail.test",
            ),
            _state(),
            "eod-ok",
            "accept",
            None,
        ),
        (
            Stage.EOD,
            _eod(dkim_selector="untrusted"),
            _state(),
            "grant",
            "reject",
            "550 5.7.1",
        ),
        (
            Stage.EOD,
            _eod(
                raw=Path("spec/corpus/15-invalid-schema.eml").read_bytes(),
                from_domain="agents.northwind.test",
            ),
            _state(),
            "invalid-machine-part",
            "reject",
            "550 5.6.0",
        ),
        (
            Stage.EOD,
            _eod(
                raw=_raw().replace(b"Auto-Submitted: auto-generated\r\n", b""),
            ),
            _state(),
            "loop-guard",
            "reject",
            "550 5.4.6",
        ),
        (
            Stage.EOD,
            _eod(size=1000),
            _state(limits=LimitsConfig(max_bytes=100)),
            "size-or-attachment",
            "reject",
            "552 5.3.4",
        ),
        (
            Stage.EOD,
            _eod(),
            _state(greylisting=True, known_domains=frozenset()),
            "first-contact-greylist",
            "tempfail",
            "451 4.7.1",
        ),
        (
            Stage.EOD,
            _eod(),
            _state(closed_tasks=frozenset({("intake", "t_policy")})),
            "closed-task",
            "reject",
            "550 5.1.6",
        ),
    ],
    ids=[
        "connect-rate",
        "mail-blocklist",
        "rcpt-unknown",
        "rcpt-invalid-task-token",
        "rcpt-closed-task",
        "rcpt-closed-task-possible-retry",
        "rcpt-watermark",
        "eod-agent-dkim",
        "eod-human-low-trust",
        "eod-grant",
        "eod-machine-schema",
        "eod-loop",
        "eod-size",
        "eod-greylist",
        "eod-closed-task",
    ],
)
def test_plan_5_2_policy_rows(
    stage: Stage,
    context: TxnContext,
    state: State,
    rule: str,
    action: str,
    code: str | None,
) -> None:
    verdict = evaluate(stage, context, state)
    assert (verdict.rule, verdict.action, verdict.code) == (rule, action, code)
    if rule == "eod-ok":
        assert ("Agent-Trust", "low") in verdict.headers
        assert ("Agent-Grant-Can-Open-Tasks", "false") in verdict.headers


def test_valid_agent_message_is_accepted_with_verified_identity_headers() -> None:
    verdict = evaluate(Stage.EOD, _eod(), _state())
    assert verdict.accepted
    assert ("Agent-Lane", "agent") in verdict.headers
    assert ("Agent-Verified-Selector", "scheduler") in verdict.headers


def test_agent_lane_never_uses_wildcard_identity_grant() -> None:
    wildcard = TrustGrant(
        d="*",
        s="*",
        intents=frozenset({"request"}),
        schemas=frozenset({"*"}),
    )
    verdict = evaluate(Stage.EOD, _eod(), _state(grants=(wildcard,)))
    assert (verdict.rule, verdict.code) == ("grant", "550 5.7.1")


def test_agent_identity_rejection_preserves_dkim_failure_reason_for_trace() -> None:
    verdict = evaluate(
        Stage.EOD,
        _eod(dkim_verified=False, identity_error="dkim fail: no key"),
        _state(),
    )
    assert verdict.rule == "agent-identity"
    assert "dkim fail: no key" in verdict.text


def test_agent_grant_cannot_open_a_fresh_task_when_capability_is_false() -> None:
    grant = TrustGrant(
        d="agents.northwind.test",
        s="restricted",
        intents=frozenset({"response"}),
        schemas=frozenset({"*"}),
        can_open_tasks=False,
    )
    raw = build(
        sender="restricted+t_fresh@agents.northwind.test",
        to="intake+t_fresh@agents.contoso.test",
        subject="Fresh response",
        intent="response",
        task="t_fresh",
        task_state="submitted",
        text="This must not open a task.",
        in_reply_to="<made-up@agents.contoso.test>",
    ).as_bytes(policy=email_policy.SMTP)
    verdict = evaluate(
        Stage.EOD,
        TxnContext(
            raw=raw,
            dkim_verified=True,
            dkim_domain="agents.northwind.test",
            dkim_selector="restricted",
            from_domain="agents.northwind.test",
            task_token="t_fresh",
        ),
        State(agent_domain="agents.contoso.test", grants=(grant,)),
    )

    assert verdict.action == "reject"
    assert verdict.rule == "grant"
    assert verdict.text == "identity is not allowed to open tasks"


@pytest.mark.parametrize(
    "name",
    [
        "Agent-Lane",
        "Agent-Trust",
        "Agent-Verified-Domain",
        "Agent-Verified-Selector",
        "Agent-Grant-Can-Open-Tasks",
        "Agent-Task-Assigned",
    ],
)
def test_sender_supplied_transport_result_headers_are_rejected(name: str) -> None:
    raw = _human_raw().replace(
        b"Subject: Hello\r\n", f"Subject: Hello\r\n{name}: forged\r\n".encode()
    )
    verdict = evaluate(
        Stage.EOD,
        TxnContext(
            raw=raw,
            mail_from="pat@plainmail.test",
            sender_domain="plainmail.test",
            from_domain="plainmail.test",
        ),
        _state(),
    )
    assert (verdict.rule, verdict.action, verdict.code) == (
        "reserved-transport-header",
        "reject",
        "550 5.7.1",
    )


def test_agent_task_must_match_recipient_subaddress_token() -> None:
    verdict = evaluate(Stage.EOD, _eod(task_token="t_other"), _state())
    assert (verdict.rule, verdict.code) == ("task-token-mismatch", "550 5.7.1")
    tokens = ("t_policy", "t_other")
    verdict = evaluate(Stage.EOD, _eod(recipient_task_tokens=tokens), _state())
    assert (verdict.rule, verdict.code) == ("task-token-mismatch", "550 5.7.1")


@pytest.mark.parametrize("tokens", [("t_policy",), ()])
def test_a_person_copied_on_an_agent_thread_needs_no_task_token(tokens) -> None:
    # The milter lists only agent recipients' tokens: () means only people (no sub-address).
    context = _eod(task_token=None, recipient_task_tokens=tokens)
    assert evaluate(Stage.EOD, context, _state()).accepted


@pytest.mark.parametrize(
    "context",
    [
        _eod(attachment_types=frozenset({"application/x-msdownload"})),
        _eod(size=1000),
    ],
)
def test_size_or_attachment_rule_covers_both_predicates(context: TxnContext) -> None:
    state = _state(limits=LimitsConfig(max_bytes=100))
    assert evaluate(Stage.EOD, context, state).code == "552 5.3.4"


def test_an_agent_lane_agent_task_that_is_not_a_task_token_is_refused() -> None:
    raw = _raw().replace(b"Agent-Task: t_policy", b"Agent-Task: ../../etc/t")
    context = _eod(raw=raw, task_token=None, recipient_task_tokens=())
    verdict = evaluate(Stage.EOD, context, _state())
    assert (verdict.rule, verdict.code) == ("invalid-task-token", "550 5.6.0")


def test_a_persons_own_subaddress_is_not_a_task_token_check() -> None:
    # ops+Newsletter@contoso.test is a person's sub-address, not an agent task: no refusal.
    raw = (
        b"From: pat@plainmail.test\r\nTo: ops+Newsletter@contoso.test\r\n"
        b"Subject: Hi\r\nMessage-ID: <h@plainmail.test>\r\n\r\nHello.\r\n"
    )
    context = TxnContext(
        raw=raw,
        mail_from="pat@plainmail.test",
        sender_domain="plainmail.test",
        from_domain="plainmail.test",
        recipient_task_tokens=(),
    )
    assert evaluate(Stage.EOD, context, _state()).accepted


def test_a_closed_task_lets_through_only_a_retry_of_mail_every_recipient_accepted() -> None:
    """docs/task-transitions.md D2-D4: RCPT defers, end of DATA decides by Message-ID."""
    closed = _state(closed_tasks=frozenset({("intake", "t_policy")}))
    tokens = ("t_policy", "t_policy")
    retry = evaluate(
        Stage.EOD, _eod(recipient_task_tokens=tokens, message_accepted=(True, True)), closed
    )
    assert (retry.action, retry.rule) == ("accept", "eod-ok")
    for accepted in ((True, False), (True,), (), (False, False)):
        verdict = evaluate(
            Stage.EOD, _eod(recipient_task_tokens=tokens, message_accepted=accepted), closed
        )
        assert (verdict.rule, verdict.code, verdict.text) == (
            "closed-task",
            "550 5.1.6",
            "task is closed",
        ), accepted
    open_task = evaluate(Stage.EOD, _eod(recipient_task_tokens=tokens), _state())
    assert open_task.accepted, "an open task never asks"


def test_a_possible_retry_into_a_closed_task_still_waits_for_a_busy_agent() -> None:
    verdict = evaluate(
        Stage.RCPT,
        TxnContext(recipient_agent="intake", task_token="t_closed", recipient_accepted_mail=True),
        _state(
            closed_tasks=frozenset({("intake", "t_closed")}),
            agents={"intake": AgentState(depth=2, watermark=2)},
        ),
    )
    assert (verdict.rule, verdict.code) == ("agent-watermark", "450 4.2.1")
    unknown = evaluate(
        Stage.RCPT,
        TxnContext(recipient_agent="intake", task_token="t_unknown", recipient_accepted_mail=True),
        _state(closed_tasks=frozenset({("intake", "t_closed")})),
    )
    assert unknown.rule == "recipient-ok", "only a closed task is deferred"
