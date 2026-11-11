from __future__ import annotations

import itertools
import random
from dataclasses import replace

import pytest

from amx.config import (
    DEFAULT_LANE_RULES,
    JUDGE_ACTIONS,
    ContentJudgeConfig,
    JudgeStep,
    LaneRules,
    TrustGrant,
)
from amx.judge import IntentJudgment, Judgment
from amx.policy import JUDGMENT_HEADER, TAINT_HEADER, Verdict, apply_judgment

AGENT_OK = Verdict(
    "accept",
    "eod-ok",
    headers=(
        ("Agent-Lane", "agent"),
        ("Agent-Trust", "verified"),
        ("Agent-Verified-Domain", "agents.northwind.test"),
        ("Agent-Verified-Selector", "scheduler"),
    ),
)
HUMAN_OK = Verdict(
    "accept",
    "eod-ok",
    headers=(
        ("Agent-Lane", "human"),
        ("Agent-Trust", "low"),
        ("Agent-Grant-Can-Open-Tasks", "false"),
    ),
)
FULL = TrustGrant(
    d="agents.northwind.test", s="scheduler", intents=frozenset({"request", "response"})
)
RESPONSE_ONLY = TrustGrant(
    d="agents.northwind.test", s="restricted", intents=frozenset({"response"})
)
HUMAN = TrustGrant(lane="human", intents=frozenset({"request", "response"}))
RESPONSE_ONLY_HUMAN = TrustGrant(lane="human", intents=frozenset({"response"}))
CONFIG = ContentJudgeConfig(mode="enforce")


def _intent(label: str, confidence: float = 0.95) -> IntentJudgment:
    return IntentJudgment(label, confidence, {label: confidence})


def _judge(**values) -> Judgment:
    return Judgment(**{"directs_recipient": 0.02, "model": "stub-1", **values})


def _apply(
    identity: Verdict,
    judgment: Judgment | None,
    *,
    lane: str,
    grant=FULL,
    error=None,
    mode="enforce",
    config=CONFIG,
):
    return apply_judgment(
        identity, judgment, error, mode=mode, lane=lane, grant=grant, config=config
    )


def test_agent_lane_ladder_follows_plan_5_7() -> None:
    refused = _apply(AGENT_OK, _judge(directs_recipient=0.97), lane="agent")
    assert (refused.action, refused.code, refused.text) == (
        "reject",
        "550 5.7.1",
        "content directs the recipient agent",
    )
    at_line = _apply(AGENT_OK, _judge(directs_recipient=0.5), lane="agent")
    assert at_line.action == "reject"
    tainted = _apply(AGENT_OK, _judge(directs_recipient=0.49), lane="agent")
    assert tainted.accepted and dict(tainted.headers)[TAINT_HEADER] == "directs-recipient"
    parts = _apply(AGENT_OK, _judge(parts_agree=0.1), lane="agent")
    assert (parts.code, parts.text) == ("550 5.6.0", "text and machine parts disagree")
    smuggled = _apply(
        AGENT_OK, _judge(content_intent=_intent("request")), lane="agent", grant=RESPONSE_ONLY
    )
    assert (smuggled.code, smuggled.text) == ("550 5.7.1", "intent not granted")
    unsure = _apply(
        AGENT_OK, _judge(content_intent=_intent("request", 0.7)), lane="agent", grant=RESPONSE_ONLY
    )
    assert unsure.accepted and TAINT_HEADER not in dict(unsure.headers)
    down = _apply(AGENT_OK, None, lane="agent", error="judge unreachable")
    assert (down.action, down.code, down.text) == (
        "tempfail",
        "451 4.7.0",
        "content check unavailable",
    )


def test_human_lane_is_tainted_never_bounced_by_default() -> None:
    for judgment, error, reason in [
        (_judge(directs_recipient=0.99), None, "directs-recipient"),
        (_judge(parts_agree=0.0), None, "parts-disagree"),
        (_judge(content_intent=_intent("request")), None, "intent-not-granted"),
        (None, "judge unreachable", "judge-unavailable"),
    ]:
        grant = RESPONSE_ONLY_HUMAN if reason == "intent-not-granted" else HUMAN
        verdict = _apply(HUMAN_OK, judgment, lane="human", grant=grant, error=error)
        assert verdict.accepted, reason
        assert dict(verdict.headers)[TAINT_HEADER] == reason


def test_observe_adds_only_the_judgment_header_and_off_changes_nothing() -> None:
    observed = _apply(AGENT_OK, _judge(directs_recipient=0.99), lane="agent", mode="observe")
    assert observed.accepted and observed.headers[:4] == AGENT_OK.headers
    assert dict(observed.headers)[JUDGMENT_HEADER].startswith("mode=observe; model=stub-1;")
    assert TAINT_HEADER not in dict(observed.headers)
    assert _apply(AGENT_OK, _judge(directs_recipient=0.99), lane="agent", mode="off") is AGENT_OK


def test_only_an_ungranted_request_escalates_past_a_grant() -> None:
    for label in ("ack", "update", "error", "response", "other"):
        judgment = _judge(content_intent=_intent(label))
        verdict = _apply(AGENT_OK, judgment, lane="agent", grant=RESPONSE_ONLY)
        assert verdict.accepted and TAINT_HEADER not in dict(verdict.headers), label


def test_ladder_order_in_configuration_does_not_matter() -> None:
    reversed_rules = dict(DEFAULT_LANE_RULES)
    reversed_rules["agent"] = replace(
        reversed_rules["agent"],
        directs_recipient=(JudgeStep(0.5, "taint"), JudgeStep(0.8, "reject")),
        parts_agree=(JudgeStep(0.5, "reject"), JudgeStep(0.2, "taint")),
    )
    config = replace(CONFIG, rules=reversed_rules)
    directs = _apply(AGENT_OK, _judge(directs_recipient=0.97), lane="agent", config=config)
    assert directs.action == "reject"
    parts = _apply(AGENT_OK, _judge(parts_agree=0.05), lane="agent", config=config)
    assert parts.action == "reject"


def test_content_cut_before_judging_is_tainted_by_default_and_configurable() -> None:
    verdict = _apply(AGENT_OK, _judge(truncated=True), lane="agent")
    assert verdict.accepted and dict(verdict.headers)[TAINT_HEADER] == "truncated"
    assert "truncated=yes" in dict(verdict.headers)[JUDGMENT_HEADER]
    rules = dict(DEFAULT_LANE_RULES)
    rules["agent"] = replace(rules["agent"], truncated="reject")
    config = replace(CONFIG, rules=rules)
    refused = _apply(AGENT_OK, _judge(truncated=True), lane="agent", config=config)
    assert (refused.code, refused.text) == ("550 5.3.4", "message too long to check")


def test_the_header_carries_every_probability_including_the_distribution() -> None:
    judgment = _judge(
        parts_agree=0.9,
        content_intent=IntentJudgment("request", 0.9, {"request": 0.9, "response": 0.1}),
        latency_ms=131.6,
    )
    header = dict(_apply(AGENT_OK, judgment, lane="agent").headers)[JUDGMENT_HEADER]
    assert "content_intent_distribution=request:0.900,response:0.100" in header
    assert "directs_recipient=0.020" in header and "parts_agree=0.900" in header
    assert "latency_ms=132" in header


def test_other_label_and_wildcard_grants_never_trigger_intent() -> None:
    wildcard = TrustGrant(d="x", s="y", intents=frozenset({"*"}))
    for grant, label in [(RESPONSE_ONLY, "other"), (wildcard, "request"), (None, "request")]:
        verdict = _apply(AGENT_OK, _judge(content_intent=_intent(label)), lane="agent", grant=grant)
        assert verdict.accepted and TAINT_HEADER not in dict(verdict.headers)


def test_the_most_severe_signal_wins_and_taint_lists_every_reason() -> None:
    both = _apply(AGENT_OK, _judge(directs_recipient=0.3, parts_agree=0.1), lane="agent")
    assert both.code == "550 5.6.0"
    human = _apply(
        HUMAN_OK, _judge(directs_recipient=0.3, parts_agree=0.1), lane="human", grant=HUMAN
    )
    assert dict(human.headers)[TAINT_HEADER] == "directs-recipient, parts-disagree"


def test_quarantine_is_an_available_action() -> None:
    rules = dict(DEFAULT_LANE_RULES)
    rules["human"] = replace(rules["human"], directs_recipient=(JudgeStep(0.9, "quarantine"),))
    verdict = _apply(
        HUMAN_OK,
        _judge(directs_recipient=0.95),
        lane="human",
        grant=HUMAN,
        config=replace(CONFIG, rules=rules),
    )
    assert verdict.accepted and verdict.quarantine == "directs-recipient"
    assert dict(verdict.headers)[TAINT_HEADER] == "directs-recipient"


# ---- monotonicity: a judgment can only take authority away --------------------

_RANK = {"reject": 4, "tempfail": 3}
_SEVERITY = {"none": 0, "taint": 1, "quarantine": 2, "tempfail": 3, "reject": 4}


def _rank(verdict: Verdict) -> int:
    if verdict.action in _RANK:
        return _RANK[verdict.action]
    if verdict.quarantine:
        return 2
    return 1 if TAINT_HEADER in dict(verdict.headers) else 0


def _assert_monotone(identity: Verdict, final: Verdict) -> None:
    if not identity.accepted:
        assert final is identity  # a judge never overrides a refusal or deferral
        return
    assert _rank(final) >= _rank(identity)
    if final.accepted:
        # every identity header survives unchanged (no grant or trust is widened) ...
        assert final.headers[: len(identity.headers)] == identity.headers
        # ... and the judge adds only its own two headers
        added = {name for name, _value in final.headers[len(identity.headers) :]}
        assert added <= {JUDGMENT_HEADER, TAINT_HEADER}


def _judgments():
    directs = (None, 0.0, 0.19, 0.2, 0.49, 0.5, 0.9, 1.0)
    parts = (None, 0.0, 0.19, 0.2, 1.0)
    intents = (
        None,
        *(
            _intent(label, conf)
            for label, conf in itertools.product(
                ("request", "response", "update", "ack", "error", "other"), (0.5, 0.8, 0.99)
            )
        ),
    )
    for d, p, i, cut in itertools.product(directs, parts, intents, (False, True)):
        judgment = Judgment(
            directs_recipient=d, parts_agree=p, content_intent=i, model="m", truncated=cut
        )
        yield judgment, None
    yield None, "judge unreachable"


def _random_config(rng: random.Random) -> ContentJudgeConfig:
    def steps() -> tuple[JudgeStep, ...]:
        return tuple(
            JudgeStep(rng.random(), rng.choice(JUDGE_ACTIONS)) for _ in range(rng.randint(1, 3))
        )

    rules = {
        lane: LaneRules(
            steps(),
            steps(),
            rng.choice(JUDGE_ACTIONS),
            rng.choice(JUDGE_ACTIONS),
            rng.choice(JUDGE_ACTIONS),
        )
        for lane in ("agent", "human")
    }
    return ContentJudgeConfig(mode="enforce", intent_min_confidence=rng.random(), rules=rules)


IDENTITIES = [
    ("agent", AGENT_OK),
    ("human", HUMAN_OK),
    ("agent", Verdict("reject", "grant", "550 5.7.1", "intent or schema is not granted")),
    ("human", Verdict("tempfail", "first-contact-greylist", "451 4.7.1", "first contact")),
]


def test_monotone_for_every_mode_grant_and_judgment_under_the_shipped_ladder() -> None:
    cases = 0
    for (lane, identity), mode, grant, (judgment, error) in itertools.product(
        IDENTITIES,
        ("off", "observe", "enforce"),
        (None, FULL, RESPONSE_ONLY, HUMAN),
        list(_judgments()),
    ):
        _assert_monotone(
            identity, _apply(identity, judgment, lane=lane, grant=grant, error=error, mode=mode)
        )
        cases += 1
    assert cases > 10_000


@pytest.mark.parametrize("seed", range(40))
def test_monotone_under_arbitrary_configured_ladders(seed: int) -> None:
    rng = random.Random(seed)
    config = _random_config(rng)
    judgments = list(_judgments())
    for _ in range(300):
        lane, identity = rng.choice(IDENTITIES)
        judgment, error = rng.choice(judgments)
        grant = rng.choice((None, FULL, RESPONSE_ONLY, HUMAN))
        mode = rng.choice(("off", "observe", "enforce"))
        final = _apply(
            identity, judgment, lane=lane, grant=grant, error=error, mode=mode, config=config
        )
        _assert_monotone(identity, final)
        if identity.accepted and mode == "enforce" and judgment is not None:
            # The verdict is at least as severe as every step that matched, in any order.
            rules = config.rules[lane]
            matched = [
                step.action
                for step in rules.directs_recipient
                if judgment.directs_recipient is not None
                and judgment.directs_recipient >= step.threshold
            ] + [
                step.action
                for step in rules.parts_agree
                if judgment.parts_agree is not None and judgment.parts_agree < step.threshold
            ]
            floor = max((_SEVERITY[action] for action in matched), default=0)
            assert _rank(final) >= floor
