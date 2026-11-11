from __future__ import annotations

import pytest

from amx.config import JudgeStep, load_config


def _write(tmp_path, body: str):
    path = tmp_path / "gateway.yaml"
    path.write_text(
        "domain: example.test\ndata_dir: state\nmailbox: {host: mail.example.test}\n"
        "agents: {intake: {handler: mailbox-only}, quiet: {handler: mailbox-only, "
        "content_judge: {mode: 'off'}}}\n" + body,
        encoding="utf-8",
    )
    return path


def test_shipped_default_is_off_with_the_plan_ladder(tmp_path) -> None:
    config = load_config(_write(tmp_path, "")).content_judge
    assert config.mode == "off" and config.backend.backend == "stub"
    assert config.rules["agent"].directs_recipient == (
        JudgeStep(0.5, "reject"),
        JudgeStep(0.2, "taint"),
    )
    assert config.rules["human"].judge_error == "taint"
    assert config.mode_for("agent", [None]) == "off"


def test_parses_modes_checks_rules_and_agent_overrides(tmp_path) -> None:
    loaded = load_config(
        _write(
            tmp_path,
            """
content_judge:
  backend: jev
  mode: enforce
  lanes: {human: {mode: observe}}
  checks: {parts_agree: false}
  stub_down_file: judge-down
  intent_min_confidence: 0.7
  rules:
    human:
      directs_recipient: [{at_least: 0.95, action: quarantine}, {at_least: 0.5, action: taint}]
      content_intent: none
  on_judge_error: {agent: reject}
""",
        )
    )
    config = loaded.content_judge
    assert config.backend.backend == "jev" and config.backend.model == "jev-1.13.0"
    assert config.backend.stub_down_file == loaded.data_dir / "judge-down"
    assert config.checks == frozenset({"directs_recipient", "content_intent"})
    assert config.rules["human"].directs_recipient[0] == JudgeStep(0.95, "quarantine")
    assert config.rules["human"].intent_not_granted == "none"
    assert config.rules["agent"].judge_error == "reject"
    assert config.rules["agent"].parts_agree == (JudgeStep(0.2, "reject"),)
    assert config.intent_min_confidence == 0.7
    assert loaded.agents["quiet"].content_judge_mode == "off"
    # agent overrides lane overrides gateway; the strictest agent recipient wins
    assert config.mode_for("human", [None]) == "observe"
    assert config.mode_for("agent", [None]) == "enforce"
    assert config.mode_for("agent", ["off"]) == "off"
    assert config.mode_for("agent", ["off", None]) == "enforce"
    assert config.mode_for("agent", []) == "off"


def test_environment_can_switch_the_backend_for_a_live_run(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("AMX_CONTENT_JUDGE_BACKEND", "laya")
    monkeypatch.setenv("AMX_CONTENT_JUDGE_BASE_URL", "http://laya.test:8610")
    backend = load_config(
        _write(tmp_path, "content_judge: {mode: enforce}\n")
    ).content_judge.backend
    assert (backend.backend, backend.base_url) == ("laya", "http://laya.test:8610")


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("content_judge: {mode: off}\n", "content_judge.mode must be one of"),  # YAML off is false
        ("content_judge: {mode: strict}\n", "content_judge.mode must be one of"),
        ("content_judge: {backend: gpt}\n", "content_judge.backend must be one of"),
        ("content_judge: {moed: enforce}\n", "unknown keys: moed"),
        ("content_judge: {lanes: {robot: {mode: enforce}}}\n", "lanes key must be one of"),
        ("content_judge: {checks: {spam: true}}\n", "checks key must be one of"),
        ("content_judge: {checks: {parts_agree: 'no'}}\n", "true or false"),
        ("content_judge: {rules: {agent: {directs_recipient: []}}}\n", "non-empty list"),
        (
            "content_judge: {rules: {agent: "
            "{directs_recipient: [{at_least: 2, action: taint}]}}}\n",
            "between 0 and 1",
        ),
        (
            "content_judge: {rules: {agent: {parts_agree: [{at_least: 0.2, action: taint}]}}}\n",
            "exactly below and action",
        ),
        ("content_judge: {rules: {agent: {content_intent: ban}}}\n", "must be one of"),
        ("content_judge: {on_judge_error: {human: explode}}\n", "must be one of"),
        ("content_judge: {intent_min_confidence: 1.5}\n", "between 0 and 1"),
    ],
)
def test_bad_content_judge_settings_fail_config_load(tmp_path, body: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        load_config(_write(tmp_path, body))
