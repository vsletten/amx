"""PLAN §5.10: an agent declares its own state to its gateway through the control address."""

from __future__ import annotations

import sqlite3
from dataclasses import replace
from datetime import UTC, datetime
from email import policy as email_policy
from email.parser import BytesParser
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from amx import runner as runner_module
from amx.cli import app, declarations
from amx.config import GatewayConfig, load_config
from amx.control import (
    COMMANDS,
    CONTROL_INTENT,
    CONTROL_SCHEMA,
    REASONS,
    ControlError,
    Declaration,
    declaration,
    iso,
    retry_after,
)
from amx.journal import Journal
from amx.narrate import policy_line
from amx.policy import AgentState, Stage, State, TxnContext, evaluate
from amx.profile import SchemaValidationError, build, parse
from amx.runtime import Backlog, Context, HandlerRegistry
from amx.sdk import Agent, Declared
from amx.store import Store

NOW = datetime(2026, 9, 27, 12, 0, 0, tzinfo=UTC).timestamp()


# --- the declaration itself (amx.control) ---


def test_a_pause_ends_in_the_future_and_within_the_maximum() -> None:
    paused = declaration(
        {"command": "pause", "until": "2026-09-27T12:10:00Z", "reason": "maintenance"},
        now=NOW,
        max_ttl=3600,
    )
    assert paused == Declaration("pause", NOW + 600, reason="maintenance")
    assert paused.summary() == "pause until=2026-09-27T12:10:00Z reason=maintenance"
    offset = declaration(
        {"command": "pause", "until": "2026-09-27T14:10:00+02:00", "reason": "offline"},
        now=NOW,
        max_ttl=3600,
    )
    assert offset.expires_at == NOW + 600, "the offset is honored"
    with pytest.raises(ControlError, match="not in the future"):
        declaration(
            {"command": "pause", "until": "2026-09-27T12:00:00Z", "reason": "offline"},
            now=NOW,
            max_ttl=3600,
        )
    with pytest.raises(ControlError, match="more than 3600 s ahead"):
        declaration(
            {"command": "pause", "until": "2026-09-27T13:00:01Z", "reason": "offline"},
            now=NOW,
            max_ttl=3600,
        )
    with pytest.raises(ControlError, match="offset"):
        declaration(
            {"command": "pause", "until": "2026-09-27T12:10:00", "reason": "offline"},
            now=NOW,
            max_ttl=3600,
        )
    # Instants the platform cannot represent are refusals, not exceptions (no 500 at DATA).
    for extreme in ("9999-12-31T23:59:59-23:59", "0001-01-01T00:00:00+23:59"):
        with pytest.raises(ControlError):
            declaration(
                {"command": "pause", "until": extreme, "reason": "offline"}, now=NOW, max_ttl=3600
            )


def test_a_capacity_lasts_its_ttl_and_no_longer_than_the_maximum() -> None:
    capped = declaration({"command": "capacity", "max": 1, "ttl_seconds": 60}, now=NOW, max_ttl=60)
    assert capped == Declaration("capacity", NOW + 60, max=1)
    assert capped.summary() == "capacity max=1 until=2026-09-27T12:01:00Z"
    with pytest.raises(ControlError, match="61 is more than the 60 s maximum"):
        declaration({"command": "capacity", "max": 1, "ttl_seconds": 61}, now=NOW, max_ttl=60)
    assert declaration({"command": "resume"}, now=NOW, max_ttl=60) == Declaration("resume")
    with pytest.raises(ControlError, match="unknown control command"):
        declaration({"command": "shutdown"}, now=NOW, max_ttl=60)


def test_the_retry_hint_rounds_the_pause_up_to_the_minute() -> None:
    assert retry_after(NOW) == "2026-09-27T12:00Z"
    assert retry_after(NOW + 1) == "2026-09-27T12:01Z"
    assert retry_after(NOW + 59.5) == "2026-09-27T12:01Z"
    assert iso(NOW + 0.9) == "2026-09-27T12:00:00Z"


def test_the_schema_admits_each_command_exactly_and_no_free_text() -> None:
    assert COMMANDS == ("pause", "resume", "capacity", "refuse")
    assert "maintenance" in REASONS and "policy" not in REASONS, "a pause's reasons only"

    def message(payload: dict[str, object]) -> bytes:
        return build(
            sender="outpost@agents.contoso.test",
            to="control@agents.contoso.test",
            subject="control",
            intent=CONTROL_INTENT,  # type: ignore[arg-type]
            task="t_ctl",
            task_state="completed",
            text="control",
            payload=payload,
            schema=CONTROL_SCHEMA,
        ).as_bytes(policy=email_policy.SMTP)

    until = "2026-09-27T12:10:00Z"
    for valid in (
        {"command": "pause", "until": until, "reason": "overloaded"},
        {"command": "pause", "until": "2026-09-27T12:10:00.250+00:00", "reason": "operator"},
        {"command": "resume"},
        {"command": "capacity", "max": 3, "ttl_seconds": 600},
        {
            "command": "refuse",
            "recipient": "outpost+t_x@agents.contoso.test",
            "message_id": "<r1@agents.northwind.test>",
            "status": "5.7.1",
            "reason": "policy",
        },
    ):
        assert parse(message(valid)).payload == {"@context": "https://schema.org", **valid}
    refuse = {
        "command": "refuse",
        "recipient": "outpost+t_x@agents.contoso.test",
        "message_id": "<r1@agents.northwind.test>",
        "status": "5.7.1",
        "reason": "policy",
    }
    for invalid in (
        {"command": "pause", "until": until},  # a reason is required
        {"command": "pause", "until": until, "reason": "the building is on fire"},
        {"command": "pause", "until": "tomorrow", "reason": "offline"},
        {"command": "pause", "until": until, "reason": "offline", "max": 1},
        {"command": "resume", "until": until},
        {"command": "capacity", "max": 0, "ttl_seconds": 60},
        {"command": "capacity", "max": 2},
        {"command": "capacity", "max": 2, "ttl_seconds": 60, "reason": "overloaded"},
        {"command": "resume", "note": "free text"},
        {"command": "refuse"},
        {"command": "resume", "@context": "https://example.test"},
        # A refusal names one filed message, with a listed status and reason: never free text.
        {**refuse, "reason": "maintenance"},  # a pause's reason
        {"command": "pause", "until": until, "reason": "policy"},  # a refusal's reason
        {**refuse, "status": "5.1.1"},
        {**refuse, "status": "4.2.1"},
        {**refuse, "recipient": "Outpost@agents.contoso.test"},  # the gateway folds case
        {**refuse, "recipient": "outpost@agents.contoso.test, pat@plainmail.test"},
        {**refuse, "message_id": "not a message id"},
        {**refuse, "message_id": "<a b@x>"},
        {**refuse, "until": until},
        {**refuse, "text": "the agent's own words"},
        {key: value for key, value in refuse.items() if key != "message_id"},
    ):
        with pytest.raises(SchemaValidationError):
            message(invalid)


# --- configuration ---


def _yaml(path: Path, **extra: object) -> Path:
    values = {
        "domain": "example.test",
        "agent_domain": "agents.example.test",
        "mailbox": {"host": "mail.example.test"},
        "agents": {"intake": {"handler": "mailbox-only"}},
        "trust": [],
        **extra,
    }
    path.write_text(yaml.safe_dump(values), encoding="utf-8")
    return path


def test_the_control_address_defaults_and_can_be_renamed(tmp_path) -> None:
    config = load_config(_yaml(tmp_path / "default.yaml"))
    assert config.control_address == "control@agents.example.test"
    assert config.control.max_ttl_seconds == 3600
    renamed = load_config(
        _yaml(tmp_path / "renamed.yaml", control={"address": "gw-ctl", "max_ttl_seconds": 600})
    )
    assert renamed.control_address == "gw-ctl@agents.example.test"
    assert renamed.control.max_ttl_seconds == 600


@pytest.mark.parametrize(
    ("control", "message"),
    [
        ({"address": "intake"}, "also an agent's name"),
        ({"address": "Control"}, "local part"),
        ({"address": "ctl+x"}, "local part"),
        ({"max_ttl_seconds": 0}, "from 1 to 86400"),
        ({"max_ttl_seconds": 86401}, "from 1 to 86400"),
        ({"max_ttl_seconds": True}, "from 1 to 86400"),
        ({"ttl": 60}, "unknown keys: ttl"),
    ],
)
def test_a_bad_control_block_fails_config_load(tmp_path, control, message) -> None:
    with pytest.raises(ValueError, match=message):
        load_config(_yaml(tmp_path / "bad.yaml", control=control))


# --- the store ---


def test_an_agent_has_one_declaration_and_a_lapsed_one_is_not_read(tmp_path) -> None:
    store = Store(tmp_path / "journal.sqlite")
    store.declare_control(
        "outpost",
        "pause",
        declared_epoch=NOW,
        expires_at=NOW + 60,
        message_id="<a@x>",
        journal_sequence=None,
    )
    store.declare_control(
        "intake",
        "capacity",
        declared_epoch=NOW,
        expires_at=NOW + 10,
        message_id="<b@x>",
        journal_sequence=None,
        maximum=1,
    )
    assert set(store.controls(NOW, 3600)) == {"outpost", "intake"}
    assert set(store.controls(NOW + 10, 3600)) == {"outpost"}, "lapsed at its expiry"
    # A maximum lowered since shortens what was declared; a clock stepped back ignores it.
    assert set(store.controls(NOW + 30, 30)) == set(), "declared 30 s ago, maximum now 30 s"
    assert set(store.controls(NOW + 29, 30)) == {"outpost"}
    assert set(store.controls(NOW - 1, 3600)) == set(), "declared after 'now'"
    store.declare_control(
        "outpost",
        "capacity",
        declared_epoch=NOW,
        expires_at=NOW + 30,
        message_id="<c@x>",
        journal_sequence=None,
        maximum=3,
    )
    [row] = store.rows("SELECT * FROM agent_controls WHERE agent = 'outpost'")
    assert (row["command"], row["max"], row["reason"]) == ("capacity", 3, None)
    assert store.clear_control("outpost") is True
    assert store.clear_control("outpost") is False
    for command, maximum in (("resume", None), ("capacity", None), ("capacity", 0)):
        with pytest.raises(sqlite3.IntegrityError):
            store.declare_control(
                "x",
                command,
                declared_epoch=NOW,
                expires_at=NOW + 1,
                message_id="<d@x>",
                journal_sequence=None,
                maximum=maximum,
            )


def test_policy_rows_name_their_agent_and_an_old_store_gains_the_column(tmp_path) -> None:
    path = tmp_path / "journal.sqlite"
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE policy_events (sequence INTEGER PRIMARY KEY AUTOINCREMENT, "
            "created_at TEXT NOT NULL DEFAULT 'x', stage TEXT NOT NULL, rule TEXT NOT NULL, "
            "action TEXT NOT NULL, code TEXT, task TEXT, detail TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO policy_events(stage, rule, action, detail) VALUES ('rcpt', 'r', 'a', 'd')"
        )
    store = Store(path)
    store.record_policy("rcpt", "agent-paused", "tempfail", "450 4.2.1", "t_x", "d", agent="o")
    rows = store.rows("SELECT agent FROM policy_events ORDER BY sequence")
    assert [row["agent"] for row in rows] == [None, "o"]


# --- policy (PLAN §5.2 rows added by §5.10) ---


def _rcpt_state(**agent: object) -> State:
    return State(
        agent_domain="agents.contoso.test",
        agents={"outpost": AgentState(**{"watermark": 2, **agent})},  # type: ignore[arg-type]
        closed_tasks=frozenset({("outpost", "t_closed")}),
        control_agent="control",
    )


def _rcpt(agent: str = "outpost", token: str | None = "t_open") -> TxnContext:
    return TxnContext(
        recipient=f"{agent}@agents.contoso.test", recipient_agent=agent, task_token=token
    )


def test_nothing_from_outside_reaches_the_control_address() -> None:
    verdict = evaluate(Stage.RCPT, _rcpt("control", None), _rcpt_state())
    assert (verdict.rule, verdict.code) == ("control-address", "550 5.7.1")
    assert evaluate(Stage.RCPT, _rcpt("control", "t_x"), _rcpt_state()).rule == "control-address"
    # A gateway configured without one (policy tests, old callers) refuses it as an unknown agent.
    unset = replace(_rcpt_state(), control_agent=None)
    assert evaluate(Stage.RCPT, _rcpt("control", None), unset).rule == "agent-unknown"


def test_a_paused_agent_answers_450_with_the_retry_time() -> None:
    paused = _rcpt_state(paused_until=NOW + 90)
    verdict = evaluate(Stage.RCPT, _rcpt(), paused)
    assert (verdict.action, verdict.rule, verdict.code) == ("tempfail", "agent-paused", "450 4.2.1")
    assert verdict.text == "agent paused, retry after 2026-09-27T12:02Z"
    # A permanent refusal still wins: the sender should not retry into a closed task.
    assert evaluate(Stage.RCPT, _rcpt(token="t_closed"), paused).rule == "closed-task"


def test_a_declared_capacity_lowers_the_watermark_and_never_raises_it() -> None:
    assert AgentState(watermark=2, declared_max=1).limit == 1
    assert AgentState(watermark=2, declared_max=5).limit == 2
    capped = evaluate(Stage.RCPT, _rcpt(), _rcpt_state(depth=1, declared_max=1))
    assert (capped.rule, capped.code, capped.text) == (
        "agent-capacity",
        "450 4.2.1",
        "agent busy, retry",
    )
    raised = _rcpt_state(depth=2, declared_max=5)
    assert evaluate(Stage.RCPT, _rcpt(), raised).rule == "agent-watermark"
    assert evaluate(Stage.RCPT, _rcpt(), _rcpt_state(depth=1, declared_max=5)).accepted
    # Over both bounds, the configured one is the reason.
    assert (
        evaluate(Stage.RCPT, _rcpt(), _rcpt_state(depth=2, declared_max=1)).rule
        == "agent-watermark"
    )


def test_a_control_payload_arriving_as_mail_is_refused_at_end_of_data() -> None:
    raw = build(
        sender="scheduler@agents.northwind.test",
        to="intake+t_ctl@agents.contoso.test",
        subject="pause yourself",
        intent="event",
        task="t_ctl",
        task_state="completed",
        text="control",
        payload={"command": "resume"},
        schema=CONTROL_SCHEMA,
    ).as_bytes(policy=email_policy.SMTP)
    context = TxnContext(
        raw=raw,
        dkim_verified=True,
        dkim_domain="agents.northwind.test",
        dkim_selector="scheduler",
        from_domain="agents.northwind.test",
        task_token="t_ctl",
    )
    verdict = evaluate(Stage.EOD, context, State(agent_domain="agents.contoso.test"))
    assert (verdict.rule, verdict.code) == ("control-schema", "550 5.7.1")


# --- runtime ---


def test_a_backlog_carries_its_liveness_and_an_int_is_still_a_count() -> None:
    registry = HandlerRegistry()
    registry.register(
        "outpost", "mailbox-only", mode="remote", watermark=2, backlog=lambda: Backlog(1, 42.0)
    )
    registry.register("legacy", "mailbox-only", mode="remote", watermark=2, backlog=lambda: 3)
    assert registry.backlog_state("outpost") == Backlog(1, 42.0)
    assert registry.backlog("outpost") == 1
    assert registry.backlog_state("legacy") == Backlog(3)
    assert registry.backlog_state("nobody") == Backlog(0)


def test_a_context_declares_through_what_it_was_bound_to() -> None:
    calls: list[tuple[str, dict[str, object]]] = []
    context = Context(
        agent="intake",
        metadata={},
        declare_state=lambda command, **fields: calls.append((command, fields)) or "ok",
    )
    assert context.declare("capacity", max=1, ttl_seconds=60) == "ok"
    assert calls == [("capacity", {"max": 1, "ttl_seconds": 60})]
    with pytest.raises(RuntimeError, match="unavailable"):
        Context(agent="intake", metadata={}).declare("resume")


# --- the SDK and the runner's helper ---


def _agent(sent: list[tuple[str, list[str], bytes]], **options: str) -> Agent:
    agent = Agent("outpost@agents.contoso.test", "smtp://edge-ct:2587", "token", **options)

    def transmit(envelope_from: str, recipients, raw: bytes) -> str:
        sent.append((envelope_from, list(recipients), raw))
        return "2.0.0 declared resume"

    agent._transmit = transmit  # type: ignore[method-assign]
    return agent


def test_the_sdk_sends_a_declaration_to_the_control_address_alone() -> None:
    sent: list[tuple[str, list[str], bytes]] = []
    declared = _agent(sent).resume()
    assert declared.applied == "resume"
    [(envelope_from, recipients, raw)] = sent
    assert (envelope_from, recipients) == (
        "outpost@agents.contoso.test",
        ["control@agents.contoso.test"],
    )
    message = BytesParser(policy=email_policy.default).parsebytes(raw)
    assert message["To"] == "control@agents.contoso.test", "no task sub-address is added"
    assert message["Agent-Task"] == declared.task
    inbound = parse(raw)
    assert (inbound.intent, inbound.schema, inbound.payload) == (
        "event",
        CONTROL_SCHEMA,
        {"@context": "https://schema.org", "command": "resume"},
    )
    renamed: list[tuple[str, list[str], bytes]] = []
    _agent(renamed, control_address="gw-ctl@agents.contoso.test").resume()
    assert renamed[0][1] == ["gw-ctl@agents.contoso.test"]


def test_the_sdk_pause_and_capacity_helpers_fill_the_schema() -> None:
    sent: list[tuple[str, list[str], bytes]] = []
    agent = _agent(sent)
    agent.pause(seconds=120, reason="overloaded")
    agent.pause(until=datetime(2026, 9, 27, 14, 0, tzinfo=UTC))
    agent.capacity(1, ttl_seconds=300)
    payloads = [parse(raw).payload for _from, _to, raw in sent]
    assert payloads[0]["reason"] == "overloaded" and payloads[0]["until"].endswith("Z")  # type: ignore[index]
    assert payloads[1]["until"] == "2026-09-27T14:00:00Z"  # type: ignore[index]
    assert payloads[2] == {
        "@context": "https://schema.org",
        "command": "capacity",
        "max": 1,
        "ttl_seconds": 300,
    }
    with pytest.raises(ValueError, match="seconds or until"):
        agent.pause()
    with pytest.raises(ValueError, match="timezone-aware"):
        agent.pause(until=datetime(2026, 9, 27, 14, 0))
    with pytest.raises(SchemaValidationError):
        agent.pause(seconds=60, reason="free text reaches nobody")
    assert len(sent) == 3, "an invalid declaration never leaves the client"


def test_amx_runner_control_declares_with_the_token_alone(monkeypatch, capsys) -> None:
    calls: list[tuple[str, dict[str, object]]] = []

    def declare(self, command: str, **fields: object) -> Declared:
        calls.append((command, fields))
        return Declared("t_ctl", "<ctl@x>", f"{command} applied")

    monkeypatch.setattr(Agent, "declare", declare)
    monkeypatch.setenv("AMX_SUBMIT_TOKEN", "token")
    monkeypatch.delenv("AMX_IMAP_PASSWORD", raising=False)
    base = ["--agent", "outpost@agents.contoso.test", "--submit", "smtp://edge-ct:2587"]
    for command in (
        ["control", "pause", "--seconds", "30", "--reason", "offline"],
        ["control", "resume"],
        ["control", "capacity", "--max", "1", "--ttl-seconds", "60"],
    ):
        with pytest.raises(SystemExit) as exited:
            runner_module.main([*base, *command])
        assert exited.value.code == 0
    assert [command for command, _fields in calls] == ["pause", "resume", "capacity"]
    assert calls[0][1]["reason"] == "offline"
    assert calls[2][1] == {"max": 1, "ttl_seconds": 60}
    assert (
        "outpost@agents.contoso.test declared resume applied (task t_ctl)"
        in capsys.readouterr().out
    )
    with pytest.raises(SystemExit):
        runner_module.main(base)  # running the agent needs --imap, --handler, and the password


def test_amx_runner_control_reports_a_refusal(monkeypatch, capsys) -> None:
    import smtplib

    def refused(self, command: str, **_fields: object) -> Declared:
        raise smtplib.SMTPDataError(550, b"5.7.1 until is more than 3600 s ahead")

    monkeypatch.setattr(Agent, "declare", refused)
    monkeypatch.setenv("AMX_SUBMIT_TOKEN", "token")
    with pytest.raises(SystemExit) as exited:
        runner_module.main(
            [
                *("--agent", "outpost@agents.contoso.test", "--submit", "smtp://edge-ct:2587"),
                *("control", "pause", "--seconds", "7200"),
            ]
        )
    assert exited.value.code == 1
    assert "3600 s ahead" in capsys.readouterr().err


# --- trace ---


def _gateway(tmp_path: Path) -> tuple[GatewayConfig, Store, Journal]:
    config = load_config(
        _yaml(tmp_path / "gateway.yaml", agents={"outpost": {"mode": "remote"}, "intake": {}})
    )
    store = Store(tmp_path / "journal.sqlite")
    return config, store, Journal(tmp_path, store)


def test_trace_shows_the_declarations_of_the_agents_a_task_touched(tmp_path) -> None:
    config, store, journal = _gateway(tmp_path)

    def declare(agent: str, task: str, created_at: str | None = None) -> None:
        journal.append(
            b"Message-ID: <c@x>\r\n\r\nx\r\n",
            direction="control",
            identity=f"agents.example.test/{agent}",
            task=task,
            message_id=f"<{task}@x>",
            event="control-pause",
            detail=f"agent={agent} pause until=2026-09-27T12:10:00Z reason=maintenance",
        )
        if created_at is not None:  # the hash chain does not cover created_at
            with sqlite3.connect(tmp_path / "journal.sqlite") as connection:
                connection.execute(
                    "UPDATE journal SET created_at = ? WHERE task = ?", (created_at, task)
                )

    declare("outpost", "t_ctl_1")
    declare("intake", "t_ctl_2")
    declare("outpost", "t_ctl_old", "2000-01-01T00:00:00.000Z")  # lapsed long before
    store.record_policy(
        "rcpt", "agent-paused", "tempfail", "450 4.2.1", "t_task", "agent paused", agent="outpost"
    )
    declare("outpost", "t_ctl_after", "2999-01-01T00:00:00.000Z")  # after the task's last row
    policy_rows = store.rows("SELECT * FROM policy_events WHERE task = 't_task'")
    shown = declarations(store, config, policy_rows, [])
    assert [row["task"] for row in shown] == ["t_ctl_1"], "only the agent the task touched"
    assert declarations(store, config, [], []) == []

    result = CliRunner().invoke(
        app,
        [
            "trace",
            "t_task",
            "--config",
            str(tmp_path / "gateway.yaml"),
            "--data-dir",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0, result.output
    lines = result.output.splitlines()
    assert "submission control-pause journal #1" in lines[0]
    assert "agent=outpost pause until=2026-09-27T12:10:00Z" in lines[0]
    assert "milter RCPT agent-paused -> tempfail 450 4.2.1" in lines[1]


def test_a_refused_declaration_reads_as_submissions_in_the_timeline() -> None:
    row = {
        "created_at": "2026-09-27T12:00:00.000Z",
        "stage": "control",
        "rule": "control-refused",
        "action": "reject",
        "code": "550 5.7.1",
        "detail": "a control declaration must come from the login's agent",
    }
    assert " submission CONTROL control-refused -> reject 550 5.7.1 " in policy_line(row, "d")


def test_in_process_agents_declare_to_the_configured_control_address(tmp_path) -> None:
    from amx.gateway import outbound_agents

    config = load_config(
        _yaml(
            tmp_path / "gateway.yaml",
            agents={"intake": {"handler": "mailbox-only", "submit_token": "t"}, "quiet": {}},
            control={"address": "gw-ctl"},
        )
    )
    agents = outbound_agents(config)
    assert set(agents) == {"intake"}, "only agents that can submit"
    assert agents["intake"].control_address == "gw-ctl@agents.example.test"


def test_amx_mcp_takes_a_renamed_control_address(monkeypatch) -> None:
    pytest.importorskip("mcp")
    from amx import mcp_server

    built: list[object] = []

    class Server:
        def run(self) -> None:
            return None

    monkeypatch.setattr(mcp_server, "build_server", lambda tools: built.append(tools) or Server())
    monkeypatch.setenv("AMX_IMAP_PASSWORD", "p")
    monkeypatch.setenv("AMX_SUBMIT_TOKEN", "t")
    mcp_server.main(
        ["--agent", "intake@agents.contoso.test", "--control-address", "gw-ctl@agents.contoso.test"]
    )
    assert built[0].agent.control_address == "gw-ctl@agents.contoso.test"  # type: ignore[attr-defined]
