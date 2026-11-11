"""Registered agents in the gateway's configuration, and reloading it while it runs (PLAN §5.2)."""

from __future__ import annotations

import logging
from dataclasses import replace
from pathlib import Path

import pytest
import yaml

from amx.adapters.lmtp import LmtpHandler
from amx.adapters.submission import SubmissionService
from amx.config import TrustGrant, load_config
from amx.credentials import hash_token
from amx.gateway import LiveGateway
from amx.journal import Journal
from amx.mailbox import MailboxAppender
from amx.policy import State
from amx.registry import Grant, Registration, write_grant, write_registration
from amx.reload import ConfigWatcher, config_fingerprint, diff_agents, restart_needed
from amx.runtime import HandlerRegistry
from amx.store import Store

BASE = {
    "domain": "example.test",
    "agent_domain": "agents.example.test",
    "data_dir": "data",
    "registry_dir": "registry",
    "mailbox": {"host": "mail.example.test"},
    "agents": {"intake": {"handler": "mailbox-only", "mode": "sync", "submit_token": "dev-t"}},
    "trust": [
        {"d": "agents.example.test", "s": "intake", "intents": ["request"], "schemas": ["*"]},
    ],
}


def _write(tmp_path: Path, **changes) -> Path:
    path = tmp_path / "gateway.yaml"
    path.write_text(yaml.safe_dump({**BASE, **changes}), encoding="utf-8")
    return path


def _register(tmp_path: Path, name: str = "probe", token: str = "probe-token", **changes) -> None:
    write_registration(
        tmp_path / "registry",
        Registration(name=name, submit_token_hash=hash_token(token), **changes),
    )


def test_registered_agents_and_their_grants_merge_into_the_config(tmp_path) -> None:
    _register(tmp_path, intents=("response",), can_open_tasks=False)
    write_grant(tmp_path / "registry", Grant("agents.other.test", "planner", intents=("request",)))
    config = load_config(_write(tmp_path))
    assert set(config.agents) == {"intake", "probe"}
    probe = config.agents["probe"]
    assert probe.mode == "remote" and probe.submit_token is None and probe.selector == "probe"
    own = config.grant_for("agents.example.test", "probe", "agent")
    assert own is not None and own.intents == frozenset({"response"}) and not own.can_open_tasks
    other = config.grant_for("agents.other.test", "planner", "agent")
    assert other is not None and other.intents == frozenset({"request"})
    assert config.registry_dir == (tmp_path / "registry").resolve()


def test_a_registered_agent_may_not_shadow_the_yamls(tmp_path) -> None:
    _register(tmp_path, name="intake")
    with pytest.raises(ValueError, match="also configured in the gateway YAML"):
        load_config(_write(tmp_path))


def test_a_yaml_token_hash_must_be_a_hash(tmp_path) -> None:
    agents = {"intake": {"handler": "mailbox-only", "submit_token_hash": "plaintext"}}
    with pytest.raises(ValueError, match="not an amx token hash"):
        load_config(_write(tmp_path, agents=agents))


def test_a_grant_names_its_agent_exactly() -> None:
    # SH-44: the identity is the signed From's local part, so no suffix may stand for the agent;
    # a key rotation never changes the name.
    grant = TrustGrant(d="agents.other.test", s="planner", intents=frozenset({"request"}))
    assert grant.names("agents.other.test", "planner")
    assert not grant.names("agents.other.test", "planner.k2")
    assert not grant.names("agents.other.test", "planner2")
    assert not grant.names("agents.other.test", "plan")
    assert not grant.names("agents.else.test", "planner")
    assert not grant.names("agents.other.test", "planner.mail")
    state = State(agent_domain="agents.example.test", grants=(grant,))
    assert state.grant_for("agents.other.test", "planner", "agent") is grant
    assert state.grant_for("agents.other.test", "planner.k7", "agent") is None
    assert state.grant_for("agents.other.test", "planner-evil", "agent") is None


def test_diff_agents_sorts_changes_by_kind(tmp_path) -> None:
    old = load_config(_write(tmp_path))
    _register(tmp_path)
    new = load_config(_write(tmp_path))
    assert diff_agents(old, new).added == ("probe",)
    assert diff_agents(new, old).removed == ("probe",)
    disabled = replace(
        new, agents={**new.agents, "probe": replace(new.agents["probe"], enabled=False)}
    )
    assert diff_agents(new, disabled).changed == ("probe",)
    rebuilt = replace(
        new, agents={**new.agents, "intake": replace(new.agents["intake"], workers=3)}
    )
    assert diff_agents(new, rebuilt).rebuilt == ("intake",)
    assert not diff_agents(new, new)
    assert diff_agents(new, disabled).summary() == "changed probe"


def test_restart_needed_names_what_a_reload_cannot_change(tmp_path) -> None:
    old = load_config(_write(tmp_path))
    assert restart_needed(old, load_config(_write(tmp_path, lmtp_port=1))) == []  # not a key
    moved = load_config(_write(tmp_path, listeners={"lmtp_port": 2525}))
    assert restart_needed(old, moved) == ["lmtp_port"]
    assert restart_needed(old, replace(old, domain="other.test")) == ["domain"]
    # Copied into every in-process agent's submission client, which a reload does not rebuild.
    renamed = replace(old, control=replace(old.control, address="gw-ctl"))
    assert restart_needed(old, renamed) == ["control.address"]
    # The declaration bound is read at each use, so it reloads.
    assert restart_needed(old, replace(old, control=replace(old.control, max_ttl_seconds=60))) == []
    assert restart_needed(old, replace(old, submission_client_host="mx")) == [
        "submission_client_host"
    ]


def test_config_fingerprint_follows_the_yaml_and_the_registry(tmp_path) -> None:
    path = _write(tmp_path)
    first = config_fingerprint(path, tmp_path / "registry")
    _register(tmp_path)
    second = config_fingerprint(path, tmp_path / "registry")
    _write(tmp_path, greylisting=True)
    third = config_fingerprint(path, tmp_path / "registry")
    assert len({first, second, third}) == 3


def _watcher(tmp_path: Path, applied: list):
    path = _write(tmp_path)
    current = [load_config(path)]

    def apply(config) -> None:
        applied.append(config)
        current[0] = config

    return ConfigWatcher(path, lambda: current[0], apply), path


def test_the_watcher_applies_a_change_once(tmp_path) -> None:
    applied: list = []
    watcher, _path = _watcher(tmp_path, applied)
    assert watcher.check()  # the first check always loads
    assert not watcher.check()
    _register(tmp_path)
    assert watcher.check()
    assert "probe" in applied[-1].agents
    assert not watcher.check()


def test_the_watcher_keeps_the_running_config_when_the_new_one_fails(tmp_path, caplog) -> None:
    applied: list = []
    watcher, path = _watcher(tmp_path, applied)
    watcher.check()
    path.write_text("domain: [", encoding="utf-8")
    with caplog.at_level(logging.ERROR):
        assert not watcher.check()
        assert not watcher.check()  # reported once, not every second
    assert len(applied) == 1
    assert sum("config reload failed" in record.message for record in caplog.records) == 1


def test_the_watcher_refuses_what_needs_a_restart(tmp_path, caplog) -> None:
    applied: list = []
    watcher, _path = _watcher(tmp_path, applied)
    watcher.check()
    _write(tmp_path, agent_domain="agents.other.test")
    with caplog.at_level(logging.ERROR):
        assert not watcher.check()
    assert "agent_domain can change only on a restart" in caplog.text
    assert len(applied) == 1


def test_a_revocation_applies_while_a_listener_change_waits_for_a_restart(tmp_path, caplog) -> None:
    """An edit only a restart applies must not hold back an agent's removal (PLAN §11.5)."""
    applied: list = []
    watcher, _path = _watcher(tmp_path, applied)
    _register(tmp_path)
    watcher.check()
    assert applied[-1].agents["probe"].enabled
    _write(tmp_path, listeners={"submission_port": 2600})
    _register(tmp_path, enabled=False)
    with caplog.at_level(logging.ERROR):
        assert watcher.check()
        assert not watcher.check()  # reported once
    running = applied[-1]
    assert not running.agents["probe"].enabled  # the revocation took effect
    assert running.submission_port == 2587  # the listener stays as bound until a restart
    assert caplog.text.count("config reload applied, except submission_port") == 1
    _register(tmp_path, enabled=True)
    assert watcher.check() and applied[-1].agents["probe"].enabled
    assert applied[-1].submission_port == 2587


def _gateway(tmp_path: Path, **changes):
    config = load_config(_write(tmp_path, **changes))
    config.data_dir.mkdir(parents=True, exist_ok=True)
    store = Store(config.data_dir / "journal.sqlite")
    journal = Journal(config.data_dir, store)
    registry = HandlerRegistry()
    mailbox = MailboxAppender(config.mailbox)
    submission = SubmissionService(config, journal, mailbox=mailbox, reinject=lambda *a: None)
    lmtp = LmtpHandler(config, store, journal, registry, mailbox, {})
    gateway = LiveGateway(config, store, registry, mailbox, submission, lmtp, start_watchers=False)
    gateway.start()
    return gateway


@pytest.mark.parametrize("running_port,new_port", [(0, 8892), (8892, 0), (8892, 8893)])
def test_people_milter_port_waits_for_restart_without_delaying_revocation(
    tmp_path, caplog, running_port, new_port
) -> None:
    _register(tmp_path)
    gateway = _gateway(
        tmp_path,
        people_domain="people.example.test",
        listeners={"people_milter_port": running_port},
    )
    watcher = ConfigWatcher(tmp_path / "gateway.yaml", gateway.current, gateway.apply)
    try:
        assert watcher.check()
        assert gateway.submission.authenticate("probe", "probe-token")
        _write(
            tmp_path,
            people_domain="people.example.test",
            listeners={"people_milter_port": new_port},
        )
        _register(tmp_path, enabled=False)
        with caplog.at_level(logging.ERROR):
            assert watcher.check()
            assert not watcher.check()
        assert (
            caplog.text.count(
                "config reload applied, except people_milter_port, which a restart applies"
            )
            == 1
        )
        running = gateway.current()
        assert running.people_milter_port == running_port  # the listener stays as initially bound
        assert running.people_domain == "people.example.test"
        assert gateway.lmtp.config is running and gateway.submission.config is running
        assert not running.agents["probe"].enabled
        assert not gateway.submission.authenticate("probe", "probe-token")
        recorded = gateway.store.agent("probe")
        assert recorded is not None and recorded["enabled"] == 0
        assert load_config(tmp_path / "gateway.yaml").people_milter_port == new_port
    finally:
        gateway.stop()
        gateway.registry.stop()


def test_apply_adds_a_registered_agent_before_the_config_names_it(tmp_path) -> None:
    gateway = _gateway(tmp_path)
    _register(tmp_path)
    new = load_config(tmp_path / "gateway.yaml")
    registered_before_swap: list[bool] = []
    original = gateway.registry.register

    def register(agent, *args, **kwargs):
        original(agent, *args, **kwargs)
        registered_before_swap.append("probe" not in gateway.current().agents)

    gateway.registry.register = register  # type: ignore[method-assign]
    gateway.apply(new)
    assert registered_before_swap == [True]
    assert gateway.registry.mode("probe") == "remote"
    assert gateway.current() is new
    assert gateway.lmtp.config is new and gateway.submission.config is new
    assert gateway.store.agent("probe")["enabled"] == 1
    assert "probe" not in gateway.lmtp.outbound_agents  # a remote agent replies from its host


def test_apply_removes_an_agent_after_the_config_drops_it(tmp_path) -> None:
    _register(tmp_path)
    gateway = _gateway(tmp_path)
    assert gateway.registry.registered("probe")
    (tmp_path / "registry" / "agents" / "probe.yaml").unlink()
    new = load_config(tmp_path / "gateway.yaml")
    unregistered_after_swap: list[bool] = []
    original = gateway.registry.unregister

    def unregister(agent):
        unregistered_after_swap.append("probe" not in gateway.current().agents)
        original(agent)

    gateway.registry.unregister = unregister  # type: ignore[method-assign]
    gateway.apply(new)
    assert unregistered_after_swap == [True]
    assert not gateway.registry.registered("probe")
    assert gateway.store.agent("probe")["enabled"] == 0


def test_apply_changes_tokens_and_watermarks_in_place(tmp_path) -> None:
    _register(tmp_path, token="first")
    gateway = _gateway(tmp_path)
    assert gateway.submission.authenticate("probe", "first")
    _register(tmp_path, token="second", watermark=5)
    gateway.apply(load_config(tmp_path / "gateway.yaml"))
    assert not gateway.submission.authenticate("probe", "first")
    assert gateway.submission.authenticate("probe", "second")
    assert gateway.registry._pools["probe"].watermark == 5


def test_a_bad_handler_leaves_everything_as_it_was(tmp_path) -> None:
    gateway = _gateway(tmp_path)
    _register(tmp_path, mode="sync", handler="amx.nowhere:handle")
    before = gateway.current()
    with pytest.raises(ModuleNotFoundError):
        gateway.apply(load_config(tmp_path / "gateway.yaml"))
    assert gateway.current() is before
    assert not gateway.registry.registered("probe")


def test_an_in_process_registered_agent_submits_with_an_internal_token(tmp_path) -> None:
    _register(tmp_path, mode="sync", handler="amx.examples.echo:handle")
    gateway = _gateway(tmp_path)
    outbound = gateway.lmtp.outbound_agents["probe"]
    assert gateway.submission.authenticate("probe", outbound.token)
    # ... which only this process knows, and which no remote agent can use.
    assert not gateway.submission.authenticate("probe", "probe-token-guess")
    _register(tmp_path, mode="remote")
    gateway.apply(load_config(tmp_path / "gateway.yaml"))
    assert not gateway.submission.authenticate("probe", outbound.token)
    assert gateway.submission.authenticate("probe", "probe-token")


def test_a_disabled_agent_cannot_authenticate(tmp_path) -> None:
    _register(tmp_path)
    gateway = _gateway(tmp_path)
    _register(tmp_path, enabled=False)
    gateway.apply(load_config(tmp_path / "gateway.yaml"))
    assert not gateway.submission.authenticate("probe", "probe-token")


def test_a_failed_apply_is_retried_until_it_applies(tmp_path, caplog) -> None:
    path = _write(tmp_path)
    current = [load_config(path)]
    attempts: list[object] = []

    def flaky(config) -> None:
        attempts.append(config)
        if len(attempts) < 3:
            raise RuntimeError("database is locked")
        current[0] = config

    watcher = ConfigWatcher(path, lambda: current[0], flaky)
    _register(tmp_path)
    with caplog.at_level(logging.ERROR):
        assert not watcher.check()
        assert not watcher.check()  # retried, but not reported again
        assert watcher.check()
        assert not watcher.check()
    assert len(attempts) == 3 and "probe" in current[0].agents
    assert caplog.text.count("database is locked") == 1


def test_apply_never_waits_on_the_store_before_the_swap(tmp_path, monkeypatch) -> None:
    gateway = _gateway(tmp_path)
    _register(tmp_path, enabled=False)

    def busy(*_args, **_kwargs):
        raise RuntimeError("database is locked")

    monkeypatch.setattr(gateway.store, "add_agent", busy)
    new = load_config(tmp_path / "gateway.yaml")
    gateway.apply(new)
    assert gateway.current() is new and not new.agents["probe"].enabled
