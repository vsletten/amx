"""The live bundle's parameters, install, DNS rendering, rotation, and certificates (amx.live)."""

from __future__ import annotations

import json
import os
import re
import socket
import stat
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from amx import live
from amx import registration as reg
from amx.accounts import read_accounts
from amx.cli import app
from amx.config import load_config
from amx.credentials import hash_password, verify_token
from amx.live import ParamsError, load_params
from amx.provision import dkim_public_key, generate_dkim_key, txt_strings, write_private
from amx.registry import read_registrations

EXAMPLE = Path(__file__).resolve().parents[2] / "deploy" / "live" / "live.example.yaml"


def _params_file(tmp_path: Path, **changes: object) -> Path:
    raw = yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))
    raw["state_dir"] = str(tmp_path / "state")
    raw.update(changes)
    path = tmp_path / "live.yaml"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    return path


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


@pytest.fixture
def quiet(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, ...]]:
    """No docker: record what would be restarted instead."""
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(live, "running", lambda _params, _service: False)
    monkeypatch.setattr(live, "run_compose", lambda _params, *args, **_kw: calls.append(args))
    return calls


def test_the_example_loads_with_the_documented_defaults(tmp_path: Path) -> None:
    params = load_params(_params_file(tmp_path))
    assert params.agent_domain == "agents.example.com"
    assert params.org_domain == params.dns_zone == "example.com"
    assert params.mx_host == "mail.example.com"
    assert (params.mailhost_ip, params.gateway_ip) == ("172.31.250.10", "172.31.250.20")
    assert params.ports == {"smtp": 25, "submission": 587, "imaps": 993, "acme_http": 80}
    assert params.tls_mode == "acme" and params.acme_server == live.LETSENCRYPT
    assert params.dmarc_policy == "none"
    assert params.dmarc_rua == "postmaster@agents.example.com"
    # Agents are registered, not listed (PLAN §11.5): the example lists none.
    assert params.legacy_agents == ()


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"TYPESAFE_API_KEY": "sk-x"}, "TYPESAFE_API_KEY"),
        ({"llm": {"api_key": "x"}}, "api_key"),
        ({"agents": [{"name": "a", "submit_token": "x"}]}, "submit_token"),
        ({"surprise": 1}, "unknown keys: surprise"),
        ({"public_ip": "2001:db8::1"}, "IPv4"),
        ({"agent_domain": "agents.other.test"}, "not inside dns_zone"),
        ({"agents": [{"name": "postmaster"}]}, "postmaster"),
        ({"agents": [{"name": "control"}]}, "control"),
        ({"agents": [{"name": "Intake"}]}, "lowercase"),
        ({"agents": [{"name": "x", "mode": "remote", "handler": "m:f"}]}, "own host"),
        ({"agents": [{"name": "x"}, {"name": "x"}]}, "unique"),
        ({"agents": {"intake": {}}}, "must be a list"),
        ({"dns": {"dmarc_rua": "me@example.org"}}, "inside example.com"),
        ({"tls": {"extra_names": ["localhost"]}}, "self-signed"),
        ({"admin_contact": "a,b@example.com"}, "email address"),
        ({"content_judge": {"mode": False}}, 'quote "off"'),
    ],
)
def test_bad_parameters_fail_with_a_reason(tmp_path: Path, changes, message: str) -> None:
    with pytest.raises(ParamsError, match=message):
        load_params(_params_file(tmp_path, **changes))


_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _amx(*arguments: str) -> tuple[int, str]:
    """Run the CLI; exit code and plain output (no colours, no error-box borders)."""
    result = CliRunner().invoke(app, list(arguments), env={"COLUMNS": "200", "NO_COLOR": "1"})
    plain = re.sub(r"[│╭╮╰╯─]", " ", _ANSI.sub("", result.output))
    return result.exit_code, re.sub(r"[ \t]*\n[ \t]*", "\n", re.sub(r"[ \t]+", " ", plain))


def _register(path: Path, name: str, *extra: str) -> str:
    """`amx live agent add` for this parameters file; returns its output."""
    code, output = _amx("live", "agent", "add", name, "--params", str(path), *extra)
    assert code == 0, output
    return output


def _register_code(path: Path, name: str, *extra: str) -> tuple[int, str]:
    return _amx("live", "agent", "add", name, "--params", str(path), *extra)


def _installed(tmp_path: Path, **changes: object) -> tuple[Path, live.LiveParams]:
    """An installed lane with the example's two agents registered: queued intake, remote outpost."""
    path = _params_file(tmp_path, **changes)
    params = load_params(path)
    live.install(params)
    _register(path, "intake", "--mode", "queued", "--handler", "amx.examples.intake:handle")
    _register(path, "outpost")
    return path, params


@pytest.mark.usefixtures("per_agent_dkim")
def test_install_writes_secrets_private_and_keeps_them(tmp_path: Path) -> None:
    path = _params_file(tmp_path)
    params = load_params(path)
    live.install(params)
    secrets_dir = params.secrets_dir
    assert _mode(secrets_dir) == 0o700
    for directory in (params.registry_dir, params.accounts_file.parent, params.bundles_dir):
        assert _mode(directory) == 0o700, directory
    for secret in (
        params.credentials_path,
        params.gateway_config,
        secrets_dir / "mailhost" / "mail-users",
        secrets_dir / "logins.txt",
    ):
        assert _mode(secret) == 0o600, secret
    credentials = yaml.safe_load(params.credentials_path.read_text())
    # The host's own logins only: an agent's secrets go to its one bundle (PLAN §5.2).
    assert set(credentials) == {"gateway_master", "approver", "postmaster"}
    values = list(credentials.values())
    assert len(set(values)) == len(values) and all(len(value) >= 32 for value in values)
    # compose.env is not a secret, and holds none.
    environment = params.compose_env.read_text()
    assert _mode(params.compose_env) == 0o644
    assert not any(value in environment for value in values)
    # A second install keeps every secret, key, and registered agent.
    _register(path, "outpost")
    key = dkim_public_key(params.keys_dir / "outpost.private.pem")
    registry = {p.name: p.read_bytes() for p in (params.registry_dir / "agents").iterdir()}
    accounts = params.accounts_file.read_bytes()
    live.install(params)
    again = yaml.safe_load(params.credentials_path.read_text())
    assert again == credentials
    assert dkim_public_key(params.keys_dir / "outpost.private.pem") == key
    assert {p.name: p.read_bytes() for p in (params.registry_dir / "agents").iterdir()} == registry
    assert params.accounts_file.read_bytes() == accounts


def test_the_rendered_gateway_config_loads_and_binds_trusted_listeners_privately(
    tmp_path: Path,
) -> None:
    path = _params_file(tmp_path)
    params = load_params(path)
    live.install(params)
    config = load_config(params.gateway_config)
    # Only the agent domain is "own": the org domain's people are external (held, rate-limited).
    assert config.agent_domain == config.domain == "agents.example.com"
    assert config.zone == "example.com"  # `amx agent` names records for the example.com zone
    assert config.milter_host == config.lmtp_host == params.gateway_ip
    assert config.submission_host == "0.0.0.0"
    assert config.submission_client_host == params.mx_host
    assert config.postfix_host == params.mailhost_ip
    assert config.dns_server is None  # the host's resolver, not the dev CoreDNS
    assert config.role_addresses == frozenset({"postmaster", "abuse"})
    # No agent is configured in the YAML; the registry and accounts paths are relative to it, so
    # they name the same files from the host and from the container's /secrets mount.
    assert config.agents == {}
    assert config.registry_dir == params.registry_dir
    assert config.accounts_file == params.accounts_file
    raw = yaml.safe_load(params.gateway_config.read_text())
    assert (raw["registry_dir"], raw["keys_dir"]) == ("registry", "keys")
    assert config.submission_tls_ca is None  # acme: the system's trust store
    assert [rule.name for rule in config.hold_rules] == ["first-contact-domain", "commits-money"]
    assert config.content_judge.backend.backend == "stub"
    assert config.content_judge.mode == "enforce"
    assert config.limits.max_bytes == 10485760
    users = (params.secrets_dir / "mailhost" / "mail-users").read_text().splitlines()
    entries = [line.split("|") for line in users if not line.startswith("#")]
    names = [name for name, _hash in entries]
    # Hashes only: no password reaches the mailhost, or any command line there.
    assert all(value.startswith("{SHA512-CRYPT}$6$") for _name, value in entries)
    credentials = yaml.safe_load(params.credentials_path.read_text())
    assert credentials["approver"] not in "\n".join(users)
    # The host's own users; the agents reach the mailhost through the accounts file.
    assert names == ["postmaster@agents.example.com", "gateway", "approver"]
    # A registered agent is in the gateway's configuration at once, with its own grant.
    _register(path, "outpost")
    config = load_config(params.gateway_config)
    assert config.agents["outpost"].mode == "remote"
    assert config.agents["outpost"].submit_token is None
    assert config.agents["outpost"].submit_token_hash
    assert config.grant_for("agents.example.com", "outpost", "agent") is not None
    assert config.grant_for("agents.other.test", "outpost", "agent") is None


@pytest.mark.usefixtures("per_agent_dkim")
def test_live_agent_add_uses_the_hosts_paths_endpoints_and_zone(tmp_path: Path) -> None:
    path = _params_file(tmp_path)
    params = load_params(path)
    live.install(params)
    output = _register(path, "outpost")
    [bundle] = params.bundles_dir.glob("outpost-*.json")
    assert _mode(bundle) == 0o600
    values = json.loads(bundle.read_text())
    # imaps://: the live Dovecot takes passwords only over TLS, and runners reach only 993.
    assert values["imap"] == "imaps://mail.example.com"
    assert values["submission"] == "smtp://mail.example.com:587"
    assert values["token"] not in output and values["password"] not in output
    # Named for the example.com zone, not relative to the agent domain.
    assert "DNS host: Type TXT | Name outpost._domainkey.agents | Value v=DKIM1" in output
    assert "_agents" not in output  # no agent card is served here
    assert "amx live preflight (dns:dkim:outpost)" in output
    assert f"amx-runner --credentials {bundle.name} --handler" in output
    [account] = read_accounts(params.accounts_file).values()
    assert account.address == "outpost@agents.example.com" and account.state == "enabled"
    assert set(read_registrations(params.registry_dir)) == {"outpost"}
    # The plain command works on the live state too: the YAML's relative paths are host paths.
    code, listed = _amx("agent", "list", "--config", str(params.gateway_config))
    assert code == 0 and "outpost: registered, remote, enabled; outpost (active)" in listed
    code, refused = _amx("live", "agent", "add", "postmaster", "--params", str(path))
    assert code != 0 and "reserved" in refused
    code, refused = _amx(
        "live", "agent", "add", "worker", "--mode", "queued", "--params", str(path)
    )
    assert code != 0 and "--handler" in refused


@pytest.mark.usefixtures("per_agent_dkim")
def test_live_agent_rotate_remove_enable_and_purge(tmp_path: Path, monkeypatch) -> None:
    path, params = _installed(tmp_path)
    hashes = read_registrations(params.registry_dir)["outpost"].submit_token_hash
    code, output = _amx("live", "agent", "rotate", "outpost", "--params", str(path))
    assert code == 0, output
    assert len(list(params.bundles_dir.glob("outpost-*.json"))) == 2
    rotated = read_registrations(params.registry_dir)["outpost"]
    assert rotated.submit_token_hash != hashes and rotated.pending_selector == "outpost.k2"
    assert "Name outpost.k2._domainkey.agents" in output
    assert f"amx live agent rotate outpost --activate --params {path}" in output
    # --activate checks the staged key in DNS, through the resolver it is given.
    asked: list[tuple[str, str | None]] = []
    monkeypatch.setattr(reg, "lookup_txt", lambda name, server: asked.append((name, server)))
    code, output = _amx(
        "live", "agent", "rotate", "outpost", "--activate", "--dns-server", "127.0.0.1:15353",
        "--params", str(path),
    )  # fmt: skip
    assert code == 1 and "missing in DNS" in output
    assert asked == [("outpost.k2._domainkey.agents.example.com", "127.0.0.1:15353")]
    code, output = _amx(
        "live", "agent", "rotate", "outpost", "--activate", "--no-dns-check", "--params", str(path)
    )
    assert code == 0 and "now signs with s=outpost.k2" in output
    selectors = {item.selector: item.role for item in live.dkim_selectors(params)}
    assert selectors["outpost.k2"] == "active"
    assert selectors["outpost"].startswith("retiring until")
    code, output = _amx("live", "agent", "remove", "outpost", "--params", str(path))
    assert code == 0 and f"amx live agent remove outpost --purge --params {path}" in output
    assert read_accounts(params.accounts_file)["outpost@agents.example.com"].state == "disabled"
    code, output = _amx("live", "agent", "enable", "outpost", "--params", str(path))
    assert code == 0 and read_registrations(params.registry_dir)["outpost"].enabled
    _amx("live", "agent", "remove", "outpost", "--params", str(path))
    code, output = _amx(
        "live", "agent", "remove", "outpost", "--purge", "--now", "--params", str(path)
    )
    assert code == 0, output
    assert "outpost" not in read_registrations(params.registry_dir)
    assert read_accounts(params.accounts_file)["outpost@agents.example.com"].state == "purge"
    assert not list(params.keys_dir.glob("outpost*.private.pem"))
    assert "(name in zone example.com: outpost.k2._domainkey.agents)" in output
    code, output = _amx("live", "agent", "list", "--params", str(path))
    assert code == 0 and "intake: registered, queued, enabled" in output


def test_an_earlier_installs_agents_move_into_the_registry_unchanged(tmp_path: Path) -> None:
    """The upgrade path (PLAN §11.5): keys, token, password, and mailbox all kept."""
    agents = [
        {"name": "intake", "mode": "queued", "handler": "amx.examples.intake:handle"},
        {"name": "outpost", "mode": "remote", "watermark": 4, "external_per_day": 3},
    ]
    path = _params_file(tmp_path, agents=agents)
    params = load_params(path)
    # What the earlier install left: its agents' secrets, a key each, and a runner's env file.
    old = {
        name: {"imap_password": f"{name}-password-" + "x" * 20, "submit_token": f"{name}-t" * 6}
        for name in ("intake", "outpost")
    }
    params.keys_dir.mkdir(parents=True)
    for name in old:
        generate_dkim_key(params.keys_dir / f"{name}.private.pem")
    keys = {name: dkim_public_key(params.keys_dir / f"{name}.private.pem") for name in old}
    body = {"gateway_master": "g" * 32, "approver": "a" * 32, "postmaster": "p" * 32, "agents": old}
    write_private(params.credentials_path, yaml.safe_dump(body))
    write_private(params.bundles_dir / "outpost.env", "AMX_SUBMIT_TOKEN=...\n")
    notes = live.install(params)
    assert any(note.startswith("migrated intake") for note in notes)
    assert any("outpost.env still holds its credentials" in note for note in notes)
    registered = read_registrations(params.registry_dir)
    assert set(registered) == {"intake", "outpost"}
    for name in old:
        assert verify_token(old[name]["submit_token"], registered[name].submit_token_hash)
        assert registered[name].selector == name  # DNS unchanged
        assert dkim_public_key(params.keys_dir / f"{name}.private.pem") == keys[name]
    assert (registered["intake"].mode, registered["intake"].handler) == (
        "queued",
        "amx.examples.intake:handle",
    )
    assert (registered["outpost"].watermark, registered["outpost"].external_per_day) == (4, 3)
    assert registered["outpost"].imap_endpoint == "imaps://mail.example.com"
    accounts = read_accounts(params.accounts_file)
    for name in old:
        account = accounts[f"{name}@agents.example.com"]
        salt = account.password_hash.split("$")[2]
        assert hash_password(old[name]["imap_password"], salt=salt) == account.password_hash
    # The mailhost adopts exactly these mailboxes, for exactly these registrations; the adoption
    # is written before the login, so a running sync never sees one without the other.
    adopt = params.adopt_file.read_text().splitlines()
    assert sorted(adopt) == sorted(f"{a.address}:{a.generation}" for a in accounts.values())
    assert _mode(params.adopt_file) == 0o600
    # The plaintext leaves the host's credentials; the gateway YAML names no agent.
    assert "agents" not in yaml.safe_load(params.credentials_path.read_text())
    config = load_config(params.gateway_config)
    assert config.agents["intake"].mode == "queued" and config.agents["intake"].submit_token_hash
    # A second install changes nothing, and says the list can go.
    again = live.install(params)
    assert read_registrations(params.registry_dir) == registered
    assert params.adopt_file.read_text().splitlines() == adopt
    assert "agents: in the parameters file is no longer read (all registered): delete it" in again
    assert not any(note.startswith("migrated") for note in again)


def test_an_earlier_installs_agent_that_agents_omits_is_refused(tmp_path: Path) -> None:
    """Dropped from agents: before the upgrade, it would lose its login and, registered again
    later, its mailbox: install says what to do instead."""
    params = load_params(_params_file(tmp_path))
    body = {"gateway_master": "g" * 32, "approver": "a" * 32, "postmaster": "p" * 32}
    body["agents"] = {"outpost": {"imap_password": "x" * 32, "submit_token": "y" * 32}}
    write_private(params.credentials_path, yaml.safe_dump(body))
    with pytest.raises(ParamsError, match="holds outpost from an earlier install"):
        live.install(params)


def test_a_migration_cut_short_is_finished_by_the_next_install(tmp_path: Path, monkeypatch) -> None:
    agents = [{"name": "intake", "mode": "queued", "handler": "amx.examples.intake:handle"}]
    params = load_params(_params_file(tmp_path, agents=agents))
    old = {"imap_password": "i" * 32, "submit_token": "t" * 32}
    body = {"gateway_master": "g" * 32, "approver": "a" * 32, "postmaster": "p" * 32}
    write_private(params.credentials_path, yaml.safe_dump({**body, "agents": {"intake": old}}))
    generate_dkim_key(params.keys_dir / "intake.private.pem")

    def crash(*_args, **_kwargs):
        raise RuntimeError("the host went down")

    monkeypatch.setattr(live, "write_registration", crash)
    with pytest.raises(RuntimeError):
        live.install(params)
    [account] = read_accounts(params.accounts_file).values()  # the login, and no registry entry
    monkeypatch.undo()
    live.install(params)
    registered = read_registrations(params.registry_dir)["intake"]
    assert verify_token(old["submit_token"], registered.submit_token_hash)
    assert read_accounts(params.accounts_file)[account.address].generation == account.generation
    assert params.adopt_file.read_text().splitlines() == [f"{account.address}:{account.generation}"]


def test_a_restart_install_leaves_pending_holds_back_agent_changes(
    tmp_path: Path, monkeypatch
) -> None:
    """After an install the running gateway cannot reload on top of (here: a new registry path,
    as when an earlier install is migrated), `amx live agent` refuses until the lane restarts."""
    path = _params_file(tmp_path)
    params = load_params(path)
    live.install(params)
    raw = yaml.safe_load(params.gateway_config.read_text())
    del raw["registry_dir"]  # what the gateway ran before
    params.gateway_config.write_text(yaml.safe_dump(raw))
    users = params.secrets_dir / "mailhost" / "mail-users"
    users.write_text(users.read_text() + "intake@agents.example.com|{SHA512-CRYPT}$6$x$y\n")
    started = {"gateway": datetime(2026, 1, 1, tzinfo=UTC), "mailhost": None}
    monkeypatch.setattr(live, "started_at", lambda _params, service: started[service])
    notes = live.install(params)
    assert any("reads registry_dir only at start" in note for note in notes)
    assert any("the mailhost's own users changed" in note for note in notes)
    # The mailhost is not running, so its next start reads the file: nothing pending there.
    assert live.pending_restarts(params) == {
        "gateway": live.OwedRestart("install changed registry_dir", "install")
    }
    code, output = _amx("live", "agent", "add", "outpost", "--params", str(path))
    assert code != 0 and "amx live compose restart gateway" in output
    assert not read_registrations(params.registry_dir)
    code, _output = _amx("live", "agent", "list", "--params", str(path))
    assert code == 0  # reading is fine
    started["gateway"] = datetime(2026, 1, 2, tzinfo=UTC)  # it restarted: its start time moved
    _register(path, "outpost")
    assert live.pending_restarts(params) == {}
    assert not (params.state_dir / live.RESTART_MARKER).exists()


def test_not_knowing_whether_the_lane_restarted_never_reads_as_restarted(
    tmp_path: Path, monkeypatch
) -> None:
    """Without Docker (another account, a stopped daemon), the owed restart stays owed: a grant
    is refused; a revocation goes ahead, since its mailbox half applies at once, and warns."""
    path = _params_file(tmp_path)
    params = load_params(path)
    live.install(params)
    _register(path, "outpost")

    def unavailable(_params, service):
        raise live.DockerUnavailable(f"cannot ask Docker about the {service}: permission denied")

    monkeypatch.setattr(live, "started_at", unavailable)
    live.record_restart(params, "gateway", "install changed registry_dir", origin="install")
    code, output = _amx("live", "agent", "rotate", "outpost", "--params", str(path))
    assert code != 0 and "cannot tell whether the lane has restarted" in output
    code, output = _amx("live", "agent", "remove", "outpost", "--params", str(path))
    assert code == 0 and "warning: the running lane cannot apply every agent change" in output
    assert not read_registrations(params.registry_dir)["outpost"].enabled
    assert (params.state_dir / live.RESTART_MARKER).exists()  # still owed


def test_a_restart_that_failed_is_owed_to_the_next_certs_run(tmp_path: Path, monkeypatch) -> None:
    params = load_params(_params_file(tmp_path, tls={"mode": "self-signed"}))
    live.install(params)
    calls: list[tuple[str, ...]] = []

    def compose_fails(_params, *args, **_kwargs):
        calls.append(args)
        raise live.typer.Exit(1)

    started = datetime(2026, 1, 1, tzinfo=UTC)
    monkeypatch.setattr(live, "running", lambda _params, _service: True)
    monkeypatch.setattr(live, "started_at", lambda _params, _service: started)
    monkeypatch.setattr(live, "run_compose", compose_fails)
    with pytest.raises(live.typer.Exit):
        live.reload_services(params, mailhost=True, gateway=False, why="a new certificate")
    # Owed, and not held against agent changes: it is not install's.
    owed = live.pending_restarts(params)
    assert owed == {"mailhost": live.OwedRestart("a new certificate", "reload")}
    code, _output = _register_code(params.path, "outpost")
    assert code == 0
    monkeypatch.setattr(live, "run_compose", lambda _params, *args, **_kw: calls.append(args))
    calls.clear()
    code, output = _amx("live", "certs", "--params", str(params.path))
    assert code == 0, output
    assert "restarted: mailhost" in output
    assert calls == [("up", "-d", "--build", "--no-deps", "--force-recreate", "--wait", "mailhost")]


@pytest.mark.usefixtures("per_agent_dkim")
def test_the_yamls_key_size_reaches_the_plain_command(tmp_path: Path) -> None:
    params = load_params(_params_file(tmp_path, tls={"dkim_bits": 1024}))
    live.install(params)
    assert load_config(params.gateway_config).dkim_bits == 1024
    code, output = _amx(
        "agent", "add", "probe", "--live", "--config", str(params.gateway_config),
        "--bundle", str(tmp_path / "probe.json"), "--imap", "imaps://mail.example.com",
        "--submission", "smtp://mail.example.com:587",
    )  # fmt: skip
    assert code == 0, output
    assert len(dkim_public_key(params.keys_dir / "probe.private.pem")) < 300


def test_an_agent_listed_but_never_installed_is_refused(tmp_path: Path) -> None:
    params = load_params(_params_file(tmp_path, agents=[{"name": "fresh"}]))
    with pytest.raises(ParamsError, match="amx live agent add fresh"):
        live.install(params)


def test_a_hold_rule_for_an_unregistered_agent_keeps_the_old_configuration(
    tmp_path: Path,
) -> None:
    path = _params_file(tmp_path)
    params = load_params(path)
    live.install(params)
    before = params.gateway_config.read_bytes()
    rule = {"name": "intake-money", "when": {"agents": ["intake"], "schema_regex": "order"}}
    params = load_params(_params_file(tmp_path, hold_rules=[rule]))
    with pytest.raises(ParamsError, match=r"would not load.*unknown agents: intake"):
        live.install(params)
    assert params.gateway_config.read_bytes() == before
    assert not list(params.gateway_config.parent.glob(".gateway.yaml*"))
    _register(path, "intake", "--mode", "queued", "--handler", "amx.examples.intake:handle")
    live.install(params)  # once it is registered, the rule loads
    assert [r.name for r in load_config(params.gateway_config).hold_rules] == ["intake-money"]


@pytest.mark.usefixtures("per_agent_dkim")
def test_dns_records_cover_every_name_the_host_sends_as(tmp_path: Path) -> None:
    _path, params = _installed(tmp_path)
    records = {
        (record.relative("example.com"), record.type): record for record in live.dns_records(params)
    }
    assert records[("mail", "A")].data == "203.0.113.10"
    assert records[("agents", "MX")].data == "mail.example.com"
    spf = "v=spf1 ip4:203.0.113.10 -all"
    # Agents' envelopes, the HELO name (DSNs from MAILER-DAEMON@mail...), and the apex.
    assert records[("agents", "TXT")].data == records[("mail", "TXT")].data == spf
    assert records[("@", "TXT")].data == "v=spf1 -all"  # the zone's own name sends nothing
    assert "p=none" in records[("_dmarc.agents", "TXT")].data
    # Relaxed SPF alignment: the gateway's own DSNs (MAILER-DAEMON@agents...) pass SPF via HELO.
    assert "adkim=s; aspf=r" in records[("_dmarc.agents", "TXT")].data
    assert "p=none" in records[("_dmarc", "TXT")].data
    assert records[("@", "CAA")].data == '0 issue "letsencrypt.org"'
    key = dkim_public_key(params.keys_dir / "intake.private.pem")
    assert records[("intake._domainkey.agents", "TXT")].data.endswith(f"p={key}")
    assert "(selector intake, active)" in records[("intake._domainkey.agents", "TXT")].note
    assert not any(name.endswith("._agents") for name, _type in records)  # no card is served
    rendered = live.render_dns(params)
    assert "PTR   203.0.113.10 -> mail.example.com" in rendered
    assert "410 characters" in rendered  # a 2048-bit key, with the pre-split form beside it


@pytest.mark.usefixtures("per_agent_dkim")
def test_dns_records_follow_a_rotation_through_its_selectors(tmp_path: Path) -> None:
    path, params = _installed(tmp_path)
    _amx("live", "agent", "rotate", "intake", "--no-credentials", "--params", str(path))
    names = {record.relative("example.com") for record in live.dns_records(params)}
    assert {"intake._domainkey.agents", "intake.k2._domainkey.agents"} <= names  # staged too
    _amx("live", "agent", "rotate", "intake", "--activate", "--no-dns-check", "--params", str(path))
    notes = {record.relative("example.com"): record.note for record in live.dns_records(params)}
    assert "active" in notes["intake.k2._domainkey.agents"]
    assert "retiring until" in notes["intake._domainkey.agents"]  # kept for the overlap


@pytest.mark.usefixtures("per_agent_dkim")
def test_the_dkim_bits_parameter_reaches_registration(tmp_path: Path) -> None:
    path = _params_file(tmp_path, tls={"dkim_bits": 1024})
    live.install(load_params(path))
    _register(path, "outpost")
    key = load_params(path).keys_dir / "outpost.private.pem"
    assert len(dkim_public_key(key)) < 300  # a 1024-bit key's p= (a 2048-bit one is ~392)


def test_without_the_apex_nothing_is_requested_outside_the_lane(tmp_path: Path) -> None:
    _path, params = _installed(tmp_path, dns={"manage_apex": False})
    names = {record.name for record in live.dns_records(params)}
    assert all(name.endswith(("agents.example.com", "mail.example.com")) for name in names)
    caa = next(record for record in live.dns_records(params) if record.type == "CAA")
    assert caa.name == "mail.example.com"


@pytest.mark.usefixtures("per_agent_dkim")
def test_zone_file_splits_long_txt_and_escapes_the_hostmaster(tmp_path: Path) -> None:
    _path, params = _installed(tmp_path, admin_contact="first.last@example.com")
    zone = live.zone_file(params, ["ns1.example.net", "ns2.example.net"])
    assert "$ORIGIN agents.example.com." in zone
    assert "ns1.example.net. first\\.last.example.com." in zone
    assert "@ IN NS ns2.example.net." in zone
    assert "mail IN A" not in zone  # the MX host is in the parent zone
    dkim_line = next(line for line in zone.splitlines() if line.startswith("intake._domainkey"))
    parts = dkim_line.split('"')[1::2]
    assert len(parts) == 2 and all(len(part) <= 255 for part in parts)
    assert txt_strings("x" * 300) == ["x" * 255, "x" * 45]


def test_rotation_replaces_a_host_login_and_restarts_its_user(
    tmp_path: Path, quiet: list[tuple[str, ...]], monkeypatch: pytest.MonkeyPatch
) -> None:
    params = load_params(_params_file(tmp_path))
    live.install(params)
    before = yaml.safe_load(params.credentials_path.read_text())
    monkeypatch.setattr(live, "running", lambda _params, _service: True)
    message = live.rotate(params, "approver")
    after = yaml.safe_load(params.credentials_path.read_text())
    assert after["approver"] != before["approver"]
    assert after["gateway_master"] == before["gateway_master"]
    # Recreated from the checkout's image: a plain restart could keep an image that predates
    # the files install now writes.
    recreate = ("up", "-d", "--build", "--no-deps", "--force-recreate", "--wait")
    assert quiet == [(*recreate, "mailhost")]
    assert (
        "logins.txt" in message
        and after["approver"] in (params.secrets_dir / "logins.txt").read_text()
    )
    quiet.clear()
    monkeypatch.setattr(live, "started_at", lambda _params, _service: None)
    live.rotate(params, "gateway-master")
    # The gateway is restarted, not recreated: it keeps the environment it was started with
    # (TYPESAFE_API_KEY), which the caller of rotate or the renewal cron may not have.
    assert quiet == [(*recreate, "mailhost"), ("restart", "gateway")]


@pytest.mark.parametrize("what", ["submit-token", "imap-password", "dkim"])
def test_an_agents_rotation_goes_through_the_registry(tmp_path: Path, what: str) -> None:
    params = load_params(_params_file(tmp_path))
    live.install(params)
    with pytest.raises(ParamsError, match="amx live agent rotate <name>"):
        live.rotate(params, what)
    # The old command line gets the pointer too, not "no such option".
    code, output = _amx(
        "live", "rotate", "--what", what, "--agent", "intake", "--params", str(params.path)
    )
    assert code != 0 and "amx live agent rotate" in output


def test_the_judge_is_jev_only_when_the_key_is_in_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    assert live.compose_environment()["AMX_CONTENT_JUDGE_BACKEND"] == "stub"
    monkeypatch.setenv("TYPESAFE_API_KEY", "sk-test")
    assert live.compose_environment()["AMX_CONTENT_JUDGE_BACKEND"] == "jev"
    params = load_params(_params_file(tmp_path, compose_overrides=["extra.yaml"]))
    live.install(params)
    command = live.compose(params, "up")
    assert command[:4] == ["docker", "compose", "--project-name", "amx-live"]
    assert str(params.compose_env) in command and command[-1] == "up"
    assert str(tmp_path / "extra.yaml") in command
    # Nothing install writes carries the key.
    assert not any("sk-test" in path.read_text() for path in params.state_dir.rglob("*.*"))


def test_certbot_runs_unprivileged_behind_port_80(tmp_path: Path) -> None:
    params = load_params(_params_file(tmp_path))
    issue = live.certbot_command(params, renew=False)
    assert "-p" in issue and "0.0.0.0:80:8080" in issue
    assert issue[issue.index("--http-01-port") + 1] == "8080"
    assert {"--standalone", "--non-interactive", "--agree-tos", "--keep-until-expiring"} <= set(
        issue
    )
    assert issue[issue.index("-m") + 1] == "ops@example.com"
    assert issue[issue.index("-d") + 1] == "mail.example.com"
    renew = live.certbot_command(params, renew=True)
    assert "renew" in renew and "certonly" not in renew
    manual = load_params(_params_file(tmp_path, tls={"challenge": "dns-01-manual"}))
    command = live.certbot_command(manual, renew=False)
    assert "-it" in command and "--manual" in command and "-p" not in command


def test_self_signed_mode_makes_a_ca_and_a_named_certificate(tmp_path: Path) -> None:
    params = load_params(
        _params_file(
            tmp_path, tls={"mode": "self-signed", "extra_names": ["localhost", "127.0.0.1"]}
        )
    )
    notes = live.install(params)
    assert any("self-signed" in note for note in notes)
    info = live.cert_info(params.tls_dir / "server.pem")
    assert info["names"] == ["mail.example.com", "localhost", "127.0.0.1"]
    assert "amx live self-signed CA" in info["issuer"] and not info["self_issued"]
    assert _mode(params.tls_dir / "server-key.pem") == 0o600
    # The CA's key is not in secrets/tls, which the containers mount, and the CA is constrained.
    assert not (params.tls_dir / "ca-key.pem").exists()
    assert _mode(params.secrets_dir / "ca" / "ca-key.pem") == 0o600
    constraints = live.subprocess.run(
        ["openssl", "x509", "-in", str(params.tls_dir / "ca.pem"), "-noout", "-ext",
         "nameConstraints"],
        capture_output=True, text=True, check=True,
    ).stdout  # fmt: skip
    assert "DNS:mail.example.com" in constraints and "IP:127.0.0.1" in constraints
    assert not live.ensure_self_signed(params)  # fresh and correctly named: unchanged
    config = load_config(params.gateway_config)
    assert config.submission_tls_ca == Path("/tls/ca.pem")


def test_backup_snapshots_and_verifies_the_journal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from amx.journal import Journal
    from amx.store import Store

    params = load_params(_params_file(tmp_path))
    live.install(params)
    journal = Journal(params.data_dir, Store(params.data_dir / "journal.sqlite"))
    journal.append(b"raw message", direction="inbound", event="delivered", detail="{}")
    docker: list[list[str]] = []

    def fake_run(command, **_kwargs):
        docker.append(command)
        (Path(command[command.index("-v") + 3].split(":")[0]) / "mail.tar.gz").write_bytes(b"")

    monkeypatch.setattr(live.subprocess, "run", fake_run)
    target = live.backup(params, tmp_path / "backup", with_secrets=False)
    assert (target / "journal-verify.txt").read_text().startswith("OK 1 entries")
    assert (target / "data" / "journal.sqlite").is_file()
    assert not (target / "secrets").exists()
    assert "amx-live_mail:/mail:ro" in docker[0] and "amx-live-mailhost" in docker[0]
    assert _mode(target / "manifest.json") == 0o600


@pytest.mark.parametrize("entry", ["socket", "regular", "other-socket", "symlink", "fifo"])
def test_backup_excludes_only_the_owned_tls_runtime_socket(entry, monkeypatch) -> None:
    from amx.journal import Journal
    from amx.store import Store

    # Keep real AF_UNIX paths below the platform limit, including under private TMPDIR.
    with tempfile.TemporaryDirectory(prefix="bk-") as directory:
        root = Path(directory)
        params = load_params(_params_file(root))
        live.install(params)
        journal = Journal(params.data_dir, Store(params.data_dir / "journal.sqlite"))
        journal.append(b"raw message", direction="inbound", event="delivered", detail="{}")
        path = params.data_dir / "tls-reload.sock"
        docker = []

        def fake_run(command, **_kwargs):
            docker.append(command)
            (root / "backup" / "mail.tar.gz").write_bytes(b"mail fixture")

        monkeypatch.setattr(live.subprocess, "run", fake_run)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as control:
            if entry == "regular":
                path.write_bytes(b"not runtime state")
            elif entry == "fifo":
                os.mkfifo(path)
            else:
                bound = (
                    root / "target.sock"
                    if entry == "symlink"
                    else params.data_dir / "unexpected.sock"
                    if entry == "other-socket"
                    else path
                )
                control.bind(str(bound))
                if entry == "symlink":
                    path.symlink_to(bound)
            if entry in {"other-socket", "symlink", "fifo"}:
                with pytest.raises(OSError):
                    live.backup(params, root / "backup", with_secrets=False)
                assert not docker
                assert not (root / "backup" / "manifest.json").exists()
                return
            target = live.backup(params, root / "backup", with_secrets=False)
            assert (target / "journal-verify.txt").read_text() == "OK 1 entries\n"
            assert Journal(target / "data", Store(target / "data/journal.sqlite")).verify().valid
            manifest = json.loads((target / "manifest.json").read_text())
            assert "data/journal.sqlite" in manifest["sha256"]
            assert "mail.tar.gz" in manifest["sha256"]
            assert len(docker) == 1
            if entry == "socket":
                assert not (target / "data" / path.name).exists()
                assert f"data/{path.name}" not in manifest["sha256"]
                assert stat.S_ISSOCK(path.lstat().st_mode)
            else:
                assert (target / "data" / path.name).read_bytes() == b"not runtime state"
                assert f"data/{path.name}" in manifest["sha256"]


def test_write_private_never_exposes_a_secret(tmp_path: Path, monkeypatch) -> None:
    import os

    previous = os.umask(0)
    try:
        write_private(tmp_path / "a" / "secret", "s3cret")
    finally:
        os.umask(previous)
    assert _mode(tmp_path / "a" / "secret") == 0o600
    assert (tmp_path / "a" / "secret").read_text() == "s3cret"
    assert not list((tmp_path / "a").glob(".*.tmp"))


def test_a_damaged_credentials_file_is_never_silently_regenerated(tmp_path: Path) -> None:
    params = load_params(_params_file(tmp_path))
    live.install(params)
    params.credentials_path.write_text("")
    with pytest.raises(ParamsError, match="damaged"):
        live.install(params)


def test_install_does_not_widen_a_directory_it_did_not_make(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o750)
    home.chmod(0o750)
    params = load_params(_params_file(tmp_path, state_dir=str(home)))
    live.install(params)
    assert _mode(home) == 0o750
    assert _mode(params.secrets_dir) == 0o700


def test_certs_switch_from_staging_issues_a_new_certificate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    params = load_params(_params_file(tmp_path))
    live.install(params)
    renewal = params.secrets_dir / "acme" / "config" / "renewal"
    renewal.mkdir(parents=True)
    (renewal / "amx-live.conf").write_text(
        f"version = 5.8.0\nserver = {live.LETSENCRYPT_STAGING}\n"
    )
    assert live.lineage_server(params) == live.LETSENCRYPT_STAGING
    replace = live.certbot_command(params, renew=False, replace=True)
    assert "--force-renewal" in replace and "--keep-until-expiring" not in replace
    assert replace[replace.index("--server") + 1] == live.LETSENCRYPT
    runs: list[list[str]] = []
    monkeypatch.setattr(live.subprocess, "run", lambda command, **_kw: runs.append(command))
    monkeypatch.setattr(live, "install_acme_certificate", lambda _params: False)
    monkeypatch.setattr(
        live, "cert_info", lambda _path: {"names": ["x"], "expires": live.datetime.now()}
    )
    live.certs_command(params.path)
    assert "certonly" in runs[0] and "--force-renewal" in runs[0]
    (renewal / "amx-live.conf").write_text(f"server = {live.LETSENCRYPT}\n")
    live.certs_command(params.path)
    assert "renew" in runs[1]


def test_compose_env_wins_over_stray_shell_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AMX_LLM_MODEL", "stray-model")
    monkeypatch.setenv("SECRETS_DIR", "/elsewhere")
    monkeypatch.setenv("TYPESAFE_API_KEY", "sk-test")
    environment = live.compose_environment()
    assert "AMX_LLM_MODEL" not in environment and "SECRETS_DIR" not in environment
    assert environment["TYPESAFE_API_KEY"] == "sk-test"  # how the key reaches the gateway


def test_purge_refuses_while_mail_waits_in_the_queue(
    tmp_path: Path, quiet: list[tuple[str, ...]], monkeypatch: pytest.MonkeyPatch
) -> None:
    import typer

    params = load_params(_params_file(tmp_path))
    live.install(params)
    monkeypatch.setattr(live, "queued_mail", lambda _params: 2)
    with pytest.raises(typer.BadParameter, match="2 messages wait"):
        live.down_command(params.path, purge=True, force=False)
    monkeypatch.setattr(live, "queued_mail", lambda _params: None)
    with pytest.raises(typer.BadParameter, match="cannot see the queue"):
        live.down_command(params.path, purge=True, force=False)
    assert quiet == []
    live.down_command(params.path, purge=False, force=False)  # the queue is a volume: kept
    live.down_command(params.path, purge=True, force=True)
    assert quiet == [("down",), ("down", "--volumes")]


def test_compose_variables_and_their_guard_list_agree(tmp_path: Path) -> None:
    params = load_params(_params_file(tmp_path, limits={"max_bytes": 20971520}))
    variables = live.compose_variables(params)
    assert set(variables) == set(live.COMPOSE_VARIABLES)
    # Postfix's limits follow the gateway's max_bytes.
    assert (variables["MAX_BYTES"], variables["GLOBAL_MAX_BYTES"]) == ("20971520", "62914560")


def test_an_apex_that_is_the_agent_domain_gets_one_spf_record(tmp_path: Path) -> None:
    params = load_params(
        _params_file(
            tmp_path,
            agent_domain="agents.example.net",
            mx_host="mail.agents.example.net",
            org_domain="agents.example.net",
        )
    )
    live.install(params)
    spf = [r for r in live.dns_records(params) if r.type == "TXT" and r.data.startswith("v=spf1")]
    names = [record.name for record in spf]
    assert len(names) == len(set(names)), "two SPF records at one name are a permanent error"
    assert not live.apex_sends_nothing(params)


def test_the_ca_is_remade_with_its_certificate_and_takes_ipv6_names(tmp_path: Path) -> None:
    params = load_params(
        _params_file(tmp_path, tls={"mode": "self-signed", "extra_names": ["localhost", "::1"]})
    )
    live.install(params)
    ca, server = params.tls_dir / "ca.pem", params.tls_dir / "server.pem"
    assert live._chains(server, ca)
    constraints = live.subprocess.run(
        ["openssl", "x509", "-in", str(ca), "-noout", "-ext", "nameConstraints"],
        capture_output=True, text=True, check=True,
    ).stdout  # fmt: skip
    assert "IP:0:0:0:0:0:0:0:1/FFFF" in constraints
    # A server certificate from another CA (a run that died midway) is replaced, not kept.
    other = tmp_path / "other"
    other.mkdir()
    live.subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30", "-subj",
         "/CN=mail.example.com", "-addext",
         "subjectAltName=DNS:mail.example.com,DNS:localhost,IP:::1",
         "-keyout", str(other / "k.pem"), "-out", str(server)],
        capture_output=True, check=True,
    )  # fmt: skip
    assert live.ensure_self_signed(params)
    assert live._chains(server, ca)


def test_the_dns_only_ca_signs_no_ip_address(tmp_path: Path) -> None:
    params = load_params(_params_file(tmp_path, tls={"mode": "self-signed"}))
    live.install(params)
    constraints = live.subprocess.run(
        ["openssl", "x509", "-in", str(params.tls_dir / "ca.pem"), "-noout", "-ext",
         "nameConstraints"],
        capture_output=True, text=True, check=True,
    ).stdout  # fmt: skip
    assert "Excluded" in constraints and "IP:0.0.0.0/0.0.0.0" in constraints


def test_the_outbound_allowlist_reaches_the_gateway(tmp_path: Path) -> None:
    default = load_params(_params_file(tmp_path))
    assert default.outbound_allowlist == ()
    live.install(default)
    assert load_config(default.gateway_config).outbound_allowlist == frozenset()

    params = load_params(
        _params_file(tmp_path, outbound_allowlist=["Victor@Example.com", "@partner.test"])
    )
    assert params.outbound_allowlist == ("partner.test", "victor@example.com")
    live.install(params)
    config = load_config(params.gateway_config)
    assert config.outbound_allowlist == frozenset({"victor@example.com", "partner.test"})
    with pytest.raises(ParamsError, match="outbound_allowlist"):
        load_params(_params_file(tmp_path, outbound_allowlist=["not an address"]))


@pytest.mark.parametrize("value", [{}, "", False, "victor@example.com"])
def test_an_outbound_allowlist_that_is_not_a_list_fails(tmp_path: Path, value: object) -> None:
    with pytest.raises(ParamsError, match="outbound_allowlist must be a list"):
        load_params(_params_file(tmp_path, outbound_allowlist=value))


def test_forwarded_role_mail_must_go_to_an_allowed_address(tmp_path: Path) -> None:
    forwarding = {"role_mail": {"forward_to_admin": True}, "admin_contact": "ops@example.com"}
    with pytest.raises(ParamsError, match="forward_to_admin"):
        load_params(_params_file(tmp_path, outbound_allowlist=["victor@example.org"], **forwarding))
    for allowed in (["ops@example.com"], ["example.com"]):
        load_params(_params_file(tmp_path, outbound_allowlist=allowed, **forwarding))
    load_params(_params_file(tmp_path, **forwarding))  # no allowlist: nothing to contradict


def test_preflight_reports_the_outbound_allowlist(tmp_path: Path) -> None:
    from amx.preflight import allowlist_check

    open_lane = allowlist_check(load_params(_params_file(tmp_path)))
    assert (open_lane.status, open_lane.check) == ("WARN", "policy:outbound")
    limited = load_params(_params_file(tmp_path, outbound_allowlist=["victor@example.com"]))
    assert allowlist_check(limited).status == "PASS"


def test_a_docker_failure_is_never_read_as_stopped(tmp_path: Path, monkeypatch) -> None:
    params = load_params(_params_file(tmp_path))
    live.install(params)

    def refused(command, **_kwargs):
        raise live.subprocess.CalledProcessError(1, command, stderr="permission denied")

    monkeypatch.setattr(live.subprocess, "run", refused)
    with pytest.raises(live.DockerUnavailable, match="permission denied"):
        live.running(params, "mailhost")
    # A new certificate's restart is owed before Docker is asked, so a failure keeps it owed.
    live.record_restart(params, "mailhost", "a new certificate", origin="reload")
    marker = json.loads((params.state_dir / live.RESTART_MARKER).read_text())
    assert marker["mailhost"]["before"] is None and marker["mailhost"]["origin"] == "reload"
    with pytest.raises(live.DockerUnavailable):
        live.pending_restarts(params)
    assert (params.state_dir / live.RESTART_MARKER).exists()
