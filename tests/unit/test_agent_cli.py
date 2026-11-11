"""The operator's commands: amx agent add --live, remove, enable, rotate, list; dns; trust."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from amx import registration as reg
from amx.cli import app
from amx.registry import read_grants, read_registrations

CONFIG = {
    "domain": "example.com",
    "agent_domain": "agents.example.com",
    "data_dir": "data",
    "keys_dir": "keys",
    "registry_dir": "registry",
    "accounts_file": "accounts/agents.passwd",
    "mailbox": {"host": "mail.example.com"},
    "agents": {"intake": {"handler": "mailbox-only", "submit_token": "dev-intake-token"}},
}


@pytest.fixture
def config_path(tmp_path) -> Path:
    path = tmp_path / "gateway.yaml"
    path.write_text(yaml.safe_dump(CONFIG), encoding="utf-8")
    return path


_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _run(*arguments: str) -> tuple[int, str]:
    """Exit code and output, with rich's colours and error-box borders taken out.

    A usage error is drawn in a box that wraps at the terminal's width, which differs in CI.
    """
    result = CliRunner().invoke(app, list(arguments), env={"COLUMNS": "200", "NO_COLOR": "1"})
    plain = _ANSI.sub("", result.output)
    plain = re.sub(r"[│╭╮╰╯─]", " ", plain)
    return result.exit_code, re.sub(r"[ \t]*\n[ \t]*", "\n", re.sub(r"[ \t]+", " ", plain))


def _add(config_path: Path, name: str = "probe", *extra: str) -> tuple[int, str]:
    return _run(
        "agent",
        "add",
        name,
        "--live",
        "--config",
        str(config_path),
        "--bundle",
        str(config_path.parent / f"{name}.json"),
        "--imap",
        "imaps://mail.example.com",
        "--submission",
        "smtp://mail.example.com:587",
        *extra,
    )


def test_add_live_prints_the_dns_to_publish_and_never_a_secret(config_path) -> None:
    code, output = _add(config_path)
    assert code == 0, output
    bundle = json.loads((config_path.parent / "probe.json").read_text(encoding="utf-8"))
    assert bundle["token"] not in output and bundle["password"] not in output
    assert "registered probe@agents.example.com (remote)" in output
    assert "zone file: probe._domainkey.agents.example.com. 3600 IN TXT" in output
    assert "DNS host: Type TXT | Name probe._domainkey.agents | Value v=DKIM1; k=rsa; p=" in output
    assert "Name probe._agents.agents | Value v=amx1; card=https://example.com/" in output
    assert "amx dns check probe" in output


def _flat(output: str) -> str:
    """Output with every run of whitespace one space: rich wraps error boxes at any width."""
    return re.sub(r"\s+", " ", output)


def test_add_live_needs_the_bundle_and_the_endpoints(config_path) -> None:
    code, output = _run("agent", "add", "probe", "--live", "--config", str(config_path))
    assert code != 0 and "--bundle, --imap, and --submission" in _flat(output)


def test_add_live_refuses_a_second_add_with_a_clear_error(config_path) -> None:
    assert _add(config_path)[0] == 0
    (config_path.parent / "probe.json").unlink()
    code, output = _add(config_path)
    assert code == 1 and "already registered" in output


def test_an_in_process_live_agent_needs_a_handler(config_path) -> None:
    code, output = _add(config_path, "probe", "--mode", "sync")
    assert code != 0 and "needs --handler" in _flat(output)


def test_remove_disables_then_purges(config_path) -> None:
    _add(config_path)
    code, output = _run("agent", "remove", "probe", "--config", str(config_path))
    assert code == 0 and "RCPT now refuses it (550 5.1.1)" in output
    code, output = _run("agent", "remove", "probe", "--purge", "--config", str(config_path))
    assert code == 1 and "grace period ends" in output
    code, output = _run(
        "agent", "remove", "probe", "--purge", "--now", "--config", str(config_path)
    )
    assert code == 0, output
    assert "(name in zone example.com: probe._domainkey.agents)" in output
    assert not (config_path.parent / "keys" / "probe.private.pem").exists()


def test_enable_undoes_a_disable(config_path) -> None:
    _add(config_path)
    _run("agent", "remove", "probe", "--config", str(config_path))
    code, output = _run("agent", "enable", "probe", "--config", str(config_path))
    assert code == 0 and "enabled probe@agents.example.com" in output


def test_rotate_then_activate_after_a_dns_check(config_path, monkeypatch) -> None:
    _add(config_path)
    code, output = _run(
        "agent",
        "rotate",
        "probe",
        "--config",
        str(config_path),
        "--bundle",
        str(config_path.parent / "probe-2.json"),
    )
    assert code == 0, output
    assert "DKIM for selector probe.k2 (staged, not signing yet)" in output
    assert "Name probe.k2._domainkey.agents" in output
    rotated = json.loads((config_path.parent / "probe-2.json").read_text(encoding="utf-8"))
    assert rotated["token"] not in output
    assert rotated["imap"] == "imaps://mail.example.com"  # kept from the add
    monkeypatch.setattr(reg, "lookup_txt", lambda _name, _server: None)
    code, output = _run("agent", "rotate", "probe", "--activate", "--config", str(config_path))
    assert code == 1 and "probe.k2 is missing in DNS" in output
    code, output = _run(
        "agent", "rotate", "probe", "--activate", "--no-dns-check", "--config", str(config_path)
    )
    assert code == 0 and "now signs with s=probe.k2; keep probe published for 7d" in output
    registration = read_registrations(config_path.parent / "registry")["probe"]
    assert registration.selector == "probe.k2"


def test_dns_check_compares_dns_with_the_local_keys(config_path, monkeypatch) -> None:
    _add(config_path)
    key = config_path.parent / "keys" / "probe.private.pem"
    published = {"probe._domainkey.agents.example.com": [reg.dkim_value(key)]}
    monkeypatch.setattr(reg, "lookup_txt", lambda name, _server: published.get(name))
    code, output = _run("dns", "check", "probe", "--config", str(config_path))
    assert code == 0, output
    assert "ok probe._domainkey.agents.example.com (active)" in output
    assert "absent (optional) probe._agents.agents.example.com" in output
    published["probe._domainkey.agents.example.com"] = ["v=DKIM1; k=rsa; p=AAAA"]
    code, output = _run("dns", "check", "probe", "--config", str(config_path))
    assert code == 1
    assert "MISMATCH probe._domainkey.agents.example.com (active)" in output
    assert "DNS host: Type TXT | Name probe._domainkey.agents" in output
    code, output = _run("dns", "check", "ghost", "--config", str(config_path))
    assert code == 1 and "ghost is not an agent" in output


def test_dns_render_publishes_every_selector_in_use(config_path) -> None:
    keys = config_path.parent / "keys"
    keys.mkdir()
    reg.generate_key(keys / "intake.private.pem")
    _add(config_path)
    _run(
        "agent",
        "rotate",
        "probe",
        "--no-credentials",
        "--config",
        str(config_path),
    )
    code, output = _run("dns", "render", "--config", str(config_path))
    assert code == 0, output
    for owner in ("intake._domainkey", "probe._domainkey", "probe.k2._domainkey", "probe._agents"):
        assert f"\n{owner} IN TXT" in output


def test_trust_add_list_remove(config_path) -> None:
    code, output = _run(
        "trust",
        "add",
        "agents.contoso.test",
        "probe",
        "--intent",
        "response",
        "--config",
        str(config_path),
    )
    assert code == 0 and "granted agents.contoso.test/probe: response" in output
    grants = read_grants(config_path.parent / "registry")
    assert [(grant.d, grant.s, grant.intents) for grant in grants] == [
        ("agents.contoso.test", "probe", ("response",))
    ]
    code, output = _run("trust", "list", "--config", str(config_path))
    assert "agents.contoso.test/probe: response; replies only" in output
    code, output = _run(
        "trust", "remove", "agents.contoso.test", "probe", "--config", str(config_path)
    )
    assert code == 0
    code, output = _run(
        "trust", "remove", "agents.contoso.test", "probe", "--config", str(config_path)
    )
    assert code == 1 and "no grant" in output
    code, output = _run("trust", "add", "*", "probe", "--config", str(config_path))
    assert code == 1


def test_agent_list_shows_both_kinds(config_path) -> None:
    _add(config_path)
    code, output = _run("agent", "list", "--config", str(config_path))
    assert code == 0
    assert "intake: gateway YAML, sync, enabled; intake" in output
    assert "probe: registered, remote, enabled; probe (active)" in output


def test_dns_render_notes_a_receive_only_agent_instead_of_failing(tmp_path) -> None:
    config = {**CONFIG, "agents": {"listener": {"handler": "mailbox-only"}}}
    path = tmp_path / "gateway.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    code, output = _run("dns", "render", "--config", str(path))
    assert code == 0, output
    assert "; listener receives only: it has no DKIM key to publish" in output
    config["agents"]["listener"]["submit_token"] = "dev-listener-token"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    code, output = _run("dns", "render", "--config", str(path))
    assert code != 0 and "missing key for listener" in _flat(output)


def test_activate_without_a_staged_key_fails_before_any_dns_check(config_path, monkeypatch) -> None:
    _add(config_path)
    looked: list[str] = []
    monkeypatch.setattr(reg, "lookup_txt", lambda name, _server: looked.append(name))
    code, output = _run("agent", "rotate", "probe", "--activate", "--config", str(config_path))
    assert code == 1 and "no staged key" in output and looked == []


def test_a_purge_that_would_break_the_gateways_config_is_refused(config_path) -> None:
    config = {**CONFIG, "hold_rules": [{"name": "watch-probe", "when": {"agents": ["probe"]}}]}
    _add(config_path)
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    _run("agent", "remove", "probe", "--config", str(config_path))
    code, output = _run(
        "agent", "remove", "probe", "--purge", "--now", "--config", str(config_path)
    )
    assert code == 1 and "would not load" in _flat(output)
    assert "probe" in read_registrations(config_path.parent / "registry")
    assert (config_path.parent / "keys" / "probe.private.pem").exists()


def test_the_dev_add_refuses_a_registered_name(config_path) -> None:
    _add(config_path)
    code, output = _run("agent", "add", "probe", "--config", str(config_path))
    assert code != 0 and "is a registered agent" in _flat(output)
    assert "probe" not in yaml.safe_load(config_path.read_text(encoding="utf-8"))["agents"]


def test_the_dev_add_needs_the_registrys_host_path(tmp_path) -> None:
    config = {**CONFIG, "registry_dir": "/nonexistent/registry"}
    path = tmp_path / "gateway.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    code, output = _run("agent", "add", "probe", "--config", str(path))
    assert code != 0 and "pass --registry-dir" in _flat(output)
    code, output = _run(
        "agent", "add", "probe", "--config", str(path), "--registry-dir", str(tmp_path / "reg")
    )
    assert code == 0, output
