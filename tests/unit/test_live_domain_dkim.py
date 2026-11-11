"""SH-44 on the live lane: one DKIM record for the domain, however many agents it has."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from amx import domain_dkim, live
from amx.cli import app
from amx.config import load_config
from amx.live import load_params
from amx.preflight import Lookup, dns_checks
from amx.registration import dkim_value

EXAMPLE = Path(__file__).resolve().parents[2] / "deploy" / "live" / "live.example.yaml"


class FakeLookup(Lookup):
    def __init__(self, records: dict[tuple[str, str], list[str]]) -> None:
        self.records = records

    def query(self, name: str, rdtype: str) -> list[str]:
        return list(self.records.get((name.rstrip(".").casefold(), rdtype), []))


def _cli(path: Path, *arguments: str) -> str:
    result = CliRunner().invoke(app, ["live", *arguments, "--params", str(path)])
    assert result.exit_code == 0, result.output
    return result.output


def _lane(tmp_path: Path) -> tuple[Path, live.LiveParams]:
    raw = yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))
    raw["state_dir"] = str(tmp_path / "state")
    path = tmp_path / "live.yaml"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    params = load_params(path)
    live.install(params)
    return path, params


def _dkim_records(params: live.LiveParams) -> list[str]:
    return [record.name for record in live.dns_records(params) if "._domainkey." in record.name]


def _zone(params: live.LiveParams) -> dict[tuple[str, str], list[str]]:
    records: dict[tuple[str, str], list[str]] = {}
    for record in live.dns_records(params):
        value = f"{record.priority} {record.data}." if record.type == "MX" else record.data
        records.setdefault((record.name, record.type), []).append(value)
    return records


def test_a_new_lane_publishes_one_dkim_record_for_every_agent(tmp_path: Path) -> None:
    path, params = _lane(tmp_path)
    state = domain_dkim.read(params.registry_dir)
    assert state is not None and state.active is not None and state.pending is None
    for name in ("claude", "codex", "hermes"):
        output = _cli(path, "agent", "add", name)
        assert "no DNS change for this agent" in output
        assert "_domainkey" not in output
        assert not (params.keys_dir / f"{name}.private.pem").exists()
    assert _dkim_records(params) == [f"{state.active}._domainkey.{params.agent_domain}"]
    assert sorted(p.name for p in params.keys_dir.glob("*.private.pem")) == [
        f"{state.active}.private.pem"
    ]
    # The gateway signs every agent with it: the running lane picks dkim.yaml up on reload.
    config = load_config(params.gateway_config)
    assert config.domain_selector == state.active
    assert {config.selector_for(name) for name in ("claude", "codex", "hermes")} == {state.active}
    # Preflight checks the one record, and passes on the bundle's own zone.
    results = {result.check: result for result in dns_checks(params, FakeLookup(_zone(params)))}
    assert results[f"dns:dkim:{state.active}"].status == "PASS"
    assert not any(name.startswith(("dns:dkim:claude", "dns:dkim:codex")) for name in results)


def test_install_is_idempotent_and_keeps_the_domain_key(tmp_path: Path) -> None:
    _path, params = _lane(tmp_path)
    before = domain_dkim.read(params.registry_dir)
    live.install(params)
    assert domain_dkim.read(params.registry_dir) == before


def test_an_agent_rotates_credentials_only_and_purge_names_no_dkim_record(tmp_path: Path) -> None:
    path, _params = _lane(tmp_path)
    _cli(path, "agent", "add", "outpost")
    output = _cli(path, "agent", "rotate", "outpost")
    assert "new credentials" in output and "_domainkey" not in output
    refused = CliRunner().invoke(
        app, ["live", "agent", "rotate", "outpost", "--no-credentials", "--params", str(path)]
    )
    assert refused.exit_code != 0 and "amx dkim stage" in refused.output
    _cli(path, "agent", "remove", "outpost")
    output = _cli(path, "agent", "remove", "outpost", "--purge", "--now")
    assert "_domainkey" not in output
    assert "outpost._agents" in output


def test_a_running_lane_migrates_only_once_dns_serves_the_domain_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A lane from before SH-44: its agents have their own keys.
    real_ensure = domain_dkim.ensure
    monkeypatch.setattr(
        domain_dkim, "ensure", lambda site, **_kw: domain_dkim.DomainDkim(active="amx.2000-01")
    )
    path, params = _lane(tmp_path)
    for name in ("intake", "outpost"):
        _cli(path, "agent", "add", name)
    assert (params.keys_dir / "outpost.private.pem").is_file()
    assert domain_dkim.read(params.registry_dir) is None

    # The upgrade's install stages the domain key; the agents keep signing as before.
    monkeypatch.setattr(domain_dkim, "ensure", real_ensure)
    notes = live.install(params)
    state = domain_dkim.read(params.registry_dir)
    assert state is not None and state.active is None and state.pending is not None
    assert any("amx live dkim activate" in note for note in notes)
    assert load_config(params.gateway_config).selector_for("outpost") == "outpost"
    assert _dkim_records(params) == [
        f"{name}._domainkey.{params.agent_domain}" for name in (state.pending, "intake", "outpost")
    ]

    # Not published yet: refused, nothing changes.
    monkeypatch.setattr("amx.registration.lookup_txt", lambda *_a, **_kw: None)
    refused = CliRunner().invoke(app, ["live", "dkim", "activate", "--params", str(path)])
    assert refused.exit_code != 0 and "missing" in refused.output
    assert domain_dkim.read(params.registry_dir) == state

    key = params.keys_dir / f"{state.pending}.private.pem"
    monkeypatch.setattr("amx.registration.lookup_txt", lambda *_a, **_kw: [dkim_value(key)])
    output = _cli(path, "dkim", "activate")
    assert f"now signs with {state.pending}" in output
    active = domain_dkim.read(params.registry_dir)
    assert active is not None and active.active == state.pending
    assert sorted(item.selector for item in active.retiring) == ["intake", "outpost"]
    assert load_config(params.gateway_config).selector_for("outpost") == state.pending
    # The agents' old records stay listed while they retire, beside the domain's.
    assert set(_dkim_records(params)) == {
        f"{name}._domainkey.{params.agent_domain}" for name in (state.pending, "intake", "outpost")
    }
    # A new agent needs nothing in DNS.
    assert "no DNS change" in _cli(path, "agent", "add", "hermes")

    # Once the overlap ends, retire deletes the old keys and names the records to delete.
    domain_dkim.write(
        params.registry_dir,
        params.agent_domain,
        domain_dkim.DomainDkim(
            active=active.active,
            retiring=tuple(
                type(item)(item.selector, datetime.now(UTC) - timedelta(seconds=1))
                for item in active.retiring
            ),
        ),
    )
    output = _cli(path, "dkim", "retire")
    assert "outpost._domainkey.agents" in output
    assert not (params.keys_dir / "outpost.private.pem").exists()
    assert _dkim_records(params) == [f"{state.pending}._domainkey.{params.agent_domain}"]


def test_the_domain_key_rotates_through_stage_and_activate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, params = _lane(tmp_path)
    first = domain_dkim.read(params.registry_dir)
    assert first is not None and first.active is not None
    output = _cli(path, "dkim", "stage")
    staged = domain_dkim.read(params.registry_dir)
    assert staged is not None and staged.pending is not None and staged.active == first.active
    assert f"{staged.pending}._domainkey" in output
    key = params.keys_dir / f"{staged.pending}.private.pem"
    monkeypatch.setattr("amx.registration.lookup_txt", lambda *_a, **_kw: [dkim_value(key)])
    _cli(path, "dkim", "activate", "--overlap", "2d")
    rotated = domain_dkim.read(params.registry_dir)
    assert rotated is not None and rotated.active == staged.pending
    assert [item.selector for item in rotated.retiring] == [first.active]
    assert first.active in _cli(path, "dkim", "status")


def test_purging_a_migrated_agent_drops_its_retiring_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_ensure = domain_dkim.ensure
    monkeypatch.setattr(
        domain_dkim, "ensure", lambda site, **_kw: domain_dkim.DomainDkim(active="amx.2000-01")
    )
    path, params = _lane(tmp_path)
    _cli(path, "agent", "add", "outpost")
    monkeypatch.setattr(domain_dkim, "ensure", real_ensure)
    live.install(params)
    pending = domain_dkim.read(params.registry_dir)
    assert pending is not None and pending.pending is not None
    key = params.keys_dir / f"{pending.pending}.private.pem"
    monkeypatch.setattr("amx.registration.lookup_txt", lambda *_a, **_kw: [dkim_value(key)])
    _cli(path, "dkim", "activate")
    _cli(path, "agent", "remove", "outpost")
    output = _cli(path, "agent", "remove", "outpost", "--purge", "--now")
    assert "outpost._domainkey.agents" in output  # it was published before the switch
    state = domain_dkim.read(params.registry_dir)
    assert state is not None and state.retiring == ()
    assert _dkim_records(params) == [f"{pending.pending}._domainkey.{params.agent_domain}"]
