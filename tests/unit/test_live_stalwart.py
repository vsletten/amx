"""SH-10: parameter-driven Stalwart bundles, without a Docker daemon."""

from __future__ import annotations

import json
import stat

import pytest
import yaml
from typer.testing import CliRunner

from amx import live
from amx.cli import app
from amx.config import load_config


def parameters(tmp_path, **changes):
    raw = {"mta": "stalwart", "profile": "private", "state_dir": str(tmp_path / "state")}
    raw.update(changes)
    path = tmp_path / "live.yaml"
    path.write_text(yaml.safe_dump(raw))
    return live.load_params(path)


def test_private_defaults_are_names_not_addresses(tmp_path):
    params = parameters(tmp_path)
    assert params.org_domain == "home.arpa"
    assert params.agent_domain == "agents.home.arpa"
    assert params.mx_host == "mail.home.arpa"
    assert params.tls_mode == "self-signed"
    assert params.bind_address == "127.0.0.1"


@pytest.mark.parametrize("changes", [{"mta": "other"}, {"profile": "other"}])
def test_unknown_selectors_are_refused(tmp_path, changes):
    with pytest.raises(live.ParamsError):
        parameters(tmp_path, **changes)


def test_ip_literal_domain_is_refused(tmp_path):
    with pytest.raises(live.ParamsError, match="DNS name"):
        parameters(tmp_path, org_domain="127.0.0.1")


def test_install_plan_and_registration_are_parameter_driven(tmp_path):
    params = parameters(tmp_path, org_domain="house.internal", webmail=True)
    result = CliRunner().invoke(app, ["live", "install", "--params", str(params.path)])
    assert result.exit_code == 0, result.output
    people_path = params.secrets_dir / "stalwart" / "people.json"
    assert people_path.read_text() == "{}\n"
    assert stat.S_IMODE(people_path.stat().st_mode) == 0o600
    bundle_path = params.secrets_dir / "stalwart" / "bundle.json"
    bundle = json.loads(bundle_path.read_text())
    assert stat.S_IMODE(bundle_path.stat().st_mode) == 0o600
    assert bundle["site"]["domain"] == "house.internal"
    assert bundle["site"]["trusted_network"] == params.gateway_ip + "/32"
    assert "dev-users" not in json.dumps(bundle)
    settings = {op["object"]: op for op in bundle["plan"]}
    assert settings["NetworkListener"]["@type"] == "reconcile"
    assert settings["NetworkListener"]["value"]["imaps"]["tlsImplicit"] is True
    assert (
        settings["Certificate"]["value"]["amx-live"]["certificate"]["filePath"] == "/tls/server.pem"
    )
    config = load_config(params.gateway_config)
    assert config.mailbox.master_login == "{user}%{master}@" + params.org_domain
    assert config.mailbox.hold_owner == "holds@" + params.org_domain
    assert config.mailbox.hold_prefix == "Holds/{agent}/"
    assert config.outbound == "local-only"
    assert params.org_domain in config.local_domains
    command = live.compose(params, "config")
    assert str(live.BUNDLE / "compose.stalwart.yaml") in command
    assert "webmail" in command
    before = (params.secrets_dir / "stalwart" / "recovery-admin").read_bytes()
    people_path.write_text('{"fixture": "retained"}\n')
    live.install(params)
    assert json.loads(people_path.read_text()) == {"fixture": "retained"}
    assert (params.secrets_dir / "stalwart" / "recovery-admin").read_bytes() == before
    assert json.loads(bundle_path.read_text()) == bundle
    assert (params.state_dir / "stalwart").is_dir()
    assert "no public DNS" in live.render_dns(params)
    result = CliRunner().invoke(
        app, ["live", "agent", "add", "outpost", "--params", str(params.path)]
    )
    assert result.exit_code == 0, result.output
    assert "outpost" in load_config(params.gateway_config).agents


def test_private_preflight_never_contacts_public_dns_or_mx(tmp_path, monkeypatch):
    from amx import live_stalwart, preflight

    params = parameters(tmp_path)
    monkeypatch.setattr(preflight, "Lookup", lambda *_: pytest.fail("private DNS lookup"))
    monkeypatch.setattr(preflight, "outbound_check", lambda *_: pytest.fail("external connect"))
    monkeypatch.setattr(preflight, "tls_checks", lambda *_: [])
    monkeypatch.setattr(live_stalwart, "preflight_checks", lambda *_: [])
    results = preflight.run_checks(params, preflight.Options())
    assert not any(r.status == "FAIL" for r in results)
    assert any(r.check == "dns:private" for r in results)


@pytest.mark.parametrize(
    ("mode", "private_ca", "expected"),
    [
        ("self-signed", False, True),
        ("files", True, True),
        ("files", False, False),
        ("acme", False, False),
    ],
)
def test_remote_runner_hint_matches_configured_trust(
    tmp_path, monkeypatch, mode, private_ca, expected
):
    from amx import cli

    tls = {"mode": mode}
    if mode == "files":
        tls.update(certificate="operator.pem", private_key="operator.key")
        if private_ca:
            tls["ca_file"] = "operator-ca.pem"
    params = parameters(tmp_path, tls=tls)
    monkeypatch.setattr(cli, "_live_site", lambda _: (params, None, None, None))
    monkeypatch.setattr(cli, "_agent_add_live", lambda *_args, **_kwargs: None)
    result = CliRunner().invoke(
        app, ["live", "agent", "add", "outpost", "--params", str(params.path)]
    )
    assert result.exit_code == 0, result.output
    assert (" --ca ca.pem" in result.output) is expected


def test_native_submission_requires_people_identity_before_local_recipient(tmp_path):
    params = parameters(tmp_path, org_domain="house.internal")
    live.install(params)
    bundle = json.loads((params.secrets_dir / "stalwart" / "bundle.json").read_text())
    settings = {op["object"]: op["value"] for op in bundle["plan"]}
    # Stalwart 0.16 MtaStageMail checks this before RCPT, including local mail.
    # Test the authenticated principal, not the easily spoofed envelope sender.
    assert settings["MtaStageMail"]["isSenderAllowed"] == {
        "else": "!is_empty(authenticated_as) || !key_exists('spam-block', sender_domain)",
        "match": {
            "0": {
                "if": "local_port == 465 || local_port == 587",
                "then": "ends_with(authenticated_as, '@house.internal')",
            }
        },
    }
    assert settings["MtaStageAuth"]["mustMatchSender"] == {"else": "true", "match": {}}


def test_public_stalwart_requires_public_parameters(tmp_path):
    with pytest.raises(live.ParamsError, match="required"):
        parameters(tmp_path, profile="public")


def test_stalwart_queue_inspection_fails_closed(tmp_path, monkeypatch):
    params = parameters(tmp_path)
    monkeypatch.setattr(live, "running", lambda *_: True)
    with pytest.raises(live.DockerUnavailable, match="Stalwart"):
        live.queued_mail(params)


@pytest.mark.parametrize("force", [False, True])
def test_stalwart_purge_refuses_before_docker(tmp_path, monkeypatch, force):
    params = parameters(tmp_path)
    monkeypatch.setattr(live, "running", lambda *_: pytest.fail("Docker inventory"))
    monkeypatch.setattr(live, "run_compose", lambda *_: pytest.fail("Docker mutation"))
    args = ["live", "down", "--params", str(params.path), "--purge"]
    if force:
        args.append("--force")
    result = CliRunner().invoke(app, args)
    assert result.exit_code != 0
    assert "Stalwart" in result.output and "retained" in result.output


def test_stalwart_regular_down_preserves_bind_data(tmp_path, monkeypatch):
    params = parameters(tmp_path)
    datastore = params.state_dir / "stalwart" / "mail"
    datastore.parent.mkdir(parents=True)
    datastore.write_bytes(b"retained fixture mail")
    calls = []
    monkeypatch.setattr(live, "run_compose", lambda _params, *args: calls.append(args))
    result = CliRunner().invoke(app, ["live", "down", "--params", str(params.path)])
    assert result.exit_code == 0, result.output
    assert calls == [("down",)]
    assert datastore.read_bytes() == b"retained fixture mail"


def test_stalwart_host_rotation_and_backup_refuse_before_mutating(tmp_path):
    params = parameters(tmp_path)
    with pytest.raises(live.ParamsError, match="offline provisioning"):
        live.rotate(params, "gateway-master")
    with pytest.raises(live.ParamsError, match="backup is not implemented"):
        live.backup(params, tmp_path / "backup", with_secrets=False)
    assert not params.state_dir.exists()


def test_stopped_stalwart_is_not_a_preflight_pass(tmp_path, monkeypatch):
    from amx import preflight

    params = parameters(tmp_path)
    monkeypatch.setattr(
        preflight, "tls_checks", lambda *_: [preflight.Result("SKIP", "tls:imaps", "refused")]
    )
    results = preflight.run_checks(params, preflight.Options())
    assert any(result.check == "tls:imaps" and result.status == "FAIL" for result in results)


def test_private_routing_has_no_mx_or_authenticated_relay(tmp_path):
    params = parameters(tmp_path, outbound_allowlist=["x@example.com", "home.arpa"])
    live.install(params)
    config = load_config(params.gateway_config)
    assert config.outbound_allowlist == {"x@example.com", "home.arpa"}
    assert config.outbound_allowed("alice@home.arpa")
    assert not config.outbound_allowed("x@example.com")
    assert not config.outbound_allowed("x@sub.home.arpa")
    bundle = json.loads((params.secrets_dir / "stalwart/bundle.json").read_text())
    settings = {op["object"]: op["value"] for op in bundle["plan"]}
    assert settings["MtaStageRcpt"]["allowRelaying"] == {
        "else": "false",
        "match": {
            "0": {
                "if": f"local_port == 10025 && remote_ip == '{params.gateway_ip}'",
                "then": "true",
            },
            "1": {
                "if": f"listener == 'sibling-in' && remote_ip == '{params.gateway_ip}'",
                "then": "true",
            },
            "2": {
                "if": "listener == 'sibling' && remote_ip == '127.0.0.1'",
                "then": "true",
            },
        },
    }
    assert settings["MtaOutboundStrategy"]["route"] == {
        "else": "'local'",
        "match": {
            "0": {"if": "received_via_port == 10027", "then": "'sibling-loop'"},
            "1": {"if": "rcpt_domain == 'agents.home.arpa'", "then": "'gateway'"},
        },
    }
    assert "'mx'" not in json.dumps(settings["MtaOutboundStrategy"])


@pytest.mark.parametrize("mta", ["postfix", "stalwart"])
def test_private_compose_removes_smtp_publication(tmp_path, mta):
    params = parameters(tmp_path, mta=mta)
    command = live.compose(params, "config")
    assert str(live.BUNDLE / f"compose.private.{mta}.yaml") in command


def test_public_stalwart_keeps_mx_and_allowlist(tmp_path):
    params = parameters(
        tmp_path,
        profile="public",
        org_domain="example.test",
        agent_domain="agents.example.test",
        mx_host="mail.example.test",
        public_ip="192.0.2.10",
        admin_contact="ops@example.test",
    )
    live.install(params)
    config = load_config(params.gateway_config)
    assert config.outbound == "unrestricted"
    assert config.outbound_allowed("x@example.com")
    bundle = json.loads((params.secrets_dir / "stalwart/bundle.json").read_text())
    settings = {op["object"]: op["value"] for op in bundle["plan"]}
    assert settings["MtaOutboundStrategy"]["route"]["else"] == "'mx'"
    assert not any("compose.private" in arg for arg in live.compose(params, "config"))
