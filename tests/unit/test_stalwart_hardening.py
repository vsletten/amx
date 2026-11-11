"""SH-10b: no daemon/network needed; effective settings are distinct from the plan."""

import json

import pytest

from amx import live
from amx.live_stalwart import hardening_checks


def installed(tmp_path):
    path = tmp_path / "live.yaml"
    path.write_text(f"mta: stalwart\nprofile: private\nstate_dir: {tmp_path / 'state'}\n")
    params = live.load_params(path)
    live.install(params)
    bundle = json.loads((params.secrets_dir / "stalwart/bundle.json").read_text())
    effective = {}
    for op in bundle["plan"]:
        effective[op["object"]] = (
            list(op["value"].values()) if op["@type"] in {"upsert", "reconcile"} else [op["value"]]
        )
    effective["WebUiStatus"] = [{"ready": True}]
    return params, effective


def test_hardening_defaults(tmp_path):
    params, effective = installed(tmp_path)
    assert all(r.status == "PASS" for r in hardening_checks(params, effective))
    config = live.gateway_config(params, live.load_credentials(params))
    assert config["mailbox"]["tls"] is True
    assert config["mailbox"]["port"] == 993
    assert effective["Imap"][0]["allowPlainTextAuth"] is False
    assert effective["Application"][0]["enabled"] is True


@pytest.mark.parametrize(
    "object_name,field,value,check",
    [
        ("OidcProvider", "requireClientRegistration", False, "oidc"),
        ("OidcProvider", "anonymousClientRegistration", True, "oidc"),
        ("Imap", "allowPlainTextAuth", True, "imap"),
        ("MtaInboundThrottle", "enable", False, "throttles"),
        ("MtaInboundThrottle", "rate", {"count": 1000000, "period": 1}, "throttles"),
        ("AllowedIp", "address", "0.0.0.0/0", "trusted-gateway"),
        ("Application", "enabled", False, "webui"),
        ("Application", "resourceUrl", "http://unsafe.invalid/bundle.zip", "webui"),
    ],
)
def test_effective_drift_refuses_despite_unchanged_installed_plan(
    tmp_path, object_name, field, value, check
):
    params, effective = installed(tmp_path)
    effective[object_name][0][field] = value
    results = {r.check: r.status for r in hardening_checks(params, effective)}
    assert results[f"stalwart:{check}"] == "FAIL"


@pytest.mark.parametrize(
    "object_name",
    ["OidcProvider", "Imap", "MtaInboundThrottle", "AllowedIp", "Application", "NetworkListener"],
)
def test_missing_effective_object_refuses(tmp_path, object_name):
    params, effective = installed(tmp_path)
    del effective[object_name]
    assert any(r.status == "FAIL" for r in hardening_checks(params, effective))


@pytest.mark.parametrize("address", ["0.0.0.0", "192.168.1.2", "203.0.113.1"])
def test_public_admin_binding_refused(tmp_path, address):
    path = tmp_path / "live.yaml"
    path.write_text(
        f"mta: stalwart\nprofile: private\nstalwart:\n  admin_bind_address: {address}\n"
    )
    with pytest.raises(live.ParamsError, match="localhost or a tailnet"):
        live.load_params(path)


@pytest.mark.parametrize(
    "broken",
    [
        None,
        "oidc",
        "imap",
        "throttles",
        "trusted-gateway",
        "webui",
        "admin-bind",
        "gateway-imaps",
        "unreadable",
    ],
)
def test_preflight_reads_effective_state_and_actual_publications(tmp_path, monkeypatch, broken):
    import subprocess
    from types import SimpleNamespace

    import yaml

    from amx import preflight

    params, effective = installed(tmp_path)
    objects = {
        "oidc": "OidcProvider",
        "imap": "Imap",
        "throttles": "MtaInboundThrottle",
        "trusted-gateway": "AllowedIp",
        "webui": "Application",
    }
    if broken in objects:
        effective[objects[broken]] = []
    if broken == "gateway-imaps":
        config = yaml.safe_load(params.gateway_config.read_text())
        config["mailbox"]["tls"] = False
        params.gateway_config.write_text(yaml.safe_dump(config))
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        from amx.adapters.stalwart import SNAPSHOT_TIMEOUT

        assert kwargs["capture_output"] and kwargs["shell"] is False
        assert kwargs["timeout"] == (SNAPSHOT_TIMEOUT if "hardening-snapshot" in command else 30)
        if "hardening-snapshot" in command:
            if broken == "unreadable":
                raise subprocess.CalledProcessError(1, command, stderr="PRIVATE-AUTH-PAYLOAD")
            output = json.dumps(effective)
        elif "inspect" in command:
            output = json.dumps(
                {
                    "443/tcp": [
                        {
                            "HostIp": "0.0.0.0" if broken == "admin-bind" else "127.0.0.1",
                            "HostPort": "443",
                        }
                    ]
                }
            )
        else:
            output = "a" * 64 + "\n"
        return SimpleNamespace(stdout=output)

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(preflight, "tls_checks", lambda *_: [])
    monkeypatch.setattr("amx.live_stalwart.read_webui", lambda _: b"verified offline fixture")
    monkeypatch.setattr(preflight, "Lookup", lambda *_: pytest.fail("private DNS access"))
    results = preflight.run_checks(params, preflight.Options())
    failed = [r.check for r in results if r.status == "FAIL"]
    assert failed == (
        [] if broken is None else ["stalwart:" + ("readback" if broken == "unreadable" else broken)]
    )
    assert "PRIVATE" not in str(results)
    assert any("hardening-snapshot" in command for command in calls)


def test_staged_bundle_is_private_and_survives_source_removal(tmp_path, monkeypatch):
    import hashlib
    import zipfile

    from amx import stalwart_webui

    staged = tmp_path / "webui.zip"
    with zipfile.ZipFile(staged, "w") as archive:
        archive.writestr("index.html", "synthetic fixture, not the real WebUI")
    monkeypatch.setattr(
        stalwart_webui, "WEBUI_SHA256", hashlib.sha256(staged.read_bytes()).hexdigest()
    )
    path = tmp_path / "live.yaml"
    path.write_text(
        f"mta: stalwart\nprofile: private\nstate_dir: {tmp_path / 'state'}\n"
        f"stalwart:\n  webui_bundle: {staged}\n"
    )
    params = live.load_params(path)
    live.install(params)
    installed_zip = params.secrets_dir / "stalwart/webui.zip"
    assert installed_zip.read_bytes() == staged.read_bytes()
    assert installed_zip.stat().st_mode & 0o777 == 0o600
    staged.unlink()
    assert zipfile.is_zipfile(installed_zip)


def test_gateway_imap_paths_keep_tls_and_hostname_validation(monkeypatch):
    from amx.config import MailboxConfig
    from amx.mailbox import ImapEndpoint, connect_mailbox

    sentinel = object()
    observed = []

    def connect(endpoint, **kwargs):
        observed.append((endpoint, kwargs))
        return sentinel

    monkeypatch.setattr(ImapEndpoint, "connect", connect)
    config = MailboxConfig(
        "172.31.250.10",
        port=993,
        tls=True,
        tls_ca_file="/fixture/ca.pem",
        tls_server_name="mail.home.arpa",
    )
    assert connect_mailbox(config, timeout=10) is sentinel
    assert observed == [
        (
            ImapEndpoint("172.31.250.10", 993, True),
            {"ca_file": "/fixture/ca.pem", "timeout": 10, "server_hostname": "mail.home.arpa"},
        )
    ]


def test_bootstrap_and_snapshot_do_not_publish_cli_credentials(monkeypatch):
    from types import SimpleNamespace

    from amx.adapters import stalwart

    def run(command, **kwargs):
        assert command[-1] == "--json"
        assert kwargs["capture_output"] and kwargs["timeout"] == stalwart.SNAPSHOT_QUERY_TIMEOUT
        assert kwargs["shell"] is False
        assert kwargs["env"] == {"PATH": "/fixture/bin", "STALWART_URL": "http://fixture.invalid"}
        return SimpleNamespace(
            stdout=json.dumps(
                {"allowPlainTextAuth": False, "credentials": "PRIVATE", "secret": "PRIVATE"}
            )
        )

    monkeypatch.setattr(stalwart.subprocess, "run", run)
    monkeypatch.setattr(stalwart, "http_ok", lambda _: True)
    result = stalwart.hardening_snapshot(
        "/usr/local/bin/stalwart-cli",
        {"PATH": "/fixture/bin", "STALWART_URL": "http://fixture.invalid"},
    )
    assert "PRIVATE" not in json.dumps(result)
    assert "Account" not in result
