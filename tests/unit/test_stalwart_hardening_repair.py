"""PR15 counterexamples; offline synthetic bytes never count as native UI proof."""

import hashlib
import io
import json
import zipfile
from dataclasses import replace
from types import SimpleNamespace

import pytest
from test_stalwart_hardening import installed
from typer.testing import CliRunner

from amx import live, stalwart_webui
from amx.adapters import stalwart
from amx.cli import app
from amx.live_stalwart import hardening_checks, preflight_checks


@pytest.fixture
def bundle(monkeypatch):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("index.html", "offline synthetic fixture")
    data = buffer.getvalue()
    monkeypatch.setattr(stalwart_webui, "WEBUI_SHA256", hashlib.sha256(data).hexdigest())
    return data


@pytest.mark.parametrize("address", ["127.0.0.1", "100.64.1.2"])
@pytest.mark.parametrize("port", ["8080/tcp", "443/tcp", "8443/tcp"])
def test_effective_publication_counterexample(tmp_path, monkeypatch, address, port):
    params, effective = installed(tmp_path)
    effective["NetworkListener"].append({"protocol": "http", "bind": {"[::]:8443": True}})

    def run(command, **kwargs):
        if "hardening-snapshot" in command:
            output = json.dumps(effective)
        elif "inspect" in command:
            output = json.dumps({port: [{"HostIp": address, "HostPort": "18080"}]})
        else:
            output = "a" * 64
        return SimpleNamespace(stdout=output)

    monkeypatch.setattr(stalwart.subprocess, "run", run)
    rows = {r.check: r.status for r in preflight_checks(params)}
    # The publication decision is independent of an unstaged offline WebUI.
    assert rows["stalwart:webui-bundle"] == "FAIL"
    assert rows["stalwart:admin-bind"] == ("FAIL" if port == "8080/tcp" else "PASS")


@pytest.mark.parametrize("mutation", ["extra", "duplicate", "replace"])
def test_throttles_are_exact_not_subset(tmp_path, mutation):
    params, effective = installed(tmp_path)
    rows = effective["MtaInboundThrottle"]
    if mutation == "extra":
        rows.append({"enable": False})
    elif mutation == "duplicate":
        rows.append(rows[0].copy())
    else:
        rows[1] = rows[0].copy()
    assert {r.check: r.status for r in hardening_checks(params, effective)}[
        "stalwart:throttles"
    ] == "FAIL"


@pytest.mark.parametrize("value", [False, None])
def test_account_portal_required(tmp_path, value):
    params, effective = installed(tmp_path)
    effective["Application"][0]["urlPrefix"]["/account"] = value
    assert {r.check: r.status for r in hardening_checks(params, effective)}[
        "stalwart:webui"
    ] == "FAIL"


@pytest.mark.parametrize("bad", [b"not zip", b"PK\x03\x04corrupt", None])
def test_bad_staged_reinstall_changes_no_generated_bytes(tmp_path, bad):
    params, _ = installed(tmp_path)
    before = {p: p.read_bytes() for p in params.state_dir.rglob("*") if p.is_file()}
    source = tmp_path / "bad.zip"
    if bad is not None:
        source.write_bytes(bad)
    changed = replace(params, webui_bundle=source, known_domains=("changed.invalid",))
    with pytest.raises((ValueError, OSError)):
        live.install(changed)
    assert {p: p.read_bytes() for p in params.state_dir.rglob("*") if p.is_file()} == before


def test_atomic_write_failure_keeps_previous_private_bundle(tmp_path, monkeypatch, bundle):
    destination = tmp_path / "webui.zip"
    destination.write_bytes(b"previous")
    real_fdopen = stalwart_webui.os.fdopen

    def fdopen(fd, mode):
        stream = real_fdopen(fd, mode)
        assert stream.fileno() >= 0
        assert (
            tmp_path / next(p.name for p in tmp_path.glob(".webui-*"))
        ).stat().st_mode & 0o777 == 0o600

        class Failing:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                stream.close()

            def write(self, data):
                stream.write(data[:5])
                raise OSError("interrupted copy")

        return Failing()

    monkeypatch.setattr(stalwart_webui.os, "fdopen", fdopen)
    with pytest.raises(OSError, match="interrupted"):
        stalwart_webui.publish_webui(destination, bundle)
    assert destination.read_bytes() == b"previous"
    assert not list(tmp_path.glob(".webui-*"))


def test_install_uses_single_source_read(tmp_path, monkeypatch, bundle):
    params, _ = installed(tmp_path)
    source = tmp_path / "source.zip"
    source.write_bytes(bundle)
    read = stalwart_webui.read_webui
    calls = []

    def once(path):
        calls.append(path)
        data = read(path)
        path.write_bytes(b"ABA changed source")
        return data

    monkeypatch.setattr(stalwart_webui, "read_webui", once)
    live.install(replace(params, webui_bundle=source))
    assert calls == [source]
    assert (params.secrets_dir / "stalwart/webui.zip").read_bytes() == bundle


def test_plan_a_b_up_stops_before_init_and_preserves_data(tmp_path, monkeypatch, bundle):
    params, _ = installed(tmp_path)
    plan = params.secrets_dir / "stalwart/bundle.json"
    original_plan = plan.read_bytes()
    params.path.write_text(params.path.read_text() + "mx_host: mail2.home.arpa\n")
    params = live.load_params(params.path)
    live.install(params)
    assert plan.read_bytes() != original_plan
    data = params.state_dir / "stalwart/retained-mail"
    data.write_bytes(b"existing mailbox")
    calls = []
    monkeypatch.setattr(stalwart_webui, "fetch_webui", lambda: bundle)

    def compose(_params, *args):
        calls.append(args)
        assert (params.secrets_dir / "stalwart/webui.zip").read_bytes() == bundle
        if args[0] == "up":
            assert calls[0] == ("down",)
            assert "--force-recreate" in args

    monkeypatch.setattr(live, "run_compose", compose)
    result = CliRunner().invoke(app, ["live", "up", "--params", str(params.path)])
    assert result.exit_code == 0, result.output
    assert len(calls) == 2
    assert data.read_bytes() == b"existing mailbox"
    assert "--reapply" in (live.BUNDLE / "compose.stalwart.yaml").read_text()


def test_allowed_ip_reapply_matches_pinned_native_host_dto(tmp_path):
    params, _ = installed(tmp_path)
    path = params.secrets_dir / "stalwart/bundle.json"
    # v0.16.25 IpAddrOrMask::Display/IntoValue omits /32 for a host.
    # v1.0.12 CLI find_match/values_match uses exact JSON equality, not
    # network equivalence. AllowedIp.address has a unique native index.
    existing = {"id": "retained-native-id", "address": params.gateway_ip}
    for _ in range(2):
        live.install(params)
        plan = json.loads(path.read_text())["plan"]
        operation = next(op for op in plan if op["object"] == "AllowedIp")
        assert operation["@type"] == "reconcile"
        assert operation["matchOn"] == ["address"]
        desired = operation["value"]["allowed-network"]
        assert all(existing[field] == desired[field] for field in operation["matchOn"])
        # Only the match representation changes, not the trusted host or mask.
        assert desired["address"] == params.gateway_ip
        assert json.loads(path.read_text())["site"]["trusted_network"] == params.gateway_ip + "/32"


def test_pinned_digest_refuses_poisoned_fetch_before_publication(tmp_path, monkeypatch):
    destination = tmp_path / "webui.zip"
    monkeypatch.setattr(
        stalwart_webui.urllib.request, "urlopen", lambda *_a, **_kw: io.BytesIO(b"poison")
    )
    with pytest.raises(ValueError, match="SHA256"):
        stalwart_webui.prepare_webui(destination, staged=False)
    assert not destination.exists()


def test_snapshot_timeout_vector_and_executable_admission(monkeypatch):
    timeouts = []

    def run(argv, **kwargs):
        assert argv[0] == "/usr/local/bin/stalwart-cli"
        assert argv[2] in {"get", "query"}
        assert argv[3] in stalwart.HARDENING_FIELDS
        assert argv[5] == ",".join(stalwart.HARDENING_FIELDS[argv[3]])
        assert kwargs["shell"] is False
        timeouts.append(kwargs["timeout"])
        return SimpleNamespace(stdout="{}")

    monkeypatch.setattr(stalwart.subprocess, "run", run)
    monkeypatch.setattr(stalwart, "http_ok", lambda _: True)
    stalwart.hardening_snapshot(
        "/usr/local/bin/stalwart-cli", {"STALWART_URL": "http://fixture.invalid"}
    )
    assert len(timeouts) == 6
    assert sum(timeouts) + 2 < stalwart.SNAPSHOT_TIMEOUT < stalwart.PREFLIGHT_TIMEOUT
    with pytest.raises(ValueError, match="pinned"):
        stalwart.hardening_snapshot("/untrusted/executable", {})
    assert len(timeouts) == 6


@pytest.mark.parametrize("valid", [True, False])
def test_preflight_checks_installed_bundle_digest(tmp_path, monkeypatch, bundle, valid):
    params, effective = installed(tmp_path)
    (params.secrets_dir / "stalwart/webui.zip").write_bytes(bundle if valid else b"poisoned ZIP")

    def run(command, **kwargs):
        if "hardening-snapshot" in command:
            output = json.dumps(effective)
        elif "inspect" in command:
            output = json.dumps({"443/tcp": [{"HostIp": "127.0.0.1", "HostPort": "443"}]})
        else:
            output = "a" * 64
        return SimpleNamespace(stdout=output)

    monkeypatch.setattr(stalwart.subprocess, "run", run)
    rows = {r.check: r.status for r in preflight_checks(params)}
    assert rows["stalwart:webui-bundle"] == ("PASS" if valid else "FAIL")


def test_bad_zip_is_rejected_even_if_digest_matches(tmp_path, monkeypatch):
    params, _ = installed(tmp_path)
    before = {p: p.read_bytes() for p in params.state_dir.rglob("*") if p.is_file()}
    source = tmp_path / "corrupt.zip"
    source.write_bytes(b"PK\x03\x04corrupt")
    monkeypatch.setattr(
        stalwart_webui, "WEBUI_SHA256", hashlib.sha256(source.read_bytes()).hexdigest()
    )
    with pytest.raises(ValueError, match="valid ZIP"):
        live.install(replace(params, webui_bundle=source, known_domains=("changed.invalid",)))
    assert {p: p.read_bytes() for p in params.state_dir.rglob("*") if p.is_file()} == before
