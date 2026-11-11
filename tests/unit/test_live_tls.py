"""Files-mode installation, explicit operator hook and fixed Stalwart action."""

import subprocess
from dataclasses import replace
from types import SimpleNamespace

import pytest
import yaml
from typer.testing import CliRunner

from amx import live
from amx.adapters import stalwart
from amx.cli import app
from amx.config import load_config


def params_at(tmp_path, tls=None, **changes):
    raw = {"mta": "stalwart", "profile": "private", "state_dir": str(tmp_path / "state")}
    raw.update(changes)
    if tls is not None:
        raw["tls"] = tls
    path = tmp_path / "live.yaml"
    path.write_text(yaml.safe_dump(raw))
    return live.load_params(path)


def test_files_paths_and_invalid_combinations(tmp_path):
    params = params_at(
        tmp_path, {"mode": "files", "certificate": "fullchain.pem", "private_key": "key.pem"}
    )
    assert params.tls_certificate == tmp_path / "fullchain.pem"
    assert params.tls_private_key == tmp_path / "key.pem"
    for tls in (
        {"mode": "files"},
        {"mode": "files", "certificate": "cert", "private_key": ""},
        {"mode": "files", "certificate": 42, "private_key": "key"},
        {"mode": "self-signed", "certificate": "cert"},
        {"mode": "files", "certificate": "cert", "private_key": "key", "ca_file": None},
    ):
        with pytest.raises(live.ParamsError):
            params_at(tmp_path, tls)
    with pytest.raises(live.ParamsError, match="stalwart"):
        params_at(
            tmp_path, {"mode": "files", "certificate": "cert", "private_key": "key"}, mta="postfix"
        )


def test_file_snapshot_validates_before_publication(tmp_path):
    source = params_at(tmp_path)
    live.ensure_self_signed(source)
    params = replace(
        source,
        state_dir=tmp_path / "target",
        tls_mode="files",
        tls_certificate=source.tls_dir / "server.pem",
        tls_private_key=source.tls_dir / "server-key.pem",
        tls_ca_file=source.tls_dir / "ca.pem",
    )
    live.install(params)
    cert, key = params.tls_dir / "server.pem", params.tls_dir / "server-key.pem"
    before = (cert.read_bytes(), key.read_bytes())
    assert before == (params.tls_certificate.read_bytes(), params.tls_private_key.read_bytes())
    assert key.stat().st_mode & 0o777 == 0o600
    assert load_config(params.gateway_config).mailbox.tls_ca_file == "/tls/ca.pem"
    live.ensure_self_signed(source, force=True)
    params.tls_private_key.write_bytes(before[1])
    with pytest.raises(OSError):
        live.install_file_certificate(params)
    assert (cert.read_bytes(), key.read_bytes()) == before
    params.tls_certificate.write_text("bad PEM")
    with pytest.raises(OSError):
        live.install_file_certificate(params)
    assert (cert.read_bytes(), key.read_bytes()) == before


@pytest.mark.parametrize("fail_at", [None, 1, 2])
def test_operator_hook_never_restarts_or_hides_failure(tmp_path, monkeypatch, fail_at):
    params = params_at(tmp_path)
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        assert kwargs["check"] and kwargs["capture_output"] and kwargs["timeout"] == 90
        if len(calls) == fail_at:
            raise subprocess.CalledProcessError(1, command, stderr="synthetic private error")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(live.subprocess, "run", run)
    if fail_at:
        with pytest.raises(live.ParamsError, match="no restart attempted") as error:
            live.reload_tls(params)
        assert "synthetic private" not in str(error.value)
        assert len(calls) == fail_at
    else:
        live.reload_tls(params)
        live.reload_tls(params)  # same files still retry both actions
        assert len(calls) == 4
    assert all("exec" in call and "restart" not in call and "up" not in call for call in calls)
    assert "reload-tls" in calls[0]
    if fail_at != 1:
        assert "amx.tls_reload" in calls[1]


def test_files_certs_cli_stages_then_reloads_every_time(tmp_path, monkeypatch):
    params = params_at(tmp_path, {"mode": "files", "certificate": "cert", "private_key": "key"})
    calls = []
    monkeypatch.setattr(live, "install_file_certificate", lambda p: calls.append(("stage", p)))
    monkeypatch.setattr(live, "reload_tls", lambda p: calls.append(("reload", p)))
    for _ in range(2):
        result = CliRunner().invoke(app, ["live", "certs", "--params", str(params.path)])
        assert result.exit_code == 0, result.output
    assert [name for name, _ in calls] == ["stage", "reload", "stage", "reload"]
    assert all(p == params for _, p in calls)


def test_pinned_stalwart_action_and_failure_propagation(monkeypatch):
    calls = []
    monkeypatch.setattr(
        stalwart.subprocess, "run", lambda command, **kw: calls.append((command, kw))
    )
    stalwart.reload_tls_certificates(
        "/usr/local/bin/stalwart-cli", {"STALWART_URL": "http://mailhost:8080"}
    )
    command, kwargs = calls[0]
    assert command == [
        "/usr/local/bin/stalwart-cli",
        "--no-color",
        "create",
        "Action/ReloadTlsCertificates",
        "--json",
        "{}",
    ]
    assert kwargs["check"] and kwargs["capture_output"]
    with pytest.raises(ValueError):
        stalwart.reload_tls_certificates("/other", {})

    def fail(*_a, **_kw):
        raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(stalwart.subprocess, "run", fail)
    with pytest.raises(subprocess.CalledProcessError):
        stalwart.reload_tls_certificates("/usr/local/bin/stalwart-cli", {})
