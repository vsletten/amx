"""Host tests never reach a real manager, home, credentials, or mail server."""

from __future__ import annotations

import json
import plistlib
import re
import shlex
import socket
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from amx import host
from amx.cli import app
from amx.credentials import write_bundle


@pytest.fixture(autouse=True)
def isolated_host(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)

    def forbidden(*args, **kwargs):
        pytest.fail("unit test crossed the service-manager/network boundary")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    calls = []

    def manager(self, *args):
        calls.append(args)
        if args[0] == "show":
            values = {"LoadState": "not-found", "ActiveState": "inactive", "MainPID": "0"}
            return subprocess.CompletedProcess(args, 0, values[args[2].split("=", 1)[1]], "")
        if args[0] == "print":
            identity = args[1].rsplit("/", 1)[1]
            return subprocess.CompletedProcess(
                args,
                113,
                "",
                f'Could not find service "{identity}" in domain for user gui: {host.os.getuid()}',
            )
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(host.Manager, "run", manager)
    monkeypatch.setattr(host.sys, "platform", "linux")
    yield calls


@pytest.fixture
def bundle(tmp_path):
    path = tmp_path / "bundle.json"
    write_bundle(
        path,
        {
            "address": "probe@agents.example.test",
            "imap": "127.0.0.1:1143",
            "submission": "smtp://127.0.0.1:2587",
            "password": "fixture-password",
            "token": "fixture-token",
        },
    )
    return path


def invoke(*args):
    return CliRunner().invoke(app, ["host", *map(str, args)], catch_exceptions=False)


@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_install_and_uninstall(bundle, isolated_host, monkeypatch, platform):
    monkeypatch.setattr(host.sys, "platform", platform)
    result = invoke("install", bundle, "--handler", "amx.examples.intake:handle")
    assert result.exit_code == 0, result.output
    identity = host.service_id("probe@agents.example.test")
    directory = host.default_state_home() / identity
    record = json.loads((directory / "install.json").read_text())
    service = Path(record["service"])
    payload = service.read_text()
    assert "fixture-password" not in payload + result.output
    assert "fixture-token" not in payload + result.output
    assert (directory / "credentials.json").stat().st_mode & 0o777 == 0o600
    assert directory.stat().st_mode & 0o777 == 0o700
    if platform == "linux":
        assert "WantedBy=default.target" in payload and "Restart=always" in payload
        assert "UMask=0077" in payload and "User=" not in payload
        assert f"WorkingDirectory={directory}/.\n" in payload
        assert ("enable", "--now", service.name) in isolated_host
    else:
        plist = plistlib.loads(service.read_bytes())
        assert plist["RunAtLoad"] and plist["KeepAlive"]
        assert plist["Umask"] == 0o077 and "UserName" not in plist
        assert plist["ProgramArguments"][1:3] == ["-m", "amx.runner"]
        assert any(command[0] == "bootstrap" for command in isolated_host)
    # Duplicate installation cannot create a second runner, even in another state root.
    assert invoke("install", bundle, "--handler", "x:y").exit_code == 1
    (directory / "runner.sqlite").write_text("handled state")
    result = invoke("uninstall", "probe@agents.example.test")
    assert result.exit_code == 0, result.output
    assert not service.exists() and not (directory / "credentials.json").exists()
    assert (directory / "runner.sqlite").read_text() == "handled state"
    assert bundle.exists()  # source belongs to the operator


def test_foreign_and_modified_services_are_not_adopted(bundle, isolated_host):
    service = host.service_path(host.service_id("probe@agents.example.test"))
    service.parent.mkdir(parents=True)
    service.write_text("foreign")
    assert invoke("install", bundle, "--handler", "x:y").exit_code == 1
    assert service.read_text() == "foreign"
    assert not any(c[0] == "enable" for c in isolated_host)
    service.unlink()
    assert invoke("install", bundle, "--handler", "x:y").exit_code == 0
    service.write_text("modified")
    assert invoke("uninstall", "probe@agents.example.test", "--purge-state").exit_code == 1
    assert service.read_text() == "modified"


def test_validate_all_bundles_before_any_install(bundle, isolated_host, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"amx_credentials": 1}')
    result = invoke("install", bundle, bad, "--handler", "x:y")
    assert result.exit_code == 1
    assert not any(c[0] == "enable" for c in isolated_host)
    assert not host.default_state_home().exists()


def test_ax_defaults_and_systemd_escaping(bundle, isolated_host, tmp_path, monkeypatch):
    monkeypatch.setattr(host.shutil, "which", lambda _: "/usr/local/bin/ax")
    state = tmp_path / 'state % $ " space'
    result = invoke("install", bundle, "--ax", "target", "--state-home", state)
    assert result.exit_code == 0, result.output
    record = json.loads(next(state.glob("*/install.json")).read_text())
    payload = Path(record["service"]).read_text()
    assert str(tmp_path / ".ax") in payload
    assert '"--offline" "hold"' in payload
    assert "%% $$" in payload and '\\"' in payload
    assert "<state>/ax" not in payload
    assert (
        invoke(
            "uninstall", "probe@agents.example.test", "--state-home", state, "--purge-state"
        ).exit_code
        == 0
    )
    assert not next(iter(state.iterdir()), None)


@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_offline_policy_is_rendered_for_host_runner(bundle, isolated_host, monkeypatch, platform):
    monkeypatch.setattr(host.sys, "platform", platform)
    monkeypatch.setattr(host.shutil, "which", lambda _: "/usr/local/bin/ax")
    result = invoke("install", bundle, "--ax", "target", "--offline", "pause")
    assert result.exit_code == 0, result.output
    record = json.loads(next(host.default_state_home().glob("*/install.json")).read_text())
    service = Path(record["service"])
    if platform == "darwin":
        argv = plistlib.loads(service.read_bytes())["ProgramArguments"]
    else:
        command = next(
            line.removeprefix("ExecStart=")
            for line in service.read_text().splitlines()
            if line.startswith("ExecStart=")
        )
        argv = shlex.split(command)
    assert argv[argv.index("--offline") + 1] == "pause"


@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_ax_names_qualify_full_address_and_survive_reinstall(
    bundle, isolated_host, tmp_path, monkeypatch, platform
):
    monkeypatch.setattr(host.sys, "platform", platform)
    monkeypatch.setattr(host.shutil, "which", lambda _: "/usr/local/bin/ax")
    second = tmp_path / "second.json"
    credentials = json.loads(bundle.read_text())
    credentials["address"] = "probe@agents.second.test"
    write_bundle(second, credentials)
    addresses = ["probe@agents.example.test", credentials["address"]]

    def ax_name(address):
        service = host.service_path(host.service_id(address))
        if platform == "darwin":
            argv = plistlib.loads(service.read_bytes())["ProgramArguments"]
        else:
            command = next(
                line.removeprefix("ExecStart=")
                for line in service.read_text().splitlines()
                if line.startswith("ExecStart=")
            )
            argv = shlex.split(command)
        assert argv[argv.index("--ax-home") + 1] == str(tmp_path / ".ax")
        assert "--ax-name" in argv
        name = argv[argv.index("--ax-name") + 1]
        assert re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_-]{0,47}", name)
        return name

    result = invoke("install", bundle, second, "--ax", "target")
    assert result.exit_code == 0, result.output
    names = [ax_name(address) for address in addresses]
    assert names[0] != names[1]
    for address in addresses:
        assert invoke("uninstall", address).exit_code == 0
    result = invoke("install", bundle, second, "--ax", "target")
    assert result.exit_code == 0, result.output
    assert [ax_name(address) for address in addresses] == names


def test_manager_failure_keeps_cleanup_receipt(bundle, monkeypatch):
    def failure(self, *args):
        if args[0] == "show":
            return subprocess.CompletedProcess(args, 0, "not-found", "")
        return subprocess.CompletedProcess(args, 1, "", "manager refused")

    monkeypatch.setattr(host.Manager, "run", failure)
    result = invoke("install", bundle, "--handler", "x:y")
    assert result.exit_code == 1
    assert "manager refused" in result.output
    assert list(host.default_state_home().glob("*/install.json"))


def test_symlink_state_refused(bundle, tmp_path):
    state = tmp_path / "host"
    state.mkdir()
    owned = state / host.service_id("probe@agents.example.test")
    owned.symlink_to(tmp_path, target_is_directory=True)
    assert invoke("install", bundle, "--handler", "x:y", "--state-home", state).exit_code == 1


def test_handler_or_ax_required(bundle, isolated_host):
    assert invoke("install", bundle).exit_code != 0
    assert isolated_host == []
