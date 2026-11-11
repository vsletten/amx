"""Hosted-review regressions: managers and all network calls are replaced."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from amx import host, runner
from amx.cli import app
from amx.credentials import write_bundle

ADDRESS = "probe@agents.example.test"
REAL_RUN = host.Manager.run


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.setattr(host.sys, "platform", "linux")

    def forbidden(*args, **kwargs):
        pytest.fail("real subprocess forbidden")

    monkeypatch.setattr(subprocess, "run", forbidden)
    calls = []

    def fake(self, *args):
        calls.append(args)
        value = {
            "LoadState": "not-found",
            "ActiveState": "inactive",
            "MainPID": "0",
            "FragmentPath": "",
            "DropInPaths": "",
        }
        if args[0] == "show":
            return subprocess.CompletedProcess(args, 0, value[args[2].split("=", 1)[1]], "")
        if args[0] == "print":
            return subprocess.CompletedProcess(args, 113, "", absent())
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(host.Manager, "run", fake)
    return calls


def absent():
    return (
        f'Bad request.\nCould not find service "{host.service_id(ADDRESS)}" '
        f"in domain for user gui: {os.getuid()}\n"
    )


def invoke(*args):
    return CliRunner().invoke(app, ["host", *map(str, args)], catch_exceptions=False)


@pytest.fixture
def bundle(tmp_path):
    path = tmp_path / "bundle.json"
    write_bundle(
        path,
        dict(
            address=ADDRESS,
            imap="127.0.0.1:1143",
            submission="smtp://127.0.0.1:2587",
            password="fixture",
            token="fixture",
        ),
    )
    return path


def installed(bundle):
    result = invoke("install", bundle, "--handler", "x:y")
    assert result.exit_code == 0, result.output
    directory = host.default_state_home() / host.service_id(ADDRESS)
    return directory, host.service_path(host.service_id(ADDRESS))


@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_manager_read_errors_fail_closed(bundle, monkeypatch, platform):
    monkeypatch.setattr(host.sys, "platform", platform)
    directory, path = installed(bundle)

    def error(self, *args):
        return subprocess.CompletedProcess(args, 1, "", "manager unavailable")

    monkeypatch.setattr(host.Manager, "run", error)
    result = invoke("uninstall", ADDRESS)
    assert result.exit_code == 1
    assert path.exists() and (directory / "credentials.json").exists()


@pytest.mark.parametrize("loaded", [False, True])
def test_launchd_disable_and_checked_post_stop(monkeypatch, loaded):
    monkeypatch.setattr(host.sys, "platform", "darwin")
    identity = host.service_id(ADDRESS)
    calls = []
    states = iter([loaded, False]) if loaded else iter([False, False])
    monkeypatch.setattr(host.Manager, "loaded", lambda *_: next(states))
    monkeypatch.setattr(host.Manager, "checked", lambda _, *args: calls.append(args) or "")
    host.Manager().stop(identity, host.service_path(identity))
    assert ("disable", f"gui/{os.getuid()}/{identity}") in calls
    assert (("bootout", f"gui/{os.getuid()}/{identity}") in calls) is loaded


@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_stop_must_prove_inactive(monkeypatch, platform):
    monkeypatch.setattr(host.sys, "platform", platform)
    monkeypatch.setattr(host.Manager, "loaded", lambda *_: True)
    monkeypatch.setattr(
        host.Manager, "checked", lambda _, *a: "active" if "--property=ActiveState" in a else ""
    )
    with pytest.raises(RuntimeError):
        host.Manager().stop(host.service_id(ADDRESS), host.service_path(host.service_id(ADDRESS)))


@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_missing_file_cleanup_recovery(bundle, monkeypatch, platform):
    monkeypatch.setattr(host.sys, "platform", platform)
    directory, path = installed(bundle)
    path.unlink()
    result = invoke("uninstall", ADDRESS)
    assert result.exit_code == 0, result.output
    assert not (directory / "install.json").exists()
    assert not (directory / "credentials.json").exists()


def test_reload_failure_retriable(bundle, monkeypatch):
    directory, path = installed(bundle)
    original = host.Manager.run

    def fail(self, *args):
        if args == ("daemon-reload",):
            return subprocess.CompletedProcess(args, 1, "", "reload failed")
        return original(self, *args)

    monkeypatch.setattr(host.Manager, "run", fail)
    assert invoke("uninstall", ADDRESS).exit_code == 1
    assert not path.exists() and (directory / "install.json").exists()
    monkeypatch.setattr(host.Manager, "run", original)
    assert invoke("uninstall", ADDRESS).exit_code == 0
    assert not (directory / "credentials.json").exists()


@pytest.mark.parametrize(
    "field,value", [("submission", "bogus"), ("submission", "smtp://host:bad")]
)
def test_bad_submission_is_preflight(bundle, field, value):
    data = json.loads(bundle.read_text())
    data[field] = value
    bundle.write_text(json.dumps(data))
    result = invoke("install", bundle, "--handler", "x:y")
    assert result.exit_code == 1
    assert not host.default_state_home().exists()


@pytest.mark.parametrize("option,value", [("--handler", "x:y\n"), ("--ax", "bad\x7f")])
def test_argv_controls_preflight(bundle, monkeypatch, option, value):
    monkeypatch.setattr(host.shutil, "which", lambda _: "/bin/ax")
    result = invoke("install", bundle, option, value)
    assert result.exit_code == 1
    assert not host.default_state_home().exists()


@pytest.mark.parametrize("fail_name", ["credentials.json", "install.json", "service"])
def test_partial_write_rollback(bundle, monkeypatch, fail_name):
    original = os.fdopen
    original_open = os.open
    names = {}

    def track_open(path, *args, **kwargs):
        fd = original_open(path, *args, **kwargs)
        names[fd] = Path(path).name
        return fd

    monkeypatch.setattr(os, "open", track_open)

    class FailWrite:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *a):
            self.stream.close()

        def write(self, data):
            self.stream.write(data[:5])
            raise OSError("simulated partial write")

    def fdopen(fd, *args, **kwargs):
        name = names[fd]
        stream = original(fd, *args, **kwargs)
        if name == fail_name or (fail_name == "service" and name.endswith(".service")):
            return FailWrite(stream)
        return stream

    monkeypatch.setattr(os, "fdopen", fdopen)
    result = invoke("install", bundle, "--handler", "x:y")
    assert result.exit_code == 1
    directory = host.default_state_home() / host.service_id(ADDRESS)
    assert not (directory / "credentials.json").exists()
    assert not (directory / "install.json").exists()
    assert not host.service_path(host.service_id(ADDRESS)).exists()


def test_activation_timeout_keeps_receipt(bundle, monkeypatch):
    monkeypatch.setattr(host.Manager, "loaded", lambda *_: False)
    monkeypatch.setattr(host.Manager, "run", REAL_RUN)

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], 45)

    monkeypatch.setattr(subprocess, "run", timeout)
    result = invoke("install", bundle, "--handler", "x:y")
    assert result.exit_code == 1 and "timed out" in result.output
    assert list(host.default_state_home().glob("*/install.json"))


@pytest.mark.parametrize(
    "platform,args",
    [
        ("linux", ("restart", "ssh.service")),
        ("linux", ("enable", "--now", "--root=/")),
        ("linux", ("daemon-reload", "extra")),
        ("darwin", ("bootout", "system")),
        ("darwin", ("bootstrap", "gui/0", "/evil")),
    ],
)
def test_manager_refuses_unsupported_operations(monkeypatch, platform, args):
    monkeypatch.setattr(host.sys, "platform", platform)
    with pytest.raises(ValueError):
        REAL_RUN(host.Manager(), *args)


def test_standalone_full_address_ax_names(tmp_path, monkeypatch):
    names = []

    class Child:
        process = None

        def __init__(self, binary, home, state, name):
            assert home == Path.home() / ".ax"
            names.append(name)

    class Presence:
        endpoint = None

        def __init__(self, child, presence):
            self.child = child

        def run(self, stop):
            pass

    monkeypatch.setenv("AMX_IMAP_PASSWORD", "fixture")
    monkeypatch.setenv("AMX_SUBMIT_TOKEN", "fixture")
    monkeypatch.setattr(runner, "AxChild", Child)
    monkeypatch.setattr(runner, "AxPresence", Presence)
    monkeypatch.setattr(runner.Runner, "run", lambda *_: None)
    monkeypatch.setattr(runner.signal, "signal", lambda *_: None)
    for address, extra in [
        (ADDRESS, []),
        ("probe@agents.second.test", []),
        (ADDRESS, ["--ax-name", "explicit"]),
    ]:
        runner.main(
            [
                "--agent",
                address,
                "--imap",
                "localhost:1143",
                "--submit",
                "smtp://localhost:2587",
                "--state",
                str(tmp_path / "state"),
                "--ax",
                "target",
                *extra,
            ]
        )
    assert names[0] != names[1]
    assert names[2] == "explicit"


@pytest.mark.parametrize(
    "argv",
    [
        ["sh", "-c", "true"],
        [sys.executable, "-c", "pass"],
        ["systemctl", "--user", "restart", "ssh.service"],
        ["ps", "-o", "uid=", "-p", "--help"],
    ],
)
def test_native_command_refuses_arbitrary_execution(argv):
    spec = importlib.util.spec_from_file_location(
        "native_repairs", Path(__file__).parents[2] / "tools/native_host_acceptance.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with pytest.raises(ValueError):
        module.command(argv)


@pytest.mark.parametrize("platform", ["linux", "darwin"])
@pytest.mark.parametrize("failure", ["bootout", "still-active", "foreign", "readback-error"])
def test_uninstall_retains_ownership_on_ambiguous_stop(bundle, monkeypatch, platform, failure):
    monkeypatch.setattr(host.sys, "platform", platform)
    directory, path = installed(bundle)
    stopped = False

    def manager(self, *args):
        nonlocal stopped
        if args[0] in {"disable", "bootout"}:
            if failure == "bootout":
                return subprocess.CompletedProcess(args, 1, "", "stop failed")
            stopped = True
            return subprocess.CompletedProcess(args, 0, "", "")
        if stopped and failure == "readback-error":
            return subprocess.CompletedProcess(args, 1, "", "readback failed")
        if args[0] == "print":
            if stopped and failure != "still-active":
                return subprocess.CompletedProcess(args, 113, "", absent())
            owner = "/foreign.plist" if failure == "foreign" else str(path)
            return subprocess.CompletedProcess(args, 0, f"path = {owner}\n", "")
        if args[0] == "show":
            values = {
                "LoadState": "loaded",
                "FragmentPath": "/foreign.service" if failure == "foreign" else str(path),
                "DropInPaths": "",
                "MainPID": "123" if failure == "still-active" else "0",
                "ActiveState": "active" if failure == "still-active" else "inactive",
            }
            return subprocess.CompletedProcess(args, 0, values[args[2].split("=", 1)[1]], "")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(host.Manager, "run", manager)
    result = invoke("uninstall", ADDRESS)
    assert result.exit_code == 1, result.output
    assert path.exists() and (directory / "credentials.json").exists()
    assert (directory / "install.json").exists()


@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_missing_file_active_or_foreign_refused(bundle, monkeypatch, platform):
    monkeypatch.setattr(host.sys, "platform", platform)
    directory, path = installed(bundle)
    path.unlink()
    monkeypatch.setattr(host.Manager, "loaded", lambda *_: True)
    monkeypatch.setattr(host.Manager, "checked", lambda _, *args: "active")
    assert invoke("uninstall", ADDRESS).exit_code == 1
    assert (directory / "install.json").exists() and (directory / "credentials.json").exists()


def test_foreign_file_winning_exclusive_create_not_unlinked(bundle, monkeypatch):
    original = host._exclusive
    path = host.service_path(host.service_id(ADDRESS))

    def race(target, data):
        if target == path:
            target.write_text("foreign winner")
        return original(target, data)

    monkeypatch.setattr(host, "_exclusive", race)
    assert invoke("install", bundle, "--handler", "x:y").exit_code == 1
    assert path.read_text() == "foreign winner"
    directory = host.default_state_home() / host.service_id(ADDRESS)
    assert not (directory / "credentials.json").exists()
    assert not (directory / "install.json").exists()


def test_batch_partial_success_is_explicit(bundle, tmp_path, monkeypatch):
    second = tmp_path / "second.json"
    data = json.loads(bundle.read_text())
    data["address"] = "second@agents.example.test"
    write_bundle(second, data)
    original = host.Manager.start

    def fail(self, identity, path):
        if identity == host.service_id(data["address"]):
            raise RuntimeError("activation failed")
        original(self, identity, path)

    monkeypatch.setattr(host.Manager, "start", fail)
    result = invoke("install", bundle, second, "--handler", "x:y")
    assert result.exit_code == 1
    assert f"completed: {ADDRESS}" in result.output
    assert (
        f"install failed for {data['address']} ({host.service_id(data['address'])})"
        in result.output
    )
    assert len(list(host.default_state_home().glob("*/install.json"))) == 2


@pytest.mark.parametrize(
    "suffix", ['quote"', r"back\slash\n", "percent%h", "trailing ", "trailing\\"]
)
def test_working_directory_literal_systemd_grammar(tmp_path, suffix):
    directory = tmp_path / suffix
    payload = host.render(host.service_id(ADDRESS), directory, [sys.executable]).decode()
    line = next(line for line in payload.splitlines() if line.startswith("WorkingDirectory="))
    # systemd config_parse_working_directory calls unit_path_printf, not extract_first_word
    # or cunescape. Quotes/backslashes remain literal; % is the only specifier escape.
    value = line.partition("=")[2].strip().replace("%%", "%")
    assert not value.endswith("\\")  # must not become an INI continuation
    assert Path(value) == directory


@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_manager_supported_grammar_uses_tokenized_shell_false(monkeypatch, platform):
    monkeypatch.setattr(host.sys, "platform", platform)
    identity = host.service_id(ADDRESS)
    path = host.service_path(identity)
    calls = []

    def capture(argv, **kwargs):
        assert kwargs == dict(shell=False, capture_output=True, text=True, timeout=45)
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(subprocess, "run", capture)
    commands = (
        [("daemon-reload",), ("enable", "--now", path.name), ("disable", "--now", path.name)]
        if platform == "linux"
        else [
            (operation, f"gui/{os.getuid()}/{identity}")
            for operation in ("print", "enable", "disable", "bootout")
        ]
        + [("bootstrap", f"gui/{os.getuid()}", str(path))]
    )
    if platform == "linux":
        commands += [
            ("show", path.name, f"--property={name}", "--value")
            for name in ("LoadState", "ActiveState", "MainPID", "FragmentPath", "DropInPaths")
        ]
    for args in commands:
        REAL_RUN(host.Manager(), *args)
    assert len(calls) == len(commands)


@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_native_supported_command_grammar(tmp_path, monkeypatch, platform):
    spec = importlib.util.spec_from_file_location(
        "native_positive", Path(__file__).parents[2] / "tools/native_host_acceptance.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(host.sys, "platform", platform)
    calls = []

    def capture(argv, **kwargs):
        assert kwargs == dict(shell=False, capture_output=True, text=True, timeout=50)
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(subprocess, "run", capture)
    identity = host.service_id(ADDRESS)
    unit = identity + ".service"
    cli = [sys.executable, "-m", "amx.cli", "host"]
    commands = [
        [
            *cli,
            "install",
            str(tmp_path / "fixture-bundle.json"),
            "--state-home",
            str(tmp_path / "state"),
            "--handler",
            "fixture_handler:handle",
        ],
        [
            *cli,
            "uninstall",
            "sh23-0123456789abcdef@agents.example.invalid",
            "--state-home",
            str(tmp_path / "state"),
            "--purge-state",
        ],
        ["ps", "-o", "uid=", "-p", "123"],
    ]
    if platform == "linux":
        commands += [
            ["systemctl", "--user", "is-enabled", unit],
            ["systemctl", "--user", "show", unit, "-p", "MainPID", "--value"],
            [
                "systemctl",
                "--user",
                "show",
                unit,
                "-p",
                "MainPID",
                "-p",
                "ActiveState",
                "-p",
                "UnitFileState",
                "-p",
                "ExecStart",
                "-p",
                "User",
                "-p",
                "UMask",
            ],
        ]
    else:
        commands += [
            ["launchctl", "print", f"gui/{os.getuid()}/{identity}"],
            ["launchctl", "print-disabled", f"gui/{os.getuid()}"],
        ]
    for argv in commands:
        module.command(argv)
    assert len(calls) == len(commands)


@pytest.mark.parametrize(
    "stderr",
    [
        "not loaded",
        'Could not find service "foreign" in domain for user gui: 0',
        "manager unavailable",
    ],
)
def test_launchd_only_exact_absence_is_accepted(monkeypatch, stderr):
    monkeypatch.setattr(host.sys, "platform", "darwin")
    monkeypatch.setattr(
        host.Manager, "run", lambda _, *a: subprocess.CompletedProcess(a, 113, "", stderr)
    )
    with pytest.raises(RuntimeError):
        host.Manager().loaded(host.service_id(ADDRESS))
