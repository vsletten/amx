"""Real native lock admission and direct-call signals, with all sockets denied.

Every interpreter installs the socket denial via sitecustomize BEFORE importing
product code; subprocess environments contain only allowlisted fixture values.
No Docker command, existing host SMTP endpoint or operator HOME is accessible.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DENY_SOCKETS = """
import socket
class DeniedSocket(socket.socket):
    def __init__(self, *args, **kwargs):
        raise AssertionError('test isolation: sockets denied')
socket.socket = DeniedSocket
"""
RUNNER = r"""
import json, os, signal, sys
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0, str(Path.cwd() / 'tools'))
import live_validate_stalwart as validator
case = os.environ['CASE']
state = Path(os.environ['STATE'])
lock = Path(os.environ['AMX_SUITE_LOCK'])
events = []
def event(value):
    events.append(value)
    (state.parent / 'events.json').write_text(json.dumps(events))
def forbidden(*args, **kwargs):
    event('FORBIDDEN')
    raise AssertionError('unadmitted side effect')
# Defend imports and verify isolation, not just an unused network mock.
import socket
try:
    socket.socket()
except AssertionError:
    pass
else:
    raise AssertionError('socket guard not installed before imports')
if case == 'spoof':
    lock.touch()
    Path(str(lock) + '.active').write_text(json.dumps({'pgid': os.getpgrp()}))
if case in ('replaced-lock', 'foreign-lock'):
    lock.rename(str(lock) + '.old')
    if case == 'foreign-lock':
        import fcntl
        replacement = lock.open('a+')
        fcntl.flock(replacement, fcntl.LOCK_EX)
    else:
        lock.touch()
if case == 'forged-active':
    Path(str(lock) + '.active').write_text(json.dumps({'pgid': os.getpid() + 1}))
if case in ('unleased', 'spoof', 'replaced-lock', 'foreign-lock', 'forged-active'):
    validator.inventory = forbidden
    validator.write_fixture = forbidden
    validator.cli = forbidden
    validator.load_params = forbidden
    validator.tempfile.mkdtemp = forbidden
    for invoke in (
        lambda: validator.validate_stalwart(SimpleNamespace(state=state, keep=False)),
        lambda: validator.functional_checks(state, forbidden),
        lambda: validator.negative_hardening_checks(state, forbidden),
        lambda: validator.stage_webui(state),
    ):
        try:
            invoke()
        except RuntimeError as error:
            assert 'requires native X0 lock custody' in str(error), str(error)
        else:
            raise AssertionError('unadmitted call accepted')
    assert not events
    assert not state.exists()
    print('REFUSED_BEFORE_SIDE_EFFECTS', flush=True)
else:
    signals = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
    def original(signum, frame):
        raise AssertionError('original handler used inside admitted boundary')
    for sig in signals:
        signal.signal(sig, original)
    before = {sig: signal.getsignal(sig) for sig in signals}
    validator.inventory = lambda: []
    validator.stage_webui = lambda *_: None
    validator.bootstrap_diagnostics = lambda *_: None
    def cli(_state, action, *args, **kwargs):
        event(action)
        if action == 'up' and case in ('term', 'hup'):
            os.kill(os.getpid(), signal.SIGTERM if case == 'term' else signal.SIGHUP)
        if action == 'down' and case == 'cleanup-error':
            raise RuntimeError('cleanup failure')
        return ''
    validator.cli = cli
    validator._functional_checks = lambda *_: event('checks')
    try:
        result = validator.validate_stalwart(SimpleNamespace(state=state, keep=False))
    except RuntimeError as error:
        assert case == 'cleanup-error' and str(error) == 'cleanup failure'
        result = 1
    assert {sig: signal.getsignal(sig) for sig in signals} == before
    expected = {'term': 143, 'hup': 129, 'cleanup-error': 1}.get(case, 0)
    assert result == expected, result
    assert events == (['install', 'up', 'down'] if case in ('term', 'hup')
                      else ['install', 'up', 'checks', 'down']), events
    print('ADMITTED_CLEANUP_AND_HANDLERS_RESTORED', result, flush=True)
"""


def isolated_fixture(tmp_path):
    isolation = tmp_path / "isolation"
    isolation.mkdir()
    (isolation / "sitecustomize.py").write_text(DENY_SOCKETS)
    runner = tmp_path / "runner.py"
    runner.write_text(RUNNER)
    home = tmp_path / "home"
    home.mkdir()
    temporary = tmp_path / "tmp"
    temporary.mkdir()
    uv = shutil.which("uv")
    assert uv is not None
    env = {
        "PATH": f"{Path(uv).parent}:/usr/bin:/bin",
        "HOME": str(home),
        "TMPDIR": str(temporary),
        "PYTHONPATH": os.pathsep.join((str(isolation), str(ROOT / "src"))),
        "UV_CACHE_DIR": str(tmp_path / "uv-cache"),
        "UV_OFFLINE": "1",
        "AMX_SUITE_LOCK": str(tmp_path / "lease"),
        "STATE": str(tmp_path / "state"),
    }
    makefile = tmp_path / "Makefile"
    makefile.write_text(f"probe:\n\t{uv} run --offline --no-sync python {runner}\n")
    return runner, makefile, env


@pytest.mark.parametrize("case", ["unleased", "spoof"])
def test_direct_unleased_and_environment_spoof_refuse_before_side_effects(tmp_path, case):
    runner, _, env = isolated_fixture(tmp_path)
    result = subprocess.run(
        [sys.executable, str(runner)],
        cwd=ROOT,
        env={**env, "CASE": case, "AMX_SUITE_MTA": "stalwart"},
        capture_output=True,
        text=True,
        timeout=15,
        start_new_session=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "REFUSED_BEFORE_SIDE_EFFECTS" in result.stdout


@pytest.mark.parametrize(
    "case",
    ["valid", "term", "hup", "cleanup-error", "replaced-lock", "foreign-lock", "forged-active"],
)
def test_actual_supervisor_make_uv_python_custody_and_direct_signals(tmp_path, case):
    _, makefile, env = isolated_fixture(tmp_path)
    result = subprocess.run(
        [
            sys.executable,
            "tools/stack_suite.py",
            "lock",
            "--",
            "make",
            "-f",
            str(makefile),
            "probe",
        ],
        cwd=ROOT,
        env={**env, "CASE": case},
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    if case in ("replaced-lock", "foreign-lock", "forged-active"):
        assert "REFUSED_BEFORE_SIDE_EFFECTS" in result.stdout
        assert not (tmp_path / "events.json").exists()
    else:
        assert "ADMITTED_CLEANUP_AND_HANDLERS_RESTORED" in result.stdout
        assert json.loads((tmp_path / "events.json").read_text())[-1] == "down"
    assert not Path(env["AMX_SUITE_LOCK"] + ".active").exists()
