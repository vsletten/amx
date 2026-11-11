"""Exercise the real validator's success/failure/termination finally without Docker."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DRIVER = """\
import os, sys, time
from pathlib import Path
state, action = Path(sys.argv[1]), sys.argv[2]
with (state / 'events').open('a') as out: out.write(action + '\\n')
if action == 'runner':
    while True: time.sleep(.01)
if action in ('seed', 'up'): (state / 'resources').touch()
if os.environ.get('HOLD_STAGE') == action:
    (state / (action + '.ready')).touch()
    while not (state / 'release').exists(): time.sleep(.01)
if action == 'down':
    (state / 'down.ready').touch()
    time.sleep(float(os.environ.get('CLEANUP_DELAY', '0')))
    (state / 'resources').unlink(missing_ok=True)
if os.environ.get('FAIL_STAGE') == action: raise RuntimeError('fixture failure')
"""
HARNESS = """\
import importlib.util, os, subprocess, sys
from pathlib import Path
from types import SimpleNamespace
spec = importlib.util.spec_from_file_location('live_test', sys.argv.pop(1))
live = importlib.util.module_from_spec(spec)
spec.loader.exec_module(live)
state = Path(os.environ['FIXTURE_STATE'])
driver = os.environ['FIXTURE_DRIVER']
def operation(action):
    subprocess.run([sys.executable, driver, str(state), action], check=True)
def amx_live(state, *args, env=None, timeout=None):
    if args[0] == 'down': assert timeout == 60
    operation(args[0])
    if args[0] == 'backup':
        backup = state / 'backup'
        backup.mkdir()
        (backup / 'journal-verify.txt').write_text('OK fixture')
        (backup / 'mail.tar.gz').touch()
        return str(backup)
    return 'migrated intake'
live.amx_live = amx_live
live.write_params = lambda *_: None
live.seed_earlier_install = lambda *_: {}
live.load_params = lambda *_: SimpleNamespace()
live.write_validation_files = lambda *_: {}
live.seed_earlier_mailbox = lambda *_: operation('seed')
live.Lane = lambda *_: SimpleNamespace()
live.check_migration = lambda *_: None
live.run_checks = lambda *_: operation('checks')
def registration(*_):
    runner = subprocess.Popen([sys.executable, driver, str(state), 'runner'])
    (state / 'runner.pid').write_text(str(runner.pid))
    return runner
live.check_registration = registration
live.check_preflight = lambda *_: None
def rotation(*args):
    operation('rotation')
    return args[-1]
live.check_rotation = rotation
live.check_removal = lambda *_: None
live.check_mailhost_restart = lambda *_: None
live.check_domain_dkim = lambda *_: None
live.check_queue_survives = lambda *_: None
sys.exit(live.main())
"""


def wait_for(probe, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if probe():
            return
        time.sleep(0.01)
    raise AssertionError("timed out waiting for validator fixture")


@pytest.fixture
def validator(tmp_path):
    driver, harness = tmp_path / "driver.py", tmp_path / "harness.py"
    driver.write_text(DRIVER)
    harness.write_text(HARNESS)
    # The only Docker call is the pre-start read-only inventory. Never pass it
    # to a real executable, socket, context or inherited provider environment.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_text("#!/bin/sh\nexit 0\n")
    docker.chmod(0o755)
    state = tmp_path / "state"
    state.mkdir()
    lock = tmp_path / "validation.lock"
    env = {
        "PATH": f"{bin_dir}:/usr/bin:/bin",
        "HOME": str(tmp_path),
        "TMPDIR": str(tmp_path),
        "FIXTURE_STATE": str(state),
        "FIXTURE_DRIVER": str(driver),
        "AMX_SUITE_LOCK": str(lock),
    }
    processes = []

    class Validator:
        def start(self, *, supervised=False, keep=False, **extra):
            command = [sys.executable, str(harness), str(ROOT / "tools/live_validate.py")]
            command += ["--state", str(state)]
            if keep:
                command.append("--keep")
            if supervised:
                command = [
                    sys.executable,
                    str(ROOT / "tools/stack_suite.py"),
                    "lock",
                    "--",
                    *command,
                ]
            log = tmp_path / f"log-{len(processes)}"
            with log.open("w") as stream:
                process = subprocess.Popen(
                    command,
                    env={**env, **extra},
                    cwd=tmp_path,
                    stdout=stream,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
            process.log = log
            processes.append(process)
            return process

        def finish(self, process, code=0):
            assert process.wait(timeout=20) == code, process.log.read_text()
            pid_file = state / "runner.pid"
            if pid_file.exists():
                stat = Path("/proc") / pid_file.read_text() / "stat"
                assert not stat.exists() or stat.read_text().rpartition(")")[2].split()[0] in (
                    "Z",
                    "X",
                ), "validator orphaned its fixture runner"

        def events(self):
            return (state / "events").read_text().splitlines()

    fixture = Validator()
    fixture.state, fixture.lock = state, lock
    yield fixture
    (state / "release").touch()
    for process in processes:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


@pytest.mark.parametrize("fail_stage", [None, "up", "checks", "rotation"])
def test_validator_preserves_success_and_failure_cleanup(validator, fail_stage):
    process = validator.start(**({"FAIL_STAGE": fail_stage} if fail_stage else {}))
    validator.finish(process, code=1 if fail_stage else 0)
    assert validator.events()[-1] == "down"
    assert not (validator.state / "resources").exists()
    results = json.loads((validator.state / "validation.json").read_text())
    assert any(not item["passed"] for item in results) == bool(fail_stage)


def test_validator_keep_preserves_explicit_opt_out(validator):
    validator.finish(validator.start(keep=True))
    assert "down" not in validator.events()
    assert (validator.state / "resources").exists()


@pytest.mark.parametrize("stage", ["seed", "up", "checks", "rotation"])
def test_actual_validator_sigterm_runs_cleanup(validator, stage):
    process = validator.start(HOLD_STAGE=stage)
    wait_for(lambda: (validator.state / f"{stage}.ready").exists())
    process.send_signal(signal.SIGTERM)
    validator.finish(process, code=128 + signal.SIGTERM)
    assert validator.events()[-1] == "down"
    assert not (validator.state / "resources").exists()


def test_supervisor_sigterm_allows_validator_cleanup_beyond_old_grace(validator):
    process = validator.start(supervised=True, HOLD_STAGE="checks", CLEANUP_DELAY="11")
    wait_for(lambda: (validator.state / "checks.ready").exists())
    process.send_signal(signal.SIGTERM)
    wait_for(lambda: (validator.state / "down.ready").exists())
    process.send_signal(signal.SIGHUP)  # repeated cancellation must not skip cleanup
    validator.finish(process, code=128 + signal.SIGTERM)
    assert validator.events()[-1] == "down"
    assert not (validator.state / "resources").exists()
    assert not validator.lock.with_name(validator.lock.name + ".active").exists()


def test_runner_shutdown_has_bounded_kill_fallback():
    import runpy
    from unittest.mock import Mock, call

    namespace = runpy.run_path(str(ROOT / "tools/live_validate.py"))
    runner = Mock()
    runner.wait.side_effect = [subprocess.TimeoutExpired("fixture", 30), 0]
    namespace["stop_runner"](runner)
    runner.send_signal.assert_called_once_with(signal.SIGTERM)
    runner.kill.assert_called_once_with()
    assert runner.wait.call_args_list == [call(timeout=30), call(timeout=5)]
