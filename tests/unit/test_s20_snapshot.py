"""The scenario evidence reader must observe the live SQLite transaction boundary."""

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.fixture
def reader(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2]))
    from scenarios import test_s20_ax as scenario

    harness = scenario.Harness()
    harness.directory = str(tmp_path)
    calls = []
    real_run = subprocess.run
    running = [False]

    def run(argv, **kwargs):
        assert kwargs["timeout"] > 0
        assert argv[:3] == ["docker", "inspect", "--format"]
        calls.append("inspect")
        return subprocess.CompletedProcess(argv, 0, "true\n" if running[0] else "false\n", "")

    def execute(*args):
        calls.append("exec")
        assert args[:2] == (scenario.PYTHON, "-c")
        return real_run(
            [sys.executable, *args[1:]], capture_output=True, text=True, check=True, timeout=10
        )

    def compose(*args, timeout=None):
        calls.append("compose")
        assert timeout is not None and 0 < timeout <= 30
        assert args[:6] == (
            "run",
            "--rm",
            "--no-deps",
            "--entrypoint",
            scenario.PYTHON,
            "runner-ct",
        )
        assert args[6] == "-c"
        return real_run(
            [sys.executable, *args[6:]], capture_output=True, text=True, check=True, timeout=10
        )

    def no_copy(*args):
        raise AssertionError("live SQLite files must not be copied independently")

    monkeypatch.setattr(scenario.subprocess, "run", run)
    monkeypatch.setattr(scenario, "compose", compose)
    monkeypatch.setattr(harness, "exec", execute)
    monkeypatch.setattr(harness, "refresh", no_copy)
    return harness, calls, running


@pytest.mark.parametrize("live", [False, True])
def test_s20_records_reads_committed_wal_in_shared_volume(tmp_path, reader, live):
    harness, calls, running = reader
    running[0] = live
    path = tmp_path / "runner.sqlite"
    target = {"key": ["<target@example.test>"], "state": "terminal"}
    other = {"key": ["<other@example.test>"], "state": "queued"}
    with sqlite3.connect(path) as writer:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("CREATE TABLE ax_deliveries (data TEXT)")
        writer.commit()
        writer.executemany(
            "INSERT INTO ax_deliveries VALUES (?)", [(json.dumps(target),), (json.dumps(other),)]
        )
        writer.commit()
        writer.execute(
            "INSERT INTO ax_deliveries VALUES (?)", (json.dumps(target | {"state": "uncommitted"}),)
        )
        assert harness.records("<target@example.test>") == [target]
        assert harness.records("<absent@example.test>") == []
        assert writer.in_transaction
        writer.rollback()
    assert calls == ["inspect", "exec" if live else "compose"] * 2


@pytest.mark.parametrize("corrupt", [False, True])
@pytest.mark.parametrize("live", [False, True])
def test_s20_records_never_creates_or_masks_bad_evidence(tmp_path, reader, corrupt, live):
    harness, _, running = reader
    running[0] = live
    path = tmp_path / "runner.sqlite"
    if corrupt:
        path.write_bytes(b"not a SQLite database")
    with pytest.raises(subprocess.CalledProcessError):
        harness.records("<target@example.test>")
    if corrupt:
        assert path.read_bytes() == b"not a SQLite database"
    else:
        assert not path.exists()


def test_s20_records_refuses_inspect_timeout(reader, monkeypatch):
    from scenarios import test_s20_ax as scenario

    harness, calls, _ = reader

    def stalled(argv, **kwargs):
        assert 0 < kwargs["timeout"] <= 5
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    monkeypatch.setattr(scenario.subprocess, "run", stalled)
    with pytest.raises(subprocess.TimeoutExpired):
        harness.records("<target@example.test>")
    assert calls == []


def test_compose_forwards_reader_timeout(monkeypatch):
    from scenarios import support

    def stalled(argv, **kwargs):
        assert kwargs["timeout"] == 17
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    monkeypatch.setattr(support.subprocess, "run", stalled)
    with pytest.raises(subprocess.TimeoutExpired):
        support.compose("run", "--rm", "runner-ct", timeout=17)


def test_s20_records_live_read_error_is_not_retried_in_new_container(reader, monkeypatch):
    harness, calls, running = reader
    running[0] = True

    def failed(*args):
        raise subprocess.CalledProcessError(1, args)

    monkeypatch.setattr(harness, "exec", failed)
    with pytest.raises(subprocess.CalledProcessError):
        harness.records("<target@example.test>")
    assert calls == ["inspect"]


def test_s20_records_propagates_reader_timeout(reader, monkeypatch):
    from scenarios import test_s20_ax as scenario

    harness, calls, _ = reader

    def stalled(*args, timeout=None):
        assert timeout is not None and 0 < timeout <= 30
        raise subprocess.TimeoutExpired(args, timeout)

    monkeypatch.setattr(scenario, "compose", stalled)
    with pytest.raises(subprocess.TimeoutExpired):
        harness.records("<target@example.test>")
    assert calls == ["inspect"]
