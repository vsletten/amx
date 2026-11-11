"""SH-26 tooling tests, not native mail acceptance; run under network confinement."""

import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import selfhost_validate as validator  # noqa: E402


def test_helpers_refuse_without_native_custody(tmp_path, monkeypatch):
    monkeypatch.setenv("AMX_SUITE_LOCK", str(tmp_path / "absent"))
    for invoke in (
        lambda: validator.prepare(tmp_path),
        lambda: validator.command(tmp_path, "up"),
        lambda: validator.checks(tmp_path, lambda _: None),
        lambda: validator.register(tmp_path, "mcp"),
        lambda: validator.host_mcp(tmp_path, "list_inbox", {}),
        lambda: validator.approve(tmp_path, "user", "secret", "Held", b"1", expected="OK"),
        lambda: validator.mailbox(tmp_path, "user", "secret"),
        lambda: validator.host_ready(tmp_path, "mcp"),
        lambda: validator.host_topology(tmp_path),
        lambda: validator.no_dns(tmp_path, "gateway"),
        lambda: validator.validate(tmp_path),
    ):
        with pytest.raises(RuntimeError, match="requires native X0 lock custody"):
            invoke()
    assert not list(tmp_path.iterdir())


def test_two_separate_sealed_agent_hosts():
    overlay = yaml.safe_load((ROOT / "deploy/live/validate/compose.selfhost.yaml").read_text())
    services = overlay["services"]
    assert set(services) == {"host-ax", "host-mcp"}
    for name, service in services.items():
        assert service["profiles"] == ["agent-hosts"]
        assert service["networks"] == {"live": {}}
        assert service["dns"] == ["127.0.0.1"]
        assert "ports" not in service
        assert service["build"]["dockerfile"] == "deploy/ax/Dockerfile"
        assert service["command"] == ["serve", name.removeprefix("host-")]
        assert any(f"/hosts/{name.removeprefix('host-')}:" in v for v in service["volumes"])
        assert not any("docker.sock" in v or "registry" in v for v in service["volumes"])


def test_teardown_explicitly_includes_profiled_hosts(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(validator.fixture, "require_fixture_state", lambda state: None)
    monkeypatch.setattr(validator.fixture, "cli", lambda *a, **kw: calls.append((a, kw)))
    validator.command(tmp_path, "down", timeout=60)
    assert calls == [((tmp_path, "compose", "--profile", "agent-hosts", "down"), {"timeout": 60})]


RUNNER = r"""
import json, os, signal, sys
from pathlib import Path
sys.path.insert(0, str(Path.cwd() / 'tools'))
import selfhost_validate as v
state = Path(os.environ['STATE'])
case = os.environ['CASE']
events = []
def event(name):
    events.append(name)
    (state.parent / 'events.json').write_text(json.dumps(events))
def forbidden(*a, **k):
    raise AssertionError('unadmitted side effect')
if case in ('unleased', 'spoof', 'replaced-lock'):
    lock = Path(os.environ['AMX_SUITE_LOCK'])
    if case == 'spoof':
        lock.touch()
        Path(str(lock)+'.active').write_text(json.dumps({'pgid': os.getpgrp()}))
    if case == 'replaced-lock':
        lock.rename(str(lock)+'.old')
        lock.touch()
    v.fixture.inventory = forbidden
    v.fixture.tempfile.mkdtemp = forbidden
    try: v.validate(state)
    except RuntimeError as e: assert 'requires native X0 lock custody' in str(e)
    else: raise AssertionError('unadmitted entry accepted')
    assert not state.exists()
else:
    handlers = {s: signal.getsignal(s) for s in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP)}
    v.fixture.inventory = lambda: ['foreign'] if case == 'foreign' else []
    v.fixture.stage_webui = lambda s: event('stage')
    def command(state, action, *a, **k):
        v.fixture.require_fixture_state(state)
        event(action)
        if action == 'up' and case in ('term','int','hup'):
            sig = {'term':signal.SIGTERM,'int':signal.SIGINT,'hup':signal.SIGHUP}[case]
            os.kill(os.getpid(), sig)
        if action == 'up' and case == 'failed-up': raise RuntimeError('PRIVATE_SECRET_MAIL')
        if action == 'down':
            os.kill(os.getpid(), signal.SIGTERM)  # repeated cleanup signal must be ignored
            if case == 'cleanup-error': raise RuntimeError('cleanup failed')
        return ''
    v.command = command
    failure_stages = {
        'stage-delivery': v.Stage.DELIVERY,
        'stage-ax-receipt': v.Stage.AX_RECEIPT,
        'stage-reply': v.Stage.REPLY,
    }
    def checks(s, record, *, stage):
        if case in failure_stages:
            stage(failure_stages[case])
            raise TimeoutError('PRIVATE_SECRET_MAIL')
        if case == 'invalid-stage':
            stage('PRIVATE_SECRET_MAIL')
            raise AssertionError('invalid stage accepted')
        record('integrated proof')
    v.checks = checks
    try:
        result = v.validate(state)
    except v.fixture.Terminated as e:
        result = 128 + e.signum
    except RuntimeError as e:
        assert case == 'cleanup-error' and str(e) == 'cleanup failed'
        result = 1
    assert {s:signal.getsignal(s) for s in handlers} == handlers
    assert v.fixture._active_fixture is None
    expected = {'foreign':2,'term':143,'int':130,'hup':129,
                'failed-up':1,'cleanup-error':1}.get(case,0)
    if case in failure_stages or case == 'invalid-stage': expected = 1
    assert result == expected, (case, result)
    if case == 'foreign':
        assert not events and not state.exists()
    else:
        assert events == ['stage','install','up','down'], events
        report = (state/'validation.json').read_text()
        assert 'PRIVATE_SECRET_MAIL' not in report
        failures = [row for row in json.loads(report) if not row['passed']]
        if case in failure_stages:
            assert failures == [{'passed':False, 'check':'native validation step',
                'stage':failure_stages[case].value, 'type':'TimeoutError'}]
        if case == 'invalid-stage':
            assert failures == [{'passed':False, 'check':'native validation step',
                'stage':v.Stage.UP.value, 'type':'ValueError'}]
print('TOOLING_CUSTODY_OK')
"""


@pytest.mark.parametrize(
    "case",
    [
        "unleased",
        "spoof",
        "replaced-lock",
        "foreign",
        "valid",
        "term",
        "int",
        "hup",
        "failed-up",
        "cleanup-error",
        "stage-delivery",
        "stage-ax-receipt",
        "stage-reply",
        "invalid-stage",
    ],
)
@pytest.mark.parametrize("inherit_tmpdir", [True, False], ids=["inherited-tmpdir", "no-tmpdir"])
def test_real_lease_lifecycle_with_synthetic_engine(tmp_path, case, inherit_tmpdir, monkeypatch):
    if inherit_tmpdir:
        monkeypatch.setenv("TMPDIR", str(tmp_path.parent))
    else:
        monkeypatch.delenv("TMPDIR", raising=False)
    home = tmp_path / "home"
    home.mkdir()
    runner = tmp_path / "runner.py"
    runner.write_text(RUNNER)
    isolation = tmp_path / "isolation"
    isolation.mkdir()
    (isolation / "sitecustomize.py").write_text(
        "import socket\n"
        "def denied(*a,**k): raise AssertionError('sockets denied before import')\n"
        "socket.socket.connect=denied\n"
    )
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(home),
        "TMPDIR": os.environ.get("TMPDIR", str(tmp_path)),
        "PYTHONPATH": str(isolation) + os.pathsep + str(ROOT / "src"),
        "AMX_SUITE_LOCK": str(tmp_path / "lease"),
        "STATE": str(tmp_path / "state"),
        "CASE": case,
        "OMP_NUM_THREADS": "8",
        "OPENBLAS_NUM_THREADS": "8",
    }
    args = [sys.executable, str(runner)]
    if case not in {"unleased", "spoof"}:
        args = [sys.executable, "tools/stack_suite.py", "lock", "--", *args]
    result = subprocess.run(
        args, cwd=ROOT, env=env, capture_output=True, text=True, timeout=30, start_new_session=True
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "TOOLING_CUSTODY_OK" in result.stdout
    assert "PRIVATE_SECRET_MAIL" not in result.stdout + result.stderr
    if case.startswith("stage-"):
        assert "FAIL  native validation step: sibling-" in result.stdout
    if case == "invalid-stage":
        assert "FAIL  native validation step: fixture-up" in result.stdout
    if case not in {"unleased", "spoof"}:
        assert not Path(env["AMX_SUITE_LOCK"] + ".active").exists()


def test_agent_host_client_refuses_outside_container():
    import selfhost_agent_host as host

    with pytest.raises(RuntimeError, match="requires admitted SH-26"):
        host.require_host()


def test_ax_session_receipt_uses_real_adapter_shape_without_logging_mail(tmp_path, monkeypatch):
    import json

    import selfhost_agent_host as host

    calls = []
    monkeypatch.setattr(host, "STATE", tmp_path)
    monkeypatch.setattr(host, "require_host", lambda: {})
    monkeypatch.setattr(host.signal, "signal", lambda *a: None)
    monkeypatch.setattr(host.subprocess, "run", lambda args, **kw: calls.append(args))

    class Event:
        count = 0

        def wait(self, _):
            self.count += 1
            return self.count > 1

    class Child:
        def __init__(self, *args):
            calls.append(args)

        def _start(self, args):
            calls.append(args)

        def close(self):
            calls.append("closed")

    class Endpoint:
        def __init__(self, child):
            pass

        def _call(self, method, **kwargs):
            calls.append((method, kwargs))
            if method == "check_inbox":
                return {
                    "message": {
                        "message_id": "ax-id",
                        "text": "PRIVATE_MAIL",
                        "data": {"message_id": "<mail-id@home.arpa>"},
                    }
                }

    monkeypatch.setattr(host.threading, "Event", Event)
    monkeypatch.setattr(host, "AxChild", Child)
    monkeypatch.setattr(host, "AxEndpoint", Endpoint)
    host.target()
    raw = (tmp_path / "received.jsonl").read_text()
    assert json.loads(raw) == {"message_id": "<mail-id@home.arpa>"}
    assert "PRIVATE_MAIL" not in raw
    assert any(isinstance(c, tuple) and c[0] == "reply" for c in calls)
    assert calls[-1] == "closed"
    assert not (tmp_path / "target-ready").exists()


def test_make_and_ci_use_one_integrated_lease():
    make = (ROOT / "Makefile").read_text().split("selfhost-validate:\n", 1)[1]
    assert make.count("tools/stack_suite.py lock --") == 1
    assert "--group gateway python tools/selfhost_validate.py" in make
    ci = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    assert ci[True] == {
        "pull_request": None,
        "push": {"branches": ["main"]},
        "workflow_dispatch": None,
    }
    selector = "${{ fromJSON(vars.AMX_CI_RUNS_ON || '\"ubuntu-24.04\"') }}"
    assert ci["jobs"]["selfhost"]["runs-on"] == selector
    assert all(job["runs-on"] == selector for job in ci["jobs"].values())
    assert "scenarios" in ci["jobs"] and "scenarios-stalwart" in ci["jobs"]
    assert any(
        "make selfhost-validate" in step.get("run", "") for step in ci["jobs"]["selfhost"]["steps"]
    )
