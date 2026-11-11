"""Real X0 process groups/kernel locks; no Docker daemon or gateway sends."""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest
from test_stack_suite import FAKE

pytest_plugins = ["test_stack_suite"]

ROOT = Path(__file__).resolve().parents[2]
RUNNER = r"""
import importlib.util, json, os, socket
from pathlib import Path
spec = importlib.util.spec_from_file_location('fixture', 'tools/stalwart_probe_fixture.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
case = os.environ.get('CUSTODY_CASE', 'valid')
lock = Path(os.environ['AMX_SUITE_LOCK'])
journal = Path(str(lock) + '.json')
if case in ('foreign-root', 'foreign-engine', 'foreign-token', 'stale-journal'):
    record = json.loads(journal.read_text())
    if case == 'foreign-root': record['root'] = str(Path.cwd().parent)
    if case == 'foreign-engine': record['engine'] = 'foreign'
    if case == 'foreign-token': record['owner'] = 'a' * 32
    if case == 'stale-journal': record['worktree']['inode'] += 1
    journal.write_text(json.dumps(record))
if case == 'forged-active':
    Path(str(lock) + '.active').write_text(json.dumps({'pgid': os.getpid()}))
if case == 'replaced-lock':
    lock.rename(str(lock) + '.old')
    lock.touch()
if case == 'foreign-lock':
    import fcntl
    lock.rename(str(lock) + '.old')
    replacement = lock.open('a+')
    fcntl.flock(replacement, fcntl.LOCK_EX)
if case == 'missing-journal': journal.unlink()
if case == 'malformed-journal': journal.write_text('{}')
def forbidden(*args, **kwargs):
    Path(os.environ['NETWORK_SENTINEL']).touch()
    raise AssertionError('gateway network access')
socket.socket.connect = forbidden
class Agent:
    def __init__(self, *args, **kwargs):
        Path(os.environ['ADMITTED_SENTINEL']).touch()
        raise RuntimeError('ADMITTED_AFTER_REAL_CUSTODY_CHECK')
fixture.Agent = Agent
fixture.main()
"""


def install_fixture(stack):
    tree = stack.trees[0]
    shutil.copyfile(
        ROOT / "tools/stalwart_probe_fixture.py", tree / "tools/stalwart_probe_fixture.py"
    )
    (tree / "runner.py").write_text(RUNNER)
    # The Docker fixture supplies explicit read-only engine/resource observations.
    # All process, ancestry, Git, inode and FLOCK evidence is from the real kernel.
    fake = FAKE.replace('"mailhost": {}, "runner-ct": {}', '"gateway-ct": {}, "mailhost-ct": {}')
    fake = fake.replace(
        'elif "inspect" in args:',
        """elif "inspect" in args and "--format" not in args:
    result = []
    for key in args[2:]:
        labels = dict(resources[key]["labels"])
        service = key.removeprefix("container-")
        labels["com.docker.compose.project"] = "amx"
        labels["com.docker.compose.service"] = service
        port, host_port = ("2587", "2588") if service == "gateway-ct" else ("143", "1432")
        ports = {port + "/tcp": [{"HostIp": "127.0.0.1", "HostPort": host_port}]}
        result.append({"Config": {"Labels": labels}, "State": {"Running": True},
                       "NetworkSettings": {"Ports": ports}})
    print(json.dumps(result))
elif "inspect" in args:""",
    )
    for name in ("docker", "uv"):
        executable = stack.tmp / "bin" / name
        executable.write_text(fake.replace("#!/usr/bin/env python3", f"#!{sys.executable}"))
    # Use the unchanged Make -> uv -> Python chain, but stop before a real send.
    uv = stack.tmp / "bin/uv"
    uv.write_text(
        uv.read_text().replace(
            "os.execv(sys.executable, [sys.executable, *args[2:]])",
            "os.execv(sys.executable, [sys.executable, 'runner.py'] "
            "if args[2:] == ['tools/stalwart_probe_fixture.py'] "
            "else [sys.executable, *args[2:]])",
        )
    )
    stack.env.update(
        PYTHONPATH=str(ROOT / "src"),
        NETWORK_SENTINEL=str(stack.tmp / "network"),
        ADMITTED_SENTINEL=str(stack.tmp / "admitted"),
    )
    return tree


@pytest.mark.parametrize(
    "case",
    [
        "valid",
        "foreign-root",
        "foreign-engine",
        "foreign-token",
        "stale-journal",
        "forged-active",
        "replaced-lock",
        "foreign-lock",
        "missing-journal",
        "malformed-journal",
    ],
)
def test_fixture_admission_uses_real_native_suite_custody(stack, case):
    tree = install_fixture(stack)
    process = stack.start(mta="stalwart", SH00_PROBE="1", CUSTODY_CASE=case)
    output = stack.finish(process, success=False)
    assert not (stack.tmp / "network").exists(), output
    assert (stack.tmp / "admitted").exists() == (case == "valid"), output
    if case == "valid":
        assert "ADMITTED_AFTER_REAL_CUSTODY_CHECK" in output
        stack.clean()
    else:
        assert "SH-00 fixture requires make suite Stalwart custody" in output
    assert not (tree / "deploy/generated/state/sh00").exists()


@pytest.mark.parametrize("held", [False, True])
def test_direct_import_with_spoofed_environment_and_journal_refuses_before_network(stack, held):
    import fcntl

    tree = install_fixture(stack)
    lock = Path(stack.env["AMX_SUITE_LOCK"])
    with lock.open("a+") as stream:
        if held:
            fcntl.flock(stream, fcntl.LOCK_EX)
        Path(str(lock) + ".active").write_text(json.dumps({"pgid": os.getpgrp()}))
        Path(str(lock) + ".json").write_text(json.dumps({"root": str(tree), "mta": "stalwart"}))
        process = stack.start(
            command=[sys.executable, "runner.py"],
            AMX_SUITE_MTA="stalwart",
            AMX_SUITE_OVERRIDE=str(lock) + ".compose.json",
        )
        output = stack.finish(process, success=False)
        assert "SH-00 fixture requires make suite Stalwart custody" in output
        if held:
            # The guard must never unlock even an unrelated owner's lease.
            with lock.open("a+") as other, pytest.raises(BlockingIOError):
                fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
    assert not (stack.tmp / "network").exists()
    assert not (stack.tmp / "admitted").exists()


def test_direct_entrypoint_spoof_refuses_before_actual_socket_or_fixture_mutation(tmp_path):
    # An actual listening socket, not a mocked admission predicate.
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(0.1)
        code = f"""import runpy, socket
from amx.sdk import Agent
Agent.send = lambda *a, **k: socket.create_connection({listener.getsockname()!r})
runpy.run_path({str(ROOT / "tools/stalwart_probe_fixture.py")!r}, run_name='__main__')
"""
        result = subprocess.run(
            [sys.executable, "-c", code],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=10,
            env={
                "PATH": "/usr/bin:/bin",
                "PYTHONPATH": str(ROOT / "src"),
                "AMX_SUITE_OVERRIDE": "/forged.compose.json",
                "AMX_SUITE_MTA": "stalwart",
                "MTA_CT": "stalwart",
                "AMX_SUITE_LOCK": str(tmp_path / "unheld.lock"),
            },
        )
        assert result.returncode != 0
        assert "SH-00 fixture requires make suite Stalwart custody" in result.stderr
        with pytest.raises(TimeoutError):
            listener.accept()
        assert not (tmp_path / "unheld.lock").exists()
