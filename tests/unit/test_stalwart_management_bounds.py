"""Real management-child timeouts, with sockets denied before every import."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DENY_SOCKETS = """
import socket
class DeniedSocket(socket.socket):
    def __init__(self, *args, **kwargs):
        raise AssertionError('fixture sockets denied')
socket.socket = DeniedSocket
"""
RUNNER = r"""
import argparse
import contextlib
import dataclasses
import json
import socket
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from amx.adapters import stalwart

try:
    socket.socket()
except AssertionError:
    pass
else:
    raise AssertionError('socket denial missing before product import')

root, mode = Path(sys.argv[1]), sys.argv[2]
site = stalwart.Site('fixture.test', 'agents.fixture.test', 'mail.fixture.test',
                     'gateway', '172.30.0.21')
bundle = root / 'bundle.json'
bundle.write_text(json.dumps({'site': dataclasses.asdict(site), 'users': [],
                              'masters': {'gateway': 'fixture'}, 'plan': []}))
accounts = root / 'accounts'
state = 'purge' if mode == 'delete' else 'disabled'
accounts.write_text('probe@agents.fixture.test:{SHA512-CRYPT}$6$salt$' + 'a' * 86
                    + ':' + state + ':0123456789abcdef\n')
arguments = argparse.Namespace(bundle=str(bundle), accounts=str(accounts), cli='fixture-cli',
    url='http://fixture.invalid', imap_host='fixture.invalid', imap_port=143,
    state_dir=str(root), stalwart='fixture-server', config='fixture-config',
    watch=mode not in ('provision-settings', 'provision-accounts', 'once'))
if mode.startswith('people-'):
    accounts.write_text('')
    people = root / 'people.json'
    people.write_text(json.dumps({'alice@fixture.test': {
        'secret': '$6$salt$' + 'a' * 86, 'ownership': 'a' * 32,
        'generation': 'current', 'generations': ['current'], 'owner': False, 'enabled': False,
    }}))
    arguments.people = str(people)
stalwart.CLI_TIMEOUT = 0.2
stopped = []
class Server:
    def __init__(self, *_): pass
    def __enter__(self): return self
    def __exit__(self, *_): stopped.append(True)
    def running(self): return True
stalwart.PrivateServer = Server
stalwart.wait_for = lambda *_: None
stalwart.ensure_mailboxes = lambda *_, **kwargs: {}
@contextlib.contextmanager
def session(*_): yield object()
stalwart._session = session
stalwart._delete_hold_queue = lambda *_: []
real_run = subprocess.run
attempts = []
timeouts = []
query = json.dumps({'id': 'p', 'emailAddress': 'probe@agents.fixture.test',
                    'description': stalwart.generation_note('0123456789abcdef')})
def run(argv, **kwargs):
    assert kwargs['timeout'] == 0.2
    assert kwargs['check'] is True
    verb = argv[2]
    target = verb
    if '--file' in argv:
        target = 'settings' if 'amx-settings.ndjson' in argv[-1] else 'accounts'
    selected = mode.removeprefix('provision-') if mode.startswith('provision-') else mode
    if mode.startswith('people-'): selected = mode.removeprefix('people-')
    if mode == 'once': selected = 'query'
    if target == selected:
        attempts.append(target)
        if len(attempts) == 1:
            try:
                # Actual child blocks, and subprocess.run must kill/reap it at the product bound.
                return real_run([sys.executable, str(root / 'hang.py')],
                                check=True, env=kwargs['env'], timeout=kwargs['timeout'])
            except subprocess.TimeoutExpired:
                timeouts.append(target)
                raise
    return subprocess.CompletedProcess(argv, 0, stdout=query if verb == 'query' else '')
stalwart.subprocess.run = run
class StopWatch(BaseException): pass
ticks = []
def tick(seconds):
    assert seconds == 1
    ticks.append(True)
    if len(ticks) == 3: raise StopWatch
stalwart.time = SimpleNamespace(sleep=tick)
if mode.startswith('provision-'):
    try: stalwart.provision(arguments)
    except subprocess.TimeoutExpired: pass
    else: raise AssertionError('provision timeout masked')
    assert stopped == [True] * (2 if mode == 'provision-accounts' else 1)
    assert not (root / 'amx-provisioned.sha256').exists()
elif mode == 'once':
    try: stalwart.sync(arguments)
    except subprocess.TimeoutExpired: pass
    else: raise AssertionError('one-shot timeout masked')
else:
    try: stalwart.sync(arguments)
    except StopWatch: pass
    assert len(attempts) == 2, attempts
assert len(timeouts) == 1, timeouts
assert (root / 'child-started').read_text() == 'socket-denied'
print('BOUNDED_CHILD_TIMEOUT', mode)
"""


@pytest.mark.parametrize(
    "mode",
    [
        "provision-settings",
        "provision-accounts",
        "query",
        "delete",
        "apply",
        "once",
        "people-query",
        "people-apply",
    ],
)
def test_management_timeout_propagation_and_watch_retry(tmp_path, mode):
    isolation = tmp_path / "isolation"
    isolation.mkdir()
    (isolation / "sitecustomize.py").write_text(DENY_SOCKETS)
    runner = tmp_path / "runner.py"
    runner.write_text(RUNNER)
    (tmp_path / "hang.py").write_text(
        "import socket, time\nfrom pathlib import Path\n"
        "try: socket.socket()\nexcept AssertionError: pass\n"
        "else: raise AssertionError('child socket denial missing')\n"
        "Path(__file__).with_name('child-started').write_text('socket-denied')\n"
        "time.sleep(30)\n"
    )
    home, temporary = tmp_path / "home", tmp_path / "tmp"
    home.mkdir()
    temporary.mkdir()
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(home),
        "TMPDIR": str(temporary),
        "PYTHONPATH": os.pathsep.join((str(isolation), str(ROOT / "src"))),
        "STALWART_RECOVERY_ADMIN": "admin:fixture-only",
    }
    result = subprocess.run(
        [sys.executable, str(runner), str(tmp_path), mode],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "BOUNDED_CHILD_TIMEOUT " + mode in result.stdout
    if mode in ("query", "delete", "apply", "people-query", "people-apply"):
        assert result.stderr.strip() == (
            "amx: accounts sync failed stage=apply type=TimeoutExpired status=n/a; retrying"
        )
        assert result.stdout.count("accounts applied (") == 1
