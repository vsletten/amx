"""pymilter runs each callback on a Python thread state of the OS thread that runs it.

Debian's libmilter is built with its worker pool: a connection's callbacks run on whichever pool
worker is free. pymilter 1.0.5 kept one thread state per connection, so it ran on other threads
and was deleted on the one that ran close; on Python 3.12+ that left a thread's PyGILState slot
pointing at freed memory, which the next connection there wrote to. gateway-ct aborted once with
glibc's "malloc_consolidate(): unaligned fastbin chunk detected" (PLAN §8). The vendored build
(third_party/pymilter/AMX.md) makes a thread state per callback on the calling thread.
"""

from __future__ import annotations

import json
import os
import socket
import struct
import subprocess
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

import pytest

pytest.importorskip("Milter")

# A filter that records, for every callback, the OS thread and whether the thread state running
# the callback is that OS thread's PyGILState thread state. An RCPT to raise@ raises.
PROBE = r"""
import ctypes, itertools, json, sys, threading
import Milter

api = ctypes.pythonapi
api.PyThreadState_Get.restype = ctypes.c_void_p
api.PyGILState_GetThisThreadState.restype = ctypes.c_void_p
out = open(sys.argv[2], "a", buffering=1)
lock = threading.Lock()
numbers = itertools.count()

def note(milter, stage):
    own = api.PyThreadState_Get() == api.PyGILState_GetThisThreadState()
    row = {"conn": milter.number, "stage": stage, "tid": threading.get_native_id(), "own": own}
    with lock:
        out.write(json.dumps(row) + "\n")

class Probe(Milter.Base):
    def __init__(self):
        self.number = next(numbers)

    def negotiate(self, opts):
        note(self, "negotiate")
        return super().negotiate(opts)

    def connect(self, hostname, family, hostaddr):
        note(self, "connect")
        return Milter.CONTINUE

    def envfrom(self, sender, *args):
        note(self, "mail")
        return Milter.CONTINUE

    def envrcpt(self, recipient, *args):
        note(self, "rcpt")
        if recipient.startswith("<raise@"):
            raise RuntimeError("the exception path")
        return Milter.CONTINUE

    def header(self, name, value):
        note(self, "header")
        return Milter.CONTINUE

    def eom(self):
        note(self, "eom")
        self.addheader("X-Probe", "1")
        return Milter.ACCEPT

    def close(self):
        note(self, "close")
        return Milter.CONTINUE

Milter.factory = Probe
Milter.set_flags(Milter.ADDHDRS)
Milter.runmilter("probe", "inet:" + sys.argv[1] + "@127.0.0.1", 30)
"""

# A filter that stops libmilter in its first header callback and waits there for milter.main()
# to return; the MTA has already sent four more headers, which workers still run afterwards.
STOPPING_PROBE = r"""
import sys, threading, time
import Milter, milter

out = open(sys.argv[2], "a", buffering=1)
returned = threading.Event()
headers = []

class Probe(Milter.Base):
    @Milter.noreply
    def header(self, name, value):
        headers.append(name)
        if len(headers) == 1:
            milter.stop()
            returned.wait(30)
        out.write(f"header {name}\n")
        return Milter.CONTINUE

Milter.factory = Probe
Milter.runmilter("probe", "inet:" + sys.argv[1] + "@127.0.0.1", 30)
returned.set()
out.write("main returned\n")
deadline = time.monotonic() + 20
while len(headers) < 5 and time.monotonic() < deadline:
    time.sleep(0.05)
time.sleep(0.5)  # the last header's callback finishes writing
"""

_NO_REPLY = {"C": 0x1000, "M": 0x4000, "R": 0x8000, "L": 0x80}  # SMFIP_NR_*
_NO_STAGE = {"C": 0x1, "M": 0x4, "R": 0x8, "L": 0x20}  # SMFIP_NO*
_CONNECT = b"client.test\0" + b"4" + struct.pack("!H", 40000) + b"192.0.2.9\0"


class _Mta:
    """The MTA side of the milter protocol (version 6), as much of it as the probes need."""

    def __init__(self, port: int) -> None:
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=10)
        self._send("O", struct.pack("!III", 6, 0x1FF, 0x1FFFFF))
        command, data = self._receive()
        assert command == "O"
        self.protocol = struct.unpack("!III", data[:12])[2]

    def _send(self, command: str, data: bytes = b"") -> None:
        self.sock.sendall(struct.pack("!I", len(data) + 1) + command.encode() + data)

    def _exactly(self, size: int) -> bytes:
        data = b""
        while len(data) < size:
            chunk = self.sock.recv(size - len(data))
            if not chunk:
                raise ConnectionError("the milter closed the connection")
            data += chunk
        return data

    def _receive(self) -> tuple[str, bytes]:
        length, command = struct.unpack("!IB", self._exactly(5))
        return chr(command), self._exactly(length - 1)

    def _final(self) -> str:
        while True:  # modifications (h, m, ...) and progress come before the final reply
            command, _data = self._receive()
            if command not in "hmiqp":
                return command

    def stage(self, command: str, data: bytes) -> str | None:
        """Send a stage; its reply, or None when the milter asked for no reply or no stage."""
        if self.protocol & _NO_STAGE.get(command, 0):
            return None
        self._send(command, data)
        if self.protocol & _NO_REPLY.get(command, 0):
            return None
        return self._final()

    def macros(self, command: str, **values: str) -> None:
        self._send(
            "D", command.encode() + b"".join(f"{k}\0{v}\0".encode() for k, v in values.items())
        )

    def end_of_message(self) -> str:
        self._send("E")
        return self._final()

    def quit(self) -> None:
        self._send("Q")
        self.sock.close()


def _stage_connection(port: int, session: int, stages: int) -> None:
    """One milter connection of a replaying MTA (Stalwart): CONNECT, then ``stages`` more."""
    mta = _Mta(port)
    mta.macros("C", j="mail.contoso.test")
    assert mta.stage("C", _CONNECT) == "c"
    if stages >= 1:
        assert mta.stage("M", f"<s{session}@fabrikam.test>\0".encode()) == "c"
    if stages >= 2:
        assert mta.stage("R", b"<intake@agents.contoso.test>\0") == "c"
    if stages >= 3:
        assert mta.stage("L", b"Subject\0probe\0") == "c"
        assert mta.end_of_message() == "a"
    mta.quit()


def _raising_connection(port: int, session: int) -> None:
    """A callback that raises: pymilter replies 451 and releases the thread state."""
    mta = _Mta(port)
    assert mta.stage("C", _CONNECT) == "c"
    assert mta.stage("M", f"<s{session}@fabrikam.test>\0".encode()) == "c"
    assert mta.stage("R", b"<raise@agents.contoso.test>\0") in ("t", "y")  # y: 451 with text
    mta.quit()


def _session(port: int, session: int) -> None:
    for stages in range(4):
        _stage_connection(port, session, stages)
    _raising_connection(port, session)
    _Mta(port).quit()  # negotiated, then gone: close with no connect


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _start(probe: str, port: int, output) -> subprocess.Popen[bytes]:
    output.touch()
    env = {name: os.environ[name] for name in ("HOME", "TMPDIR", "PATH") if name in os.environ}
    server = subprocess.Popen([sys.executable, "-c", probe, str(port), str(output)], env=env)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        assert server.poll() is None, "the probe milter exited"
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            return server
        except OSError:
            time.sleep(0.05)
    server.kill()
    raise AssertionError("the probe milter never listened")


def _records(path, closes: int) -> list[dict]:
    """The probe's rows, once ``closes`` connections have closed (libmilter closes after QUIT)."""
    deadline = time.monotonic() + 10
    while True:
        # Only whole lines: the probe may be writing the last one.
        rows = [json.loads(line) for line in path.read_text().split("\n")[:-1]]
        if sum(row["stage"] == "close" for row in rows) >= closes:
            return rows
        assert time.monotonic() < deadline, "not every connection was closed"
        time.sleep(0.05)


def test_every_callback_runs_on_its_own_threads_thread_state(tmp_path) -> None:
    port, output = _free_port(), tmp_path / "callbacks.jsonl"
    server = _start(PROBE, port, output)
    try:
        sessions = 40
        with ThreadPoolExecutor(8) as pool:
            for future in [pool.submit(_session, port, n) for n in range(sessions)]:
                future.result()
        rows = _records(output, sessions * 6)
    finally:
        server.kill()  # every row is written; libmilter's orderly stop takes seconds
        server.wait(10)

    threads = defaultdict(set)
    for row in rows:
        threads[row["conn"]].add(row["tid"])
    # The hazard needs libmilter's worker pool: a connection's callbacks on several threads.
    assert any(len(tids) > 1 for tids in threads.values()), (
        "libmilter ran every connection on one thread, so this test cannot see the hazard"
    )
    foreign = [row for row in rows if not row["own"]]
    assert not foreign, f"{len(foreign)} of {len(rows)} callbacks, e.g. {foreign[:3]}"


def test_callbacks_still_run_after_milter_main_returns(tmp_path) -> None:
    """libmilter's workers run commands they already read after smfi_main() returns. pymilter
    1.0.5 ran them on the connection's thread state; the per-callback one must still be made."""
    port, output = _free_port(), tmp_path / "stopping.log"
    server = _start(STOPPING_PROBE, port, output)
    mta = None
    try:
        mta = _Mta(port)  # the probe has only a header callback: the other stages go unsent
        mta.stage("C", _CONNECT)
        mta.stage("M", b"<s@fabrikam.test>\0")
        mta.stage("R", b"<intake@agents.contoso.test>\0")
        assert mta.protocol & _NO_REPLY["L"], "the probe's headers must need no reply"
        for n in range(5):
            mta.stage("L", f"X-H{n}\0v\0".encode())
        assert server.wait(40) == 0, output.read_text()
    finally:
        if mta is not None:
            mta.sock.close()
        if server.poll() is None:
            server.kill()
            server.wait(10)
    lines = output.read_text().splitlines()
    assert "main returned" in lines
    assert [line for line in lines if line.startswith("header ")] == [
        f"header X-H{n}" for n in range(5)
    ]


def test_native_sibling_frontend_keeps_stalwart_replay_and_refuses_ingress(tmp_path):
    """Real TCP frontends + native libmilter, not mocked endpoint provenance."""
    from email import policy
    from email.parser import BytesParser

    import yaml

    from amx.identity import sign
    from amx.profile import build
    from amx.provision import generate_dkim_key
    from amx.store import Store

    ingress, sibling = _free_port(), _free_port()
    key = tmp_path / "alpha.private.pem"
    generate_dkim_key(key, bits=1024)
    path = tmp_path / "gateway.yaml"
    values = {
        "domain": "home.arpa",
        "agent_domain": "agents.home.arpa",
        "data_dir": str(tmp_path),
        "keys_dir": str(tmp_path),
        "listeners": {
            "milter_host": "127.0.0.1",
            "milter_port": ingress,
            "sibling_milter_port": sibling,
            "people_milter_port": _free_port(),
        },
        "agents": {
            "alpha": {"handler": "mailbox-only"},
            "beta": {"handler": "mailbox-only"},
        },
        "trust": [
            {
                "d": "agents.home.arpa",
                "s": "alpha",
                "intents": ["request"],
                "schemas": ["*"],
                "can_open_tasks": True,
            }
        ],
    }
    path.write_text(yaml.safe_dump(values))
    probe = f"""
from amx.adapters.milter import run_milter
from amx.config import load_config
from amx.runtime import HandlerRegistry
from amx.store import Store
config = load_config({str(path)!r})
registry = HandlerRegistry()
registry.register('beta', 'mailbox-only')
run_milter(config, Store(config.data_dir / 'journal.sqlite'), registry)
"""
    raw = sign(
        build(
            sender="alpha+t_native@agents.home.arpa",
            to="beta@agents.home.arpa",
            subject="native sibling",
            intent="request",
            task="t_native",
            task_state="submitted",
            text="A signed sibling request.",
            message_id="<native@agents.home.arpa>",
        ).as_bytes(policy=policy.SMTP),
        selector="alpha",
        domain="agents.home.arpa",
        private_key=key,
    )
    server = _start(probe, ingress, tmp_path / "native.log")
    try:
        for port, expected in ((sibling, "a"), (ingress, "r")):
            # Stalwart opens three milter connections for one SMTP transaction.
            for stage in range(1, 4):
                mta = _Mta(port)
                try:
                    mta.macros("C", **{"{daemon_name}": "Stalwart v0.16.25", "j": "mail.home.arpa"})
                    assert mta.stage("C", _CONNECT) == "c"
                    assert mta.stage("M", b"<alpha+t_native@agents.home.arpa>\0") == "c"
                    if stage >= 2:
                        assert mta.stage("R", b"<beta@agents.home.arpa>\0") == "c"
                    if stage == 3:
                        headers = BytesParser(policy=policy.SMTP).parsebytes(raw).raw_items()
                        for name, value in headers:
                            frame = name.encode() + b"\0" + value.encode() + b"\0"
                            assert mta.stage("L", frame) == "c"
                        assert mta.stage("B", raw) == "c"
                        result = mta.end_of_message()
                        assert result == expected or (expected == "r" and result == "y")
                finally:
                    mta.quit()
        rules = Store(tmp_path / "journal.sqlite").rows(
            "SELECT rule, action FROM policy_events WHERE stage = 'eod'"
        )
        assert [(row["rule"], row["action"]) for row in rules] == [
            ("eod-ok", "accept"),
            ("own-agent-ingress", "reject"),
        ]
    finally:
        server.kill()
        server.wait(10)
