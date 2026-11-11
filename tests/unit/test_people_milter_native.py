"""Exercise submission endpoint -> real libmilter -> owner policy over milter v6."""

import os
import subprocess
import sys
import time

import pytest

pytest.importorskip("Milter")
from test_milter_threads import _CONNECT, _free_port, _Mta

PROBE = """
import sys
from pathlib import Path
from amx.adapters.milter import run_milter
from amx.config import GatewayConfig, LimitsConfig, MailboxConfig, TrustGrant
from amx.runtime import HandlerRegistry
from amx.store import Store
config = GatewayConfig(
    domain='home.arpa', agent_domain='agents.home.arpa', data_dir=Path(sys.argv[3]),
    agents={}, trust=(TrustGrant(lane='human'),), limits=LimitsConfig(),
    mailbox=MailboxConfig(host='unused.invalid'), people_domain='home.arpa',
    milter_host='127.0.0.1', milter_port=int(sys.argv[1]), people_milter_port=int(sys.argv[2]),
    sibling_milter_port=int(sys.argv[4]),
)
run_milter(config, Store(Path(sys.argv[3])/'journal.sqlite'), HandlerRegistry())
"""


def _transaction(port, header="pat@home.arpa", *, auth=True, stages=3):
    mta = _Mta(port)
    try:
        mta.macros("C", **{"{daemon_name}": "Stalwart v0.16.25", "j": "mail.home.arpa"})
        assert mta.stage("C", _CONNECT) == "c"
        mta.macros("M", **({"{auth_authen}": "pat@home.arpa"} if auth else {}))
        assert mta.stage("M", b"<pat@home.arpa>\0") == "c"
        if stages == 1:
            return None
        assert mta.stage("R", b"<other@home.arpa>\0") == "c"
        if stages == 2:
            return None
        headers = {"From": header, "To": "other@home.arpa", "Subject": "Native owner fixture"}
        for key, value in headers.items():
            assert mta.stage("L", f"{key}\0{value}\0".encode()) == "c"
        raw = b"".join(f"{key}: {value}\r\n".encode() for key, value in headers.items())
        mta._send("B", raw + b"\r\nPlease help.\r\n")
        # BODY may negotiate no reply, just as HEADER/MAIL can.
        if not mta.protocol & 0x80000:
            assert mta._final() == "c"
        mta._send("E")
        added = {}
        while True:
            command, data = mta._receive()
            if command == "h":
                key, value = data.rstrip(b"\0").split(b"\0", 1)
                added[key.decode()] = value.decode()
            elif command not in "miqp":
                return command, added
    finally:
        mta.quit()


@pytest.mark.parametrize("sibling_enabled", [False, True])
def test_native_people_endpoint_and_public_ingress_are_distinct(tmp_path, sibling_enabled):
    ingress, people = _free_port(), _free_port()
    sibling = _free_port() if sibling_enabled else 0
    # Explicit fixture subprocess environment; no operator configuration inherited.
    env = {key: os.environ[key] for key in ("HOME", "PATH", "TMPDIR") if key in os.environ}
    server = subprocess.Popen(
        [sys.executable, "-c", PROBE, str(ingress), str(people), str(tmp_path), str(sibling)],
        env=env,
    )
    try:
        deadline = time.monotonic() + 10
        while True:
            assert server.poll() is None
            try:
                connection = _Mta(ingress)
                connection.quit()
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.05)
        # All three Stalwart stage connections reach the same trusted endpoint;
        # MAIL replay must re-read auth and preserve the whole-message dialect.
        _transaction(people, stages=1)
        _transaction(people, stages=2)
        action, added = _transaction(people)
        assert action == "a"
        assert added["Agent-Trust"] == "high"
        assert added["Agent-Grant-Role"] == "owner"
        assert added["Agent-Grant-Can-Open-Tasks"] == "true"
        action, added = _transaction(ingress)
        assert action == "a"
        assert added["Agent-Trust"] == "low"
        assert "Agent-Grant-Role" not in added
        if sibling_enabled:
            action, added = _transaction(sibling)
            assert action == "a"
            assert added["Agent-Trust"] == "low"
            assert "Agent-Grant-Role" not in added
        assert _transaction(people, "forged@home.arpa")[0] == "y"
        assert _transaction(people, auth=False)[1]["Agent-Trust"] == "low"
    finally:
        server.terminate()
        server.wait(timeout=10)
