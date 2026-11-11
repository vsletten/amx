"""Fake-child transport, presence and runner proof for AX Phase 1."""

from __future__ import annotations

import concurrent.futures
import http.client
import json
import os
import queue
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest
from test_remote_agent import ADDRESS, FakeImap, _agent_request

from amx import runner as runner_module
from amx.adapters.ax import (
    AxChild,
    AxEndpoint,
    AxError,
    AxPresence,
    Contract,
    OfflinePolicy,
    Presence,
    WakeSocket,
    address_name,
    default_name,
)
from amx.runner import HandledLog, ImapLogin, Runner
from amx.sdk import Agent

FAKE = Path(__file__).with_name("fake_ax.py")


def target(**fields):
    return {
        "name": "live",
        "agent_id": "agt_live",
        "online": True,
        "state": "ready",
        "policy": "accept",
        "external": "verified",
        **fields,
    }


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class Declarations:
    def __init__(self):
        self.calls = []
        self.fail = False

    def pause(self, **fields):
        if self.fail:
            raise OSError("submission unavailable")
        self.calls.append(("pause", fields))

    def resume(self):
        if self.fail:
            raise OSError("submission unavailable")
        self.calls.append(("resume", {}))


@pytest.fixture
def fake(monkeypatch):
    # AX and AF_UNIX paths must fit macOS's 104-byte sockaddr_un.
    with tempfile.TemporaryDirectory(prefix="amx-", dir="/tmp") as directory:
        root = Path(directory).resolve()
        cfg = {
            "contract": "v1",
            "agents": [target()],
            "interleave": True,
            "log": str(root / "calls.jsonl"),
        }
        path = root / "config.json"

        def update(**fields):
            cfg.update(fields)
            temporary = root / "config.new"
            temporary.write_text(json.dumps(cfg))
            temporary.replace(path)

        update()
        monkeypatch.setenv("FAKE_AX_CONFIG", str(path))
        child = AxChild(
            [sys.executable, str(FAKE)], root / "ax", root / "state", "amx-outpost", timeout=0.75
        )
        try:
            yield child, update, cfg
        finally:
            child.close()


def calls(cfg):
    return [json.loads(line) for line in Path(cfg["log"]).read_text().splitlines()]


def eventually(condition, timeout=2):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(0.01)
    assert condition()


@pytest.mark.parametrize("contract", [Contract.V1, Contract.INTERIM])
def test_enrollment_discovery_interleaving_and_shutdown(fake, contract, caplog):
    child, update, cfg = fake
    update(contract=contract)
    with caplog.at_level("INFO"):
        assert child.connect() == contract
    assert f"detected contract {contract}" in caplog.text
    endpoint = AxEndpoint(child)
    assert endpoint.list_agents()["agents"] == [target()]
    assert endpoint.list_agents()["ax_home"] == str(child.home)
    assert child.events.get(timeout=1)["method"].startswith("notifications/ax/")
    starts = [call for call in calls(cfg) if "argv" in call]
    assert starts[0]["argv"] == ["attach", "--relay", "-n", "amx-outpost"]
    if contract == Contract.INTERIM:
        native = (child.state / "ax-session-id").read_text().strip()
        assert starts[1]["argv"] == [
            "attach",
            "-n",
            "amx-outpost-interim",
            "-s",
            native,
            "-p",
            "read-only",
            "-w",
            str(child.wake.path),
        ]
        child.connect()
        assert (child.state / "ax-session-id").read_text().strip() == native
    else:
        assert child.wake is None
        assert not (child.state / "ax-session-id").exists()
    process = child.process
    threads = list(child._threads)
    child.close()
    assert process.poll() is not None
    assert all(not thread.is_alive() for thread in threads)
    assert not (child.state / "ax-wake.sock").exists()


def test_v1_ordinary_session_hides_provenance_so_relay_bootstrap_is_required(fake):
    child, _update, _cfg = fake
    discovery = child._start(["-n", "amx-outpost", "-s", "native", "-p", "read-only"])
    assert Contract.detect(discovery) == Contract.INTERIM
    assert child.connect() == Contract.V1


@pytest.mark.parametrize(
    "failure",
    [
        "running broker does not support relays; finish the broker update",
        "agent name is already running",
        "permission denied",
    ],
)
def test_startup_failure_is_never_an_interim_downgrade(fake, failure):
    child, update, cfg = fake
    update(startup_error=failure)
    with pytest.raises(AxError, match=failure):
        child.connect()
    assert len([call for call in calls(cfg) if "argv" in call]) == 1
    assert child.wake is None
    assert not (child.state / "ax-session-id").exists()


def test_broken_relay_schema_is_an_error_not_interim(fake):
    child, update, _cfg = fake
    update(broken_schema=True)
    with pytest.raises(AxError, match="refusing interim downgrade"):
        child.connect()


def test_missing_binary_is_a_transport_failure(tmp_path):
    child = AxChild(str(tmp_path / "missing"), tmp_path / "ax", tmp_path, "bridge")
    with pytest.raises(FileNotFoundError):
        child.connect()
    child.close()


def test_response_ids_route_concurrent_out_of_order_calls(fake):
    child, update, _cfg = fake
    update(delay_tool="get_message")
    child.connect()
    endpoint = AxEndpoint(child)
    with concurrent.futures.ThreadPoolExecutor() as executor:
        delayed = executor.submit(endpoint.get_message, "msg_slow")
        quick = executor.submit(endpoint.ack_message, "msg_quick")
        assert quick.result()["arguments"] == {"message_id": "msg_quick"}
        assert delayed.result()["arguments"] == {"message_id": "msg_slow"}


def test_endpoint_wrappers_preserve_arguments_and_structured_errors(fake):
    child, update, _cfg = fake
    child.connect()
    endpoint = AxEndpoint(child)
    fields = {
        "data": {"task": "t_one"},
        "provenance": {"origin": "amx", "trust": "system", "tainted": False},
    }
    assert endpoint.send_message("live", "hello", "id_send", 3600, **fields)["arguments"] == {
        "target": "live",
        "text": "hello",
        "client_message_id": "id_send",
        "ttl_seconds": 3600,
        **fields,
    }
    assert endpoint.follow_up("msg_1", "more", "id_follow", 60, **fields)["arguments"] == {
        "message_id": "msg_1",
        "text": "more",
        "client_message_id": "id_follow",
        "ttl_seconds": 60,
        **fields,
    }
    assert endpoint.resend_message("msg_1", "id_retry", 45)["arguments"] == {
        "message_id": "msg_1",
        "client_message_id": "id_retry",
        "ttl_seconds": 45,
    }
    assert endpoint.list_pending()["tool"] == "list_pending"
    assert endpoint.get_message("msg_1")["arguments"] == {"message_id": "msg_1"}
    assert endpoint.ack_message("msg_1")["tool"] == "ack_message"
    assert endpoint.delivery_status("msg_1")["tool"] == "delivery_status"
    assert endpoint.list_notifications()["tool"] == "list_notifications"
    assert endpoint.ack_notification("ntf_1")["arguments"] == {"notification_id": "ntf_1"}
    update(error_tool="send_message")
    with pytest.raises(AxError, match="external policy refuse") as caught:
        endpoint.send_message("live", "hello", "id_fail", 60)
    assert caught.value.details["rpc_code"] == -32002
    assert caught.value.details["submission"] == "not_submitted"
    update(rpc_error_tool="list_agents")
    with pytest.raises(AxError, match="broker paused") as caught:
        endpoint.list_agents()
    assert caught.value.details["code"] == -32000


@pytest.mark.parametrize(
    "result",
    [
        {"content": []},
        {"content": [{"type": "image"}]},
        {"content": [{"type": "text", "text": "not JSON"}]},
        {"content": [{"type": "text", "text": "[]"}]},
    ],
)
def test_malformed_tool_result_is_useful_error(fake, result):
    child, update, _cfg = fake
    child.connect()
    update(bad_tool="list_pending", bad_result=result)
    with pytest.raises(AxError):
        AxEndpoint(child).list_pending()


@pytest.mark.parametrize("failure", ["timeout_tool", "eof_tool"])
def test_request_timeout_or_eof_releases_call_and_reconnects(fake, failure):
    child, update, _cfg = fake
    child.connect()
    update(**{failure: "list_agents"})
    start = time.monotonic()
    with pytest.raises(AxError, match=r"timed out|EOF"):
        AxEndpoint(child).list_agents()
    assert time.monotonic() - start < 1.5
    assert not child.alive
    assert not child._pending
    update(**{failure: None})
    child.connect()
    assert AxEndpoint(child).list_agents()["agents"] == [target()]


@pytest.mark.parametrize("contract", [Contract.V1, Contract.INTERIM])
@pytest.mark.parametrize(
    "unavailable",
    [
        None,
        {"online": False},
        {"state": "blocked"},
        {"state": "permission-blocked"},
    ],
)
def test_presence_grace_renewal_and_resume_once(contract, unavailable):
    clock, declarations = Clock(), Declarations()
    presence = Presence(declarations, "live", clock=clock)
    presence.observe([target()], contract)
    presence.tick()
    assert declarations.calls == []
    clock.now = 10
    presence.observe([] if unavailable is None else [target(**unavailable)], contract)
    clock.now = 39.9
    presence.tick()
    assert declarations.calls == []
    clock.now = 40
    presence.tick()
    assert declarations.calls == [("pause", {"seconds": 600, "reason": "offline"})]
    clock.now = 339.9
    presence.tick()
    assert len(declarations.calls) == 1
    clock.now = 340
    presence.tick()
    assert len(declarations.calls) == 2
    presence.observe([target(state="busy")], contract)
    presence.tick()
    presence.tick()
    assert declarations.calls[-1] == ("resume", {})
    assert len(declarations.calls) == 3


def test_transient_offline_resets_grace_and_busy_does_not_pause():
    clock, declarations = Clock(), Declarations()
    presence = Presence(declarations, "agt_live", clock=clock)
    presence.observe([target(state="busy")], Contract.V1)
    clock.now = 90
    presence.tick()
    assert declarations.calls == []
    presence.observe([], Contract.V1)
    clock.now = 119
    presence.observe([target()], Contract.V1)
    presence.tick()
    presence.observe([], Contract.V1)
    clock.now = 148
    presence.tick()
    assert declarations.calls == []
    clock.now = 149
    presence.tick()
    assert declarations.calls[-1][0] == "pause"


def test_hold_policy_keeps_absent_target_queued_and_clears_old_offline_pause():
    clock, declarations = Clock(), Declarations()
    presence = Presence(declarations, "live", clock=clock, offline=OfflinePolicy.HOLD)
    clock.now = 300
    presence.tick()
    assert declarations.calls == []

    presence.declared = "offline"
    presence.declared_at = clock.now
    presence.tick()
    assert declarations.calls == [("resume", {})]


@pytest.mark.parametrize("owner_policy", ["hold", "refuse"])
@pytest.mark.parametrize("offline", list(OfflinePolicy))
def test_owner_policy_always_declares_operator_pause(owner_policy, offline):
    clock, declarations = Clock(), Declarations()
    presence = Presence(declarations, "live", clock=clock, offline=offline)
    presence.observe([target(policy=owner_policy)], Contract.V1)
    presence.tick()
    assert declarations.calls == [("pause", {"seconds": 600, "reason": "operator"})]

    presence.observe([], Contract.V1)
    clock.now = 300
    presence.tick()
    assert len(declarations.calls) == 1, "absence must not clear the owner's pause"

    presence.observe([target()], Contract.V1)
    presence.tick()
    assert declarations.calls[-1] == ("resume", {})


def test_policy_closure_pauses_operator_and_reopens_once():
    clock, declarations = Clock(), Declarations()
    presence = Presence(declarations, "live", clock=clock)
    presence.observe([target(external="refuse")], Contract.V1)
    presence.tick()
    assert declarations.calls == [("pause", {"seconds": 600, "reason": "operator"})]
    clock.now = 300
    presence.tick()
    assert len(declarations.calls) == 2
    presence.observe([target(external="all")], Contract.V1)
    presence.tick()
    presence.tick()
    assert declarations.calls[-1] == ("resume", {})
    assert len(declarations.calls) == 3
    presence.observe([target(external="refuse")], Contract.INTERIM)
    presence.tick()
    assert len(declarations.calls) == 3, "interim has no external-policy contract"


def test_failed_submission_does_not_record_pause_or_resume():
    clock, declarations = Clock(), Declarations()
    presence = Presence(declarations, "live", clock=clock)
    clock.now = 30
    declarations.fail = True
    presence.tick()
    assert presence.declared is None
    declarations.fail = False
    clock.now = 35
    presence.tick()
    assert presence.declared == "offline"
    presence.observe([target()], Contract.V1)
    declarations.fail = True
    presence.tick()
    assert presence.declared == "offline"
    clock.now = 40
    declarations.fail = False
    presence.tick()
    presence.tick()
    assert declarations.calls == [("pause", {"seconds": 600, "reason": "offline"}), ("resume", {})]


@pytest.mark.parametrize("contract", [Contract.V1, Contract.INTERIM])
def test_worker_startup_notifications_or_poll_backstop(fake, contract):
    child, update, _cfg = fake
    update(contract=contract)
    clock, declarations = Clock(), Declarations()
    worker = AxPresence(child, Presence(declarations, "live", clock=clock))
    worker.step()
    assert worker.poll_at == (300 if contract == Contract.V1 else 15)
    update(agents=[])
    if contract == Contract.V1:
        eventually(lambda: not child.events.empty())
        # Fake emits a snapshot asynchronously, just like AX's bridge.
        eventually(
            lambda: any(
                event.get("params", {}).get("agents") == [] for event in list(child.events.queue)
            )
        )
    clock.now = 15
    worker.step()
    clock.now = 44.9
    worker.step()
    assert declarations.calls == []
    clock.now = 45
    worker.step()
    assert declarations.calls == [("pause", {"seconds": 600, "reason": "offline"})]
    update(agents=[target()])
    if contract == Contract.V1:
        eventually(
            lambda: any(
                event.get("params", {}).get("agents") == [target()]
                for event in list(child.events.queue)
            )
        )
    clock.now = 60
    worker.step()
    worker.step()
    assert declarations.calls[-1] == ("resume", {})


def test_v1_policy_notification_and_five_minute_confirmation(fake):
    child, _update, cfg = fake
    clock, declarations = Clock(), Declarations()
    worker = AxPresence(child, Presence(declarations, "live", clock=clock))
    worker.step()
    # Drain fake startup hints before injecting the receiving owner's policy snapshot.
    while not child.events.empty():
        child.events.get_nowait()
    child.events.put(
        {"method": "notifications/ax/agents", "params": {"agents": [target(external="refuse")]}}
    )
    clock.now = 1
    worker.step()
    assert declarations.calls[-1] == ("pause", {"seconds": 600, "reason": "operator"})
    before = len(
        [call for call in calls(cfg) if call.get("params", {}).get("name") == "list_agents"]
    )
    clock.now = 299
    worker.step()
    assert (
        len([call for call in calls(cfg) if call.get("params", {}).get("name") == "list_agents"])
        == before
    )
    clock.now = 300
    worker.step()
    assert declarations.calls[-1] == ("resume", {}), "backstop corrects a missed reopen hint"


def test_recovery_backoff_caps_and_offline_pause_continues(fake):
    child, update, cfg = fake
    update(startup_error="broker unavailable")
    clock, declarations = Clock(), Declarations()
    worker = AxPresence(child, Presence(declarations, "live", clock=clock))
    for delay in [5, 10, 20, 40, 80, 160, 300, 300]:
        worker.step()
        assert worker.reconnect_at == clock.now + delay
        count = len(calls(cfg))
        clock.now += delay - 0.1
        worker.step()
        assert len(calls(cfg)) == count
        clock.now += 0.1
    assert declarations.calls and all(call[1]["reason"] == "offline" for call in declarations.calls)
    update(startup_error=None)
    worker.step()
    assert declarations.calls[-1] == ("resume", {})
    assert worker.backoff == 5
    process = child.process
    process.kill()
    process.wait()
    eventually(lambda: not child.alive)
    worker.step()
    assert worker.reconnect_at == clock.now + 5
    assert not child.alive
    clock.now += 5
    worker.step()
    assert child.alive


def wake_request(path, native, *, text="AX pending", url="/wake"):
    connection = http.client.HTTPConnection("localhost", timeout=2)
    sock = socket.socket(socket.AF_UNIX)
    sock.connect(str(path))
    connection.sock = sock
    try:
        connection.request(
            "POST",
            url,
            json.dumps({"native": native, "text": text}),
            {"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        response.read()
        return response.status
    finally:
        connection.close()


def test_wake_is_private_validates_native_and_does_not_replace_existing_path(fake):
    child, update, _cfg = fake
    update(contract="interim")
    child.connect()
    path = child.wake.path
    native = (child.state / "ax-session-id").read_text().strip()
    assert path.stat().st_mode & 0o777 == 0o600
    while not child.events.empty():
        child.events.get_nowait()
    assert wake_request(path, "wrong") == 403
    assert wake_request(path, native, url="/other") == 404
    assert wake_request(path, native, text=1) == 400
    assert child.events.empty()
    assert wake_request(path, native) == 204
    assert child.events.get(timeout=1) == {
        "method": "amx/wake",
        "params": {"native": native, "text": "AX pending"},
    }
    with pytest.raises(BlockingIOError):
        WakeSocket(path, native, queue.Queue())
    assert wake_request(path, native) == 204
    child.close()
    assert not path.exists()


@pytest.mark.parametrize("with_handler", [False, True])
def test_runner_ax_only_leaves_mail_untaken_or_preserves_handler(tmp_path, with_handler):
    agent = Agent(ADDRESS, "smtp://gateway:2587", "token")
    seen = []
    handler = (lambda msg, ctx: seen.append(msg.task)) if with_handler else None
    runner = Runner(
        agent,
        ImapLogin("imap", 143, ADDRESS, "password"),
        handler,
        HandledLog(tmp_path / "runner.sqlite"),
    )
    imap = FakeImap()
    raw = _agent_request()
    uid = imap.add(raw)
    assert runner.drain(imap) == 0
    if with_handler:
        assert seen == ["t_remote"]
        assert imap.flags(uid) == {"\\Seen", "$AmxHandled"}
    else:
        assert imap.flags(uid) == set()
        assert imap.stored == []
        assert (
            runner.handled.outcome(
                "outpost+t_remote@agents.contoso.test <r1@agents.northwind.test>"
            )
            is None
        )
        assert not runner.handle(imap, str(uid), raw)
        assert imap.stored == []


@pytest.mark.parametrize("with_handler", [False, True])
def test_runner_cli_starts_worker_with_options_and_stops_child(fake, monkeypatch, with_handler):
    child, _update, _cfg = fake
    monkeypatch.setenv("HOME", str(child.home.parent / "login-home"))
    started = threading.Event()
    seen = {}
    original = AxPresence.run

    def run_worker(self, stop):
        seen["offline"] = self.presence.offline
        self.step()
        started.set()
        original(self, stop)

    def run_imap(self, stop):
        assert started.wait(2)
        seen["handler"] = self.handler
        assert self.agent.name == "outpost"
        stop.set()

    def construct(binary, home, state, name):
        seen.update(binary=binary, home=home, state=state, name=name)
        return child

    monkeypatch.setenv("AMX_IMAP_PASSWORD", "password")
    monkeypatch.setenv("AMX_SUBMIT_TOKEN", "token")
    monkeypatch.setattr(runner_module, "AxChild", construct)
    monkeypatch.setattr(AxPresence, "run", run_worker)
    monkeypatch.setattr(Runner, "run", run_imap)
    monkeypatch.setattr(runner_module.signal, "signal", lambda *_: None)
    argv = [
        "--agent",
        ADDRESS,
        "--imap",
        "imap:143",
        "--submit",
        "smtp://gateway:2587",
        "--state",
        str(child.state),
        "--ax",
        "live",
        "--ax-binary",
        "custom-ax",
        "--ax-ttl-seconds",
        "90",
    ]
    if with_handler:
        argv += [
            "--handler",
            "amx.examples.intake:handle",
            "--ax-home",
            str(child.home),
            "--ax-name",
            "bridge",
        ]
    runner_module.main(argv)
    assert seen["offline"] == OfflinePolicy.PAUSE
    assert seen["name"] == ("bridge" if with_handler else address_name(ADDRESS))
    assert seen["home"] == (child.home if with_handler else Path.home() / ".ax")
    assert seen["binary"] == "custom-ax"
    assert (seen["handler"] is not None) == with_handler
    assert child.process is None


@pytest.mark.ax_binary
def test_real_ax_attach_enrollment_and_policy_in_isolated_home(monkeypatch):
    binary = os.environ.get("AX_BINARY")
    if not binary:
        pytest.skip("set AX_BINARY to a worktree-local AX build; no installed broker is used")
    # The release's documented relay enrollment must work without a bypass opt-in.
    monkeypatch.setenv("AX_ALLOW_BYPASS", "0")
    binary = str(Path(binary).resolve())
    with tempfile.TemporaryDirectory(prefix="amx-real-", dir="/tmp") as directory:
        root = Path(directory).resolve()
        home = root / "ax"
        home.mkdir(mode=0o700)
        env = {**os.environ, "AX_HOME": str(home)}
        # Start an owned foreground broker so cleanup never touches the user's live broker.
        broker = subprocess.Popen(
            [binary, "serve"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
        )
        relay = AxChild(binary, home, root / "relay", default_name("a" * 63))
        recipient = AxChild(binary, home, root / "target", "live")
        try:
            eventually(lambda: (home / "broker.sock").exists(), timeout=5)
            contract = relay.connect()
            # An ordinary target has the intentionally hidden provenance schema.
            discovery = recipient._start(["-n", "live", "-s", "test-native", "-p", "read-only"])
            assert Contract.detect(discovery) == Contract.INTERIM
            endpoint = AxEndpoint(relay)
            eventually(
                lambda: any(
                    a["name"] == "live" and a["online"] for a in endpoint.list_agents()["agents"]
                ),
                timeout=5,
            )
            listing = endpoint.list_agents()
            assert "agents" in listing and "ax_home" in listing
            if contract == Contract.V1:
                assert relay.wake is None
                enrolled = next(a for a in listing["agents"] if a["name"] == relay.name)
                assert enrolled["kind"] == "relay"
                assert enrolled["permission_mode"] == "relay"
                assert enrolled["state"] == "ready"
                subprocess.run(
                    [binary, "external", "live", "verified"],
                    env=env,
                    check=True,
                    capture_output=True,
                    timeout=5,
                )
                eventually(
                    lambda: any(
                        a["name"] == "live" and a.get("external") == "verified"
                        for a in endpoint.list_agents()["agents"]
                    )
                )

            else:
                assert relay.wake.path.stat().st_mode & 0o777 == 0o600
        finally:
            recipient.close()
            relay.close()
            broker.terminate()
            broker.wait(timeout=5)
            broker.stderr.close()


def test_wake_reclaims_crashed_socket_but_preserves_non_socket(fake):
    child, _update, _cfg = fake
    child.state.mkdir()
    path = child.state / "ax-wake.sock"
    stale = socket.socket(socket.AF_UNIX)
    stale.bind(str(path))
    stale.close()
    wake = WakeSocket(path, "native", queue.Queue())
    try:
        assert wake_request(path, "native") == 204
    finally:
        wake.close()
    path.write_text("another owner's file")
    with pytest.raises(AxError, match="refusing to replace"):
        WakeSocket(path, "native", queue.Queue())
    assert path.read_text() == "another owner's file"


def test_disconnect_releases_outstanding_request_without_waiting_for_timeout(fake):
    child, update, _cfg = fake
    child.connect()
    update(timeout_tool="list_agents")
    child.timeout = 15
    with concurrent.futures.ThreadPoolExecutor() as executor:
        pending = executor.submit(AxEndpoint(child).list_agents)
        eventually(lambda: bool(child._pending))
        child.close()
        with pytest.raises(AxError, match=r"disconnected|EOF"):
            pending.result(timeout=1)
    assert not child._pending


def test_frame_bound_and_full_sized_notification_are_independent_of_responses(fake):
    child, update, _cfg = fake
    child.connect()
    # Includes JSON escaping in the MCP envelope; fits the actual 576 KiB bound.
    content = '\\"' * 100_000
    update(notification_text=content)
    assert AxEndpoint(child).list_agents()["agents"] == [target()]
    assert any(
        event.get("params", {}).get("content") == content for event in list(child.events.queue)
    )
    with pytest.raises(AxError, match="576 KiB"):
        child.notify("test", {"text": "x" * (576 * 1024)})
    update(notification_text="x" * (576 * 1024))
    with pytest.raises(AxError, match="576 KiB"):
        AxEndpoint(child).list_agents()


@pytest.mark.parametrize("with_handler", [False, True])
def test_runner_sigterm_cleans_ax_worker_and_socket(fake, monkeypatch, with_handler):
    child, update, _cfg = fake
    update(contract="interim")
    ready = threading.Event()
    signals = {}
    original = AxPresence.run

    def run_worker(self, stop):
        self.step()
        ready.set()
        original(self, stop)

    def run_imap(self, stop):
        assert ready.wait(2)
        assert child.wake is not None
        self.busy = with_handler
        signals["terminate"](15, None)
        # A busy handler returns normally and stops at the loop boundary.
        assert stop.is_set()

    monkeypatch.setenv("AMX_IMAP_PASSWORD", "password")
    monkeypatch.setenv("AMX_SUBMIT_TOKEN", "token")
    monkeypatch.setattr(runner_module, "AxChild", lambda *_: child)
    monkeypatch.setattr(AxPresence, "run", run_worker)
    monkeypatch.setattr(Runner, "run", run_imap)
    monkeypatch.setattr(
        runner_module.signal, "signal", lambda _signal, callback: signals.update(terminate=callback)
    )
    argv = [
        "--agent",
        ADDRESS,
        "--imap",
        "imap:143",
        "--submit",
        "smtp://gateway:2587",
        "--state",
        str(child.state),
        "--ax",
        "live",
    ]
    if with_handler:
        argv += ["--handler", "amx.examples.intake:handle"]
        runner_module.main(argv)
    else:
        with pytest.raises(SystemExit) as exited:
            runner_module.main(argv)
        assert exited.value.code == 0
    assert child.process is None and child.wake is None
    assert not (child.state / "ax-wake.sock").exists()


def test_interim_names_are_distinct_bounded_and_stable(tmp_path):
    def child(name):
        return AxChild("ax", tmp_path / "ax", tmp_path, name)

    assert child("amx-outpost").interim_name == "amx-outpost-interim"
    long = "a" * 48
    derived = child(long).interim_name
    assert len(derived) == 48 and derived != long
    assert derived == child(long).interim_name
    assert derived != child("a" * 47 + "b").interim_name


@pytest.mark.ax_binary
def test_real_interim_to_v1_upgrade_preserves_name_binding():
    baseline = os.environ.get("AX_BASELINE_BINARY")
    current = os.environ.get("AX_BINARY")
    if not (baseline and current):
        pytest.skip("set AX_BASELINE_BINARY and AX_BINARY for isolated interim-to-v1 upgrade proof")
    baseline, current = str(Path(baseline).resolve()), str(Path(current).resolve())
    with tempfile.TemporaryDirectory(prefix="amx-upgrade-", dir="/tmp") as directory:
        root = Path(directory).resolve()
        home = root / "ax"
        home.mkdir(mode=0o700)
        env = {**os.environ, "AX_HOME": str(home)}
        broker = None
        child = AxChild(baseline, home, root / "state", "amx-upgrade")
        try:
            broker = subprocess.Popen(
                [baseline, "serve"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
            )
            eventually(lambda: (home / "broker.sock").exists(), timeout=5)
            assert child.connect() == Contract.INTERIM
            listing = AxEndpoint(child).list_agents()["agents"]
            assert any(a["name"] == "amx-upgrade-interim" for a in listing)
            session_id = (child.state / "ax-session-id").read_text()
            child.disconnect()
            broker.terminate()
            broker.wait(timeout=5)
            broker.stderr.close()
            broker = subprocess.Popen(
                [current, "serve"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
            )
            eventually(lambda: (home / "broker.sock").exists(), timeout=5)
            child.command = [current]
            assert child.connect() == Contract.V1
            listing = AxEndpoint(child).list_agents()["agents"]
            assert any(a["name"] == "amx-upgrade" and a.get("kind") == "relay" for a in listing)
            assert (child.state / "ax-session-id").read_text() == session_id
            assert child.wake is None
            assert not (child.state / "ax-wake.sock").exists()
        finally:
            child.close()
            if broker is not None:
                broker.terminate()
                broker.wait(timeout=5)
                if not broker.stderr.closed:
                    broker.stderr.close()


def test_default_name_supports_long_registered_agents_and_explicit_names_are_validated(tmp_path):
    from amx.registry import check_name

    assert default_name("outpost") == "amx-outpost"
    for size in (44, 45, 63):
        local = check_name("a" * size)
        name = default_name(local)
        assert len(name) == 48
        assert name == default_name(local)
        assert name != default_name(local[:-1] + "b")
        child = AxChild("ax", tmp_path / "ax", tmp_path, name)
        assert len(child.interim_name) == 48
    for bad in ("1bad", "a.b", "a" * 49):
        with pytest.raises(ValueError, match="set --ax-name"):
            AxChild("ax", tmp_path / "ax", tmp_path, bad)


def test_runner_invalid_explicit_ax_name_fails_before_starting_worker(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setenv("AMX_IMAP_PASSWORD", "password")
    monkeypatch.setenv("AMX_SUBMIT_TOKEN", "token")
    argv = [
        "--agent",
        ADDRESS,
        "--imap",
        "imap:143",
        "--submit",
        "smtp://gateway:2587",
        "--state",
        str(tmp_path),
        "--ax",
        "live",
        "--ax-name",
        "a" * 49,
    ]
    with pytest.raises(SystemExit) as exited:
        runner_module.main(argv)
    assert exited.value.code == 2
    assert "fit 48 characters" in capsys.readouterr().err
