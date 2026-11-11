"""SH-24b: bidirectional handoffs, uncertain custody and independent presence."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from test_ax_delivery import setup
from test_remote_agent import _agent_request

from amx.adapters.ax import AxError, Contract, Presence
from amx.custody import Custody
from amx.mailbox import HANDLED_KEYWORD, TAKEN_KEYWORD
from amx.mcp_server import AgentTools, Fetched
from amx.runner import delivery_key


class SharedMailbox:
    def __init__(self, imap):
        self.imap = imap

    def fetch(self, folder, *, unseen_only=False, limit=None):
        if folder != "INBOX":
            return []
        result = []
        for uid, (flags, raw) in sorted(self.imap.messages.items(), reverse=True):
            if unseen_only and "\\Seen" in flags:
                continue
            result.append(
                Fetched(
                    folder,
                    uid,
                    raw,
                    "\\Seen" in flags,
                    TAKEN_KEYWORD in flags,
                    HANDLED_KEYWORD in flags,
                )
            )
        return result[:limit] if limit is not None else result

    def flag(self, folder, uid, flags):
        status, _ = self.imap.uid("STORE", str(uid), "+FLAGS", f"({flags})")
        assert status == "OK"


def tools_for(runner, imap):
    return AgentTools(runner.agent, SharedMailbox(imap))


def test_attach_does_not_steal_mcp_message_or_starve_next_copy(tmp_path):
    runner, delivery, imap, endpoint, submissions = setup(tmp_path)
    delivery.worker.presence.observe([], Contract.V1)
    raw = _agent_request()
    first = imap.add(raw)
    tools = tools_for(runner, imap)
    assert tools.list_inbox()[0]["taken"]
    # Attaching AX must not interrupt the existing MCP reply/done cycle.
    delivery.worker.presence.observe(
        [{"name": "live", "online": True, "state": "ready", "external": "verified"}],
        Contract.V1,
    )
    second_raw = _agent_request(message_id="<next@x>")
    second = imap.add(second_raw)
    assert runner.drain(imap) == 0
    assert len(endpoint.sent) == 1
    assert imap.flags(first) == {TAKEN_KEYWORD}
    assert imap.flags(second) == {"\\Seen"}
    tools.reply("<r1@agents.northwind.test>", "MCP finished")
    tools.done("<r1@agents.northwind.test>")
    assert len(submissions) == 1
    assert imap.flags(first) == {TAKEN_KEYWORD, HANDLED_KEYWORD}
    assert runner.drain(imap) == 0 and len(endpoint.sent) == 1


@pytest.mark.parametrize("uncertain", [False, True])
def test_ax_leaves_mid_message_never_hands_accepted_or_uncertain_copy_to_mcp(tmp_path, uncertain):
    calls = []
    runner, delivery, imap, endpoint, _ = setup(tmp_path, handler=lambda *a: calls.append(a))
    raw = _agent_request()
    uid = imap.add(raw)
    if uncertain:
        endpoint.failure = AxError("lost acceptance response")
    runner.handle(imap, str(uid), raw)
    delivery.connected = False
    delivery.worker.presence.observe([], Contract.V1)
    runner.handle(imap, str(uid), raw)
    assert not calls
    with runner.custody.locked() as state:
        assert state["claims"][delivery_key(raw)] == "runner"
    tools = tools_for(runner, imap)
    assert not tools.list_inbox()[0]["taken"]
    with pytest.raises(ValueError, match="runner/AX"):
        tools.reply("<r1@agents.northwind.test>", "must not duplicate")
    # A different message is immediately available to MCP while AX is absent.
    next_uid = imap.add(_agent_request(task="t_next", message_id="<next@x>"))
    assert tools.wait_for_reply("t_next", 0)["status"] == "received"
    assert imap.flags(next_uid) == {TAKEN_KEYWORD}
    assert TAKEN_KEYWORD not in imap.flags(uid)
    endpoint.failure = None
    delivery.connected = True
    delivery.recover_at = 0
    delivery.step()
    record = runner.handled.ax_record(delivery_key(raw))
    endpoint.messages[record["message_id"]]["status"] = "acknowledged"
    delivery.recover_at = delivery.sweep_at = 0
    delivery.step()
    assert HANDLED_KEYWORD in imap.flags(uid)
    assert len(endpoint.sent) == 1


def test_no_ax_does_not_call_explicit_fallback_or_touch_inbox(tmp_path):
    calls = []
    runner, delivery, imap, endpoint, _ = setup(tmp_path, handler=lambda *a: calls.append(a))
    delivery.worker.presence.observe([], Contract.V1)
    imap.add(_agent_request())
    assert runner.drain(imap) == 0
    assert not imap.stored and not calls and not endpoint.sent


@pytest.mark.parametrize("disconnect", [False, True])
def test_detach_between_runner_preflight_and_ax_offer_must_not_invoke_handler(tmp_path, disconnect):
    calls = []
    runner, delivery, imap, endpoint, _ = setup(tmp_path, handler=lambda *a: calls.append(a))
    raw = _agent_request()
    uid = imap.add(raw)
    offer = delivery.offer

    def detach_then_offer(*args):
        # Schedule the presence worker's transition after preflight committed
        # its provisional claim, but before the real offer-time check.
        with runner.custody.locked() as state:
            assert state["claims"][delivery_key(raw)] == "runner"
        if disconnect:
            delivery.connected = False
        delivery.worker.presence.observe([], Contract.V1)
        return offer(*args)

    delivery.offer = detach_then_offer
    runner.handle(imap, str(uid), raw)
    assert calls == [], "No AX target: optional handler must not run"
    assert imap.flags(uid) == set() and not imap.stored
    assert not endpoint.sent and not endpoint.calls
    assert runner.handled.ax_record(delivery_key(raw)) is None
    assert runner.handled.outcome(delivery_key(raw)) is None
    with runner.custody.locked() as state:
        assert delivery_key(raw) not in state["claims"]
    # Deferral must leave this very copy available to MCP, not just unhandled.
    tools = tools_for(runner, imap)
    answer = tools.wait_for_reply("t_remote", 0)
    assert answer["status"] == "received" and answer["message"]["taken"]
    assert imap.flags(uid) == {TAKEN_KEYWORD}


def test_present_target_definitive_policy_rejection_retains_handler_fallback(tmp_path):
    calls = []
    runner, _, imap, endpoint, _ = setup(tmp_path, handler=lambda *a: calls.append(a))
    endpoint.failure = AxError(
        "closed",
        {"code": "external_policy", "rpc_code": -32002, "submission": "not_submitted"},
    )
    raw = _agent_request()
    uid = imap.add(raw)
    assert runner.handle(imap, str(uid), raw)
    assert len(calls) == 1 and not endpoint.sent
    assert imap.flags(uid) == {"\\Seen", HANDLED_KEYWORD}


def test_empty_mcp_poll_suppresses_pause_then_both_absent_timeout_and_resume(tmp_path):
    now = [0.0]
    custody = Custody("presence@x", directory=tmp_path, clock=lambda: now[0])
    calls = []

    class Agent:
        def pause(self, **kwargs):
            calls.append(("pause", kwargs))

        def resume(self):
            calls.append(("resume", {}))

    presence = Presence(
        Agent(), "live", clock=lambda: now[0], custody=custody, mcp_grace=10, presence_timeout=5
    )
    custody.poll()
    now[0] = 10
    presence.tick()
    assert not calls
    now[0] = 11
    presence.tick()
    now[0] = 15.9
    presence.tick()
    assert not calls
    now[0] = 16
    presence.tick()
    assert calls == [("pause", {"seconds": 600, "reason": "offline"})]
    custody.poll()
    presence.tick()
    presence.tick()
    assert calls[-1] == ("resume", {}) and len(calls) == 2


def test_same_user_simultaneous_claim_has_exactly_one_consumer(tmp_path):
    runner, _, imap, endpoint, _ = setup(tmp_path)
    tools = tools_for(runner, imap)
    raw = _agent_request()
    uid = imap.add(raw)
    barrier = threading.Barrier(2)

    def ax():
        barrier.wait()
        runner.handle(imap, str(uid), raw)

    def mcp():
        barrier.wait()
        return tools.list_inbox()[0]

    with ThreadPoolExecutor(max_workers=2) as pool:
        future = pool.submit(ax)
        message = pool.submit(mcp).result(timeout=5)
        future.result(timeout=5)
    assert (bool(endpoint.sent), message["taken"]) in {(True, False), (False, True)}
    assert not ({"\\Seen", TAKEN_KEYWORD} <= imap.flags(uid))


def test_ax_presence_prioritizes_next_copy_but_not_existing_mcp_claim(tmp_path):
    runner, _, imap, endpoint, _ = setup(tmp_path)
    tools = tools_for(runner, imap)
    first = imap.add(_agent_request())
    tools.list_inbox()
    runner.custody.ax_presence(True)
    second = imap.add(_agent_request(task="t_next", message_id="<next@x>"))
    assert tools.wait_for_reply("t_next", 0)["status"] == "timeout"
    assert imap.flags(second) == set()
    tools.done("<r1@agents.northwind.test>")
    runner.drain(imap)
    assert imap.flags(first) == {TAKEN_KEYWORD, HANDLED_KEYWORD}
    assert imap.flags(second) == {"\\Seen"} and len(endpoint.sent) == 1


def test_stale_mcp_snapshot_cannot_claim_after_runner_takes(tmp_path):
    runner, _, imap, endpoint, _ = setup(tmp_path)
    tools = tools_for(runner, imap)
    raw = _agent_request()
    uid = imap.add(raw)
    [stale] = tools.mailbox.fetch("INBOX")
    runner.handle(imap, str(uid), raw)
    fresh = tools._take(stale)
    assert fresh.seen and not fresh.taken
    assert len(endpoint.sent) == 1 and imap.flags(uid) == {"\\Seen"}


def test_empty_tools_poll_presence_but_done_does_not(tmp_path):
    runner, _, imap, _, _ = setup(tmp_path)
    tools = tools_for(runner, imap)
    now = [10.0]
    tools.custody.clock = lambda: now[0]
    for name in ("list_inbox", "read_thread", "wait_for_reply"):
        now[0] += 10
        if name == "list_inbox":
            assert tools.list_inbox() == []
        elif name == "read_thread":
            assert tools.read_thread("empty") == []
        else:
            assert tools.wait_for_reply("empty", 0)["status"] == "timeout"
        assert tools.custody.recent(0)
    imap.add(_agent_request())
    tools.list_inbox()
    now[0] += 10
    tools.done("<r1@agents.northwind.test>")
    assert not tools.custody.recent(1)


def test_expiring_runner_presence_lease_never_expires_message_fence(tmp_path):
    now = [10.0]
    custody = Custody("lease@x", directory=tmp_path, clock=lambda: now[0])
    with custody.locked() as state:
        state["claims"]["uncertain-message"] = "runner"
    custody.ax_presence(True)
    now[0] = 16
    with custody.locked() as state:
        assert not custody.ax_available(state)
        assert state["claims"]["uncertain-message"] == "runner"


def test_mcp_presence_does_not_override_explicit_owner_external_refusal(tmp_path):
    runner, delivery, _, _, _ = setup(tmp_path)
    presence = delivery.worker.presence
    presence.custody = runner.custody
    runner.custody.poll()
    presence.observe(
        [{"name": "live", "online": True, "state": "ready", "external": "refuse"}],
        Contract.V1,
    )
    presence.tick()
    assert presence.declared == "operator"
