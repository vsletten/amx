"""AX custody and crash recovery at external side-effect boundaries."""

from __future__ import annotations

import hashlib
import json
import smtplib
from dataclasses import replace
from types import SimpleNamespace

import pytest
from test_remote_agent import FakeImap, _agent_request, _human_reply

from amx.adapters.ax import AxError, Contract, Presence, _size, envelope, parse_reply
from amx.ax_delivery import AxDelivery
from amx.mailbox import HANDLED_KEYWORD, NOT_DELIVERED_KEYWORD
from amx.runner import HandledLog, ImapLogin, Runner, bind, delivery_key
from amx.sdk import Agent


class Crash(BaseException):
    pass


class Mailbox(FakeImap):
    def __init__(self):
        super().__init__()
        self.untagged_responses["UIDVALIDITY"] = [b"10"]

    def logout(self):
        pass


class Endpoint:
    def __init__(self):
        self.sent = {}
        self.messages = {}
        self.pending = []
        self.notices = []
        self.acked = []
        self.acked_notices = []
        self.calls = []
        self.failure = None

    def _send(self, op, parent, client_id, text=None, **fields):
        self.calls.append((op, parent, client_id, text, fields))
        if self.failure:
            raise self.failure
        if client_id not in self.sent:
            message = {"message_id": f"ax_{len(self.sent)}", "status": "queued"}
            self.sent[client_id] = message
            self.messages[message["message_id"]] = message
        return {"message": self.sent[client_id], "submission": "submitted"}

    def send_message(self, target, text, client_id, ttl, **fields):
        return self._send("send", target, client_id, text, **fields)

    def follow_up(self, parent, text, client_id, ttl, **fields):
        return self._send("follow_up", parent, client_id, text, **fields)

    def resend_message(self, parent, client_id, ttl):
        return self._send("resend", parent, client_id)

    def delivery_status(self, message_id):
        return {"message": self.messages[message_id]}

    def list_pending(self, cursor=0):
        return {"messages": self.pending.copy()}

    def get_message(self, message_id):
        return self.messages[message_id]

    def ack_message(self, message_id):
        self.acked.append(message_id)
        self.pending = [m for m in self.pending if m["message_id"] != message_id]

    def list_notifications(self):
        return {"notifications": self.notices.copy()}

    def ack_notification(self, notice_id):
        self.acked_notices.append(notice_id)
        self.notices = [n for n in self.notices if n["notification_id"] != notice_id]

    def reply(self, parent, message_id="reply1", **fields):
        message = {
            "message_id": message_id,
            "in_reply_to": parent,
            "text": "Yes, Tuesday works.",
            "status": "content_served",
            **fields,
        }
        self.messages[message_id] = message
        self.messages[parent]["status"] = "acknowledged"
        self.pending.append(message)
        return message


def setup(tmp_path, *, contract=Contract.V1, handler=None):
    agent = Agent("outpost@agents.contoso.test", "smtp://gateway:2587", "token")
    submissions = []
    agent._transmit = lambda sender, recipients, raw: submissions.append(raw) or "2.0.0 sent"
    agent.resume = lambda: None
    agent.pause = lambda **_: None
    mailbox = Mailbox()
    endpoint = Endpoint()
    runner = Runner(
        agent,
        ImapLogin("edge", 143, agent.address, "password"),
        handler,
        HandledLog(tmp_path / "runner.sqlite"),
        connect=lambda: mailbox,
    )
    presence = Presence(agent, "live", clock=lambda: 100)
    presence.observe(
        [
            {
                "name": "live",
                "online": True,
                "state": "user-turn",
                "external": "verified",
            }
        ],
        contract,
    )
    worker = SimpleNamespace(
        endpoint=endpoint,
        presence=presence,
        child=SimpleNamespace(
            contract=contract,
            home=tmp_path / "ax",
            name="amx-outpost",
            interim_name="amx-outpost-interim",
        ),
    )
    delivery = AxDelivery(runner, worker, ttl_seconds=5)
    delivery.connected = True
    runner.ax_delivery = delivery
    return runner, delivery, mailbox, endpoint, submissions


def restart(delivery):
    new = AxDelivery(delivery.runner, delivery.worker, ttl_seconds=5)
    new.connected = True
    delivery.runner.ax_delivery = new
    return new


def offer(runner, mailbox, raw=None):
    raw = raw or _agent_request()
    uid = mailbox.add(raw)
    assert runner.handle(mailbox, str(uid), raw)
    return uid, runner.handled.ax_record(delivery_key(raw))


@pytest.mark.parametrize("contract", list(Contract))
def test_envelope_is_deterministic_and_bounded_in_utf8(contract):
    inbound = bind(_agent_request())
    large = replace(inbound, text="🙂<&\u2028" * 20000, payload={"large": "é" * 20000})
    first = envelope(large, "outpost+t@agents.test", contract)
    assert first == envelope(large, "outpost+t@agents.test", contract)
    text, data, provenance = first
    assert len(text.encode()) <= (16 if contract == Contract.V1 else 64) * 1024
    if data:
        assert _size(data) <= 32 * 1024
        assert data["payload"] == {"truncated": True}
        assert data["truncated"] is True
        assert provenance == {"origin": "mail", "trust": "verified", "tainted": False}
    else:
        assert text.startswith("External mail")


def test_payload_truncation_and_metadata_overflow():
    inbound = bind(_agent_request())
    inbound = replace(inbound, payload={"large": "x" * 32768})
    assert envelope(inbound, "outpost", Contract.V1)[1]["payload"] == {"truncated": True}
    huge = replace(inbound, task="x" * 40000, text="x" * 40000)
    assert envelope(huge, "outpost", Contract.V1)[1] == {
        "truncated": True,
        "raw_sha256": hashlib.sha256(huge.raw).hexdigest(),
    }


def test_provenance_binds_system_taint_and_verified_identity():
    inbound = bind(_agent_request())
    assert (
        envelope(replace(inbound, lane="system", sender=None), "a", Contract.V1)[2]["trust"]
        == "system"
    )
    tainted = bind(_human_reply(taint="directs-recipient"))
    assert envelope(tainted, "a", Contract.V1)[2] == {
        "origin": "mail",
        "trust": "unverified",
        "tainted": True,
    }


def test_reply_defaults_overrides_and_validation():
    assert parse_reply({"text": "yes"}).task_state == "working"
    assert (
        parse_reply({"text": "yes", "data": {"intent": "update", "task_state": "completed"}}).intent
        == "update"
    )
    with pytest.raises(ValueError):
        parse_reply({"text": "yes", "data": {"intent": "bogus"}})
    with pytest.raises(ValueError):
        parse_reply({"text": "yes", "data": []})


@pytest.mark.parametrize("contract", list(Contract))
def test_custody_is_seen_and_never_fallback_or_completion(tmp_path, contract):
    handled = []
    runner, delivery, mailbox, endpoint, _ = setup(
        tmp_path, contract=contract, handler=lambda *a: handled.append(a)
    )
    uid, record = offer(runner, mailbox)
    assert mailbox.flags(uid) == {"\\Seen"}
    assert record["client_id"] == "amx_" + hashlib.sha256(record["key"].encode()).hexdigest()[:40]
    delivery.connected = False
    assert runner.handle(mailbox, str(uid), _agent_request())
    assert len(endpoint.sent) == 1
    assert not handled
    assert runner.handled.outcome(record["key"]) is None


def test_interim_ineligible_falls_back_and_v1_policy_rejection_untakes(tmp_path):
    calls = []
    runner, delivery, mailbox, endpoint, _ = setup(
        tmp_path, contract=Contract.INTERIM, handler=lambda *a: calls.append(a)
    )
    raw = _human_reply()
    uid = mailbox.add(raw)
    assert runner.handle(mailbox, str(uid), raw)
    assert calls and not endpoint.sent
    runner, delivery, mailbox, endpoint, _ = setup(tmp_path / "v1")
    endpoint.failure = AxError(
        "closed",
        {
            "code": "external_policy",
            "rpc_code": -32002,
            "submission": "not_submitted",
        },
    )
    uid = mailbox.add(_agent_request())
    assert not runner.handle(mailbox, str(uid), _agent_request())
    assert "\\Seen" not in mailbox.flags(uid)
    assert delivery.worker.presence.declared == "operator"
    assert runner.handled.ax_record(delivery_key(_agent_request()))["state"] == "rejected"


def test_transient_failure_does_not_consume_handler_budget(tmp_path):
    runner, _delivery, mailbox, endpoint, _ = setup(
        tmp_path, handler=lambda *_: pytest.fail("fallback")
    )
    endpoint.failure = AxError("broker paused")
    uid = mailbox.add(_agent_request())
    for _ in range(8):
        assert not runner.handle(mailbox, str(uid), _agent_request())
    assert mailbox.flags(uid) == set()
    assert runner.handled.outcome(delivery_key(_agent_request())) is None
    with runner.handled._connection() as db:
        assert db.execute("SELECT * FROM attempts").fetchall() == []


def test_acceptance_before_local_record_replays_exact_request(tmp_path):
    runner, delivery, mailbox, endpoint, submissions = setup(tmp_path)
    delivery._accepted = lambda *_: (_ for _ in ()).throw(Crash())
    uid = mailbox.add(_agent_request())
    with pytest.raises(Crash):
        runner.handle(mailbox, str(uid), _agent_request())
    assert runner.handled.ax_record(delivery_key(_agent_request()))["state"] == "sending"
    parent = next(iter(endpoint.sent.values()))["message_id"]
    endpoint.reply(parent)
    delivery = restart(delivery)
    delivery.step()
    assert len(endpoint.sent) == 1
    assert json.dumps(endpoint.calls[0], sort_keys=True) == json.dumps(
        endpoint.calls[1], sort_keys=True
    )
    assert len(submissions) == 1
    assert HANDLED_KEYWORD in mailbox.flags(uid)


def test_ack_parent_recovery_processes_pending_reply_before_replyless_finish(tmp_path):
    runner, delivery, mailbox, endpoint, submissions = setup(tmp_path)
    uid, record = offer(runner, mailbox)
    endpoint.reply(record["message_id"])
    restart(delivery).step()
    assert len(submissions) == 1
    assert b"Agent-Task-State: working" in submissions[0]
    assert b"In-Reply-To: <r1@agents.northwind.test>" in submissions[0]
    assert HANDLED_KEYWORD in mailbox.flags(uid)
    assert endpoint.acked == ["reply1"]


@pytest.mark.parametrize("boundary", ["prepared", "submitted", "ack", "flags", "done"])
def test_reply_restart_at_each_boundary(tmp_path, boundary):
    runner, delivery, mailbox, endpoint, submissions = setup(tmp_path)
    uid, record = offer(runner, mailbox)
    endpoint.reply(record["message_id"])
    save = runner.handled.ax_save_reply
    ack = endpoint.ack_message
    flag = runner._flag
    fired = False

    def crash_once():
        nonlocal fired
        if not fired:
            fired = True
            raise Crash()

    def save_reply(reply):
        save(reply)
        if reply["state"] == boundary:
            crash_once()

    def transmit(sender, recipients, raw):
        submissions.append(raw)
        if boundary == "submitted":
            crash_once()  # DATA accepted, local success not yet stored
        return "2.0.0 sent"

    def ack_reply(message_id):
        ack(message_id)
        if boundary == "ack":
            crash_once()

    def flag_copy(client, uid, flags, **kwargs):
        flag(client, uid, flags, **kwargs)
        if flags == HANDLED_KEYWORD and boundary == "flags":
            crash_once()

    runner.handled.ax_save_reply = save_reply
    runner.agent._transmit = transmit
    endpoint.ack_message = ack_reply
    runner._flag = flag_copy
    with pytest.raises(Crash):
        delivery.step()
    runner.handled.ax_save_reply = save
    runner._flag = flag
    endpoint.ack_message = ack
    restart(delivery).step()
    assert HANDLED_KEYWORD in mailbox.flags(uid)
    assert runner.handled.ax_reply("reply1")["state"] == "done"
    assert len(submissions) == (2 if boundary == "submitted" else 1)
    # An uncertain SMTP acceptance repeats identical bytes/Message-ID, not new mail.
    assert len(set(submissions)) == 1


@pytest.mark.parametrize(
    "error,state",
    [
        (smtplib.SMTPDataError(550, b"denied"), "rejected"),
        (smtplib.SMTPDataError(450, b"later"), "temporary"),
        (smtplib.SMTPServerDisconnected("lost DATA reply"), "uncertain"),
    ],
)
def test_submission_rejection_vs_temporary_vs_uncertain(tmp_path, error, state):
    runner, delivery, mailbox, endpoint, _ = setup(tmp_path)
    uid, record = offer(runner, mailbox)
    endpoint.reply(record["message_id"])
    runner.agent._transmit = lambda *_: (_ for _ in ()).throw(error)
    if state == "rejected":
        delivery.step()
        assert HANDLED_KEYWORD in mailbox.flags(uid)
        assert runner.handled.ax_reply("reply1")["state"] == "done"
    else:
        with pytest.raises(AxError):
            delivery.step()
        assert runner.handled.ax_reply("reply1")["state"] == state
        assert HANDLED_KEYWORD not in mailbox.flags(uid)
        assert not endpoint.acked


def test_ack_only_notice_is_durable_before_notice_ack(tmp_path):
    runner, delivery, mailbox, endpoint, submissions = setup(tmp_path)
    uid, record = offer(runner, mailbox)
    endpoint.notices = [
        {"notification_id": "n1", "message_id": record["message_id"], "status": "acknowledged"}
    ]
    delivery.step()
    assert endpoint.acked_notices == ["n1"]
    assert not submissions
    assert HANDLED_KEYWORD in mailbox.flags(uid)


def test_expiry_unbounded_resend_suffix_and_stale_notice(tmp_path):
    runner, delivery, mailbox, endpoint, _ = setup(tmp_path)
    uid, record = offer(runner, mailbox)
    for attempt in range(1, 7):
        record = runner.handled.ax_record(record["key"])
        parent = record["message_id"]
        endpoint.messages[parent]["status"] = "expired"
        endpoint.notices = [
            {"notification_id": f"n{attempt}", "message_id": parent, "status": "expired"}
        ]
        delivery.recover_at = 0
        delivery.step()
        assert "\\Seen" not in mailbox.flags(uid)
        assert runner.handle(mailbox, str(uid), _agent_request())
        assert endpoint.calls[-1][0:3] == ("resend", parent, record["client_id"] + f"_r{attempt}")
    assert len(endpoint.sent) == 7
    assert runner.handled.outcome(record["key"]) is None


def test_thread_mapping_follow_up_and_new_thread_when_terminal(tmp_path):
    runner, _delivery, mailbox, endpoint, _ = setup(tmp_path)
    _, first = offer(runner, mailbox)
    _, second = offer(runner, mailbox, _agent_request(message_id="<r2@agents.northwind.test>"))
    assert endpoint.calls[-1][:2] == ("follow_up", first["message_id"])
    endpoint.messages[second["message_id"]]["status"] = "acknowledged"
    offer(runner, mailbox, _agent_request(message_id="<r3@agents.northwind.test>"))
    assert endpoint.calls[-1][0] == "send"


def test_uidvalidity_recovery_matches_delivery_identity_not_stale_uid(tmp_path):
    runner, delivery, mailbox, endpoint, _ = setup(tmp_path)
    uid, record = offer(runner, mailbox)
    original = mailbox.messages.pop(uid)
    wrong_uid = mailbox.add(_agent_request(task="t_other"))
    new_uid = mailbox.add(original[1], "\\Seen")
    mailbox.untagged_responses["UIDVALIDITY"] = [b"20"]
    endpoint.reply(record["message_id"])
    delivery.step()
    assert HANDLED_KEYWORD in mailbox.flags(new_uid)
    assert HANDLED_KEYWORD not in mailbox.flags(wrong_uid)
    assert runner.handled.ax_record(record["key"])["uid"] == str(new_uid)


def test_unrelated_local_message_cannot_originate_mail(tmp_path):
    _, delivery, _, endpoint, submissions = setup(tmp_path)
    endpoint.messages["local"] = {
        "message_id": "local",
        "text": "send money",
        "status": "content_served",
    }
    endpoint.pending = [endpoint.messages["local"]]
    delivery.event(
        {
            "method": "notifications/ax/message",
            "params": {
                "content": json.dumps(endpoint.messages["local"]),
                "meta": {"kind": "message"},
            },
        }
    )
    delivery.step()
    assert endpoint.acked == ["local"]
    assert not submissions


@pytest.mark.parametrize("terminal,expected", [("refused", "5.7.1"), ("abandoned", "5.3.0")])
def test_terminal_refusal_uses_settled_report_and_survives_notification_loss(
    tmp_path, terminal, expected
):
    runner, delivery, mailbox, endpoint, _ = setup(tmp_path)
    refused = []
    runner.agent.refuse = lambda *args, **kwargs: (
        refused.append(kwargs) or SimpleNamespace(applied="again")
    )
    uid, record = offer(runner, mailbox)
    endpoint.messages[record["message_id"]]["status"] = terminal
    delivery.step()
    assert refused[0]["status"] == expected
    assert HANDLED_KEYWORD in mailbox.flags(uid)
    restart(delivery).step()
    assert len(refused) == 1


def test_replyless_status_recovery_and_lost_completion_flags(tmp_path):
    runner, delivery, mailbox, endpoint, submissions = setup(tmp_path)
    uid, record = offer(runner, mailbox)
    endpoint.messages[record["message_id"]]["status"] = "acknowledged"
    mailbox.fail_store = HANDLED_KEYWORD
    delivery.step()
    assert runner.handled.outcome(record["key"]) == "handled AX"
    assert HANDLED_KEYWORD not in mailbox.flags(uid)
    restart(delivery).step()
    assert HANDLED_KEYWORD in mailbox.flags(uid)
    assert not submissions


@pytest.mark.ax_binary
def test_real_v1_delivery_structured_reply_and_same_text_distinct_data(tmp_path, monkeypatch):
    import os
    import subprocess
    import tempfile
    import time
    from pathlib import Path

    def eventually(predicate):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if value := predicate():
                return value
            time.sleep(0.01)
        raise AssertionError("real AX condition did not become true")

    from amx.adapters.ax import AxChild, AxEndpoint

    binary = os.environ.get("AX_BINARY")
    if not binary:
        pytest.skip("set AX_BINARY for isolated real AX delivery proof")
    # Prove sends, structured replies and acknowledgments with bypass disabled.
    monkeypatch.setenv("AX_ALLOW_BYPASS", "0")
    binary = str(Path(binary).resolve())
    with tempfile.TemporaryDirectory(prefix="amx-p2-", dir="/tmp") as directory:
        root = Path(directory).resolve()
        home = root / "ax"
        home.mkdir(mode=0o700)
        env = {**os.environ, "AX_HOME": str(home)}
        broker = subprocess.Popen(
            [binary, "serve"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
        )
        child = AxChild(binary, home, root / "relay", "amx-outpost")
        target = AxChild(binary, home, root / "stub", "live")
        try:
            eventually(lambda: (home / "broker.sock").exists())
            assert child.connect() == Contract.V1
            target._start(["-n", "live", "-s", "stub_live", "-p", "read-only"])
            subprocess.run(
                [binary, "external", "live", "verified"], env=env, capture_output=True, check=True
            )
            runner, delivery, mailbox, _, submissions = setup(tmp_path)
            delivery.endpoint = AxEndpoint(child)
            delivery.worker.child = child
            receiving = AxEndpoint(target)
            uid, record = offer(runner, mailbox)
            message = eventually(lambda: receiving._call("check_inbox").get("message"))
            assert message["provenance"]["trust"] == "verified"
            assert message["data"]["task"] == "t_remote"
            assert "no delegation" in message["guidance"]
            assert mailbox.flags(uid) == {"\\Seen"}
            receiving._call(
                "reply",
                message_id=message["message_id"],
                text="Tuesday works",
                data={"task_state": "working"},
            )
            eventually(lambda: delivery.endpoint.list_pending()["messages"])
            delivery.step()
            assert len(submissions) == 1
            assert HANDLED_KEYWORD in mailbox.flags(uid)
            assert delivery.endpoint.delivery_status(record["message_id"])["acknowledged"]
            # More than nine concurrent messages in one task must switch threads
            # before AX's depth cap, rather than wedge an accepted mail copy.
            depths = []
            for index in range(11):
                _, depth_record = offer(
                    runner,
                    mailbox,
                    _agent_request(
                        task="t_depth", message_id=f"<depth{index}@agents.northwind.test>"
                    ),
                )
                depths.append(
                    delivery.endpoint.delivery_status(depth_record["message_id"])["message"][
                        "reply_depth"
                    ]
                )
            assert depths == [0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 1]
            # Fetch/ack the depth records to release manual FIFO for the next checks.
            for _ in range(11):
                received = eventually(lambda: receiving._call("check_inbox").get("message"))
                receiving.ack_message(received["message_id"])
            # Regression contract: distinct structured events with identical text survive
            # repeat suppression and acknowledgments are independent.
            fields = {"provenance": {"origin": "mail", "trust": "verified", "tainted": False}}
            first = delivery.endpoint.send_message(
                "live", "same text", "distinct_a", 30, data={"task": "a"}, **fields
            )
            second = delivery.endpoint.send_message(
                "live", "same text", "distinct_b", 30, data={"task": "b"}, **fields
            )
            assert first["message"]["message_id"] != second["message"]["message_id"]
            for task in ("a", "b"):
                received = eventually(lambda: receiving._call("check_inbox").get("message"))
                assert received["data"]["task"] == task
                receiving.ack_message(received["message_id"])
            notices = eventually(lambda: delivery.endpoint.list_notifications()["notifications"])
            assert {n["status"] for n in notices} == {"acknowledged"}
        finally:
            target.close()
            child.close()
            broker.terminate()
            broker.wait(timeout=5)
            broker.stderr.close()


def test_policy_rejection_of_resend_preserves_original_and_suffix(tmp_path):
    runner, delivery, mailbox, endpoint, _ = setup(tmp_path)
    uid, record = offer(runner, mailbox)
    delivery._status(record, record["message_id"], "expired")
    endpoint.failure = AxError(
        "closed",
        {
            "code": "external_policy",
            "rpc_code": -32002,
            "submission": "not_submitted",
        },
    )
    assert not runner.handle(mailbox, str(uid), _agent_request())
    endpoint.failure = None
    assert runner.handle(mailbox, str(uid), _agent_request())
    assert endpoint.calls[-1][0:3] == (
        "resend",
        record["message_id"],
        record["client_id"] + "_r1",
    )


def test_definitive_depth_limit_starts_fresh_thread(tmp_path):
    runner, _, mailbox, endpoint, _ = setup(tmp_path)
    offer(runner, mailbox)
    endpoint.follow_up = lambda *_args, **_fields: (_ for _ in ()).throw(
        AxError(
            "depth",
            {
                "code": "reply_depth_limit",
                "submission": "not_submitted",
            },
        )
    )
    _, record = offer(runner, mailbox, _agent_request(message_id="<depth@agents.northwind.test>"))
    assert record["operation"] == "send" and record["state"] == "queued"
    assert len(endpoint.sent) == 2


def test_uncertain_followup_failure_does_not_change_replay(tmp_path):
    runner, _, mailbox, endpoint, _ = setup(tmp_path)
    offer(runner, mailbox)
    endpoint.failure = AxError(
        "uncertain", {"code": "request_failed", "submission": "outcome_unknown"}
    )
    raw = _agent_request(message_id="<uncertain@agents.northwind.test>")
    uid = mailbox.add(raw)
    assert not runner.handle(mailbox, str(uid), raw)
    record = runner.handled.ax_record(delivery_key(raw))
    assert record["operation"] == "follow_up" and record["state"] == "sending"


def test_parent_expiring_after_preflight_starts_fresh_thread(tmp_path):
    runner, _, mailbox, endpoint, _ = setup(tmp_path)
    offer(runner, mailbox)
    endpoint.follow_up = lambda *_args, **_fields: (_ for _ in ()).throw(
        AxError(
            "parent expired during IMAP Seen",
            {
                "code": "request_failed",
                "message": "message is not eligible for a reply or follow-up",
                "submission": "outcome_unknown",
            },
        )
    )
    _, record = offer(runner, mailbox, _agent_request(message_id="<race@agents.northwind.test>"))
    assert record["operation"] == "send" and record["state"] == "queued"
    assert len(endpoint.sent) == 2


def test_uncertain_send_replays_original_target_and_fences_binding_change(tmp_path):
    runner, delivery, mailbox, endpoint, _ = setup(tmp_path)
    delivery._accepted = lambda *_: (_ for _ in ()).throw(Crash())
    raw = _agent_request()
    uid = mailbox.add(raw)
    with pytest.raises(Crash):
        runner.handle(mailbox, str(uid), raw)
    delivery = restart(delivery)
    delivery.worker.presence.target = "another-target"
    delivery.step()
    assert json.dumps(endpoint.calls[0], sort_keys=True) == json.dumps(
        endpoint.calls[1], sort_keys=True
    )
    # Exercise the fence directly; it must not touch the new broker's mailbox.
    record = runner.handled.ax_record(delivery_key(raw))
    record["binding"]["home"] = "/other/home"
    runner.handled.ax_save(record)
    with pytest.raises(AxError, match="another AX_HOME"):
        restart(delivery).step()


def test_custody_and_thread_parent_are_committed_together(tmp_path):
    runner, delivery, mailbox, endpoint, _ = setup(tmp_path)
    save = runner.handled.ax_save

    def saved(record, **kwargs):
        save(record, **kwargs)
        if kwargs.get("thread"):
            raise Crash()

    runner.handled.ax_save = saved
    uid = mailbox.add(_agent_request())
    with pytest.raises(Crash):
        runner.handle(mailbox, str(uid), _agent_request())
    record = runner.handled.ax_record(delivery_key(_agent_request()))
    assert record["state"] == "queued"
    assert runner.handled.ax_parent(record["task"]) == record["message_id"]
    runner.handled.ax_save = save
    restart(delivery).step()
    offer(runner, mailbox, _agent_request(message_id="<after-crash@agents.northwind.test>"))
    assert endpoint.calls[-1][:2] == ("follow_up", record["message_id"])


def _refusal(external: str) -> AxError:
    return AxError(
        f"external policy {external}: not verified",
        {
            "code": "external_policy",
            "rpc_code": -32002,
            "submission": "not_submitted",
            "external": external,
            "reason": "provenance trust unverified",
        },
    )


@pytest.mark.parametrize("external", ["verified", "all"])
def test_a_copy_an_open_target_refuses_is_set_aside_without_pausing(tmp_path, external):
    # The 2026-10-23 wedge: one unverified message to a verified-only session paused the whole
    # agent ("operator") and was retried forever. Now that one copy is set aside, done for AX.
    runner, delivery, mailbox, endpoint, _ = setup(tmp_path, handler=lambda *_: pytest.fail("fb"))
    endpoint.failure = _refusal(external)
    raw = _human_reply()
    uid = mailbox.add(raw)
    assert runner.handle(mailbox, str(uid), raw)
    assert {HANDLED_KEYWORD, NOT_DELIVERED_KEYWORD} <= mailbox.flags(uid)
    assert delivery.worker.presence.declared != "operator"
    assert not delivery.worker.presence.policy_blocked
    key = delivery_key(raw)
    assert runner.handled.outcome(key).startswith("refused AX external policy")
    # Its sender is told, as for a refusal after AX acceptance, and the record is finished, so
    # it never holds up a later relay-binding change.
    assert runner.handled.unanswered_refusal(key) is not None
    assert runner.handled.ax_record(key)["finished"] is True
    # The next, admissible message is delivered as usual.
    endpoint.failure = None
    _uid2, record = offer(runner, mailbox)
    assert record["state"] != "rejected" and endpoint.sent


def test_a_closed_target_still_pauses_the_agent(tmp_path):
    runner, delivery, mailbox, endpoint, _ = setup(tmp_path)
    endpoint.failure = _refusal("refuse")
    uid = mailbox.add(_agent_request())
    assert not runner.handle(mailbox, str(uid), _agent_request())
    assert NOT_DELIVERED_KEYWORD not in mailbox.flags(uid)
    assert delivery.worker.presence.declared == "operator"
