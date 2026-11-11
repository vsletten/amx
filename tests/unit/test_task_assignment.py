"""SH-01: delivery assigns correlation, not task lifecycle or trust."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser

import pytest
from test_lmtp import FailOnceMailbox, _deliver, _handler, _queued_handler
from test_submission import RecordingMailbox, _config

from amx.adapters.lmtp import LmtpHandler
from amx.adapters.submission import SubmissionError, SubmissionService
from amx.journal import Journal
from amx.profile import ProfileError, parse
from amx.runtime import HandlerRegistry
from amx.sdk import Agent
from amx.store import Store
from amx.tasks import valid_token


def human(*, opens=True, token=None):
    message = EmailMessage(policy=policy.SMTP)
    message["From"] = "pat@plainmail.test"
    message["To"] = "intake@agents.example.test"
    message["Message-ID"] = "<first@plainmail.test>"
    message["Subject"] = "Please help"
    message["Agent-Lane"] = "human"
    message["Agent-Trust"] = "low"
    message["Agent-Grant-Can-Open-Tasks"] = str(opens).lower()
    if token:
        message["Agent-Task-Assigned"] = token
    message.set_content("Hello")
    return message.as_bytes()


def test_delivery_assigns_once_without_opening_task_and_sdk_replies(tmp_path):
    seen = []
    handler, store, _, _ = _handler(tmp_path, intake_handler=lambda msg, ctx: seen.append(msg))
    raw = human()
    assert _deliver(handler, raw, ["intake@agents.example.test"]).values[0].startswith("250")
    inbound = seen[0]
    assert valid_token(inbound.task)
    assert inbound.task_state is None
    assert store.task(inbound.task) is None
    assert inbound.lane == "human" and inbound.trust == "low"
    assert parse(inbound.raw).task == inbound.task
    assert (
        BytesParser(policy=policy.default).parsebytes(inbound.raw)["Agent-Task-Assigned"]
        == inbound.task
    )
    assert _deliver(handler, raw, ["intake@agents.example.test"]).values[0].startswith("250")
    assert len(seen) == 1
    agent = Agent("intake@agents.example.test", "smtp://localhost", "fixture")
    sent = []
    agent._transmit = lambda sender, recipients, raw: sent.append(raw) or "2.0.0 sent"
    reply = agent.parse(inbound.raw).reply(text="Thanks")
    message = parse(sent[0])
    assert reply.task == inbound.task
    assert message.thread.in_reply_to == "<first@plainmail.test>"
    assert message.thread.references == ("<first@plainmail.test>",)


def test_delivery_retry_keeps_assignment_and_taint(tmp_path):
    seen = []
    handler, store, _, _ = _handler(
        tmp_path, mailbox=FailOnceMailbox(), intake_handler=lambda msg, ctx: seen.append(msg)
    )
    raw = b"Agent-Taint: directs-recipient\r\n" + human()
    assert _deliver(handler, raw, ["intake@agents.example.test"]).values[0].startswith("450")
    token = seen[0].task
    assert token and store.task_taint("intake", token) == "directs-recipient"
    assert _deliver(handler, raw, ["intake@agents.example.test"]).values[0].startswith("250")
    assert len(seen) == 1
    assert store.task(token) is None
    assert (
        Store(store.path).assigned_task(
            "intake@agents.example.test", "<first@plainmail.test>", "unused"
        )
        == token
    )


def test_ineligible_human_gets_no_assignment(tmp_path):
    seen = []
    handler, store, _, _ = _handler(tmp_path, intake_handler=lambda msg, ctx: seen.append(msg))
    assert (
        _deliver(handler, human(opens=False), ["intake@agents.example.test"])
        .values[0]
        .startswith("250")
    )
    assert seen[0].task is None
    assert store.rows("SELECT * FROM task_assignments") == []


def test_assignment_is_recipient_scoped_and_atomic(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    with ThreadPoolExecutor(max_workers=4) as pool:
        tokens = list(
            pool.map(lambda i: store.assigned_task("intake@x", "<one@x>", f"t_{i}"), range(8))
        )
    assert len(set(tokens)) == 1
    assert store.assigned_task("echo@x", "<one@x>", "t_other") == "t_other"
    assert store.task(tokens[0]) is None


@pytest.mark.parametrize("tainted", [False, True])
def test_ctx_reply_opens_only_at_authenticated_submission_and_preserves_holds(tmp_path, tainted):
    config = _config(tmp_path)
    store = Store(tmp_path / "journal.sqlite")
    journal = Journal(tmp_path, store)
    mailbox = RecordingMailbox()
    reinjected = []
    submission = SubmissionService(
        config,
        journal,
        mailbox=mailbox,
        reinject=lambda sender, recipients, raw: reinjected.append(raw),
    )
    outbound = Agent("scheduler@agents.northwind.test", "smtp://localhost", "fixture")

    def transmit(sender, recipients, raw):
        submission.submit("scheduler", "secret-scheduler-token", raw)
        return "2.0.0 sent"

    outbound._transmit = transmit
    seen = []
    registry = HandlerRegistry()

    def handle(message, context):
        assert store.task(message.task) is None
        seen.append(message)
        context.reply(text="Thanks", task_state="completed")

    registry.register("scheduler", handle)
    delivery = LmtpHandler(config, store, journal, registry, mailbox, {"scheduler": outbound})
    raw = human().replace(b"intake@agents.example.test", b"scheduler@agents.northwind.test")
    if tainted:
        raw = b"Agent-Taint: directs-recipient\r\n" + raw
    assert _deliver(delivery, raw, ["scheduler@agents.northwind.test"]).values[0].startswith("250")
    task = seen[0].task
    assert store.task(task)["state"] == "completed"
    if tainted:
        assert not reinjected
        assert store.rows("SELECT rule FROM holds")[0]["rule"] == "tainted-input"
    else:
        reply = parse(reinjected[0])
        assert reply.task == task
        assert reply.thread.in_reply_to == "<first@plainmail.test>"
    # Delivery correlation does not override a local agent's replies-only grant.
    submission.config = replace(
        config, trust=tuple(replace(grant, can_open_tasks=False) for grant in config.trust)
    )
    prepared = []
    outbound._transmit = lambda sender, recipients, raw: prepared.append(raw) or "2.0.0 sent"
    outbound.parse(human(token="t_new")).reply(text="Not authorized")
    with pytest.raises(SubmissionError, match="not allowed to open tasks"):
        submission.submit("scheduler", "secret-scheduler-token", prepared[0])


@pytest.mark.parametrize("token", ["../bad", "", "UPPER"])
def test_invalid_assigned_token_is_rejected(token):
    raw = human(token="placeholder").replace(b"placeholder", token.encode())
    with pytest.raises(ProfileError, match="Agent-Task-Assigned"):
        parse(raw)


def test_queued_restart_recovers_the_journaled_assignment(tmp_path):
    handler, store, _, _, registry = _queued_handler(tmp_path)
    registry.stop()
    recipient = "intake@agents.example.test"
    task = store.assigned_task(recipient, "<first@plainmail.test>", "t_recovered")
    handler.journal.append_delivery(
        human(token=task),
        recipient=recipient,
        agent="intake",
        identity=None,
        task=task,
        message_id="<first@plainmail.test>",
    )
    store.mark_delivery_accepted(recipient, "<first@plainmail.test>")
    recovered, _, calls, _, registry = _queued_handler(tmp_path)
    try:
        assert recovered.recover() == 1
        registry.join("intake")
        assert calls == [("intake", task)]
        assert store.task(task) is None
    finally:
        registry.stop()


def test_remote_filed_copy_exposes_assignment_to_sdk(tmp_path):
    handler, store, _, _ = _handler(tmp_path)
    mailbox = RecordingMailbox()
    handler.mailbox = mailbox
    handler.registry.register("intake", "mailbox-only", mode="remote")
    recipient = "intake@agents.example.test"
    assert _deliver(handler, human(), [recipient]).values[0].startswith("250")
    [(address, raw, folder)] = mailbox.appended
    assert address == recipient and folder == "INBOX"
    received = Agent(recipient, "smtp://localhost", "fixture").parse(raw)
    assert received.task and valid_token(received.task)
    assert store.task(received.task) is None
