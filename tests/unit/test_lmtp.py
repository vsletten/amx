from __future__ import annotations

import asyncio
import sqlite3
import threading
from dataclasses import replace
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path
from types import SimpleNamespace

import pytest

from amx.adapters.lmtp import LmtpHandler, LmtpProtocol, RecipientStatuses
from amx.config import AgentConfig, GatewayConfig, LimitsConfig, MailboxConfig, TrustGrant
from amx.journal import Journal
from amx.profile import SCHEMA_BASE, build
from amx.runtime import Context, HandlerRegistry, Refuse, TryLater
from amx.store import Store


class RecordingMailbox:
    def __init__(self) -> None:
        self.addresses: list[str] = []

    def append(self, address: str, _raw: bytes, folder: str = "INBOX") -> None:
        assert folder == "INBOX"
        self.addresses.append(address)


class FailOnceMailbox(RecordingMailbox):
    def __init__(self) -> None:
        super().__init__()
        self.attempts = 0

    def append(self, address: str, raw: bytes, folder: str = "INBOX") -> None:
        self.attempts += 1
        if self.attempts == 1:
            raise OSError("mailbox unavailable")
        super().append(address, raw, folder)


class RecordingWriter:
    def __init__(self) -> None:
        self.content = b""

    def write(self, value: bytes) -> None:
        self.content += value

    async def drain(self) -> None:
        return None


def _config(tmp_path) -> GatewayConfig:
    return GatewayConfig(
        domain="example.test",
        agent_domain="agents.example.test",
        data_dir=tmp_path,
        agents={
            "intake": AgentConfig(handler="mailbox-only"),
            "echo": AgentConfig(handler="mailbox-only"),
        },
        trust=(),
        limits=LimitsConfig(),
        mailbox=MailboxConfig(host="mail.example.test"),
    )


def _agent_raw(task: str = "t_multi") -> bytes:
    message = build(
        sender="scheduler@agents.sender.test",
        to=f"intake+{task}@agents.example.test",
        subject="LMTP multi-recipient fixture",
        intent="request",
        task=task,
        task_state="submitted",
        text="Process this request.",
        payload={"action": "intake"},
        schema=f"{SCHEMA_BASE}request.json",
        message_id="<multi@agents.sender.test>",
    )
    message["Agent-Lane"] = "agent"
    message["Agent-Trust"] = "verified"
    message["Agent-Verified-Domain"] = "agents.sender.test"
    message["Agent-Verified-Selector"] = "scheduler"
    return message.as_bytes(policy=policy.SMTP)


def _human_raw(*, trust: str = "low") -> bytes:
    message = EmailMessage(policy=policy.SMTP)
    message["From"] = "pat@people.test"
    message["To"] = "intake+t_human@agents.example.test"
    message["Subject"] = "Human request"
    message["Message-ID"] = "<human@people.test>"
    message["Agent-Lane"] = "human"
    message["Agent-Trust"] = trust
    message.set_content("Hello")
    return message.as_bytes(policy=policy.SMTP)


def _handler(tmp_path, *, intake_handler=None, mailbox=None):
    config = _config(tmp_path)
    store = Store(tmp_path / "journal.sqlite")
    journal = Journal(tmp_path, store)
    calls: list[tuple[str, str | None]] = []
    registry = HandlerRegistry()

    def record(message, context: Context) -> None:
        calls.append((context.agent, message.task))

    registry.register("intake", intake_handler or record)
    registry.register("echo", record)
    mailbox = mailbox or RecordingMailbox()
    handler = LmtpHandler(config, store, journal, registry, mailbox)  # type: ignore[arg-type]
    return handler, store, calls, mailbox


def _deliver(handler: LmtpHandler, raw: bytes, recipients: list[str]) -> RecipientStatuses:
    envelope = SimpleNamespace(original_content=raw, rcpt_tos=recipients)
    return asyncio.run(handler.handle_DATA(None, None, envelope))


def test_lmtp_processes_and_deduplicates_every_recipient(tmp_path) -> None:
    handler, store, calls, mailbox = _handler(tmp_path)
    recipients = [
        "intake+t_multi@agents.example.test",
        "echo+t_multi@agents.example.test",
    ]

    first = _deliver(handler, _agent_raw(), recipients)
    assert len(first.values) == 2
    assert all(status.startswith("250 2.0.0 delivered") for status in first.values)
    assert calls == [("intake", "t_multi"), ("echo", "t_multi")]
    assert mailbox.addresses == ["intake@agents.example.test", "echo@agents.example.test"]
    deliveries = store.rows("SELECT * FROM deliveries ORDER BY recipient")
    assert [row["recipient"] for row in deliveries] == sorted(recipients)

    replay = _deliver(handler, _agent_raw(), recipients)
    assert replay.values == (
        "250 2.0.0 duplicate already delivered",
        "250 2.0.0 duplicate already delivered",
    )
    assert calls == [("intake", "t_multi"), ("echo", "t_multi")]
    assert len(store.rows("SELECT * FROM journal")) == 2


def test_a_locked_store_defers_only_its_recipient_and_the_retry_completes(tmp_path) -> None:
    """aiosmtpd answers an exception with 500, which the MTA would bounce: a store failure is a
    451 for its own recipient, and the MTA's retry finishes the delivery once."""
    handler, store, calls, mailbox = _handler(tmp_path)
    recipients = ["intake+t_multi@agents.example.test", "echo+t_multi@agents.example.test"]
    append_delivery = handler.journal.append_delivery

    def locked_for_echo(raw: bytes, **kwargs):
        if kwargs["agent"] == "echo":
            raise sqlite3.OperationalError("database is locked")
        return append_delivery(raw, **kwargs)

    handler.journal.append_delivery = locked_for_echo  # type: ignore[method-assign]
    first = _deliver(handler, _agent_raw(), recipients)
    assert first.values[0].startswith("250 2.0.0 delivered")
    assert first.values[1] == "451 4.3.0 gateway store unavailable: database is locked"

    handler.journal.append_delivery = append_delivery  # type: ignore[method-assign]
    retry = _deliver(handler, _agent_raw(), recipients)
    assert retry.values[0] == "250 2.0.0 duplicate already delivered"
    assert retry.values[1].startswith("250 2.0.0 delivered")
    assert calls == [("intake", "t_multi"), ("echo", "t_multi")]
    assert mailbox.addresses == ["intake@agents.example.test", "echo@agents.example.test"]
    assert len(store.rows("SELECT * FROM journal")) == 2


def test_lmtp_try_later_reuses_journal_then_completes_once(tmp_path) -> None:
    attempts = 0

    def try_once(_message, _context: Context) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise TryLater("busy")

    handler, store, _calls, mailbox = _handler(tmp_path, intake_handler=try_once)
    recipient = "intake+t_multi@agents.example.test"
    raw = _agent_raw()

    first = _deliver(handler, raw, [recipient])
    assert first.values == ("450 4.3.0 busy",)
    second = _deliver(handler, raw, [recipient])
    assert second.values[0].startswith("250 2.0.0 delivered")

    assert attempts == 2
    assert mailbox.addresses == ["intake@agents.example.test"]
    assert len(store.rows("SELECT * FROM journal")) == 1
    assert len(store.rows("SELECT * FROM deliveries")) == 1


def test_lmtp_refuse_is_persisted_without_mailbox_or_completion(tmp_path) -> None:
    attempts = 0

    def refuse(_message, _context: Context) -> None:
        nonlocal attempts
        attempts += 1
        raise Refuse("5.7.1", "not permitted")

    handler, store, _calls, mailbox = _handler(tmp_path, intake_handler=refuse)
    recipient = "intake+t_multi@agents.example.test"
    raw = _agent_raw()

    first = _deliver(handler, raw, [recipient])
    replay = _deliver(handler, raw, [recipient])

    assert first.values == ("550 5.7.1 not permitted",)
    assert replay.values == first.values
    assert attempts == 1
    assert mailbox.addresses == []
    assert len(store.rows("SELECT * FROM journal")) == 1
    assert store.rows("SELECT * FROM deliveries") == []
    progress = store.delivery_progress(recipient, "<multi@agents.sender.test>")
    assert progress is not None
    assert progress["state"] == "refused"


def test_lmtp_mailbox_retry_does_not_rerun_successful_handler(tmp_path) -> None:
    attempts = 0

    def succeed(_message, _context: Context) -> None:
        nonlocal attempts
        attempts += 1

    mailbox = FailOnceMailbox()
    handler, store, _calls, _mailbox = _handler(tmp_path, intake_handler=succeed, mailbox=mailbox)
    recipient = "intake+t_multi@agents.example.test"
    raw = _agent_raw()

    first = _deliver(handler, raw, [recipient])
    second = _deliver(handler, raw, [recipient])
    replay = _deliver(handler, raw, [recipient])

    assert first.values == ("450 4.3.0 mailbox error: mailbox unavailable",)
    assert second.values[0].startswith("250 2.0.0 delivered")
    assert replay.values == ("250 2.0.0 duplicate already delivered",)
    assert attempts == 1
    assert mailbox.attempts == 2
    assert mailbox.addresses == ["intake@agents.example.test"]
    assert len(store.rows("SELECT * FROM journal")) == 1
    assert len(store.rows("SELECT * FROM deliveries")) == 1


def test_lmtp_preflights_all_task_tokens_before_any_delivery(tmp_path) -> None:
    handler, store, calls, mailbox = _handler(tmp_path)
    statuses = _deliver(
        handler,
        _agent_raw("t_closed"),
        [
            "intake+t_other@agents.example.test",
            "echo+t_closed@agents.example.test",
        ],
    )
    assert statuses.values == (
        "550 5.7.1 Agent-Task does not match recipient subaddress token",
        "450 4.3.0 another recipient failed transaction preflight",
    )
    assert calls == []
    assert mailbox.addresses == []
    assert store.rows("SELECT * FROM deliveries") == []
    assert store.rows("SELECT * FROM journal") == []


def test_lmtp_fails_closed_on_duplicate_or_inconsistent_transport_metadata(tmp_path) -> None:
    handler, store, calls, mailbox = _handler(tmp_path)
    inconsistent = _human_raw(trust="verified")
    duplicate = _human_raw().replace(
        b"Agent-Lane: human\r\n",
        b"Agent-Lane: human\r\nAgent-Lane: agent\r\n",
    )
    forged_agent = _human_raw().replace(
        b"Agent-Lane: human\r\nAgent-Trust: low\r\n",
        b"Agent-Lane: agent\r\nAgent-Trust: verified\r\n"
        b"Agent-Verified-Domain: agents.sender.test\r\n"
        b"Agent-Verified-Selector: scheduler\r\n",
    )

    for raw in (inconsistent, duplicate, forged_agent):
        result = _deliver(handler, raw, ["intake+t_human@agents.example.test"])
        assert result.values[0].startswith("550 5.6.0")
    assert calls == []
    assert mailbox.addresses == []
    assert store.rows("SELECT * FROM deliveries") == []


def test_lmtp_accepts_local_system_report_without_milter_metadata(tmp_path) -> None:
    handler, store, calls, mailbox = _handler(tmp_path)
    raw = Path("spec/corpus/10-dsn-failed.eml").read_bytes()
    result = _deliver(handler, raw, ["intake+t_dsn@agents.example.test"])
    assert result.values[0].startswith("250 2.0.0 delivered")
    assert calls == [("intake", "t_dsn")]
    task = store.task("t_dsn")
    assert task is not None
    assert task["state"] == "failed"
    assert mailbox.addresses == ["intake@agents.example.test"]


def test_lmtp_human_lane_binds_task_from_unique_envelope_subaddress(tmp_path) -> None:
    handler, store, calls, mailbox = _handler(tmp_path)
    raw = _human_raw().replace(
        b"To: intake+t_human@agents.example.test",
        b"To: intake@agents.example.test",
    )
    result = _deliver(handler, raw, ["intake+t_human@agents.example.test"])
    assert result.values[0].startswith("250 2.0.0 delivered")
    assert calls == [("intake", "t_human")]
    assert store.task("t_human") is None
    assert mailbox.addresses == ["intake@agents.example.test"]


def test_lmtp_binds_handler_context_to_outbound_submission(tmp_path) -> None:
    outbound_calls: list[tuple[str, dict[str, object]]] = []

    class Outbound:
        def send(self, **message: object) -> str:
            outbound_calls.append(("send", message))
            return "sent"

    def local_handler(_message, context: Context) -> None:
        assert context.send(to="pat@people.test", intent="request", text="Hello") == "sent"
        assert context.reply(intent="response", text="Done") == "sent"

    lmtp, _store, _calls, _mailbox = _handler(tmp_path, intake_handler=local_handler)
    lmtp.outbound_agents["intake"] = Outbound()  # type: ignore[assignment]
    result = _deliver(lmtp, _agent_raw(), ["intake+t_multi@agents.example.test"])
    assert result.values[0].startswith("250 2.0.0 delivered")
    assert outbound_calls[0][0] == "send"
    assert outbound_calls[1][0] == "send"
    assert outbound_calls[1][1]["task"] == "t_multi"
    assert outbound_calls[1][1]["in_reply_to"] == "<multi@agents.sender.test>"


def test_lmtp_protocol_emits_one_wire_status_per_recipient() -> None:
    protocol = object.__new__(LmtpProtocol)
    writer = RecordingWriter()
    protocol._writer = writer
    protocol.session = SimpleNamespace(peer=("test", 1))
    protocol.enable_SMTPUTF8 = True

    asyncio.run(protocol.push(RecipientStatuses(("250 2.0.0 first", "550 5.1.1 second"))))
    assert writer.content == b"250 2.0.0 first\r\n550 5.1.1 second\r\n"


def _queued_handler(tmp_path, *, intake_handler=None, watermark: int = 2, mailbox=None):
    config = _config(tmp_path)
    config = replace(
        config,
        agents={
            **config.agents,
            "intake": AgentConfig(handler="mailbox-only", mode="queued", watermark=watermark),
        },
    )
    store = Store(tmp_path / "journal.sqlite")
    journal = Journal(tmp_path, store)
    calls: list[tuple[str, str | None]] = []
    registry = HandlerRegistry()

    def record(message, context: Context) -> None:
        calls.append((context.agent, message.task))

    registry.register("intake", intake_handler or record, mode="queued", watermark=watermark)
    registry.register("echo", record)
    mailbox = mailbox or RecordingMailbox()
    handler = LmtpHandler(
        config,
        store,
        journal,
        registry,
        mailbox,  # type: ignore[arg-type]
        retry_delays=(0.01, 0.01),
    )
    return handler, store, calls, mailbox, registry


def _agent_raw_with(task: str, message_id: str) -> bytes:
    return _agent_raw(task).replace(b"<multi@agents.sender.test>", message_id.encode())


def test_queued_lmtp_accepts_into_the_queue_then_a_worker_completes(tmp_path) -> None:
    handler, store, calls, mailbox, registry = _queued_handler(tmp_path)
    result = _deliver(handler, _agent_raw("t_q"), ["intake+t_q@agents.example.test"])
    assert result.values[0].startswith("250 2.0.0 queued journal=1")
    registry.join("intake")
    assert calls == [("intake", "t_q")]
    assert mailbox.addresses == ["intake@agents.example.test"]
    assert store.delivered("intake+t_q@agents.example.test", "<multi@agents.sender.test>")
    task = store.task("t_q")
    assert task is not None and task["state"] == "submitted"
    replay = _deliver(handler, _agent_raw("t_q"), ["intake+t_q@agents.example.test"])
    assert replay.values == ("250 2.0.0 duplicate already delivered",)
    registry.stop()


def test_queued_lmtp_full_queue_answers_450_before_journaling(tmp_path) -> None:
    import threading

    gate = threading.Event()
    handler, store, _calls, _mailbox, registry = _queued_handler(
        tmp_path, intake_handler=lambda _message, _context: gate.wait(5), watermark=1
    )
    first = _deliver(
        handler, _agent_raw_with("t_a", "<a@sender.test>"), ["intake+t_a@agents.example.test"]
    )
    assert first.values[0].startswith("250 2.0.0 queued")
    busy = _deliver(
        handler, _agent_raw_with("t_b", "<b@sender.test>"), ["intake+t_b@agents.example.test"]
    )
    assert busy.values == ("450 4.2.1 agent busy, retry",)
    assert len(store.rows("SELECT * FROM journal")) == 1
    replay = _deliver(
        handler, _agent_raw_with("t_a", "<a@sender.test>"), ["intake+t_a@agents.example.test"]
    )
    assert replay.values == ("250 2.0.0 duplicate already queued",)
    gate.set()
    registry.join("intake")
    registry.stop()


def test_queued_lmtp_keeps_the_rcpt_admission_counted_until_the_job_is_queued(tmp_path) -> None:
    import threading

    gate = threading.Event()
    handler, _store, _calls, _mailbox, registry = _queued_handler(
        tmp_path, intake_handler=lambda _message, _context: gate.wait(5)
    )
    registry.bind(registry.reserve("intake"), "<multi@agents.sender.test>")
    depths: list[int] = []
    append_delivery = handler.journal.append_delivery

    def observing_append(*args, **kwargs):
        depths.append(registry.depth("intake"))
        return append_delivery(*args, **kwargs)

    handler.journal.append_delivery = observing_append  # type: ignore[method-assign]
    result = _deliver(handler, _agent_raw("t_q"), ["intake+t_q@agents.example.test"])
    assert result.values[0].startswith("250 2.0.0 queued")
    assert depths == [1], "the message must count toward depth while it is being journaled"
    assert registry.depth("intake") == 1, "admission became the queue slot, not an extra one"
    gate.set()
    registry.join("intake")
    assert registry.depth("intake") == 0
    registry.stop()


def test_lmtp_drops_the_admission_when_delivery_fails_early(tmp_path) -> None:
    handler, _store, _calls, _mailbox, registry = _queued_handler(tmp_path)
    registry.bind(registry.reserve("intake"), "<multi@agents.sender.test>")
    unknown = _deliver(handler, _agent_raw(), ["nobody+t_multi@agents.example.test"])
    assert unknown.values == ("550 5.1.1 unknown agent",)
    assert registry.depth("intake") == 1, "a different recipient must not settle intake's"
    bad = _deliver(
        handler, b"From: x@y.test\r\n\r\nno metadata\r\n", ["intake@agents.example.test"]
    )
    assert bad.values[0].startswith("550 5.6.0")
    assert registry.depth("intake") == 1, "only the matching Message-ID settles"
    refused = _deliver(
        handler, _agent_raw("t_other"), ["intake+t_multi@agents.example.test"]
    )  # Agent-Task mismatch fails preflight
    assert refused.values[0].startswith("550 5.7.1")
    assert registry.depth("intake") == 0
    registry.stop()


def test_queued_worker_retries_mailbox_failure_without_rerunning_the_handler(tmp_path) -> None:
    handler, store, calls, mailbox, registry = _queued_handler(tmp_path, mailbox=FailOnceMailbox())
    result = _deliver(handler, _agent_raw("t_q"), ["intake+t_q@agents.example.test"])
    assert result.values[0].startswith("250 2.0.0 queued")
    registry.join("intake")
    assert calls == [("intake", "t_q")]
    assert mailbox.attempts == 2
    assert store.delivered("intake+t_q@agents.example.test", "<multi@agents.sender.test>")
    registry.stop()


def test_queued_worker_persists_refusal_and_retries_try_later(tmp_path) -> None:
    attempts: list[str] = []

    def flaky(message, _context: Context) -> None:
        attempts.append(message.task)
        if message.task == "t_refuse":
            raise Refuse("5.7.1", "not for me")
        if len(attempts) == 1:
            raise TryLater("busy")

    handler, store, _calls, mailbox, registry = _queued_handler(tmp_path, intake_handler=flaky)
    _deliver(handler, _agent_raw("t_later"), ["intake+t_later@agents.example.test"])
    registry.join("intake")
    assert attempts == ["t_later", "t_later"]
    assert store.delivered("intake+t_later@agents.example.test", "<multi@agents.sender.test>")

    raw = _agent_raw_with("t_refuse", "<refuse@sender.test>")
    _deliver(handler, raw, ["intake+t_refuse@agents.example.test"])
    registry.join("intake")
    progress = store.delivery_progress(
        "intake+t_refuse@agents.example.test", "<refuse@sender.test>"
    )
    assert progress is not None and progress["state"] == "refused"
    assert mailbox.addresses == ["intake@agents.example.test"]
    registry.stop()


def test_recover_requeues_only_deliveries_answered_250_queued(tmp_path) -> None:
    first, _store, _calls, _mailbox, first_registry = _queued_handler(tmp_path)
    # Simulate the crash: journaled rows, one answered "250 queued", one answered 4xx.
    for task, message_id in (("t_q", "<accepted@sender.test>"), ("t_x", "<deferred@sender.test>")):
        first.journal.append_delivery(
            _agent_raw_with(task, message_id),
            recipient=f"intake+{task}@agents.example.test",
            agent="intake",
            identity="agents.sender.test",
            task=task,
            message_id=message_id,
        )
    first.store.mark_delivery_accepted("intake+t_q@agents.example.test", "<accepted@sender.test>")
    first_registry.stop()

    restarted, store, calls, mailbox, registry = _queued_handler(tmp_path)
    assert restarted.recover() == 1
    registry.join("intake")
    assert calls == [("intake", "t_q")], "the 4xx delivery still belongs to the sending MTA"
    assert mailbox.addresses == ["intake@agents.example.test"]
    assert store.delivered("intake+t_q@agents.example.test", "<accepted@sender.test>")
    assert restarted.recover() == 0
    registry.stop()


def test_recover_resumes_a_handled_delivery_without_rerunning_the_handler(tmp_path) -> None:
    first, store, _calls, _mailbox, first_registry = _queued_handler(tmp_path)
    first.journal.append_delivery(
        _agent_raw("t_q"),
        recipient="intake+t_q@agents.example.test",
        agent="intake",
        identity="agents.sender.test",
        task="t_q",
        message_id="<multi@agents.sender.test>",
    )
    store.mark_delivery_accepted("intake+t_q@agents.example.test", "<multi@agents.sender.test>")
    store.mark_handler_completed("intake+t_q@agents.example.test", "<multi@agents.sender.test>")
    first_registry.stop()

    restarted, store, calls, mailbox, registry = _queued_handler(tmp_path)
    assert restarted.recover() == 1
    registry.join("intake")
    assert calls == []
    assert mailbox.addresses == ["intake@agents.example.test"]
    assert store.delivered("intake+t_q@agents.example.test", "<multi@agents.sender.test>")
    registry.stop()


def test_recover_skips_a_delivery_whose_raw_file_is_missing(tmp_path) -> None:
    first, store, _calls, _mailbox, first_registry = _queued_handler(tmp_path)
    entry = first.journal.append_delivery(
        _agent_raw("t_q"),
        recipient="intake+t_q@agents.example.test",
        agent="intake",
        identity="agents.sender.test",
        task="t_q",
        message_id="<multi@agents.sender.test>",
    )
    store.mark_delivery_accepted("intake+t_q@agents.example.test", "<multi@agents.sender.test>")
    entry.raw_path.unlink()
    first_registry.stop()
    restarted, _store, calls, _mailbox, registry = _queued_handler(tmp_path)
    assert restarted.recover() == 0
    assert calls == []
    registry.stop()


def test_queued_lmtp_marks_the_delivery_accepted_only_when_it_answers_250(tmp_path) -> None:
    import threading

    gate = threading.Event()
    handler, store, _calls, _mailbox, registry = _queued_handler(
        tmp_path, intake_handler=lambda _message, _context: gate.wait(5), watermark=1
    )
    _deliver(handler, _agent_raw_with("t_a", "<a@sender.test>"), ["intake+t_a@agents.example.test"])
    progress = store.delivery_progress("intake+t_a@agents.example.test", "<a@sender.test>")
    assert progress is not None and progress["accepted"] == 1
    gate.set()
    registry.join("intake")
    registry.stop()


def test_a_retry_answered_duplicate_queued_records_the_acceptance_first(tmp_path) -> None:
    """Queued, then the acceptance could not be recorded (451). The MTA's retry, while the job
    still runs, gets 250: it must leave the delivery accepted, for restart recovery to resume."""
    import threading

    gate = threading.Event()
    handler, store, _calls, _mailbox, registry = _queued_handler(
        tmp_path, intake_handler=lambda _message, _context: gate.wait(5), watermark=1
    )
    recipient, message_id = "intake+t_a@agents.example.test", "<a@sender.test>"
    raw = _agent_raw_with("t_a", message_id)
    mark_accepted = store.mark_delivery_accepted

    def locked(*_args) -> None:
        raise sqlite3.OperationalError("database is locked")

    store.mark_delivery_accepted = locked  # type: ignore[method-assign]
    first = _deliver(handler, raw, [recipient])
    assert first.values == ("451 4.3.0 gateway store unavailable: database is locked",)
    store.mark_delivery_accepted = mark_accepted  # type: ignore[method-assign]
    retry = _deliver(handler, raw, [recipient])
    assert retry.values == ("250 2.0.0 duplicate already queued",)
    assert [row["recipient"] for row in store.pending_deliveries()] == [recipient]
    gate.set()
    registry.join("intake")
    registry.stop()


def test_deliver_local_hands_a_task_event_to_sync_and_queued_handlers(tmp_path) -> None:
    from amx.profile import Inbound as InboundValue
    from amx.profile import Thread

    handler, _store, calls, _mailbox, registry = _queued_handler(tmp_path)
    event = InboundValue(
        intent="update",
        task="t_held",
        task_state="canceled",
        schema=None,
        payload=None,
        text="rejected",
        sender=None,
        lane="system",
        trust=None,
        thread=Thread(message_id="<held@test>", in_reply_to=None, references=()),
        raw=b"",
    )
    handler.deliver_local("echo", event)
    handler.deliver_local("intake", event)
    registry.join("intake")
    assert calls == [("echo", "t_held"), ("intake", "t_held")]
    registry.stop()


def _tainted_human_raw(task: str = "t_human") -> bytes:
    message = EmailMessage(policy=policy.SMTP)
    message["From"] = "pat@people.test"
    message["To"] = f"intake+{task}@agents.example.test"
    message["Subject"] = "Human request"
    message["Message-ID"] = "<tainted@people.test>"
    message["Agent-Lane"] = "human"
    message["Agent-Trust"] = "low"
    message["Agent-Content-Judgment"] = "mode=enforce; model=stub-1; directs_recipient=0.970"
    message["Agent-Taint"] = "directs-recipient"
    message.set_content("Hello")
    return message.as_bytes(policy=policy.SMTP)


def test_lmtp_hands_the_handler_a_tainted_inbound_and_taints_its_task(tmp_path) -> None:
    seen = []
    handler, store, _calls, _mailbox = _handler(
        tmp_path, intake_handler=lambda message, _context: seen.append(message)
    )
    result = _deliver(handler, _tainted_human_raw(), ["intake+t_human@agents.example.test"])
    assert result.values[0].startswith("250 2.0.0 delivered")
    [message] = seen
    assert message.tainted and message.taint_reasons == ("directs-recipient",)
    assert "tainted" not in message.as_dict()
    assert store.task_taint("intake", "t_human") == "directs-recipient"
    [row] = store.rows("SELECT detail FROM journal")
    assert "judgment=[mode=enforce; model=stub-1; directs_recipient=0.970]" in row["detail"]
    assert "taint=directs-recipient" in row["detail"]


def test_a_tainted_handler_that_opens_a_task_taints_it_before_submission(tmp_path) -> None:
    sent = []

    class Outbound:
        def send(self, **message):
            sent.append(message)
            return "sent"

    def opens_a_task(_message, context: Context) -> None:
        context.send(to="someone@else.test", intent="request", text="Follow-up")

    handler, store, _calls, _mailbox = _handler(tmp_path, intake_handler=opens_a_task)
    handler.outbound_agents["intake"] = Outbound()  # type: ignore[assignment]
    _deliver(handler, _tainted_human_raw(), ["intake+t_human@agents.example.test"])
    [message] = sent
    assert store.task_taint("intake", message["task"]) == "directs-recipient"


def test_lmtp_rejects_taint_without_milter_lane_metadata(tmp_path) -> None:
    handler, _store, calls, _mailbox = _handler(tmp_path)
    raw = (
        _tainted_human_raw()
        .replace(b"Agent-Lane: human\r\n", b"")
        .replace(b"Agent-Trust: low\r\n", b"")
    )
    result = _deliver(handler, raw, ["intake+t_human@agents.example.test"])
    assert result.values[0].startswith("550 5.6.0")
    assert calls == []


def test_a_tainted_task_keeps_tainting_new_tasks_from_clean_mail_and_local_events(tmp_path) -> None:
    from amx.profile import Inbound as InboundValue
    from amx.profile import Thread

    sent = []

    class Outbound:
        def send(self, **message):
            sent.append(message)
            return "sent"

    def opens_a_task(_message, context: Context) -> None:
        context.send(to="someone@else.test", intent="request", text="Follow-up")

    handler, store, _calls, _mailbox = _handler(tmp_path, intake_handler=opens_a_task)
    handler.outbound_agents["intake"] = Outbound()  # type: ignore[assignment]
    store.taint_task("intake", "t_multi", ("directs-recipient",))
    _deliver(handler, _agent_raw("t_multi"), ["intake+t_multi@agents.example.test"])
    handler.deliver_local(
        "intake",
        InboundValue(
            intent="update",
            task="t_multi",
            task_state="canceled",
            schema=None,
            payload=None,
            text="rejected",
            sender=None,
            lane="system",
            trust=None,
            thread=Thread(message_id="<held@test>", in_reply_to=None, references=()),
            raw=b"",
        ),
    )
    assert len(sent) == 2
    for message in sent:
        assert store.task_taint("intake", message["task"]) == "directs-recipient"


def test_mail_that_should_have_been_judged_but_was_not_is_tainted(tmp_path) -> None:
    from amx.config import ContentJudgeConfig

    seen = []
    handler, store, _calls, _mailbox = _handler(
        tmp_path, intake_handler=lambda message, _context: seen.append(message)
    )
    handler.config = replace(handler.config, content_judge=ContentJudgeConfig(mode="enforce"))
    _deliver(handler, _agent_raw("t_multi"), ["intake+t_multi@agents.example.test"])
    [message] = seen
    assert message.tainted and message.taint_reasons == ("unjudged",)
    assert store.task_taint("intake", "t_multi") == "unjudged"
    [row] = store.rows("SELECT detail FROM journal")
    assert "taint=unjudged" in row["detail"]


def test_judged_or_judging_off_mail_is_not_flagged_unjudged(tmp_path) -> None:
    from amx.config import ContentJudgeConfig

    seen = []
    handler, _store, _calls, _mailbox = _handler(
        tmp_path, intake_handler=lambda message, _context: seen.append(message)
    )
    _deliver(handler, _agent_raw("t_off"), ["intake+t_off@agents.example.test"])
    handler.config = replace(handler.config, content_judge=ContentJudgeConfig(mode="enforce"))
    judged = (
        _agent_raw("t_on")
        .replace(b"Agent-Lane: agent", b"Agent-Content-Judgment: mode=enforce\r\nAgent-Lane: agent")
        .replace(b"<multi@agents.sender.test>", b"<judged@agents.sender.test>")
    )
    _deliver(handler, judged, ["intake+t_on@agents.example.test"])
    assert [message.tainted for message in seen] == [False, False]


def test_restart_recovery_keeps_the_unjudged_backstop(tmp_path) -> None:
    from amx.config import ContentJudgeConfig

    first, store, _calls, _mailbox, first_registry = _queued_handler(tmp_path)
    first.journal.append_delivery(
        _agent_raw("t_q"),
        recipient="intake+t_q@agents.example.test",
        agent="intake",
        identity="agents.sender.test",
        task="t_q",
        message_id="<multi@agents.sender.test>",
    )
    store.mark_delivery_accepted("intake+t_q@agents.example.test", "<multi@agents.sender.test>")
    first_registry.stop()

    seen = []
    restarted, store, _calls, _mailbox, registry = _queued_handler(
        tmp_path, intake_handler=lambda message, _context: seen.append(message)
    )
    restarted.config = replace(restarted.config, content_judge=ContentJudgeConfig(mode="enforce"))
    assert restarted.recover() == 1
    registry.join("intake")
    [message] = seen
    assert message.taint_reasons == ("unjudged",)
    assert store.task_taint("intake", "t_q") == "unjudged"
    registry.stop()


def test_a_header_block_that_ends_early_is_refused_and_settles_admissions(tmp_path) -> None:
    handler, _store, calls, _mailbox, registry = _queued_handler(tmp_path)
    registry.bind(registry.reserve("intake"), "<multi@agents.sender.test>")
    raw = _agent_raw().replace(b"Agent-Lane: agent", b"X-Pad : y\r\nAgent-Lane: agent")
    result = _deliver(handler, raw, ["intake+t_multi@agents.example.test"])
    assert result.values == ("550 5.6.0 malformed header block",)
    assert calls == []
    assert registry.depth("intake") == 0
    registry.stop()


def test_lmtp_refuses_a_subaddress_that_is_not_a_task_token(tmp_path) -> None:
    handler, _store, calls, mailbox = _handler(tmp_path)
    statuses = _deliver(handler, _agent_raw("../t_x"), ["intake+../t_x@agents.example.test"])
    assert statuses.values == ("550 5.1.3 invalid task token in sub-address",)
    assert calls == [] and mailbox.addresses == []


class RawMailbox:
    def __init__(self) -> None:
        self.appended: list[tuple[str, bytes, str]] = []

    def append(self, address: str, raw: bytes, folder: str = "INBOX") -> None:
        self.appended.append((address, raw, folder))


def _remote(tmp_path, **config_changes):
    """A gateway whose ``outpost`` is remote (PLAN §5.9): LMTP files its mail and runs nothing."""
    config = replace(
        _config(tmp_path),
        agents={"outpost": AgentConfig(handler="mailbox-only", mode="remote")},
        **config_changes,
    )
    store = Store(tmp_path / "journal.sqlite")
    registry = HandlerRegistry()
    registry.register("outpost", "mailbox-only", mode="remote")
    mailbox = RawMailbox()
    handler = LmtpHandler(config, store, Journal(tmp_path, store), registry, mailbox)  # type: ignore[arg-type]
    return handler, store, mailbox


def _to_outpost(raw: bytes) -> bytes:
    return raw.replace(b"intake+", b"outpost+")


def test_a_remote_agents_copy_is_stamped_with_its_envelope_recipient(tmp_path) -> None:
    handler, store, mailbox = _remote(tmp_path)
    raw = _to_outpost(_human_raw())
    recipient = "outpost+t_human@agents.example.test"
    assert _deliver(handler, raw, [recipient]).values[0].startswith("250 2.0.0 delivered")
    [(address, filed, folder)] = mailbox.appended
    assert (address, folder) == ("outpost@agents.example.test", "INBOX")
    assert filed == f"Delivered-To: {recipient}\r\n".encode() + raw, "the delivered bytes, stamped"
    assert store.delivered(recipient, "<human@people.test>")
    assert _deliver(handler, raw, [recipient]).values == ("250 2.0.0 duplicate already delivered",)
    assert len(mailbox.appended) == 1, "a replay is never filed twice (S10 at the edge)"


def test_a_remote_copy_carries_the_taint_an_in_process_context_would(tmp_path) -> None:
    from amx.config import ContentJudgeConfig
    from amx.runner import bind

    handler, store, mailbox = _remote(tmp_path)
    store.taint_task("outpost", "t_human", ("directs-recipient",))
    _deliver(handler, _to_outpost(_human_raw()), ["outpost+t_human@agents.example.test"])
    filed = mailbox.appended[-1][1]
    assert filed.startswith(
        b"Delivered-To: outpost+t_human@agents.example.test\r\n"
        b"Agent-Task-Taint: directs-recipient\r\n"
    ), "a clean message in a tainted task"
    assert b"Agent-Taint:" not in filed, "the message itself was judged clean"
    bound = bind(filed)
    assert bound.tainted and bound.taint_reasons == ("directs-recipient",)

    judged = _to_outpost(_human_raw()).replace(
        b"Agent-Trust: low\r\n",
        b"Agent-Trust: low\r\nAgent-Content-Judgment: mode=enforce\r\nAgent-Taint: parts-agree\r\n",
    )
    handler, _store, mailbox = _remote(tmp_path / "judged")
    _deliver(handler, judged, ["outpost+t_human@agents.example.test"])
    filed = mailbox.appended[-1][1]
    assert filed.count(b"Agent-Taint:") == 1, "the milter's own taint stands"
    assert b"Agent-Task-Taint: parts-agree\r\n" in filed, "LMTP tainted the task before filing"

    handler, _store, mailbox = _remote(
        tmp_path / "unjudged", content_judge=ContentJudgeConfig(mode="enforce")
    )
    _deliver(handler, _to_outpost(_human_raw()), ["outpost+t_human@agents.example.test"])
    assert b"\r\nAgent-Taint: unjudged\r\n" in mailbox.appended[-1][1], "the backstop's taint"


def test_a_bounce_in_a_tainted_task_is_filed_readable_and_tainted(tmp_path) -> None:
    from amx.runner import bind

    handler, store, mailbox = _remote(tmp_path)
    # A DSN the mailhost generated for outpost's own send: no milter ran, so no transport headers.
    raw = (Path("spec/corpus") / "10-dsn-failed.eml").read_bytes()
    task = bind(raw).task
    assert task, "the corpus DSN names its task"
    store.taint_task("outpost", task, ("directs-recipient",))
    recipient = f"outpost+{task}@agents.example.test"
    assert _deliver(handler, raw, [recipient]).values[0].startswith("250 2.0.0 delivered")
    filed = mailbox.appended[-1][1]
    stamps = f"Delivered-To: {recipient}\r\nAgent-Task-Taint: directs-recipient\r\n"
    assert filed == stamps.encode() + raw, "no Agent-Taint: that would make it unreadable"
    bound = bind(filed)
    assert (bound.lane, bound.tainted, bound.taint_reasons) == (
        "system",
        True,
        ("directs-recipient",),
    )


def test_a_remote_agents_copy_is_filed_and_its_admission_settled_under_one_lock(tmp_path) -> None:
    handler, _store, mailbox = _remote(tmp_path)
    registry = handler.registry
    reservation = registry.reserve("outpost")
    registry.bind(reservation, "<human@people.test>")
    seen: list[tuple[bool, int]] = []
    append = mailbox.append

    def append_while_counting(address: str, raw: bytes, folder: str = "INBOX") -> None:
        # The milter reads admissions and the mailbox under this lock, so it sees neither half.
        seen.append((registry.admission.locked(), registry.depth("outpost")))
        append(address, raw, folder)

    mailbox.append = append_while_counting  # type: ignore[method-assign]
    raw = _to_outpost(_human_raw())
    envelope = SimpleNamespace(
        original_content=raw, rcpt_tos=["outpost+t_human@agents.example.test"]
    )
    asyncio.run(handler.handle_DATA(None, None, envelope))
    assert seen == [(True, 1)], "appended under the admission lock, admission not yet settled"
    assert registry.depth("outpost") == 0, "settled with the append, not after it"
    assert not registry.admission.locked()


def test_a_rejected_hold_reaches_a_remote_agent_as_a_system_event_in_its_inbox(tmp_path) -> None:
    from amx.profile import Inbound, Thread
    from amx.runner import bind

    handler, store, mailbox = _remote(tmp_path)
    store.taint_task("outpost", "t_held", ("directs-recipient",))
    event = Inbound(
        intent="update",
        task="t_held",
        task_state="canceled",
        schema=None,
        payload=None,
        text="A person rejected held message <h@agents.example.test>. It was not sent.",
        sender=None,
        lane="system",
        trust=None,
        thread=Thread(message_id="<h@agents.example.test>", in_reply_to=None, references=()),
        raw=b"the held message",
    )
    handler.deliver_local("outpost", event)
    [(address, raw, folder)] = mailbox.appended
    assert (address, folder) == ("outpost@agents.example.test", "INBOX")
    assert raw.startswith(b"Agent-Lane: system\r\nAgent-Task-Taint: directs-recipient\r\n")
    bound = bind(raw)
    assert (bound.lane, bound.intent, bound.task, bound.task_state) == (
        "system",
        "update",
        "t_held",
        "canceled",
    )
    assert bound.thread.message_id == "<h@agents.example.test>", "threaded on the held message"
    assert bound.tainted and bound.taint_reasons == ("directs-recipient",), (
        "a tainted task stays tainted in the event, as in-process"
    )


# --- #21: the handler's reply wins, and a closed task never reopens (docs/task-transitions.md) ---


def _key(path) -> None:
    import subprocess

    subprocess.run(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:1024",
            "-out",
            path,
        ],
        check=True,
        capture_output=True,
    )


class Submitting:
    """``ctx.reply`` through the real submission service, as ``amx.sdk.Agent.send`` does over
    SMTP: submission, not a stub, records the reply's task state (sent or held)."""

    def __init__(self, service, agent: str = "intake") -> None:
        self.service = service
        self.agent = agent
        self.results: list = []

    def send(self, *, to, subject, intent, text, task, task_state, in_reply_to, references, **_):
        raw = build(
            sender=f"{self.agent}@agents.example.test",
            to=to,
            subject=subject,
            intent=intent,
            task=task,
            task_state=task_state,
            text=text,
            in_reply_to=in_reply_to,
            references=references,
        ).as_bytes(policy=policy.SMTP)
        self.results.append(self.service.submit(self.agent, "intake-token", raw))
        return self.results[-1]


def _replying(tmp_path, handler, *, mode: str = "sync", held: bool = False, mailbox=None):
    """intake runs ``handler`` in ``mode`` and replies through submission; with ``held``, its
    replies to the sender's domain wait in Outbox/Held (a first contact)."""
    from amx.adapters.submission import SubmissionService
    from amx.config import HoldRule, TrustGrant

    keys = tmp_path / "keys"
    keys.mkdir(parents=True)
    _key(keys / "intake.private.pem")
    config = replace(
        _config(tmp_path),
        agents={
            "intake": AgentConfig(handler="mailbox-only", mode=mode, submit_token="intake-token")
        },
        trust=(
            TrustGrant(
                d="agents.example.test",
                s="intake",
                intents=frozenset({"*"}),
                schemas=frozenset({"*"}),
                can_open_tasks=True,
            ),
        ),
        keys_dir=keys,
        hold_rules=(HoldRule(name="first-contact-domain", recipient_domain_seen=False),),
        known_domains=frozenset() if held else frozenset({"agents.sender.test"}),
    )
    store = Store(tmp_path / "journal.sqlite")
    journal = Journal(tmp_path, store)
    reinjected: list[bytes] = []
    service = SubmissionService(
        config,
        journal,
        reinject=lambda _sender, _recipients, raw: reinjected.append(raw),
        mailbox=RawMailbox(),  # type: ignore[arg-type]
    )
    registry = HandlerRegistry()
    registry.register("intake", handler, mode=mode)
    lmtp = LmtpHandler(
        config,
        store,
        journal,
        registry,
        mailbox or RecordingMailbox(),  # type: ignore[arg-type]
        retry_delays=(0.01, 0.01),
    )
    outbound = Submitting(service)
    lmtp.outbound_agents["intake"] = outbound  # type: ignore[assignment]
    return lmtp, store, service, registry, outbound


def _reply_with(state: str):
    def reply(_message, context: Context) -> None:
        context.reply(intent="response", text=f"Intake answers {state}.", task_state=state)

    return reply


def test_a_handlers_closing_reply_stays_closed_once_delivery_finishes(tmp_path) -> None:
    lmtp, store, _service, _registry, outbound = _replying(tmp_path, _reply_with("completed"))
    result = _deliver(lmtp, _agent_raw(), ["intake+t_multi@agents.example.test"])
    assert result.values[0].startswith("250 2.0.0 delivered")
    assert outbound.results[0].held is None, "sent, not held"
    task = store.task("t_multi")
    assert task is not None
    assert task["state"] == "completed", "LMTP used to write the request's `submitted` over it"
    assert store.closed_tasks() == frozenset({("intake", "t_multi")})


def test_a_handlers_open_reply_wins_over_the_request_it_answered(tmp_path) -> None:
    lmtp, store, *_rest = _replying(tmp_path, _reply_with("working"))
    _deliver(lmtp, _agent_raw(), ["intake+t_multi@agents.example.test"])
    assert store.task("t_multi")["state"] == "working"


def test_a_queued_handlers_closing_reply_stays_closed(tmp_path) -> None:
    lmtp, store, _service, registry, _outbound = _replying(
        tmp_path, _reply_with("completed"), mode="queued"
    )
    result = _deliver(lmtp, _agent_raw(), ["intake+t_multi@agents.example.test"])
    assert result.values[0].startswith("250 2.0.0 queued")
    registry.join("intake")
    assert store.delivered("intake+t_multi@agents.example.test", "<multi@agents.sender.test>")
    assert store.task("t_multi")["state"] == "completed"


def test_a_held_closing_reply_stays_closed_and_a_rejection_cancels_it(tmp_path) -> None:
    lmtp, store, service, _registry, outbound = _replying(
        tmp_path, _reply_with("completed"), held=True
    )
    _deliver(lmtp, _agent_raw(), ["intake+t_multi@agents.example.test"])
    [held] = outbound.results
    assert held.held == "first-contact-domain"
    assert store.task("t_multi")["state"] == "completed", "held replies record their state too"
    message_id = str(BytesParser(policy=policy.default).parsebytes(held.raw)["Message-ID"])
    assert service.reject("intake", message_id) is not None
    assert store.task("t_multi")["state"] == "canceled", "a closed state replaces a closed state"


def test_a_mailbox_retry_keeps_the_handlers_closing_reply(tmp_path) -> None:
    lmtp, store, *_rest, outbound = _replying(
        tmp_path, _reply_with("completed"), mailbox=FailOnceMailbox()
    )
    recipient, raw = "intake+t_multi@agents.example.test", _agent_raw()
    assert _deliver(lmtp, raw, [recipient]).values[0].startswith("450 4.3.0 mailbox")
    assert _deliver(lmtp, raw, [recipient]).values[0].startswith("250 2.0.0 delivered")
    assert len(outbound.results) == 1, "the retry resumed at the mailbox append"
    assert store.task("t_multi")["state"] == "completed"


@pytest.mark.parametrize("existing_task", [False, True])
@pytest.mark.parametrize("newer_reply", [False, True])
def test_task_write_failure_resumes_without_rerunning_the_handler(
    tmp_path, existing_task, newer_reply, caplog
) -> None:
    handler, store, calls, mailbox = _handler(tmp_path)
    if existing_task:
        store.put_task("t_multi", "intake", "working")
    with store.connection() as connection:
        for operation in ("INSERT", "UPDATE"):
            connection.execute(
                f"CREATE TRIGGER task_{operation} BEFORE {operation} ON tasks "
                "BEGIN SELECT RAISE(ABORT, 'task write unavailable'); END"
            )
    recipient, message_id = "intake+t_multi@agents.example.test", "<multi@agents.sender.test>"
    raw = _agent_raw()
    first = _deliver(handler, raw, [recipient])
    assert first.values == ("450 4.3.0 task state error: task write unavailable",)
    progress = store.delivery_progress(recipient, message_id)
    assert progress["state"] == "handled"
    assert progress["task_revision"] == (0 if existing_task else -1)
    assert calls == [("intake", "t_multi")]
    assert mailbox.addresses == []
    assert store.accepted_delivery(recipient, message_id)
    assert any(record.event == "task-state-deferred" for record in caplog.records)
    with store.connection() as connection:
        for operation in ("INSERT", "UPDATE"):
            connection.execute(f"DROP TRIGGER task_{operation}")
    if newer_reply:
        store.put_task("t_multi", "intake", "input-required")
    # A new adapter/store proves the snapshot survives process lifetime, not just one call.
    restarted, store, retry_calls, retry_mailbox = _handler(tmp_path)
    assert _deliver(restarted, raw, [recipient]).values[0].startswith("250 2.0.0 delivered")
    assert retry_calls == [], "the successful handler checkpoint is durable"
    assert retry_mailbox.addresses == ["intake@agents.example.test"]
    assert store.task("t_multi")["state"] == ("input-required" if newer_reply else "submitted")


def test_recovery_resumes_a_failed_task_write_without_rerunning_the_handler(tmp_path) -> None:
    handler, store, calls, mailbox, registry = _queued_handler(tmp_path)
    with store.connection() as connection:
        connection.execute(
            "CREATE TRIGGER task_unavailable BEFORE INSERT ON tasks "
            "BEGIN SELECT RAISE(ABORT, 'task write unavailable'); END"
        )
    recipient, message_id = "intake+t_multi@agents.example.test", "<multi@agents.sender.test>"
    try:
        assert _deliver(handler, _agent_raw(), [recipient]).values[0].startswith("250 2.0.0 queued")
        registry.join("intake")
        assert calls == [("intake", "t_multi")], "in-place retries do not repeat the handler"
        assert mailbox.addresses == []
        assert store.delivery_progress(recipient, message_id)["state"] == "handled"
    finally:
        registry.stop()
    with store.connection() as connection:
        connection.execute("DROP TRIGGER task_unavailable")
    store.put_task("t_multi", "intake", "working")  # a reply arrives before recovery
    restarted, store, calls, mailbox, registry = _queued_handler(tmp_path)
    try:
        assert restarted.recover() == 1
        registry.join("intake")
        assert calls == []
        assert mailbox.addresses == ["intake@agents.example.test"]
        assert store.task("t_multi")["state"] == "working", (
            "saved absent revision cannot overwrite it"
        )
        assert store.delivered(recipient, message_id)
    finally:
        registry.stop()


def test_a_refused_delivery_records_no_task_state_of_its_own(tmp_path) -> None:
    def refuse(_message, _context: Context) -> None:
        raise Refuse("5.7.1", "not for this agent")

    lmtp, store, *_rest = _replying(tmp_path, refuse)
    status = _deliver(lmtp, _agent_raw(), ["intake+t_multi@agents.example.test"]).values
    assert status == ("550 5.7.1 not for this agent",)
    assert store.task("t_multi") is None, "a refused request opens no task"

    def fail_then_refuse(message, context: Context) -> None:
        _reply_with("failed")(message, context)
        raise Refuse("5.7.1", "cannot do this")

    lmtp, store, *_rest = _replying(tmp_path / "replied", fail_then_refuse)
    _deliver(lmtp, _agent_raw(), ["intake+t_multi@agents.example.test"])
    assert store.task("t_multi")["state"] == "failed", "what it submitted before refusing stands"


def test_without_a_reply_the_delivered_messages_state_is_recorded(tmp_path) -> None:
    handler, store, _calls, _mailbox = _handler(tmp_path)
    _deliver(handler, _agent_raw(), ["intake+t_multi@agents.example.test"])
    assert store.task("t_multi")["state"] == "submitted"
    working = _agent_raw_with("t_multi", "<second@agents.sender.test>").replace(
        b"Agent-Task-State: submitted", b"Agent-Task-State: input-required"
    )
    _deliver(handler, working, ["intake+t_multi@agents.example.test"])
    assert store.task("t_multi")["state"] == "input-required"


def test_mail_delivered_into_a_closed_task_does_not_reopen_it(tmp_path) -> None:
    # Accepted at the milter while the task was open, delivered after a reply closed it.
    handler, store, calls, mailbox = _handler(tmp_path)
    store.put_task("t_multi", "intake", "completed")
    result = _deliver(handler, _agent_raw(), ["intake+t_multi@agents.example.test"])
    assert result.values[0].startswith("250 2.0.0 delivered"), "LMTP applies no task rule (D5)"
    assert calls == [("intake", "t_multi")]
    assert mailbox.addresses == ["intake@agents.example.test"]
    assert store.task("t_multi")["state"] == "completed"


def test_a_bounce_fails_a_task_its_reply_completed(tmp_path) -> None:
    handler, store, _calls, _mailbox = _handler(tmp_path)
    store.put_task("t_dsn", "intake", "completed")
    raw = Path("spec/corpus/10-dsn-failed.eml").read_bytes()
    assert _deliver(handler, raw, ["intake+t_dsn@agents.example.test"]).values[0].startswith("250")
    assert store.task("t_dsn")["state"] == "failed"


def test_a_remote_agents_state_is_recorded_before_filing_and_its_close_stands(tmp_path) -> None:
    handler, store, mailbox = _remote(tmp_path)
    recipient = "outpost+t_multi@agents.example.test"
    states: list[str | None] = []
    append = mailbox.append

    def append_after_the_state(address: str, raw: bytes, folder: str = "INBOX") -> None:
        row = store.task("t_multi")
        states.append(None if row is None else str(row["state"]))
        append(address, raw, folder)

    mailbox.append = append_after_the_state  # type: ignore[method-assign]
    assert _deliver(handler, _to_outpost(_agent_raw()), [recipient]).values[0].startswith("250")
    assert states == ["submitted"], "recorded before the runner can take the message"
    store.put_task("t_multi", "outpost", "completed")  # the runner's reply, as submission writes it
    later = _to_outpost(_agent_raw_with("t_multi", "<later@agents.sender.test>"))
    assert _deliver(handler, later, [recipient]).values[0].startswith("250 2.0.0 delivered")
    assert store.task("t_multi")["state"] == "completed", "filed after the close, still closed"


def test_a_retry_into_a_task_the_handler_closed_is_acknowledged_without_a_rerun(
    tmp_path, monkeypatch
) -> None:
    """The whole #21 path on one store: LMTP delivers, intake's reply closes the task, and the
    sender's MTA retries through the milter. The retry is a duplicate, not a bounce; new mail to
    the closed task is still refused."""
    milter_lib = pytest.importorskip("Milter")
    from amx.adapters import milter as milter_module
    from amx.identity import DkimResult

    calls: list[str | None] = []

    def reply_and_count(message, context: Context) -> None:
        calls.append(message.thread.message_id)
        _reply_with("completed")(message, context)

    lmtp, store, _service, registry, outbound = _replying(tmp_path, reply_and_count)
    recipient, raw = "intake+t_multi@agents.example.test", _agent_raw()
    assert _deliver(lmtp, raw, [recipient]).values[0].startswith("250 2.0.0 delivered")
    assert store.task("t_multi")["state"] == "completed"

    monkeypatch.setattr(
        milter_module,
        "verify_dkim",
        lambda _raw, _dns, **_local: DkimResult(
            True, "agents.sender.test", "scheduler", True, "pass", agent="scheduler"
        ),
    )
    scheduler = TrustGrant(
        d="agents.sender.test",
        s="scheduler",
        intents=frozenset({"request"}),
        schemas=frozenset({"*"}),
        can_open_tasks=True,
    )
    config = replace(lmtp.config, trust=(*lmtp.config.trust, scheduler))
    milter_class = milter_module.build_milter(config, store, registry)
    replies: list[tuple[str, str, str]] = []

    def through_the_milter(message: bytes) -> int:
        milter = milter_class()
        milter.setreply = lambda code, enhanced, text: replies.append((code, enhanced, text))
        milter.addheader = lambda _name, _value: None
        milter.chgheader = lambda _name, _index, _value: None  # drops the old transport headers
        milter.envfrom("<scheduler+t_multi@agents.sender.test>")
        assert milter.envrcpt(f"<{recipient}>") == milter_lib.CONTINUE, replies
        for name, value in BytesParser(policy=policy.SMTP).parsebytes(message).raw_items():
            milter.header(name, str(value).encode())
        milter.body(message.partition(b"\r\n\r\n")[2])
        result = milter.eom()
        milter.close()
        return result

    assert through_the_milter(raw) == milter_lib.ACCEPT, replies
    assert _deliver(lmtp, raw, [recipient]).values == ("250 2.0.0 duplicate already delivered",)
    fresh = _agent_raw_with("t_multi", "<fresh@agents.sender.test>")
    assert through_the_milter(fresh) == milter_lib.REJECT
    assert replies[-1] == ("550", "5.1.6", "task is closed")

    assert calls == ["<multi@agents.sender.test>"], "the handler ran once"
    assert len(outbound.results) == 1, "and replied once"
    decided = store.rows(
        "SELECT stage, rule FROM policy_events WHERE stage IN ('rcpt', 'eod') ORDER BY sequence"
    )
    assert [(row["stage"], row["rule"]) for row in decided] == [
        ("rcpt", "closed-task-at-eod"),
        ("eod", "eod-ok"),
        ("rcpt", "closed-task-at-eod"),
        ("eod", "closed-task"),
    ]
    assert store.task("t_multi")["state"] == "completed"


def test_an_in_process_handler_declares_through_its_own_submission_even_when_tainted(
    tmp_path,
) -> None:
    declared: list[tuple[str, dict[str, object]]] = []

    class Outbound:
        def send(self, **_message: object) -> str:
            return "sent"

        def declare(self, command: str, **fields: object) -> str:
            declared.append((command, fields))
            return "declared"

    def overloaded(_message, context: Context) -> None:
        assert context.declare("capacity", max=1, ttl_seconds=60) == "declared"

    handler, _store, _calls, _mailbox = _handler(tmp_path, intake_handler=overloaded)
    handler.outbound_agents["intake"] = Outbound()  # type: ignore[assignment]
    result = _deliver(handler, _tainted_human_raw(), ["intake+t_human@agents.example.test"])
    assert result.values[0].startswith("250")
    # A declaration carries nothing a person must approve (PLAN §5.10), so taint passes it by.
    assert declared == [("capacity", {"max": 1, "ttl_seconds": 60})]


def test_a_queued_agent_rebuilt_mid_delivery_gets_a_retry_not_a_bounce(tmp_path) -> None:
    from types import SimpleNamespace

    from amx.adapters.lmtp import LmtpHandler

    class Rebuilt:
        def submit(self, *_args, **_kwargs):
            raise ValueError("agent is not in queued mode: intake")

    handler = LmtpHandler.__new__(LmtpHandler)
    handler.registry = Rebuilt()
    handler._inflight = set()
    handler._inflight_lock = threading.Lock()
    delivery = SimpleNamespace(
        recipient="intake@agents.example.test", message_id="<m@x>", agent="intake"
    )
    assert handler._enqueue(delivery).startswith("451 4.3.0")
    assert handler._inflight == set()


def test_a_local_event_for_an_agent_rebuilt_mid_submit_follows_its_new_mode(monkeypatch) -> None:
    from types import SimpleNamespace

    from amx.adapters.lmtp import LmtpHandler

    class Rebuilt:
        """Queued when the event reads the mode, then rebuilt as remote before it submits."""

        def __init__(self) -> None:
            self.modes = iter(["queued", "queued", "remote"])

        def mode(self, _agent):
            return next(self.modes)

        def submit(self, *_args, **_kwargs):
            raise ValueError("agent is not in queued mode: probe")

    filed: list[tuple[str, bytes]] = []
    handler = LmtpHandler.__new__(LmtpHandler)
    handler.registry = Rebuilt()
    handler.config = SimpleNamespace(agent_domain="agents.example.test")
    handler.store = SimpleNamespace(task_taint=lambda *_args: None)
    handler.mailbox = SimpleNamespace(append=lambda address, raw: filed.append((address, raw)))
    handler._context = lambda *_args: None
    import amx.adapters.lmtp as lmtp_module

    monkeypatch.setattr(lmtp_module, "system_event", lambda *_args: b"event")
    handler.deliver_local("probe", SimpleNamespace(task=None))  # type: ignore[arg-type]
    assert filed == [("probe@agents.example.test", b"event")]
