"""SH-46: the people an agent's owner names on a task are recipients the agent may write to."""

from __future__ import annotations

import json
import re
import smtplib
from dataclasses import replace
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser

import pytest
from test_ax_delivery import offer, restart, setup
from test_signed_in_owner import context, state
from test_submission import RecordingMailbox, _config, _held_id, _hold_service, _request

from amx.adapters.ax import AxError, Contract, envelope, reply_cc
from amx.adapters.submission import SubmissionError
from amx.config import LimitsConfig
from amx.mailbox import HANDLED_KEYWORD
from amx.policy import Stage, evaluate
from amx.profile import named_addresses
from amx.runner import bind

TOKEN = "secret-scheduler-token"


def _headers(raw: str):
    return BytesParser(policy=policy.default).parsebytes(raw.encode(), headersonly=True)


def test_named_addresses_reads_from_to_and_cc_once_each_and_fails_closed() -> None:
    headers = _headers(
        "From: Victor <Victor@Gmail.test>\r\n"
        "To: claude@agents.example.test, Dana <dana@acme.test>\r\n"
        "Cc: DANA@acme.test, team: lee@acme.test, kim@acme.test;\r\n"
        "Bcc: hidden@acme.test\r\n\r\n"
    )
    assert named_addresses(headers) == (
        "victor@gmail.test",
        "claude@agents.example.test",
        "dana@acme.test",
        "lee@acme.test",
        "kim@acme.test",
    )
    assert named_addresses(headers, ("Cc",)) == ("dana@acme.test", "lee@acme.test", "kim@acme.test")
    odd = _headers('To: "a b"@acme.test, x%y@acme.test, a!b@acme.test, o\'brien@acme.test\r\n\r\n')
    assert named_addresses(odd) == ("o'brien@acme.test",), "dot-atoms submission takes, no more"
    assert (
        named_addresses(_headers("To: ok@acme.test\r\nCc: <unterminated@acme.test\r\n\r\n")) == ()
    )
    assert named_addresses(_headers("To: undisclosed-recipients:;\r\n\r\n")) == ()


def test_a_named_recipient_needs_no_allowlist_entry_and_is_no_first_contact(tmp_path) -> None:
    service, store, reinjected, mailbox = _hold_service(
        tmp_path, outbound_allowlist=frozenset({"pat@plainmail.test"})
    )
    store.name_recipients("scheduler", "t_hold", ("Dana@Acme.test",))

    sent = service.submit("scheduler", TOKEN, _request("dana@acme.test"))
    assert sent.held is None, "the owner's naming is the approval"
    assert [recipients for _sender, recipients, _raw in reinjected] == [("dana@acme.test",)]
    assert [folder for _address, _raw, folder in mailbox.appended] == ["Sent"], "nothing held"

    with pytest.raises(SubmissionError, match=re.escape("outbound allowlist: dana@acme.test")):
        service.submit("scheduler", TOKEN, _request("dana@acme.test", task="t_other"))
    with pytest.raises(SubmissionError, match=re.escape("outbound allowlist: lee@acme.test")):
        service.submit("scheduler", TOKEN, _request("dana@acme.test, lee@acme.test"))
    events = store.rows("SELECT rule, task FROM policy_events")
    assert [(row["rule"], row["task"]) for row in events] == [
        ("outbound-not-allowlisted", "t_other"),
        ("outbound-not-allowlisted", "t_hold"),
    ]


def test_naming_one_person_approves_no_one_else_in_their_domain(tmp_path) -> None:
    service, store, reinjected, _mailbox = _hold_service(tmp_path)
    store.name_recipients("scheduler", "t_hold", ("dana@acme.test",))
    result = service.submit("scheduler", TOKEN, _request("dana@acme.test, lee@acme.test"))
    assert result.held == "first-contact-domain", "lee is still a first contact"
    assert reinjected == []

    assert service.submit("scheduler", TOKEN, _request("dana@acme.test")).held is None
    assert len(reinjected) == 1
    assert "acme.test" not in store.contacted_domains("scheduler"), "dana's domain is not a contact"
    later = service.submit("scheduler", TOKEN, _request("lee@acme.test", task="t_later"))
    assert later.held == "first-contact-domain", "writing to dana opened no door to lee"


def test_a_closed_task_names_nobody(tmp_path) -> None:
    service, store, reinjected, _mailbox = _hold_service(
        tmp_path, outbound_allowlist=frozenset({"pat@plainmail.test"})
    )
    store.name_recipients("scheduler", "t_hold", ("dana@acme.test",))
    assert store.named_recipients("scheduler", "t_hold") == {"dana@acme.test"}
    assert store.put_task("t_hold", "scheduler", "completed")
    assert store.named_recipients("scheduler", "t_hold") == frozenset()
    with pytest.raises(SubmissionError, match="outbound allowlist"):
        service.submit("scheduler", TOKEN, _request("dana@acme.test"))
    assert reinjected == []


def test_naming_does_not_lift_the_local_only_ceiling(tmp_path) -> None:
    service, store, reinjected, _mailbox = _hold_service(tmp_path, outbound="local-only")
    store.name_recipients("scheduler", "t_hold", ("dana@acme.test",))
    with pytest.raises(SubmissionError, match="outbound allowlist"):
        service.submit("scheduler", TOKEN, _request("dana@acme.test"))
    assert reinjected == []


def test_a_tainted_task_still_holds_mail_to_a_named_recipient(tmp_path) -> None:
    service, store, reinjected, _mailbox = _hold_service(tmp_path)
    store.name_recipients("scheduler", "t_hold", ("dana@acme.test",))
    store.taint_task("scheduler", "t_hold", ("directs-recipient",))
    assert service.submit("scheduler", TOKEN, _request("dana@acme.test")).held == "tainted-input"
    assert reinjected == []


def test_named_recipients_still_count_against_the_daily_ceiling(tmp_path) -> None:
    service, store, reinjected, _mailbox = _hold_service(
        tmp_path, limits=LimitsConfig(external_per_day=1)
    )
    store.name_recipients("scheduler", "t_hold", ("dana@acme.test", "lee@acme.test"))
    with pytest.raises(SubmissionError, match="per day ceiling"):
        service.submit("scheduler", TOKEN, _request("dana@acme.test, lee@acme.test"))
    assert reinjected == []


def test_a_held_message_to_a_named_recipient_is_released_past_the_allowlist(tmp_path) -> None:
    service, store, reinjected, _mailbox = _hold_service(
        tmp_path, outbound_allowlist=frozenset({"pat@plainmail.test"})
    )
    store.name_recipients("scheduler", "t_hold", ("dana@acme.test",))
    store.taint_task("scheduler", "t_hold", ("directs-recipient",))
    held = service.submit("scheduler", TOKEN, _request("dana@acme.test"))
    assert held.held == "tainted-input"
    assert service.release("scheduler", _held_id(held)) is not None
    assert [recipients for _sender, recipients, _raw in reinjected] == [("dana@acme.test",)]


def _owner_mail(cc: str) -> tuple[bytes, list[tuple[str, str]]]:
    """A signed-in owner's message to scheduler, Cc'ing ``cc``, as the milter passes it on."""
    ctx = context()
    raw = ctx.raw.replace(
        b"To: intake@agents.home.arpa\r\n",
        f"To: scheduler@agents.northwind.test\r\nCc: {cc}\r\n".encode(),
    )
    verdict = evaluate(Stage.EOD, replace(ctx, raw=raw), state())
    assert dict(verdict.headers)["Agent-Trust"] == "high"
    delivered = b"".join(f"{key}: {value}\r\n".encode() for key, value in verdict.headers) + raw
    return delivered, verdict.headers


def _lmtp(tmp_path, handle):
    from test_lmtp import _deliver

    from amx.adapters.lmtp import LmtpHandler
    from amx.adapters.submission import SubmissionService
    from amx.journal import Journal
    from amx.runtime import HandlerRegistry
    from amx.sdk import Agent
    from amx.store import Store

    config = replace(
        _config(tmp_path),
        domain="agents.northwind.test",
        people_domain="home.arpa",
        outbound_allowlist=frozenset({"someone-else@home.arpa"}),
    )
    store = Store(tmp_path / "journal.sqlite")
    journal = Journal(tmp_path, store)
    sent: list[tuple[str, tuple[str, ...], bytes]] = []
    service = SubmissionService(
        config, journal, mailbox=RecordingMailbox(), reinject=lambda *args: sent.append(args)
    )
    outbound = Agent("scheduler@agents.northwind.test", "smtp://localhost", "fixture")
    outbound._transmit = lambda sender, recipients, data: (
        service.submit("scheduler", TOKEN, data) and "2.0.0 sent"
    )
    registry = HandlerRegistry()
    registry.register("scheduler", handle)
    handler = LmtpHandler(
        config, store, journal, registry, RecordingMailbox(), {"scheduler": outbound}
    )

    def deliver(raw: bytes):
        return _deliver(handler, raw, ["scheduler@agents.northwind.test"])

    deliver.handler = handler  # type: ignore[attr-defined]
    return deliver, store, sent, registry


def test_owner_mail_records_who_it_names_and_a_reply_reaches_them(tmp_path) -> None:
    seen = []

    def handle(message, ctx):
        seen.append(message)
        ctx.reply(text="Here is the write-up.", cc=["dana@acme.test"])

    deliver, store, sent, registry = _lmtp(tmp_path, handle)
    try:
        raw, _headers = _owner_mail("Dana <dana@acme.test>")
        assert deliver(raw).values[0].startswith("250")
        task = seen[0].task
        assert store.named_recipients("scheduler", task) == {
            "pat@home.arpa",
            "scheduler@agents.northwind.test",
            "dana@acme.test",
        }
        [(_sender, recipients, signed)] = sent
        assert recipients == ("pat@home.arpa", "dana@acme.test")
        reply = BytesParser(policy=policy.default).parsebytes(signed)
        assert reply["Cc"] == "dana@acme.test" and reply["DKIM-Signature"] is not None
        assert store.named_recipients("scheduler", "t_elsewhere") == frozenset()
    finally:
        registry.stop()


@pytest.mark.parametrize("trust", [b"low", b"domain"])
def test_mail_from_anyone_but_the_owner_names_nobody(tmp_path, trust) -> None:
    deliver, store, _sent, registry = _lmtp(tmp_path, lambda message, ctx: None)
    try:
        raw, _headers = _owner_mail("dana@acme.test")
        low = raw.replace(b"Agent-Trust: high\r\n", b"Agent-Trust: " + trust + b"\r\n")
        for name in (b"Agent-Grant-Role", b"Agent-Grant-Can-Open-Tasks"):
            low = re.sub(rb"(?m)^" + name + rb": [^\r]*\r\n", b"", low)
        assert deliver(low).values[0].startswith("250")
        assert store.rows("SELECT * FROM named_recipients") == []
    finally:
        registry.stop()


def _owner_ax_mail(cc: str) -> bytes:
    """An owner's message in outpost's INBOX, Cc'ing ``cc``, as the gateway filed it."""
    message = EmailMessage(policy=policy.SMTP)
    message["From"] = "Victor <victor@gmail.test>"
    message["To"] = "outpost@agents.contoso.test"
    message["Cc"] = cc
    message["Subject"] = "Write this up for Dana"
    message["Message-ID"] = "<owner-1@gmail.test>"
    message["Agent-Lane"] = "human"
    message["Agent-Trust"] = "high"
    message["Agent-Grant-Role"] = "owner"
    message["Agent-Grant-Can-Open-Tasks"] = "true"
    message.set_content("Please write up what amx does and send it to Dana.")
    stamp = b"Delivered-To: outpost+t_owner@agents.contoso.test\r\n"
    return stamp + message.as_bytes(policy=policy.SMTP)


def test_the_relay_answers_the_owner_reply_all_and_tells_the_session_so(tmp_path) -> None:
    raw = _owner_ax_mail(
        "Dana <dana@acme.test>, codex@agents.contoso.test, bot@agents.partner.test, "
        "victor@gmail.test"
    )
    inbound = bind(raw)
    assert reply_cc(inbound, "outpost+t_owner@agents.contoso.test") == ("dana@acme.test",)
    text, data, provenance = envelope(inbound, "outpost+t_owner@agents.contoso.test", Contract.V1)
    assert "Your reply also goes to (named by the sender): dana@acme.test\n" in text
    assert data["reply_cc"] == ["dana@acme.test"] and provenance["trust"] == "verified"

    runner, delivery, mailbox, endpoint, submissions = setup(tmp_path)
    _uid, record = offer(runner, mailbox, raw)
    endpoint.reply(record["message_id"])
    delivery.step()
    [submitted] = submissions
    reply = BytesParser(policy=policy.default).parsebytes(submitted)
    assert reply["To"] == "victor@gmail.test"
    assert reply["Cc"] == "dana@acme.test"


def test_anyone_elses_mail_is_answered_to_its_sender_alone(tmp_path) -> None:
    raw = _owner_ax_mail("dana@acme.test").replace(b"Agent-Trust: high", b"Agent-Trust: low")
    raw = re.sub(rb"Agent-Grant-[^\r]*\r\n", b"", raw)
    inbound = bind(raw)
    assert inbound.trust == "low"
    assert reply_cc(inbound, "outpost@agents.contoso.test") == ()
    text, data, _provenance = envelope(inbound, "outpost@agents.contoso.test", Contract.V1)
    assert "reply also goes to" not in text and "reply_cc" not in data


def test_a_refused_cc_still_gets_the_owner_an_answer(tmp_path) -> None:
    runner, delivery, mailbox, endpoint, submissions = setup(tmp_path)
    attempts: list[bytes] = []

    def transmit(sender, recipients, raw):
        attempts.append(raw)
        if b"\nCc:" in raw.replace(b"\r\n", b"\n"):
            raise smtplib.SMTPResponseException(
                550, b"5.7.1 recipient not on this gateway's outbound allowlist: dana@acme.test"
            )
        submissions.append(raw)
        return "2.0.0 sent"

    runner.agent._transmit = transmit
    uid, record = offer(runner, mailbox, _owner_ax_mail("dana@acme.test"))
    endpoint.reply(record["message_id"])
    delivery.step()

    assert len(attempts) == 2
    [sent] = submissions
    reply = BytesParser(policy=policy.default).parsebytes(sent)
    assert reply["To"] == "victor@gmail.test" and reply["Cc"] is None
    body = reply.get_body().get_content()
    assert "meant to reach dana@acme.test too" in body
    assert "(550 5.7.1 recipient not on this gateway's outbound allowlist: dana@acme.test)" in body
    saved = runner.handled.ax_reply("reply1")
    assert saved["state"] == "done" and saved["sender_only"]
    assert HANDLED_KEYWORD in mailbox.flags(uid) and endpoint.acked == ["reply1"]


def test_a_temporary_refusal_is_retried_reply_all_not_narrowed(tmp_path) -> None:
    runner, delivery, mailbox, endpoint, _submissions = setup(tmp_path)
    runner.agent._transmit = lambda *_: (_ for _ in ()).throw(
        smtplib.SMTPResponseException(450, b"4.7.1 external rate limit reached")
    )
    _uid, record = offer(runner, mailbox, _owner_ax_mail("dana@acme.test"))
    endpoint.reply(record["message_id"])
    with pytest.raises(AxError):
        delivery.step()
    saved = runner.handled.ax_reply("reply1")
    assert saved["state"] == "temporary" and not saved.get("sender_only")
    assert saved["cc"] == ["dana@acme.test"]


def test_a_retry_of_a_reply_that_closed_its_task_is_answered_as_sent(tmp_path) -> None:
    service, store, reinjected, _mailbox = _hold_service(
        tmp_path, outbound_allowlist=frozenset({"pat@plainmail.test"})
    )
    store.name_recipients("scheduler", "t_hold", ("pat@plainmail.test", "dana@acme.test"))
    raw = _request("pat@plainmail.test").replace(
        b"To: pat@plainmail.test\r\n",
        b"To: pat@plainmail.test\r\nCc: dana@acme.test\r\nMessage-ID: <reply-1@agents.test>\r\n",
    )
    raw = raw.replace(b"Agent-Task-State: submitted", b"Agent-Task-State: completed")
    first = service.submit("scheduler", TOKEN, raw)
    assert store.task("t_hold", "scheduler")["state"] == "completed"
    assert store.named_recipients("scheduler", "t_hold") == frozenset(), "the task is closed"
    again = service.submit("scheduler", TOKEN, raw)
    assert again.raw == first.raw and len(reinjected) == 1, "answered as sent, sent once"


def _outpost_service(tmp_path):
    """The gateway's real submission service for outpost, with nobody outside allowlisted."""
    from test_submission import _key

    from amx.adapters.submission import SubmissionService
    from amx.config import AgentConfig, TrustGrant
    from amx.journal import Journal
    from amx.store import Store

    tmp_path.mkdir()
    base = _config(tmp_path)
    _key(base.keys_dir / "outpost.private.pem")
    config = replace(
        base,
        domain="contoso.test",
        agent_domain="agents.contoso.test",
        agents={"outpost": AgentConfig(handler="mailbox-only", submit_token="outpost-token")},
        trust=(
            TrustGrant(
                d="agents.contoso.test",
                s="outpost",
                intents=frozenset({"*"}),
                schemas=frozenset({"*"}),
                can_open_tasks=True,
            ),
        ),
        outbound_allowlist=frozenset({"someone-else@else.test"}),
    )
    store = Store(tmp_path / "journal.sqlite")
    sent: list[tuple[str, tuple[str, ...], bytes]] = []
    service = SubmissionService(
        config,
        Journal(tmp_path, store),
        mailbox=RecordingMailbox(),
        reinject=lambda *args: sent.append(args),
    )
    return service, store, sent


def test_a_reply_all_replayed_after_a_lost_answer_is_sent_once_and_not_narrowed(tmp_path) -> None:
    service, store, sent = _outpost_service(tmp_path / "gateway")
    store.name_recipients("outpost", "t_owner", ("victor@gmail.test", "dana@acme.test"))
    runner, delivery, mailbox, endpoint, _submissions = setup(tmp_path)
    lost = []

    def transmit(sender, recipients, raw):
        try:
            service.submit(
                "outpost",
                "outpost-token",
                raw,
                envelope_from=sender,
                envelope_recipients=recipients,
            )
        except SubmissionError as error:
            raise smtplib.SMTPResponseException(550, str(error).encode()) from error
        if not lost:
            lost.append(raw)
            raise smtplib.SMTPServerDisconnected("connection lost before the 250")
        return "2.0.0 sent"

    runner.agent._transmit = transmit
    uid, record = offer(runner, mailbox, _owner_ax_mail("dana@acme.test"))
    endpoint.reply(record["message_id"], data={"task_state": "completed"})
    with pytest.raises(AxError, match="uncertain"):
        delivery.step()
    assert store.task("t_owner", "outpost")["state"] == "completed"

    restart(delivery).step()
    [(_sender, recipients, _raw)] = sent
    assert recipients == ("victor@gmail.test", "dana@acme.test")
    saved = runner.handled.ax_reply("reply1")
    assert saved["state"] == "done" and not saved.get("sender_only")
    assert HANDLED_KEYWORD in mailbox.flags(uid)


def test_a_held_final_reply_to_a_named_person_can_still_be_approved(tmp_path) -> None:
    service, store, reinjected, _mailbox = _hold_service(
        tmp_path, outbound_allowlist=frozenset({"pat@plainmail.test"})
    )
    store.name_recipients("scheduler", "t_hold", ("dana@acme.test",))
    store.taint_task("scheduler", "t_hold", ("directs-recipient",))
    raw = _request("dana@acme.test").replace(
        b"Agent-Task-State: submitted", b"Agent-Task-State: completed"
    )
    held = service.submit("scheduler", TOKEN, raw)
    assert held.held == "tainted-input"
    assert store.task("t_hold", "scheduler")["state"] == "completed", "holding closed the task"
    with pytest.raises(SubmissionError, match="outbound allowlist"):
        service.submit("scheduler", TOKEN, _request("dana@acme.test"))
    assert service.release("scheduler", _held_id(held)) is not None, "its approval still stands"
    assert [recipients for _sender, recipients, _raw in reinjected] == [("dana@acme.test",)]


@pytest.mark.parametrize("state", [b"working", b"completed"])
def test_a_retry_of_a_held_reply_all_is_answered_as_held_once(tmp_path, state) -> None:
    service, store, reinjected, mailbox = _hold_service(
        tmp_path, outbound_allowlist=frozenset({"pat@plainmail.test"})
    )
    store.name_recipients("scheduler", "t_hold", ("pat@plainmail.test", "dana@acme.test"))
    store.taint_task("scheduler", "t_hold", ("directs-recipient",))
    raw = _request("pat@plainmail.test, dana@acme.test").replace(
        b"Agent-Task-State: submitted",
        b"Agent-Task-State: " + state + b"\r\nMessage-ID: <held-1@agents.test>",
    )
    first = service.submit("scheduler", TOKEN, raw)
    again = service.submit("scheduler", TOKEN, raw)
    assert first.held == again.held == "tainted-input"
    assert len(store.rows("SELECT * FROM holds")) == 1 and len(mailbox.appended) == 1
    assert reinjected == []
    changed = raw.replace(b"Please inspect", b"Please re-inspect")
    with pytest.raises(SubmissionError):
        service.submit("scheduler", TOKEN, changed)
    widened = raw.replace(b"Subject:", b"Bcc: lee@other.test\r\nSubject:", 1)
    with pytest.raises(SubmissionError, match=r"outbound allowlist: .*lee@other\.test"):
        service.submit("scheduler", TOKEN, widened)
    assert len(store.rows("SELECT * FROM holds")) == 1


def test_a_lost_held_answer_is_replayed_without_a_second_message(tmp_path) -> None:
    service, store, sent = _outpost_service(tmp_path / "gateway")
    store.name_recipients("outpost", "t_owner", ("victor@gmail.test", "dana@acme.test"))
    store.taint_task("outpost", "t_owner", ("directs-recipient",))
    runner, delivery, mailbox, endpoint, _submissions = setup(tmp_path)
    answers = []

    def transmit(sender, recipients, raw):
        try:
            result = service.submit(
                "outpost",
                "outpost-token",
                raw,
                envelope_from=sender,
                envelope_recipients=recipients,
            )
        except SubmissionError as error:
            raise smtplib.SMTPResponseException(550, str(error).encode()) from error
        answers.append(result.held)
        if len(answers) == 1:
            raise smtplib.SMTPServerDisconnected("connection lost before the 250 held")
        return f"2.0.0 held rule={result.held}"

    runner.agent._transmit = transmit
    uid, record = offer(runner, mailbox, _owner_ax_mail("dana@acme.test"))
    endpoint.reply(record["message_id"], data={"task_state": "completed"})
    with pytest.raises(AxError, match="uncertain"):
        delivery.step()
    restart(delivery).step()

    assert answers == ["tainted-input", "tainted-input"] and sent == []
    [hold] = store.rows("SELECT recipients FROM holds")
    assert json.loads(hold["recipients"]) == ["victor@gmail.test", "dana@acme.test"]
    saved = runner.handled.ax_reply("reply1")
    assert saved["state"] == "done" and not saved.get("sender_only")
    assert HANDLED_KEYWORD in mailbox.flags(uid)


def test_a_delivery_the_journal_refuses_names_nobody(tmp_path) -> None:
    deliver, store, _sent, registry = _lmtp(tmp_path, lambda message, ctx: None)

    def refuse(*_args, **_kwargs):
        raise ValueError("journaled delivery does not match")

    deliver.handler.journal.append_delivery = refuse
    try:
        raw, _headers = _owner_mail("dana@acme.test")
        assert deliver(raw).values[0].startswith("550 5.6.0")
        assert store.rows("SELECT * FROM named_recipients") == []
    finally:
        registry.stop()
