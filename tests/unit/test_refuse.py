"""PLAN §5.11: a remote agent's refusal becomes a DSN at a verified sender, exactly once."""

from __future__ import annotations

import asyncio
import smtplib
import sqlite3
import ssl
from dataclasses import replace
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from types import SimpleNamespace

import pytest
from test_remote_agent import FakeImap

from amx.adapters.lmtp import LmtpHandler
from amx.adapters.submission import (
    ControlRefused,
    RefusalDeferred,
    SubmissionHandler,
    SubmissionService,
)
from amx.config import AgentConfig, GatewayConfig, LimitsConfig, MailboxConfig, TrustGrant
from amx.control import CONTROL_SCHEMA, Declaration, declaration, refusal_reason, refusal_status
from amx.dsn import bounce_verdict, build_dsn, dsn_message_id
from amx.journal import Journal
from amx.policy import Stage, State, TxnContext, evaluate
from amx.profile import SCHEMA_BASE, build, parse
from amx.runner import REFUSED_KEYWORD, HandledLog, ImapLogin, Runner, delivery_key
from amx.runtime import Context, HandlerRegistry, Refuse
from amx.sdk import Agent, Declared
from amx.store import Store

TOKEN = "dev-outpost-token"
AGENT_DOMAIN = "agents.contoso.test"
CONTROL = f"control@{AGENT_DOMAIN}"
SENDER = "scheduler+t_x@agents.northwind.test"
RECIPIENT = f"outpost+t_x@{AGENT_DOMAIN}"
MESSAGE_ID = "<r1@agents.northwind.test>"
GRANT = TrustGrant(
    d="agents.northwind.test",
    s="scheduler",
    intents=frozenset({"*"}),
    schemas=frozenset({"*"}),
    can_open_tasks=True,
)


def _grant(domain: str, selector: str) -> TrustGrant | None:
    return GRANT if (domain, selector) == ("agents.northwind.test", "scheduler") else None


def _delivered(*, lane: str = "agent", task: str = "t_x", message_id: str = MESSAGE_ID) -> bytes:
    """A request as contoso's LMTP journaled it, the milter's verdict headers on top."""
    message = build(
        sender=f"scheduler+{task}@agents.northwind.test",
        to=f"outpost+{task}@{AGENT_DOMAIN}",
        subject="Site inspection [refuse]",
        intent="request",
        task=task,
        task_state="submitted",
        text="Please confirm Tuesday.",
        payload={"action": "confirm"},
        schema=f"{SCHEMA_BASE}request.json",
        message_id=message_id,
    )
    if lane == "agent":
        verdicts = (
            "Agent-Lane: agent\r\nAgent-Trust: verified\r\n"
            "Agent-Verified-Domain: agents.northwind.test\r\nAgent-Verified-Selector: scheduler\r\n"
            "Agent-Content-Judgment: mode=enforce; directs_recipient=0.020\r\n"
        )
        return verdicts.encode() + message.as_bytes(policy=policy.SMTP)
    person = EmailMessage(policy=policy.SMTP)
    person["From"] = "pat@plainmail.test"
    person["To"] = f"outpost@{AGENT_DOMAIN}"
    person["Subject"] = "Hello [refuse]"
    person["Message-ID"] = message_id
    person.set_content("Could you look at this?")
    return b"Agent-Lane: human\r\nAgent-Trust: low\r\n" + person.as_bytes(policy=policy.SMTP)


# --- the command and its status/reason vocabulary ---


def test_a_handlers_refusal_maps_onto_the_short_list() -> None:
    assert [refusal_status(code) for code in ("5.7.1", "5.6.0", "5.3.0")] == [
        "5.7.1",
        "5.6.0",
        "5.3.0",
    ]
    assert refusal_status("5.6.3") == "5.6.0", "any content code is content"
    assert refusal_status("5.1.1") == "5.7.1" and refusal_status("nonsense") == "5.7.1"
    assert refusal_reason("5.7.1", None) == "policy"
    assert refusal_reason("5.6.0", None) == "content"
    assert refusal_reason("5.3.0", None) == "handler-failed"
    assert refusal_reason("5.7.1", "unsupported") == "unsupported"
    assert refusal_reason("5.7.1", "the building is on fire") == "policy", "never free text"
    assert Refuse("5.7.1", "no", reason="content").reason == "content"
    assert Refuse("5.7.1", "no").reason is None, "the in-process signature is unchanged"


def test_a_refuse_declaration_names_one_message_and_never_expires() -> None:
    payload = {
        "command": "refuse",
        "recipient": RECIPIENT,
        "message_id": MESSAGE_ID,
        "status": "5.6.0",
        "reason": "content",
    }
    declared = declaration(payload, now=0.0, max_ttl=60)
    assert declared == Declaration(
        "refuse", reason="content", recipient=RECIPIENT, message_id=MESSAGE_ID, status="5.6.0"
    )
    assert declared.expires_at is None
    assert declared.summary() == (
        f"refuse recipient={RECIPIENT} message_id={MESSAGE_ID} status=5.6.0 reason=content"
    )


def test_the_sdk_sends_a_refusal_to_the_control_address() -> None:
    sent: list[tuple[str, list[str], bytes]] = []
    agent = Agent(f"outpost@{AGENT_DOMAIN}", "smtp://edge-ct:2587", TOKEN)

    def transmit(envelope_from: str, recipients, raw: bytes) -> str:
        sent.append((envelope_from, list(recipients), raw))
        return "2.0.0 declared refuse dsn=sent why=verified"

    agent._transmit = transmit  # type: ignore[method-assign]
    declared = agent.refuse(RECIPIENT, MESSAGE_ID, status="5.7.1", reason="unsupported")
    assert declared.applied == "refuse dsn=sent why=verified"
    [(envelope_from, recipients, raw)] = sent
    assert (envelope_from, recipients) == (f"outpost@{AGENT_DOMAIN}", [CONTROL])
    inbound = parse(raw)
    assert (inbound.intent, inbound.schema) == ("event", CONTROL_SCHEMA)
    assert inbound.payload == {
        "@context": "https://schema.org",
        "command": "refuse",
        "recipient": RECIPIENT,
        "message_id": MESSAGE_ID,
        "status": "5.7.1",
        "reason": "unsupported",
    }
    with pytest.raises(ValueError):
        agent.refuse(RECIPIENT, "free text", status="5.7.1")


# --- the backscatter guard ---


@pytest.mark.parametrize(
    ("delivered", "envelope_from", "send", "why"),
    [
        (_delivered(), SENDER, True, "verified"),
        (_delivered(), "scheduler@mx.agents.northwind.test", True, "verified"),
        (_delivered(), "SCHEDULER+t_x@Agents.Northwind.Test.", True, "verified"),
        (_delivered(), "", False, "null-sender"),
        (_delivered(), None, False, "sender-unrecorded"),
        (_delivered(), "pat@plainmail.test", False, "sender-unaligned"),
        (_delivered(), "x@evilagents.northwind.test", False, "sender-unaligned"),
        (_delivered(lane="human"), "pat@plainmail.test", False, "sender-unverified"),
        (
            b"From: MAILER-DAEMON@contoso.test\r\n\r\nno verdicts",
            SENDER,
            False,
            "sender-unverified",
        ),
        (b"Agent-Lane: agent\r\n\r\nincomplete verdicts", SENDER, False, "sender-unverified"),
    ],
)
def test_only_a_sender_verified_at_ingress_gets_a_dsn(
    delivered: bytes, envelope_from: str | None, send: bool, why: str
) -> None:
    verdict = bounce_verdict(delivered, envelope_from, _grant)
    assert (verdict.send, verdict.why) == (send, why)


def test_a_grant_revoked_since_the_delivery_gets_no_dsn() -> None:
    verdict = bounce_verdict(_delivered(), SENDER, lambda _domain, _selector: None)
    assert (verdict.send, verdict.why) == (False, "no-grant")


# --- the report ---


def _report(**overrides: object) -> bytes:
    fields: dict[str, object] = {
        "original": _delivered(),
        "envelope_from": SENDER,
        "recipient": RECIPIENT,
        "status": "5.7.1",
        "reason": "policy",
        "domain": "contoso.test",
        "reporting_mta": AGENT_DOMAIN,
        "message_id": dsn_message_id(RECIPIENT, MESSAGE_ID, AGENT_DOMAIN),
        "arrival": "Sun, 27 Sep 2026 12:00:00 +0000",
        **overrides,
    }
    return build_dsn(**fields)  # type: ignore[arg-type]


def test_the_dsn_is_an_rfc3464_report_the_sender_reads_as_a_failed_task() -> None:
    report = _report()
    message = BytesParser(policy=policy.default).parsebytes(report)
    assert message.get_content_type() == "multipart/report"
    assert message.get_param("report-type") == "delivery-status"
    assert str(message["From"]) == "Mail Delivery System <MAILER-DAEMON@contoso.test>"
    assert (str(message["To"]), str(message["Auto-Submitted"])) == (SENDER, "auto-replied")
    assert "DKIM-Signature" not in message, "unsigned, as the MTAs' bounces are"
    parts = [part.get_content_type() for part in message.iter_parts()]
    assert parts == ["text/plain", "message/delivery-status", "text/rfc822-headers"]
    inbound = parse(report)
    assert (inbound.intent, inbound.task, inbound.task_state, inbound.lane) == (
        "error",
        "t_x",
        "failed",
        "system",
    )
    assert inbound.status == "5.7.1"
    assert inbound.report is not None and inbound.report.recipient == RECIPIENT
    assert inbound.diagnostic == "smtp; 550 5.7.1 refused by the recipient agent (policy)"
    returned = message.get_payload()[2].get_payload()
    assert "Subject: Site inspection [refuse]" in returned and MESSAGE_ID in returned
    for verdict in ("Agent-Lane", "Agent-Trust", "Agent-Verified", "Agent-Content-Judgment"):
        assert verdict not in returned, "this gateway's own verdicts stay here"
    assert "Arrival-Date: Sun, 27 Sep 2026 12:00:00 +0000" in report.decode()


def test_the_senders_milter_accepts_the_dsn_on_the_human_lane() -> None:
    accepted = evaluate(
        Stage.EOD,
        TxnContext(
            mail_from="",
            recipient=SENDER,
            recipient_agent="scheduler",
            task_token="t_x",
            raw=_report(),
            from_domain="contoso.test",
        ),
        State(agent_domain="agents.northwind.test", known_tasks=frozenset({("scheduler", "t_x")})),
    )
    assert accepted.accepted, accepted
    assert ("Agent-Lane", "human") in accepted.headers


def test_the_same_refusal_always_has_the_same_dsn_message_id() -> None:
    first = dsn_message_id(RECIPIENT, MESSAGE_ID, AGENT_DOMAIN)
    assert first == dsn_message_id(RECIPIENT, MESSAGE_ID, AGENT_DOMAIN)
    assert first != dsn_message_id(RECIPIENT, "<r2@agents.northwind.test>", AGENT_DOMAIN)
    assert first.startswith("<dsn-") and first.endswith(f"@{AGENT_DOMAIN}>")


def test_eight_bit_headers_are_returned_as_eight_bit() -> None:
    original = "Subject: Café\r\nMessage-ID: <u@x>\r\n\r\nbody".encode()
    report = _report(original=original)
    assert b"Content-Transfer-Encoding: 8bit" in report
    assert "Café".encode() in report


# --- the gateway: submission's control path ---


def _config(tmp_path, **agents: AgentConfig) -> GatewayConfig:
    return GatewayConfig(
        domain="contoso.test",
        agent_domain=AGENT_DOMAIN,
        data_dir=tmp_path,
        agents=agents
        or {
            "outpost": AgentConfig(handler="mailbox-only", mode="remote", submit_token=TOKEN),
            "intake": AgentConfig(handler="mailbox-only", submit_token="dev-intake-token"),
        },
        trust=(GRANT,),
        limits=LimitsConfig(),
        mailbox=MailboxConfig(host="mail.contoso.test"),
    )


class Reinject:
    def __init__(self) -> None:
        self.sent: list[tuple[str, tuple[str, ...], bytes]] = []
        self.failures: list[Exception] = []

    def __call__(self, sender: str, recipients: tuple[str, ...], raw: bytes) -> None:
        if self.failures:
            raise self.failures.pop(0)
        self.sent.append((sender, recipients, raw))


class Inbox:
    """The agent's INBOX as the gateway's master login reads it: its unfinished copies."""

    def __init__(self) -> None:
        self.unfinished_copies: set[tuple[str, str]] = {(RECIPIENT, MESSAGE_ID)}
        self.error: Exception | None = None
        self.reads: list[str] = []

    def unfinished(self, address: str, recipient: str, message_id: str) -> bool:
        self.reads.append(address)
        if self.error is not None:
            raise self.error
        return (recipient, message_id) in self.unfinished_copies


def _gateway(tmp_path, **agents: AgentConfig):
    store = Store(tmp_path / "journal.sqlite")
    journal = Journal(tmp_path, store)
    reinject = Reinject()
    service = SubmissionService(
        _config(tmp_path, **agents),
        journal,
        reinject=reinject,
        mailbox=Inbox(),  # type: ignore[arg-type]
    )
    return service, store, journal, reinject


def _file(
    journal: Journal,
    store: Store,
    raw: bytes | None = None,
    *,
    recipient: str = RECIPIENT,
    agent: str = "outpost",
    message_id: str = MESSAGE_ID,
    envelope_from: str | None = SENDER,
    complete: bool = True,
) -> None:
    """File a delivery as LMTP does for a remote agent: journaled, handled, completed."""
    raw = raw if raw is not None else _delivered()
    entry = journal.append_delivery(
        raw,
        recipient=recipient,
        agent=agent,
        identity="agents.northwind.test",
        task="t_x",
        message_id=message_id,
        envelope_from=envelope_from,
    )
    if complete:
        store.mark_handler_completed(recipient, message_id)
        store.complete_delivery(recipient, message_id, agent, entry.raw_sha256)


def _command(
    recipient: str = RECIPIENT,
    message_id: str = MESSAGE_ID,
    *,
    sender: str = f"outpost@{AGENT_DOMAIN}",
    status: str = "5.7.1",
    reason: str = "policy",
) -> bytes:
    return build(
        sender=sender,
        to=CONTROL,
        subject="AMX control: refuse",
        intent="event",
        task="t_ctl",
        task_state="completed",
        text="A control declaration.",
        payload={
            "command": "refuse",
            "recipient": recipient,
            "message_id": message_id,
            "status": status,
            "reason": reason,
        },
        schema=CONTROL_SCHEMA,
    ).as_bytes(policy=policy.SMTP)


def _refuse(service: SubmissionService, raw: bytes | None = None, agent: str = "outpost") -> str:
    token = TOKEN if agent == "outpost" else "dev-intake-token"
    result = service.submit(
        agent,
        token,
        raw or _command(),
        envelope_from=f"{agent}@{AGENT_DOMAIN}",
        envelope_recipients=(CONTROL,),
    )
    assert result.declared is not None and result.recipients == (CONTROL,)
    return result.declared


def test_a_refusal_bounces_to_the_verified_sender_once(tmp_path) -> None:
    service, store, journal, reinject = _gateway(tmp_path)
    _file(journal, store)
    store.put_task("t_x", "outpost", "submitted")

    applied = _refuse(service)

    summary = f"refuse recipient={RECIPIENT} message_id={MESSAGE_ID} status=5.7.1 reason=policy"
    assert applied == "refuse status=5.7.1 reason=policy dsn=sent why=verified"
    assert service.mailbox.reads == [f"outpost@{AGENT_DOMAIN}"]  # type: ignore[union-attr]
    [(sender, recipients, report)] = reinject.sent
    assert (sender, recipients) == ("", (SENDER,)), "null envelope sender, to the MAIL FROM"
    dsn = parse(report)
    assert (dsn.intent, dsn.task, dsn.task_state, dsn.status) == ("error", "t_x", "failed", "5.7.1")
    assert b"intake does not take" not in report
    row = store.refusal(RECIPIENT, MESSAGE_ID)
    assert row is not None
    assert (row["agent"], row["task"], row["dsn"], row["why"], row["claimed_epoch"]) == (
        "outpost",
        "t_x",
        "sent",
        "verified",
        None,
    )
    assert row["dsn_message_id"] == dsn_message_id(RECIPIENT, MESSAGE_ID, AGENT_DOMAIN)
    events = store.rows("SELECT direction, event, task, message_id, detail FROM journal")
    assert [(event["direction"], event["event"]) for event in events] == [
        ("inbound", "lmtp-received"),
        ("control", "control-refuse"),
        ("outbound", "dsn"),
    ]
    assert events[1]["detail"] == f"agent=outpost {summary} dsn=pending why=verified"
    assert (events[1]["task"], events[1]["message_id"]) == ("t_x", MESSAGE_ID), "traced there"
    assert (events[2]["task"], events[2]["message_id"]) == ("t_x", row["dsn_message_id"])
    assert store.task("t_x")["state"] == "submitted", "a refusal writes no task state"
    assert store.delivery_progress(RECIPIENT, MESSAGE_ID)["state"] == "completed"

    service.mailbox.unfinished_copies.clear()  # type: ignore[union-attr]  # the runner finished
    again = _refuse(service)
    assert again == "refuse status=5.7.1 reason=policy dsn=sent why=verified again"
    assert len(reinject.sent) == 1, "a repeated command sends no second DSN"
    assert store.rows("SELECT event, detail FROM journal")[-1]["detail"].endswith("again dsn=sent")
    other_reason = _refuse(service, _command(status="5.6.0", reason="content"))
    assert other_reason.endswith("again") and len(reinject.sent) == 1
    assert store.refusal(RECIPIENT, MESSAGE_ID)["status"] == "5.7.1", "the first refusal stands"


@pytest.mark.parametrize("live_domain", [False, True])
def test_local_refusal_dsn_reaches_completed_senders_task_only(
    tmp_path, monkeypatch, live_domain
) -> None:
    sender = f"scheduler+t_x@{AGENT_DOMAIN}"
    config = replace(
        _config(
            tmp_path,
            outpost=AgentConfig(handler="mailbox-only", mode="remote", submit_token=TOKEN),
            scheduler=AgentConfig(handler="mailbox-only"),
        ),
        domain=AGENT_DOMAIN if live_domain else "contoso.test",
        sibling_port=10027,
        trust=(replace(GRANT, d=AGENT_DOMAIN),),
    )
    store = Store(tmp_path / "journal.sqlite")
    journal = Journal(tmp_path, store)
    service = SubmissionService(config, journal, mailbox=Inbox())
    original = _delivered().replace(b"agents.northwind.test", AGENT_DOMAIN.encode())
    local_id = f"<r1@{AGENT_DOMAIN}>"
    _file(journal, store, original, message_id=local_id, envelope_from=sender)
    service.mailbox.unfinished_copies = {(RECIPIENT, local_id)}
    store.put_task("t_x", "scheduler", "completed")
    store.put_task("t_x", "outpost", "submitted")
    before = dict(store.task("t_x", "outpost"))
    calls = []
    monkeypatch.setattr(service, "_smtp_send", lambda *args: calls.append(args))

    assert "dsn=sent" in _refuse(service, _command(message_id=local_id))
    [(envelope_from, recipients, report, port)] = calls
    assert (envelope_from, recipients, port) == ("", (sender,), config.postfix_port)
    assert store.task("t_x", "scheduler")["state"] == "completed", "sending is not delivery"
    assert dict(store.task("t_x", "outpost")) == before
    parsed = parse(report)
    assert (parsed.lane, parsed.task, parsed.task_state) == ("system", "t_x", "failed")
    assert b"Auto-Submitted: auto-replied" in report

    registry = HandlerRegistry()
    received = []
    registry.register("scheduler", lambda message, _context: received.append(message))
    copies = []
    mailbox = SimpleNamespace(append=lambda *args, **kwargs: copies.append(args))
    handler = LmtpHandler(config, store, journal, registry, mailbox)
    envelope = SimpleNamespace(original_content=report, rcpt_tos=list(recipients), mail_from="")
    [status] = asyncio.run(handler.handle_DATA(None, None, envelope)).values
    assert status.startswith("250"), status
    assert len(received) == 1 and received[0].lane == "system"
    assert copies[0][0] == f"scheduler@{AGENT_DOMAIN}"
    assert store.task("t_x", "scheduler")["state"] == "failed"
    assert dict(store.task("t_x", "outpost")) == before
    assert store.delivered(sender, parsed.thread.message_id)


def test_a_dsn_that_could_not_be_sent_is_sent_by_the_retry(tmp_path) -> None:
    service, store, journal, reinject = _gateway(tmp_path)
    _file(journal, store)
    reinject.failures = [smtplib.SMTPServerDisconnected("mailhost went away")]
    with pytest.raises(smtplib.SMTPServerDisconnected):
        _refuse(service)
    row = store.refusal(RECIPIENT, MESSAGE_ID)
    assert (row["dsn"], row["claimed_epoch"]) == ("pending", None), "released for the retry"
    events = store.rows("SELECT event, raw_sha256 FROM journal")
    assert [event["event"] for event in events][-2:] == ["control-refuse", "dsn-failed"]

    assert _refuse(service).endswith("dsn=sent why=verified again")
    assert len(reinject.sent) == 1
    assert store.refusal(RECIPIENT, MESSAGE_ID)["dsn"] == "sent"
    events = store.rows("SELECT event, raw_sha256 FROM journal")
    assert [event["event"] for event in events][-2:] == ["dsn-failed", "dsn"], (
        "a retry of a pending DSN is journaled by its attempt alone"
    )
    assert events[-1]["raw_sha256"] == events[-2]["raw_sha256"], "the same bytes each attempt"


def test_a_dsn_another_command_is_sending_answers_451(tmp_path) -> None:
    service, store, journal, reinject = _gateway(tmp_path)
    _file(journal, store)
    reinject.failures = [smtplib.SMTPServerDisconnected("mailhost went away")]
    with pytest.raises(smtplib.SMTPServerDisconnected):
        _refuse(service)
    assert store.claim_refusal_dsn(RECIPIENT, MESSAGE_ID, now=service.clock())
    with pytest.raises(RefusalDeferred):
        _refuse(service)
    assert reinject.sent == []
    reply = asyncio.run(
        SubmissionHandler(service).handle_DATA(
            None,
            SimpleNamespace(auth_data=("outpost", TOKEN)),
            SimpleNamespace(
                original_content=_command(),
                mail_from=f"outpost@{AGENT_DOMAIN}",
                rcpt_tos=[CONTROL],
            ),
        )
    )
    assert reply.startswith("451 4.3.0 the DSN for this refusal is being sent")
    later = service.clock() + 61
    assert store.claim_refusal_dsn(RECIPIENT, MESSAGE_ID, now=later), "a stale claim lapses"


@pytest.mark.parametrize(
    ("raw", "envelope_from", "why"),
    [
        (_delivered(lane="human"), "pat@plainmail.test", "sender-unverified"),
        (_delivered(), "pat@plainmail.test", "sender-unaligned"),
        (_delivered(), "", "null-sender"),
        (_delivered(), None, "sender-unrecorded"),
    ],
)
def test_a_refusal_of_an_unverified_sender_is_recorded_without_a_dsn(
    tmp_path, raw: bytes, envelope_from: str | None, why: str
) -> None:
    service, store, journal, reinject = _gateway(tmp_path)
    _file(journal, store, raw, envelope_from=envelope_from)
    assert _refuse(service).endswith(f"dsn=dropped why={why}")
    assert reinject.sent == []
    row = store.refusal(RECIPIENT, MESSAGE_ID)
    assert (row["dsn"], row["why"], row["dsn_message_id"]) == ("dropped", why, None)
    [control] = store.rows("SELECT detail FROM journal WHERE event = 'control-refuse'")
    assert control["detail"].endswith(f"dsn=dropped why={why}")
    assert _refuse(service).endswith(f"dsn=dropped why={why} again") and reinject.sent == []


@pytest.mark.parametrize(
    ("command", "agent", "match"),
    [
        (_command(message_id="<never@agents.northwind.test>"), "outpost", "no message"),
        (_command(recipient=f"intake+t_x@{AGENT_DOMAIN}"), "outpost", "not an address of"),
        (_command(recipient="outpost+t_x@agents.northwind.test"), "outpost", "not an address"),
        (_command(recipient=f"outposts@{AGENT_DOMAIN}"), "outpost", "not an address of"),
        (_command(sender=f"intake@{AGENT_DOMAIN}"), "intake", "remote agent"),
    ],
)
def test_a_refusal_must_name_mail_filed_for_the_login_s_remote_agent(
    tmp_path, command: bytes, agent: str, match: str
) -> None:
    service, store, journal, reinject = _gateway(tmp_path)
    _file(journal, store)
    _file(journal, store, recipient=f"intake+t_x@{AGENT_DOMAIN}", agent="intake")
    with pytest.raises(ControlRefused, match=match):
        _refuse(service, command, agent=agent)
    assert reinject.sent == [] and store.rows("SELECT 1 FROM refusals") == []
    [refused] = store.rows("SELECT * FROM policy_events")
    assert (refused["rule"], refused["agent"]) == ("control-refused", agent)


def test_a_refusal_racing_the_gateways_own_completion_write_is_taken(tmp_path) -> None:
    # LMTP appends the copy, then records the delivery completed; the runner can be faster.
    service, store, journal, reinject = _gateway(tmp_path)
    _file(journal, store, complete=False)
    store.mark_handler_completed(RECIPIENT, MESSAGE_ID)
    assert _refuse(service).endswith("dsn=sent why=verified"), "the copy is in the INBOX: filed"
    assert len(reinject.sent) == 1


def test_a_refusal_of_mail_not_filed_yet_is_deferred_not_refused(tmp_path) -> None:
    service, store, journal, reinject = _gateway(tmp_path)
    _file(journal, store, complete=False)
    service.mailbox.unfinished_copies.clear()  # type: ignore[union-attr]
    with pytest.raises(RefusalDeferred, match="not filed yet"):
        _refuse(service)
    service.mailbox.error = OSError("mailhost down")  # type: ignore[union-attr]
    with pytest.raises(RefusalDeferred, match="cannot read outpost's INBOX"):
        _refuse(service)
    assert reinject.sent == [] and store.rows("SELECT 1 FROM refusals") == []


def test_mail_the_agent_already_finished_cannot_be_refused_later(tmp_path) -> None:
    service, store, journal, reinject = _gateway(tmp_path)
    _file(journal, store)
    service.mailbox.unfinished_copies.clear()  # type: ignore[union-attr]
    with pytest.raises(ControlRefused, match="not waiting in outpost's INBOX"):
        _refuse(service)
    assert reinject.sent == [] and store.rows("SELECT 1 FROM refusals") == []
    [refused] = store.rows("SELECT rule, agent FROM policy_events")
    assert (refused["rule"], refused["agent"]) == ("control-refused", "outpost")


def test_a_dsn_the_mta_refuses_for_good_is_dropped_not_retried(tmp_path) -> None:
    service, store, journal, reinject = _gateway(tmp_path)
    _file(journal, store)
    reinject.failures = [smtplib.SMTPSenderRefused(550, b"5.7.1 null sender refused", "")]
    assert _refuse(service).endswith("dsn=dropped why=reinject-refused")
    row = store.refusal(RECIPIENT, MESSAGE_ID)
    assert (row["dsn"], row["why"], row["claimed_epoch"]) == ("dropped", "reinject-refused", None)
    [failed] = store.rows("SELECT detail FROM journal WHERE event = 'dsn-failed'")
    assert "reinjection refused, DSN dropped" in failed["detail"]
    assert _refuse(service).endswith("again") and reinject.sent == []


def test_a_dsn_to_a_sender_off_the_outbound_allowlist_is_dropped(tmp_path) -> None:
    service, store, journal, reinject = _gateway(tmp_path)
    service.config = replace(service.config, outbound_allowlist=frozenset({"other@else.test"}))
    _file(journal, store)
    assert _refuse(service).endswith("dsn=dropped why=not-allowlisted")
    assert reinject.sent == []
    row = store.refusal(RECIPIENT, MESSAGE_ID)
    assert (row["dsn"], row["why"], row["claimed_epoch"]) == ("dropped", "not-allowlisted", None)
    [failed] = store.rows("SELECT detail FROM journal WHERE event = 'dsn-failed'")
    assert failed["detail"].endswith("sender not on the outbound allowlist")


def test_every_refusal_the_gateway_will_never_take_is_marked(tmp_path) -> None:
    service, store, journal, _reinject = _gateway(tmp_path)
    _file(journal, store)
    reply = asyncio.run(
        SubmissionHandler(service).handle_DATA(
            None,
            SimpleNamespace(auth_data=("outpost", TOKEN)),
            SimpleNamespace(
                original_content=_command(message_id="<never@x.test>"),
                mail_from=f"outpost@{AGENT_DOMAIN}",
                rcpt_tos=[CONTROL],
            ),
        )
    )
    assert reply.startswith("550 5.7.1 refusal rejected: no message <never@x.test>"), reply


def test_a_dsn_that_can_never_be_sent_is_dropped_not_retried(tmp_path) -> None:
    service, store, journal, reinject = _gateway(tmp_path)
    _file(journal, store)
    reinject.failures = [UnicodeEncodeError("ascii", "ü", 0, 1, "an SMTPUTF8 sender")]
    assert _refuse(service).endswith("dsn=dropped why=dsn-error")
    assert store.refusal(RECIPIENT, MESSAGE_ID)["claimed_epoch"] is None


def test_a_dsn_whose_report_cannot_be_built_is_dropped(tmp_path, monkeypatch) -> None:
    service, store, journal, reinject = _gateway(tmp_path)
    _file(journal, store)

    def broken(*_args: object, **_kwargs: object) -> bytes:
        raise KeyError("a report-building bug")

    monkeypatch.setattr(service, "_dsn_report", broken)
    assert _refuse(service).endswith("dsn=dropped why=dsn-error")
    [failed] = store.rows("SELECT detail FROM journal WHERE event = 'dsn-failed'")
    assert "not built, DSN dropped" in failed["detail"] and reinject.sent == []


def test_a_refusal_whose_journaled_original_is_gone_gets_no_dsn(tmp_path) -> None:
    service, store, journal, reinject = _gateway(tmp_path)
    _file(journal, store)
    digest = str(store.delivery_progress(RECIPIENT, MESSAGE_ID)["raw_sha256"])
    journal.raw_path(digest).unlink()
    assert _refuse(service).endswith("dsn=dropped why=original-unreadable")
    assert reinject.sent == []


def test_a_dsn_still_pending_after_its_attempt_is_never_answered_250(tmp_path, monkeypatch) -> None:
    service, store, journal, _reinject = _gateway(tmp_path)
    _file(journal, store)
    monkeypatch.setattr(store, "finish_refusal_dsn", lambda *_args, **_kwargs: None)
    with pytest.raises(RefusalDeferred, match="still pending"):
        _refuse(service)


def test_a_gateway_without_a_mailbox_defers_refusals(tmp_path) -> None:
    store = Store(tmp_path / "journal.sqlite")
    journal = Journal(tmp_path, store)
    service = SubmissionService(_config(tmp_path), journal, reinject=Reinject())
    _file(journal, store)
    with pytest.raises(RefusalDeferred, match="no mailbox"):
        _refuse(service)


def test_one_agents_token_cannot_refuse_another_agents_mail(tmp_path) -> None:
    remote = AgentConfig(handler="mailbox-only", mode="remote", submit_token=TOKEN)
    other = AgentConfig(handler="mailbox-only", mode="remote", submit_token="other-token")
    service, store, journal, reinject = _gateway(tmp_path, outpost=remote, relay=other)
    _file(journal, store)
    with pytest.raises(ControlRefused):
        service.submit(
            "relay",
            "other-token",
            _command(sender=f"relay@{AGENT_DOMAIN}"),
            envelope_recipients=(CONTROL,),
        )
    with pytest.raises(ControlRefused, match="login's agent"):
        service.submit("relay", "other-token", _command(), envelope_recipients=(CONTROL,))
    assert reinject.sent == []


# --- LMTP keeps the envelope sender ---


def test_lmtp_keeps_each_deliverys_envelope_sender(tmp_path) -> None:
    config = _config(tmp_path, intake=AgentConfig(handler="mailbox-only"))
    store = Store(tmp_path / "journal.sqlite")
    registry = HandlerRegistry()
    registry.register("intake", lambda _message, _context: None)

    class Mailbox:
        def append(self, *_args: object, **_kwargs: object) -> None:
            return None

    handler = LmtpHandler(config, store, Journal(tmp_path, store), registry, Mailbox())  # type: ignore[arg-type]
    recipient = f"intake+t_x@{AGENT_DOMAIN}"
    raw = _delivered().replace(b"outpost+t_x", b"intake+t_x")
    for mail_from, message_id, stored in (
        (f"<{SENDER}>", MESSAGE_ID, SENDER),
        ("<>", "<bounce@x>", ""),
    ):
        envelope = SimpleNamespace(
            original_content=raw.replace(MESSAGE_ID.encode(), message_id.encode()),
            rcpt_tos=[recipient],
            mail_from=mail_from,
        )
        [status] = asyncio.run(handler.handle_DATA(None, None, envelope)).values
        assert status.startswith("250"), status
        assert store.delivery_progress(recipient, message_id)["envelope_from"] == stored
    details = [row["detail"] for row in store.rows("SELECT detail FROM journal")]
    assert details[0].startswith(f"recipient={recipient} agent=intake from=<{SENDER}>")
    assert details[1].startswith(f"recipient={recipient} agent=intake from=<>")


def test_an_older_store_gains_the_envelope_sender_column(tmp_path) -> None:
    path = tmp_path / "journal.sqlite"
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE delivery_progress (message_id TEXT NOT NULL, recipient TEXT NOT NULL, "
        "agent TEXT NOT NULL, raw_sha256 TEXT NOT NULL, journal_sequence INTEGER NOT NULL, "
        "state TEXT NOT NULL, response TEXT, "
        "updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')), "
        "PRIMARY KEY (recipient, message_id))"
    )
    connection.commit()
    connection.close()
    store = Store(path)
    with store.connection() as reading:
        info = reading.execute("PRAGMA table_info(delivery_progress)").fetchall()
    columns = {row["name"] for row in info}
    assert "envelope_from" in columns
    assert store.rows("SELECT 1 FROM refusals") == []


# --- the runner reports what it refused ---

ADDRESS = f"outpost@{AGENT_DOMAIN}"


def _filed_copy(message_id: str = MESSAGE_ID, task: str = "t_x") -> bytes:
    return f"Delivered-To: outpost+{task}@{AGENT_DOMAIN}\r\n".encode() + _delivered(
        task=task, message_id=message_id
    )


class Clock:
    def __init__(self) -> None:
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now


REJECTED = "5.7.1 refusal rejected:"


def _runner(tmp_path, handler, answers: list[object], clock: Clock | None = None):
    """A runner whose gateway answers each refuse command with the next item of ``answers``."""
    agent = Agent(ADDRESS, "smtp://gateway-ct:2587", TOKEN)
    agent.send = lambda **_message: None  # type: ignore[method-assign]
    calls: list[dict[str, object]] = []

    def refuse(recipient: str, message_id: str, **fields: object) -> Declared:
        calls.append({"recipient": recipient, "message_id": message_id, **fields})
        answer = answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return Declared("t_ctl", "<ctl@x>", str(answer))

    agent.refuse = refuse  # type: ignore[method-assign]
    log = HandledLog(tmp_path / "runner.sqlite")
    runner = Runner(
        agent,
        ImapLogin("mailhost-ct", 143, ADDRESS, "dev-outpost"),
        handler,
        log,
        clock=clock or Clock(),
    )
    return runner, calls


def _refused(code: str = "5.7.1", reason: str | None = None):
    def handle(_message, _context: Context) -> None:
        raise Refuse(code, "intake does not take this request", reason=reason)

    return handle


def test_the_runner_reports_a_refusal_before_it_finishes_the_message(tmp_path) -> None:
    runner, calls = _runner(tmp_path, _refused(), ["refuse dsn=sent why=verified"])
    imap = FakeImap()
    uid = imap.add(_filed_copy())
    assert runner.drain(imap) == 0  # type: ignore[arg-type]
    assert calls == [
        {"recipient": RECIPIENT, "message_id": MESSAGE_ID, "status": "5.7.1", "reason": "policy"}
    ]
    assert imap.flags(uid) == {"\\Seen", "$AmxHandled", REFUSED_KEYWORD}
    assert runner.handled.unanswered_refusal(delivery_key(_filed_copy())) is None
    assert runner.drain(imap) == 0 and len(calls) == 1  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("code", "reason", "status", "token"),
    [
        ("5.6.3", None, "5.6.0", "content"),
        ("5.1.1", "unsupported", "5.7.1", "unsupported"),
        ("5.7.1", "free text", "5.7.1", "policy"),
    ],
)
def test_the_runner_sends_a_listed_status_and_reason(
    tmp_path, code: str, reason: str | None, status: str, token: str
) -> None:
    runner, calls = _runner(tmp_path, _refused(code, reason), ["ok"])
    imap = FakeImap()
    imap.add(_filed_copy())
    runner.drain(imap)  # type: ignore[arg-type]
    assert (calls[0]["status"], calls[0]["reason"]) == (status, token)


def test_a_lost_refusal_is_sent_again_without_running_the_handler_again(tmp_path) -> None:
    ran: list[str | None] = []

    def handle(message, _context: Context) -> None:
        ran.append(message.task)
        raise Refuse("5.7.1", "no")

    answers: list[object] = [
        OSError("gateway unreachable"),
        smtplib.SMTPDataError(451, b"4.3.0 the DSN for this refusal is being sent; retry"),
        "refuse dsn=sent why=verified",
    ]
    clock = Clock()
    runner, calls = _runner(tmp_path, handle, answers, clock)
    imap = FakeImap()
    uid = imap.add(_filed_copy())
    assert runner.drain(imap) == 1  # type: ignore[arg-type]
    assert imap.flags(uid) == set(), "unfinished, and not taken while the report waits"
    clock.now += 4
    assert runner.drain(imap) == 1 and len(calls) == 1, "backing off: 5 s after the first"  # type: ignore[arg-type]
    clock.now += 1
    assert runner.drain(imap) == 1  # type: ignore[arg-type]
    assert imap.flags(uid) == set() and len(calls) == 2
    clock.now += 9
    assert runner.drain(imap) == 1 and len(calls) == 2, "then 10 s"  # type: ignore[arg-type]
    clock.now += 1
    assert runner.drain(imap) == 0  # type: ignore[arg-type]
    assert imap.flags(uid) == {"\\Seen", "$AmxHandled", REFUSED_KEYWORD}
    assert ran == ["t_x"] and len(calls) == 3


def test_a_refusal_the_control_path_rejects_is_final(tmp_path) -> None:
    rejected = smtplib.SMTPDataError(550, f"{REJECTED} no message <r1@x> was delivered".encode())
    runner, calls = _runner(tmp_path, _refused(), [rejected])
    imap = FakeImap()
    uid = imap.add(_filed_copy())
    assert runner.drain(imap) == 0  # type: ignore[arg-type]
    assert REFUSED_KEYWORD in imap.flags(uid)
    assert runner.drain(imap) == 0 and len(calls) == 1  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "answer",
    [
        smtplib.SMTPAuthenticationError(535, b"5.7.8 authentication failed"),
        smtplib.SMTPDataError(500, b"Error: (AssertionError) inside the gateway"),
        smtplib.SMTPDataError(550, b"5.6.0 something else"),
        # A gateway older than the command: its 550 5.7.1 has no marker, so keep trying.
        smtplib.SMTPDataError(550, b"5.7.1 invalid control declaration: 'refuse' is not one of"),
        smtplib.SMTPDataError(550, b"5.7.1 \xff\xfe not UTF-8"),
        RuntimeError("an unexpected client bug"),
        # An expired or rotated certificate is an OSError and a ValueError at once: retried.
        ssl.SSLCertVerificationError(1, "certificate has expired"),
        ConnectionRefusedError(111, "gateway down"),
        smtplib.SMTPRecipientsRefused({CONTROL: (451, b"4.3.0 try again")}),
        smtplib.SMTPDataError(451, b"4.3.0 not filed yet; retry"),
    ],
)
def test_any_other_answer_is_retried(tmp_path, answer: Exception) -> None:
    clock = Clock()
    runner, calls = _runner(tmp_path, _refused(), [answer, "refuse dsn=sent why=verified"], clock)
    imap = FakeImap()
    uid = imap.add(_filed_copy())
    assert runner.drain(imap) == 1  # type: ignore[arg-type]
    assert imap.flags(uid) == set()
    clock.now += 5
    assert runner.drain(imap) == 0  # type: ignore[arg-type]
    assert REFUSED_KEYWORD in imap.flags(uid) and len(calls) == 2


def test_a_handler_that_keeps_failing_is_reported_as_handler_failed(tmp_path) -> None:
    def crash(_message, _context: Context) -> None:
        raise RuntimeError("model endpoint down")

    runner, calls = _runner(tmp_path, crash, ["ok"])
    imap = FakeImap()
    uid = imap.add(_filed_copy())
    for _attempt in range(3):
        assert runner.drain(imap) == 1  # type: ignore[arg-type]
    assert calls == []
    assert runner.drain(imap) == 0  # type: ignore[arg-type]
    assert (calls[0]["status"], calls[0]["reason"]) == ("5.3.0", "handler-failed")
    assert REFUSED_KEYWORD in imap.flags(uid)


def test_an_unreadable_copy_is_reported_as_unreadable(tmp_path, monkeypatch) -> None:
    from amx import runner as runner_module

    def broken(_raw: bytes):
        raise RuntimeError("parser bug")

    monkeypatch.setattr(runner_module, "bind", broken)
    runner, calls = _runner(tmp_path, _refused(), ["ok"])
    imap = FakeImap()
    imap.add(_filed_copy())
    runner.drain(imap)  # type: ignore[arg-type]
    assert (calls[0]["status"], calls[0]["reason"]) == ("5.3.0", "unreadable")


def test_a_refused_gateway_event_is_not_reported(tmp_path) -> None:
    event = build(
        sender=f"postmaster@{AGENT_DOMAIN}",
        to=ADDRESS,
        subject="AMX task t_x: canceled",
        intent="update",
        task="t_x",
        task_state="canceled",
        text="A person rejected the held reply.",
        in_reply_to="<held@agents.contoso.test>",
    )
    raw = b"Agent-Lane: system\r\n" + event.as_bytes(policy=policy.SMTP)
    runner, calls = _runner(tmp_path, _refused(), [])
    imap = FakeImap()
    uid = imap.add(raw)
    assert runner.drain(imap) == 0  # type: ignore[arg-type]
    assert calls == [] and REFUSED_KEYWORD in imap.flags(uid)


def test_an_older_runner_state_file_still_finishes_what_it_refused(tmp_path) -> None:
    log = HandledLog(tmp_path / "runner.sqlite")
    key = delivery_key(_filed_copy())
    log.record(key, "refused 5.7.1 no")  # recorded before refusals were reported
    runner, calls = _runner(tmp_path, _refused(), [])
    imap = FakeImap()
    uid = imap.add(_filed_copy(), "\\Seen")
    assert runner.drain(imap) == 0  # type: ignore[arg-type]
    assert calls == [] and REFUSED_KEYWORD in imap.flags(uid)


# --- the gateway's view of the INBOX, and trace ---


def test_the_gateway_finds_an_unfinished_copy_by_its_stamp_and_message_id(monkeypatch) -> None:
    from amx import mailbox as mailbox_module
    from amx.config import MailboxConfig
    from amx.mailbox import MailboxAppender

    imap = FakeImap()
    monkeypatch.setattr(mailbox_module.imaplib, "IMAP4", lambda *_args, **_kwargs: imap)
    view = MailboxAppender(MailboxConfig(host="mailhost-ct", master_password="dev-gateway"))
    assert not view.unfinished(ADDRESS, RECIPIENT, MESSAGE_ID), "an empty INBOX"
    imap.add(_filed_copy(), "\\Seen", "$AmxHandled")
    assert not view.unfinished(ADDRESS, RECIPIENT, MESSAGE_ID), "finished"
    imap.add(_filed_copy(task="t_other"))
    assert not view.unfinished(ADDRESS, RECIPIENT, MESSAGE_ID), "another task's copy"
    imap.add(_filed_copy(message_id="<r2@agents.northwind.test>"))
    assert not view.unfinished(ADDRESS, RECIPIENT, MESSAGE_ID), "another message"
    imap.add(_filed_copy())
    assert view.unfinished(ADDRESS, RECIPIENT.upper(), MESSAGE_ID), "unfinished (case folded)"


def test_trace_shows_a_refusal_under_the_refused_task_and_not_as_a_declaration(tmp_path) -> None:
    from amx.cli import declarations

    service, store, journal, _reinject = _gateway(tmp_path)
    _file(journal, store)
    _refuse(service)
    policy_rows = store.rows("SELECT * FROM policy_events")
    outbound = store.rows("SELECT * FROM journal WHERE task = 't_x'")
    assert [row["event"] for row in outbound] == ["lmtp-received", "control-refuse", "dsn"]
    store.record_policy("rcpt", "recipient-ok", "accept", None, "t_other", "", agent="outpost")
    other_task = store.rows("SELECT * FROM policy_events WHERE task = 't_other'")
    assert declarations(store, service.config, other_task, []) == [], "not another task's"
    assert policy_rows == []


def test_the_backoff_is_capped_and_never_overflows(tmp_path) -> None:
    runner, _calls = _runner(tmp_path, _refused(), [OSError("down")])
    imap = FakeImap()
    imap.add(_filed_copy())
    runner.drain(imap)  # type: ignore[arg-type]
    key = delivery_key(_filed_copy())
    assert runner.handled.defer(key, 0.0) == 10.0, "the second attempt waits 10 s"
    with sqlite3.connect(runner.handled.path) as connection:  # a week of 5-minute retries, and more
        connection.execute("UPDATE refusals SET attempts = 5000 WHERE key = ?", (key,))
    assert runner.handled.defer(key, 0.0) == 300.0


def test_a_copy_backing_off_is_never_left_taken(tmp_path) -> None:
    clock = Clock()
    runner, calls = _runner(tmp_path, _refused(), [OSError("down"), "ok"], clock)
    imap = FakeImap()
    uid = imap.add(_filed_copy())
    assert runner.drain(imap) == 1  # type: ignore[arg-type]
    imap.messages[uid][0].add("\\Seen")  # the un-take was lost with the connection
    assert runner.drain(imap) == 1 and len(calls) == 1  # type: ignore[arg-type]
    assert imap.flags(uid) == set(), "cleared again while it backs off"


def test_a_clock_stepped_back_does_not_delay_the_report(tmp_path) -> None:
    clock = Clock()
    runner, calls = _runner(tmp_path, _refused(), [OSError("down"), "ok"], clock)
    imap = FakeImap()
    uid = imap.add(_filed_copy())
    assert runner.drain(imap) == 1  # type: ignore[arg-type]
    clock.now -= 3600
    assert runner.drain(imap) == 0 and len(calls) == 2  # type: ignore[arg-type]
    assert REFUSED_KEYWORD in imap.flags(uid)


def test_a_failure_in_the_runners_own_state_never_escapes_with_the_copy_taken(
    tmp_path, monkeypatch
) -> None:
    runner, _calls = _runner(tmp_path, _refused(), ["ok"])

    def locked(_key: str, _answer: str) -> None:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(runner.handled, "answer", locked)
    imap = FakeImap()
    uid = imap.add(_filed_copy())
    assert runner.drain(imap) == 1  # type: ignore[arg-type]
    assert imap.flags(uid) == set()


def test_a_dsn_sent_is_never_sent_again_because_its_journal_entry_failed(
    tmp_path, monkeypatch
) -> None:
    service, store, journal, reinject = _gateway(tmp_path)
    _file(journal, store)
    append = journal.append

    def failing(raw: bytes, **fields: object):
        if fields.get("event") == "dsn":
            raise sqlite3.OperationalError("database is locked")
        return append(raw, **fields)  # type: ignore[arg-type]

    monkeypatch.setattr(journal, "append", failing)
    assert _refuse(service).endswith("dsn=sent why=verified")
    assert _refuse(service).endswith("again") and len(reinject.sent) == 1


def test_a_refused_reinjection_is_settled_even_if_its_journal_entry_fails(
    tmp_path, monkeypatch
) -> None:
    service, store, journal, reinject = _gateway(tmp_path)
    _file(journal, store)
    reinject.failures = [smtplib.SMTPDataError(554, b"5.7.1 refused")]
    append = journal.append

    def failing(raw: bytes, **fields: object):
        if fields.get("event") == "dsn-failed":
            raise sqlite3.OperationalError("database is locked")
        return append(raw, **fields)  # type: ignore[arg-type]

    monkeypatch.setattr(journal, "append", failing)
    assert _refuse(service).endswith("dsn=dropped why=reinject-refused")
    assert store.refusal(RECIPIENT, MESSAGE_ID)["claimed_epoch"] is None


@pytest.mark.parametrize(
    ("error", "outcome"),
    [
        (FileNotFoundError(2, "gone"), "dropped why=original-unreadable"),
        (OSError(24, "too many open files"), "pending"),
        (sqlite3.OperationalError("database is locked"), "pending"),
    ],
)
def test_a_report_that_cannot_be_built_now_stays_pending(
    tmp_path, monkeypatch, error: Exception, outcome: str
) -> None:
    service, store, journal, reinject = _gateway(tmp_path)
    _file(journal, store)

    def broken(*_args: object, **_kwargs: object) -> bytes:
        raise error

    monkeypatch.setattr(service, "_dsn_report", broken)
    if outcome == "pending":
        with pytest.raises(RefusalDeferred, match="cannot build the DSN now"):
            _refuse(service)
        row = store.refusal(RECIPIENT, MESSAGE_ID)
        assert (row["dsn"], row["claimed_epoch"]) == ("pending", None)
    else:
        assert _refuse(service).endswith(f"dsn={outcome}")
    assert reinject.sent == []


def test_a_refused_message_that_cannot_be_read_now_is_deferred(tmp_path, monkeypatch) -> None:
    service, store, journal, _reinject = _gateway(tmp_path)
    _file(journal, store)
    digest = str(store.delivery_progress(RECIPIENT, MESSAGE_ID)["raw_sha256"])
    path = journal.raw_path(digest)
    real = type(path).read_bytes

    def emfile(self):
        if self == path:
            raise OSError(24, "too many open files")
        return real(self)

    monkeypatch.setattr(type(path), "read_bytes", emfile)
    with pytest.raises(RefusalDeferred, match="cannot read the refused message now"):
        _refuse(service)
    assert store.rows("SELECT 1 FROM refusals") == []
