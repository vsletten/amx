"""S18k to S18m: a remote agent's refusal reaches the sender as a DSN (PLAN §5.11).

outpost's gateway accepted and filed the message with 250 before outpost's runner ever saw it, so
no SMTP reply can carry outpost's refusal. The runner tells the gateway instead, with a ``refuse``
command to the control address, and the gateway writes the bounce an in-process agent's 550 would
have produced: once, and only to a sender it verified when the message arrived.
"""

from __future__ import annotations

import smtplib
import time
import uuid
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser

import pytest

from amx.mailbox import HANDLED_KEYWORD
from amx.profile import parse
from amx.runner import REFUSED_KEYWORD
from amx.store import Store
from amx.testkit import folder_messages, smtp_transaction
from scenarios.support import (
    CT_DB,
    GENERATED,
    HANDLER_LOG,
    NW_DB,
    NW_HANDLER_LOG,
    signed_request,
    trace_task,
    wait_for_handler,
    wait_for_task,
)
from scenarios.test_s18_control import _drained, _outpost
from scenarios.test_s18_remote_agent import RUNNER_LOG, _copies, _scheduler, _wait

pytestmark = pytest.mark.integration

AGENT_DOMAIN = "agents.contoso.test"
PAT = ("127.0.0.1", "pat@plainmail.test", "dev-pat")


def _refusal(recipient: str, message_id: str, dsn: str | None = None):
    """contoso's record of outpost's refusal, once it has one (in state ``dsn``, if given)."""
    row = Store(CT_DB).refusal(recipient, message_id)
    return row if row is not None and (dsn is None or row["dsn"] == dsn) else None


def _dsns_sent(message_id: str) -> int:
    """How many DSNs about ``message_id`` contoso reinjected: each attempt journals ``dsn``, and
    one that failed also journals ``dsn-failed``."""
    rows = Store(CT_DB).rows(
        "SELECT event FROM journal WHERE event IN ('dsn', 'dsn-failed') AND detail LIKE ?",
        (f"% message_id={message_id} %",),
    )
    events = [str(row["event"]) for row in rows]
    return events.count("dsn") - events.count("dsn-failed")


def _received_at_northwind(dsn_message_id: str) -> list[str]:
    """The raw digests of northwind's LMTP deliveries of that DSN: one per copy it accepted."""
    rows = Store(NW_DB).rows(
        "SELECT raw_sha256 FROM journal WHERE event = 'lmtp-received' AND message_id = ?",
        (dsn_message_id,),
    )
    return [str(row["raw_sha256"]) for row in rows]


def _nw_report_statuses(task: str) -> list[str | None]:
    """The Status of each DSN northwind's LMTP delivered in ``task``."""
    rows = Store(NW_DB).rows(
        "SELECT raw_sha256 FROM journal WHERE task = ? AND event = 'lmtp-received'", (task,)
    )
    statuses = []
    for row in rows:
        digest = str(row["raw_sha256"])
        inbound = parse(
            (GENERATED / "state" / "nw" / "raw" / digest[:2] / f"{digest}.eml").read_bytes()
        )
        if inbound.intent == "error":
            statuses.append(inbound.status)
    return statuses


def _nw_task_state(task: str) -> str | None:
    row = Store(NW_DB).task(task)
    return None if row is None else str(row["state"])


def _finished_as_refused(message_id: str) -> bool:
    return any(
        HANDLED_KEYWORD in flags and REFUSED_KEYWORD in flags for flags, _ in _copies(message_id)
    )


def test_s18k_a_remote_refusal_reaches_the_verified_sender_as_one_dsn() -> None:
    _drained()
    suffix = uuid.uuid4().hex[:10]
    scheduler = _scheduler()
    sent = scheduler.send(
        to=f"outpost@{AGENT_DOMAIN}",
        subject=f"S18k {suffix} [refuse]",
        intent="request",
        text="Please book the site inspection for Tuesday.",
    )
    task, message_id = sent.task, sent.message_id
    recipient = f"outpost+{task}@{AGENT_DOMAIN}"

    # outpost's runner ran its handler, which refused, and told the gateway, which bounced it.
    [ran] = wait_for_handler(message_id, path=RUNNER_LOG, timeout=60)
    assert (ran["agent"], ran["lane"], ran["task"]) == ("outpost", "agent", task)
    refusal = _wait(lambda: _refusal(recipient, message_id, "sent"), 60, "no DSN was sent")
    assert (refusal["status"], refusal["reason"], refusal["why"]) == ("5.7.1", "policy", "verified")
    assert refusal["envelope_from"] == f"scheduler+{task}@agents.northwind.test"
    _wait(lambda: _finished_as_refused(message_id), 30, "the runner never finished it as refused")

    # northwind's scheduler got the DSN, as a failure of its task: S03b's milter refusal, remote.
    [failure] = wait_for_task(task, path=NW_HANDLER_LOG, intent="error", timeout=90)
    assert failure["task_state"] == "failed"
    assert failure["diagnostic"] == "smtp; 550 5.7.1 refused by the recipient agent (policy)"
    _wait(lambda: _nw_task_state(task) == "failed", 15, "northwind's task never failed")
    [raw_sha256] = _received_at_northwind(str(refusal["dsn_message_id"]))
    raw = (GENERATED / "state" / "nw" / "raw" / raw_sha256[:2] / f"{raw_sha256}.eml").read_bytes()
    report = BytesParser(policy=policy.default).parsebytes(raw)
    assert (report.get_content_type(), report.get_param("report-type")) == (
        "multipart/report",
        "delivery-status",
    )
    assert str(report["From"]) == "Mail Delivery System <MAILER-DAEMON@contoso.test>"
    assert "DKIM-Signature" not in report, "unsigned, as the MTAs' bounces are"
    assert b"intake does not take this request" not in raw, "the handler's text stays home"
    # northwind's milter added its own verdicts on top; the returned headers carry none of
    # contoso's (lane, trust, judgment), and do carry the refused message's own.
    [returned] = [p for p in report.walk() if p.get_content_type() == "text/rfc822-headers"]
    headers = returned.get_payload(decode=True).decode()
    assert message_id in headers and f"S18k {suffix} [refuse]" in headers
    assert "Agent-Lane" not in headers and "Agent-Content-Judgment" not in headers

    # The same command again, as the runner resends after a lost reply, bounces nothing more.
    # (The runner's own resend path is unit-tested; this proves the gateway's side live.)
    again = _outpost().refuse(recipient, message_id, status="5.7.1", reason="policy")
    assert again.applied.endswith("dsn=sent why=verified again"), again.applied
    time.sleep(5)
    assert _dsns_sent(message_id) == 1
    assert len(_received_at_northwind(str(refusal["dsn_message_id"]))) == 1
    errors = wait_for_task(task, path=NW_HANDLER_LOG, intent="error")
    assert len(errors) == 1, errors

    trace = trace_task(task)
    assert f"refused recipient={recipient} message_id={message_id}" in trace, trace

    # The same refusal in process: intake-off runs the same handler (sync), and its 550 becomes
    # the MTA's own bounce. Both reach the scheduler as a failed task with the same status.
    compared = scheduler.send(
        to=f"intake-off@{AGENT_DOMAIN}",
        subject=f"S18k {suffix} in process [refuse]",
        intent="request",
        text="Please book the site inspection for Tuesday.",
    )
    [in_process] = wait_for_task(compared.task, path=NW_HANDLER_LOG, intent="error", timeout=90)
    assert in_process["task_state"] == "failed"
    # The Status field, not the diagnostic: Stalwart's bounce writes `smtp;550 <text>`, without
    # the enhanced code, where Postfix writes `smtp; 550 5.7.1 <text>`.
    assert _nw_report_statuses(compared.task) == ["5.7.1"]
    assert _nw_report_statuses(task) == ["5.7.1"]


def test_s18l_a_refusal_must_name_mail_the_gateway_filed_for_that_agent() -> None:
    suffix = uuid.uuid4().hex[:10]
    outpost = _outpost()
    with pytest.raises(smtplib.SMTPDataError) as never:
        outpost.refuse(f"outpost+t_s18l_{suffix}@{AGENT_DOMAIN}", f"<never-{suffix}@x.test>")
    assert never.value.smtp_code == 550
    assert b"was delivered to" in never.value.smtp_error

    # A message the gateway delivered, but to another agent: outpost's token cannot refuse it.
    sent = _scheduler().send(
        to=f"intake-off@{AGENT_DOMAIN}",
        subject=f"S18l {suffix}",
        intent="request",
        text="An ordinary request.",
    )
    wait_for_task(sent.task, path=HANDLER_LOG, timeout=60)
    with pytest.raises(smtplib.SMTPDataError) as other:
        outpost.refuse(f"intake-off+{sent.task}@{AGENT_DOMAIN}", sent.message_id)
    assert other.value.smtp_code == 550
    assert b"is not an address of outpost" in other.value.smtp_error
    assert _refusal(f"intake-off+{sent.task}@{AGENT_DOMAIN}", sent.message_id) is None
    for named in (f"<never-{suffix}@x.test>", f"intake-off+{sent.task}@"):
        rows = Store(CT_DB).rows(
            "SELECT 1 FROM policy_events WHERE rule = 'control-refused' AND agent = 'outpost' "
            "AND detail LIKE ?",
            (f"%{named}%",),
        )
        assert rows, f"the refusal naming {named} is a control-refused policy row"


def _pat_bounces(message_id: str) -> list[object]:
    return [
        message
        for message in folder_messages(PAT[0], PAT[1], PAT[2], "INBOX", port=1433)
        if message.get_content_type() == "multipart/report" and message_id in message.as_string()
    ]


def test_s18m_an_unverified_sender_gets_no_dsn() -> None:
    _drained()
    suffix = uuid.uuid4().hex[:10]
    # A person's mail: the human lane, whose sender the gateway never verifies.
    person_task = f"t_s18m_{suffix}"
    person_id = f"<s18m-person-{suffix}@plainmail.test>"
    message = EmailMessage(policy=policy.SMTP)
    message["From"] = "pat@plainmail.test"
    message["To"] = f"outpost+{person_task}@{AGENT_DOMAIN}"
    message["Subject"] = f"S18m {suffix} [refuse]"
    message["Message-ID"] = person_id
    message.set_content("Could you look at the attached quote?")
    code, response = smtp_transaction(
        "127.0.0.1",
        "pat@plainmail.test",
        f"outpost+{person_task}@{AGENT_DOMAIN}",
        message.as_bytes(policy=policy.SMTP),
        port=2526,
    )
    assert code == 250, (code, response)

    # A verified agent's signature, but a MAIL FROM in someone else's domain: backscatter bait.
    forged_task = f"t_s18m_forged_{suffix}"
    forged_id = f"<s18m-forged-{suffix}@agents.northwind.test>"
    forged_to = f"outpost+{forged_task}@{AGENT_DOMAIN}"
    raw = signed_request(forged_task, forged_id, recipient=forged_to, subject="S18m [refuse]")
    code, response = smtp_transaction("127.0.0.1", "pat@plainmail.test", forged_to, raw, port=2526)
    assert code == 250, (code, response)

    for recipient, message_id, why in (
        (f"outpost+{person_task}@{AGENT_DOMAIN}", person_id, "sender-unverified"),
        (forged_to, forged_id, "sender-unaligned"),
    ):
        refusal = _wait(lambda r=recipient, m=message_id: _refusal(r, m), 60, f"{why}: no refusal")
        assert (refusal["dsn"], refusal["why"], refusal["dsn_message_id"]) == ("dropped", why, None)
        assert refusal["envelope_from"] == "pat@plainmail.test"
        _wait(lambda m=message_id: _finished_as_refused(m), 30, "never finished as refused")
        [control] = Store(CT_DB).rows(
            "SELECT detail FROM journal WHERE event = 'control-refuse' AND detail LIKE ?",
            (f"% message_id={message_id} %",),
        )
        assert str(control["detail"]).endswith(f"dsn=dropped why={why}")
        assert _dsns_sent(message_id) == 0
    # The control: the same kind of mail refused in process (intake-off, sync) is bounced by the
    # MTA, which applies no guard, so a bounce to pat is something this check does see.
    control_task = f"t_s18m_control_{suffix}"
    control_id = f"<s18m-control-{suffix}@plainmail.test>"
    del message["To"], message["Message-ID"]
    message["To"] = f"intake-off+{control_task}@{AGENT_DOMAIN}"
    message["Message-ID"] = control_id
    code, response = smtp_transaction(
        "127.0.0.1",
        "pat@plainmail.test",
        f"intake-off+{control_task}@{AGENT_DOMAIN}",
        message.as_bytes(policy=policy.SMTP),
        port=2526,
    )
    # contoso's MTA queues it (250), and its LMTP delivery then gets the handler's 550.
    assert code == 250, (code, response)
    _wait(lambda: _pat_bounces(control_id), 60, "the in-process refusal never bounced to pat")
    assert _pat_bounces(person_id) == [] and _pat_bounces(forged_id) == []
