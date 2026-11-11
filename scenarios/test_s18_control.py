"""S18f to S18j: a remote agent declares its own state to its gateway (PLAN §5.10).

outpost mails ``control@agents.contoso.test`` over the submission path it already sends through,
from its own host (``amx-runner ... control``) or with its token from anywhere (the SDK). The
gateway applies the declaration and relays nothing. A pause answers every sender's RCPT with 450,
a capacity lowers the watermark and cannot raise it, and both lapse on their own. Nothing from
outside reaches the control address, and one agent's login cannot declare for another.
"""

from __future__ import annotations

import re
import smtplib
import ssl
import time
import uuid
from email import policy

import pytest

from amx.control import CONTROL_SCHEMA
from amx.mailbox import HANDLED_KEYWORD
from amx.profile import build
from amx.sdk import Agent
from amx.store import Store
from amx.testkit import send_raw, smtp_transaction
from scenarios.support import (
    CT_DB,
    DEV_TLS_CA,
    NW_HANDLER_LOG,
    compose,
    compose_exec,
    postfix_log,
    queued_at,
    signed_request,
    trace_task,
    wait_for_handler,
    wait_for_task,
)
from scenarios.test_s18_remote_agent import RUNNER_LOG, _copies, _inbox, _scheduler, _wait

pytestmark = pytest.mark.integration

OUTPOST = "outpost@agents.contoso.test"
CONTROL = "control@agents.contoso.test"
# outpost's host declares through edge-ct, as its runner submits (compose.yaml, runner-ct).
RUNNER_CONTROL = [
    "/app/.venv/bin/amx-runner",
    f"--agent={OUTPOST}",
    "--submit=smtp://edge-ct:2587",
    "--ca=/tls/dev-ca.pem",
    "control",
]


def _outpost() -> Agent:
    """outpost's own token, used from the host: contoso's submission port is 2588 there."""
    return Agent(OUTPOST, "smtp://127.0.0.1:2588", "dev-outpost-token", tls_ca_file=str(DEV_TLS_CA))


def _runner_declares(*command: str) -> str:
    """Declare from outpost's own host, with the runner's own credentials."""
    return compose_exec("runner-ct", *RUNNER_CONTROL, *command).stdout


def _unfinished() -> int:
    return sum(
        1
        for flags, _headers in _inbox()
        if HANDLED_KEYWORD not in flags and "\\Deleted" not in flags
    )


def _drained() -> None:
    """Start from a clear state: no declaration, and nothing waiting in outpost's INBOX."""
    _outpost().resume()
    _wait(lambda: _unfinished() == 0, 45, "outpost's runner never drained its INBOX")


def _request_to_outpost(label: str) -> tuple[str, str, tuple[int, bytes]]:
    """A signed request from scheduler, straight to contoso's MX: its RCPT reply, unqueued."""
    suffix = uuid.uuid4().hex[:8]
    task = f"t_s18{label}_{suffix}"
    message_id = f"<s18{label}-{suffix}@agents.northwind.test>"
    recipient = f"outpost+{task}@agents.contoso.test"
    raw = signed_request(task, message_id, recipient=recipient)
    sender = f"scheduler+{task}@agents.northwind.test"
    return task, message_id, smtp_transaction("127.0.0.1", sender, recipient, raw, port=2526)


def _journal_line(declared: str) -> str:
    """The trace line of the declaration a ``control`` command printed ("... (task <token>)")."""
    task = re.search(r"\(task (\S+)\)", declared)[1]  # type: ignore[index]
    [row] = Store(CT_DB).rows("SELECT sequence, event FROM journal WHERE task = ?", (task,))
    return f"agents.contoso.test submission {row['event']} journal #{row['sequence']} sha256"


def _rcpt_rows(task: str) -> list:
    return Store(CT_DB).rows(
        "SELECT * FROM policy_events WHERE stage = 'rcpt' AND task = ? ORDER BY sequence", (task,)
    )


def test_s18f_a_pause_answers_450_at_rcpt_and_resume_lets_the_senders_queue_drain() -> None:
    _drained()
    declared = _runner_declares("pause", "--seconds", "120", "--reason", "maintenance")
    assert f"{OUTPOST} declared pause until=" in declared and "reason=maintenance" in declared
    try:
        # Straight to the MX: RCPT is refused with a retry hint, before any backlog is read.
        task, _message_id, (code, response) = _request_to_outpost("f")
        assert code == 450, (code, response)
        assert b"4.2.1" in response and b"agent paused, retry after 20" in response
        [row] = _rcpt_rows(task)
        assert (row["rule"], row["agent"]) == ("agent-paused", "outpost")
        # A backlog read always shows its depth, so none here means none was read.
        assert "declared pause until" in row["detail"] and "depth" not in row["detail"]

        # A real sender's MTA queues the request and keeps retrying it (northwind's Postfix).
        sent = _scheduler().send(
            to=OUTPOST,
            subject=f"S18f {task}",
            intent="request",
            task=f"{task}_q",
            text="A request that waits out outpost's pause in the sender's queue.",
        )
        _wait(
            lambda: [
                line
                for line in postfix_log("mailhost-nw").splitlines()
                if sent.task in line and "status=deferred" in line and "agent paused" in line
            ],
            30,
            "northwind never logged a deferral for the pause",
        )
        assert queued_at("mailhost-nw", sent.task)
    finally:
        resumed = _runner_declares("resume")
    assert f"{OUTPOST} declared resume" in resumed
    # Postfix retries within its backoff (5 s, then 10 s), well inside its 30 s queue lifetime.
    wait_for_handler(sent.message_id, path=RUNNER_LOG, timeout=45)
    answer = wait_for_task(sent.task, path=NW_HANDLER_LOG, intent="response", timeout=30)[-1]
    assert answer["text"] == "Intake completed the request."
    # The deferred task's timeline: this pause, the 450, this resume, then the delivery.
    lines = trace_task(sent.task).splitlines()

    def at(needle: str) -> int:
        return next(index for index, line in enumerate(lines) if needle in line)

    assert (
        at(_journal_line(declared))
        < at("milter RCPT agent-paused -> tempfail 450 4.2.1")
        < at(_journal_line(resumed))
        < at("agents.contoso.test lmtp lmtp-received")
    )
    print(f"S18f PAUSE: {sent.task} deferred while paused, delivered after resume")


def test_s18g_a_declared_capacity_tightens_the_watermark_and_cannot_raise_it() -> None:
    _drained()
    outpost = _outpost()
    assert outpost.capacity(1, ttl_seconds=120).applied.endswith("effective=1")
    compose("stop", "runner-ct")  # so what is filed stays unfinished, and counts
    try:
        first, first_id, (code, response) = _request_to_outpost("g")
        assert code == 250, (code, response)
        _wait(lambda: _copies(first_id), 15, "the first request was never filed")

        # One unfinished message fills a capacity of 1, below the configured watermark of 2.
        second, second_id, (code, response) = _request_to_outpost("g")
        assert (code, b"4.2.1 agent busy" in response) == (450, True), (code, response)
        [row] = _rcpt_rows(second)
        assert row["rule"] == "agent-capacity"
        assert "depth 1/1, declared capacity 1 (configured 2)" in row["detail"]
        assert "oldest untaken" in row["detail"], "the runner is gone: nothing takes mail"

        # Declaring more than the configuration allows does not raise it: two, not five.
        assert outpost.capacity(5, ttl_seconds=120).applied.endswith("effective=2")
        second, second_id, (code, response) = _request_to_outpost("g")
        assert code == 250, (code, response)
        _wait(lambda: _copies(second_id), 15, "the second request was never filed")
        third, _third_id, (code, response) = _request_to_outpost("g")
        assert code == 450, (code, response)
        [row] = _rcpt_rows(third)
        assert row["rule"] == "agent-watermark"
        assert "depth 2/2, declared capacity 5 (configured 2)" in row["detail"]
        assert _unfinished() == 2
    finally:
        outpost.resume()
        compose("start", "runner-ct")
    for message_id in (first_id, second_id):
        wait_for_handler(message_id, path=RUNNER_LOG, timeout=45)
    print(
        f"S18g CAPACITY: {first} filed at 1/1, {second} refused then filed at 2/2, {third} at 2/2"
    )


def test_s18h_a_declaration_lapses_on_its_own_when_the_agent_is_gone() -> None:
    _drained()
    _runner_declares("pause", "--seconds", "8", "--reason", "offline")
    started = time.monotonic()
    compose("stop", "runner-ct")  # the agent's host goes away without resuming
    try:
        paused, _paused_id, (code, _response) = _request_to_outpost("h")
        assert code == 450 and _rcpt_rows(paused)[0]["rule"] == "agent-paused"
        # Nobody resumes; the pause lapses at its own time and the configuration governs again.
        time.sleep(max(0.0, 9 - (time.monotonic() - started)))
        lapsed, lapsed_id, (code, response) = _request_to_outpost("h")
        assert code == 250, (code, response)
        [row] = _rcpt_rows(lapsed)
        assert (row["rule"], row["agent"]) == ("recipient-ok", "outpost")
        assert "declared" not in row["detail"] and "depth 0/2" in row["detail"]
        [stale] = Store(CT_DB).rows("SELECT * FROM agent_controls WHERE agent = 'outpost'")
        assert stale["command"] == "pause" and stale["expires_at"] < time.time(), (
            "the lapsed row is still there: time retired it, not a resume"
        )
        _wait(lambda: _copies(lapsed_id), 15, "the request after the pause was never filed")

        # A capacity lapses the same way (declared here with outpost's token from anywhere).
        _outpost().capacity(1, ttl_seconds=5)
        capped_at = time.monotonic()
        capped, _capped_id, (code, _response) = _request_to_outpost("h")
        assert code == 450 and _rcpt_rows(capped)[0]["rule"] == "agent-capacity"
        time.sleep(max(0.0, 6 - (time.monotonic() - capped_at)))
        restored, restored_id, (code, response) = _request_to_outpost("h")
        assert code == 250, (code, response)
        assert "declared" not in _rcpt_rows(restored)[0]["detail"]
    finally:
        _outpost().resume()
        compose("start", "runner-ct")
    for message_id in (lapsed_id, restored_id):
        wait_for_handler(message_id, path=RUNNER_LOG, timeout=45)
    print("S18h EXPIRY: a pause and a capacity lapsed with outpost's host down; config governed")


@pytest.mark.parametrize("recipient", [CONTROL, "control+t_s18i@agents.contoso.test"])
@pytest.mark.parametrize("sender", ["scheduler@agents.northwind.test", "pat@plainmail.test"])
def test_s18i_nothing_from_outside_reaches_the_control_address(sender, recipient) -> None:
    with smtplib.SMTP("127.0.0.1", 2526, timeout=10) as client:
        assert client.mail(sender)[0] == 250
        code, response = client.rcpt(recipient)
    assert code == 550, (code, response)
    assert b"5.7.1" in response and b"control address accepts only agent submission" in response


def _bounces_to_control(service: str) -> int:
    return sum(
        1
        for line in postfix_log(service).splitlines()
        if "to=<control@agents.contoso.test>" in line
        and "status=bounced" in line
        and "550 5.7.1" in line
    )


def test_s18i_the_control_address_bounces_through_the_senders_own_mtas() -> None:
    before = {row["agent"]: dict(row) for row in Store(CT_DB).rows("SELECT * FROM agent_controls")}
    bounced = {service: _bounces_to_control(service) for service in ("mailhost-pm", "mailhost-nw")}
    suffix = uuid.uuid4().hex[:8]
    # What an outsider would forge: outpost's pause, as mail from anywhere.
    forged = build(
        sender=OUTPOST,
        to=CONTROL,
        subject=f"S18i {suffix}",
        intent="event",
        task=f"t_s18i_{suffix}",
        task_state="completed",
        text="Pause outpost.",
        payload={"command": "pause", "until": "2099-01-01T00:00:00Z", "reason": "operator"},
        schema=CONTROL_SCHEMA,
    ).as_bytes(policy=policy.SMTP)
    # plainmail's MX, and northwind's milter-less :10025, each relay it to contoso's MX.
    assert send_raw("127.0.0.1", "pat@plainmail.test", CONTROL, forged, port=2527) == {}
    envelope = f"scheduler+t_s18i_{suffix}@agents.northwind.test"
    assert send_raw("127.0.0.1", envelope, CONTROL, forged, port=11025) == {}
    for service, count in bounced.items():
        _wait(
            lambda service=service, count=count: _bounces_to_control(service) > count,
            30,
            f"{service} never bounced mail to the control address",
        )
    after = {row["agent"]: dict(row) for row in Store(CT_DB).rows("SELECT * FROM agent_controls")}
    assert after == before, "no declaration changed"
    print("S18i CONTROL ADDRESS: 550 at RCPT from northwind and plainmail, direct and relayed")


def _submit_as(login: str, token: str, envelope_from: str, raw: bytes, *recipients: str):
    """One submission to contoso's gateway with ``login``'s credentials: the DATA reply."""
    with smtplib.SMTP("127.0.0.1", 2588, timeout=15) as client:
        client.starttls(context=ssl.create_default_context(cafile=str(DEV_TLS_CA)))
        client.login(login, token)
        assert client.mail(envelope_from)[0] == 250
        for recipient in recipients:
            assert client.rcpt(recipient)[0] == 250
        return client.data(raw)


def _declaration(sender: str, *, cc: str | None = None) -> bytes:
    return build(
        sender=sender,
        to=CONTROL,
        cc=cc,
        subject="S18j",
        intent="event",
        task=f"t_s18j_{uuid.uuid4().hex[:8]}",
        task_state="completed",
        text="A control declaration.",
        payload={"command": "capacity", "max": 1, "ttl_seconds": 600},
        schema=CONTROL_SCHEMA,
    ).as_bytes(policy=policy.SMTP)


def test_s18j_one_agents_login_cannot_declare_for_another() -> None:
    _drained()
    store = Store(CT_DB)
    before = store.rows("SELECT MAX(sequence) AS last FROM policy_events")[0]["last"] or 0
    # intake's own token, claiming outpost in the header, then in the envelope as well.
    forged = _declaration(OUTPOST)
    for envelope in ("intake@agents.contoso.test", OUTPOST):
        code, response = _submit_as("intake", "dev-intake-token", envelope, forged, CONTROL)
        assert code == 550, (code, response)
        assert b"must come from the login's agent, intake@agents.contoso.test" in response
    # outpost's login with intake's token does not authenticate at all.
    with pytest.raises(smtplib.SMTPAuthenticationError):
        _submit_as("outpost", "dev-intake-token", OUTPOST, forged, CONTROL)
    # And outpost's own declaration cannot carry mail to anyone else.
    mixed = _declaration(OUTPOST, cc="pat@plainmail.test")
    code, response = _submit_as(
        "outpost", "dev-outpost-token", OUTPOST, mixed, CONTROL, "pat@plainmail.test"
    )
    assert code == 550 and b"goes to control@agents.contoso.test and nowhere else" in response

    assert not store.rows("SELECT 1 FROM agent_controls WHERE expires_at > ?", (time.time(),))
    refused = store.rows(
        "SELECT agent, rule FROM policy_events WHERE sequence > ? AND stage = 'control'", (before,)
    )
    assert [(row["agent"], row["rule"]) for row in refused] == [
        ("intake", "control-refused"),
        ("intake", "control-refused"),
        ("outpost", "control-refused"),
    ]
    # outpost still takes mail at its configured watermark.
    task, message_id, (code, response) = _request_to_outpost("j")
    assert code == 250, (code, response)
    wait_for_handler(message_id, path=RUNNER_LOG, timeout=45)
    print(f"S18j FORGERY: intake's login refused for outpost; {task} delivered as usual")
