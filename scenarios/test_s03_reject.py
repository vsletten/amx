from __future__ import annotations

import smtplib
import time
import uuid

import pytest

from amx.sdk import Agent
from amx.store import Store
from amx.testkit import send_raw, smtp_transaction, wait_for_message
from scenarios.support import (
    DEV_TLS_CA,
    NW_DB,
    NW_HANDLER_LOG,
    compose_exec,
    mta_ct,
    signed_invalid_schema,
    trace_task,
    wait_for_task,
)


@pytest.mark.integration
def test_s03a_unknown_agent_rejected_at_rcpt() -> None:
    task = f"t_s03a_{uuid.uuid4().hex[:10]}"
    with smtplib.SMTP("127.0.0.1", 2526, timeout=10) as client:
        assert client.mail("scheduler@agents.northwind.test")[0] == 250
        code, response = client.rcpt(f"unknown+{task}@agents.contoso.test")
    assert code == 550
    assert b"5.1.1" in response
    assert b"unknown or disabled agent" in response
    trace = trace_task(task)
    assert "milter RCPT agent-unknown -> reject 550 5.1.1" in trace
    if mta_ct() == "postfix":
        assert "postfix" in trace  # Postfix logs the refusal with the recipient
    # Stalwart logs a milter-refused RCPT without the recipient (milter.action-reply-code), so
    # only the gateway's row ties it to the task (docs/findings-stalwart.md).
    print(f"S03a REJECT {code}: {response.decode()}")


@pytest.mark.integration
def test_s03b_invalid_schema_rejected_and_bounce_contains_reason() -> None:
    suffix = uuid.uuid4().hex[:10]
    task = f"t_s03b_{suffix}"
    message_id = f"<s03b-{suffix}@agents.northwind.test>"
    raw = signed_invalid_schema(task, message_id)
    recipient = f"intake+{task}@agents.contoso.test"

    code, response = smtp_transaction(
        "127.0.0.1",
        f"scheduler+{task}@agents.northwind.test",
        recipient,
        raw,
        port=2526,
    )
    assert code == 550
    assert b"5.6.0" in response
    assert b"schema validation failed" in response
    print(f"S03b REJECT {code}: {response.decode()}")

    refusals = send_raw(
        "127.0.0.1",
        f"scheduler+{task}@agents.northwind.test",
        recipient,
        raw,
        port=11025,
    )
    assert refusals == {}
    bounce = wait_for_message(
        "127.0.0.1",
        "scheduler@agents.northwind.test",
        "dev-scheduler",
        lambda message: (
            message.get_content_type() == "multipart/report" and message_id in message.as_string()
        ),
        port=1431,
        timeout=45,
    )
    rendered = bounce.as_string()
    assert "5.6.0" in rendered
    assert "schema validation failed" in rendered
    trace = trace_task(task)
    assert "milter EOD invalid-machine-part -> reject 550 5.6.0" in trace
    assert "postfix" in trace
    print("S03b BOUNCE: contains 5.6.0 schema validation failed")


@pytest.mark.integration
def test_s03c_closed_port_mx_produces_dsn_and_failed_state() -> None:
    dns_probe = compose_exec(
        "gateway-nw",
        "/app/.venv/bin/python",
        "-c",
        "import dns.resolver; "
        "r=dns.resolver.Resolver(configure=False); r.nameservers=['172.30.0.53']; "
        "mx=str(r.resolve('dead.test','MX')[0].exchange); "
        "print(mx, r.resolve(mx,'A')[0])",
    )
    assert dns_probe.stdout.strip() == "mail.dead.test. 172.30.0.53"
    task = f"t_s03c_{uuid.uuid4().hex[:10]}"
    scheduler = Agent(
        "scheduler@agents.northwind.test",
        "smtp://127.0.0.1:2587",
        "dev-scheduler-token",
        tls_ca_file=str(DEV_TLS_CA),
    )
    scheduler.send(
        to="nobody@dead.test",
        subject="Closed MX",
        intent="request",
        task=task,
        text="This must bounce.",
    )
    matches = wait_for_task(task, path=NW_HANDLER_LOG, intent="error", timeout=90)
    assert matches[-1]["task_state"] == "failed"
    assert any(
        phrase in (matches[-1]["diagnostic"] or "").casefold()
        for phrase in ("connection refused", "connect to", "timed out")
    )
    # The LMTP path records the task state just after the handler returns (the handler log above
    # is written first), so give the store a moment instead of reading it in that gap.
    deadline = time.monotonic() + 10
    task_row = Store(NW_DB).task(task)
    while (task_row is None or task_row["state"] != "failed") and time.monotonic() < deadline:
        time.sleep(0.1)
        task_row = Store(NW_DB).task(task)
    assert task_row is not None
    assert task_row["state"] == "failed"
