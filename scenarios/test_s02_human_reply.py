from __future__ import annotations

import uuid
from email import policy
from email.message import EmailMessage

import pytest

from amx.sdk import Agent
from amx.store import Store
from amx.testkit import send_raw, wait_for_message
from scenarios.support import DEV_TLS_CA, NW_DB, NW_HANDLER_LOG, wait_for_task


@pytest.mark.integration
def test_s02_plain_smtplib_human_reply_correlates_without_profile() -> None:
    suffix = uuid.uuid4().hex[:10]
    task = f"t_s02_{suffix}"
    # Precondition: scheduler already corresponds with plainmail.test, so the M4 first-contact
    # hold rule (exercised by S06) does not apply here.
    Store(NW_DB).remember_contact("scheduler", "plainmail.test")
    scheduler = Agent(
        "scheduler@agents.northwind.test",
        "smtp://127.0.0.1:2587",
        "dev-scheduler-token",
        tls_ca_file=str(DEV_TLS_CA),
    )
    sent = scheduler.send(
        to="pat@plainmail.test",
        subject=f"S02 quote {suffix}",
        intent="request",
        task=task,
        text="Pat, please send a quote.",
    )
    original = wait_for_message(
        "127.0.0.1",
        "pat@plainmail.test",
        "dev-pat",
        lambda message: message.get("Message-ID") == sent.message_id,
        port=1433,
    )
    reply = EmailMessage(policy=policy.SMTP)
    reply["From"] = "pat@plainmail.test"
    reply["To"] = str(original["Reply-To"])
    reply["Subject"] = f"Re: {original['Subject']}"
    reply["Message-ID"] = f"<s02-human-{suffix}@plainmail.test>"
    reply["In-Reply-To"] = sent.message_id
    reply["References"] = sent.message_id
    reply.set_content("The quote is 42 dollars.")
    assert (
        send_raw(
            "127.0.0.1",
            "pat@plainmail.test",
            str(original["Reply-To"]),
            reply.as_bytes(policy=policy.SMTP),
            port=2527,
        )
        == {}
    )
    matches = wait_for_task(task, path=NW_HANDLER_LOG, intent="response")
    assert matches[-1]["lane"] == "human"
    assert matches[-1]["text"] == "The quote is 42 dollars."
