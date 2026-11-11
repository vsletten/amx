"""S23: a signed-in local person opens a task and receives the agent's answer."""

from __future__ import annotations

import os
import re
import smtplib
import ssl
import uuid
from email import policy
from email.message import EmailMessage

import pytest

from amx.store import Store
from amx.tasks import valid_token
from amx.testkit import smtp_transaction, wait_for_message
from scenarios.support import CT_DB, DEV_TLS_CA, wait_for_handler

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("AMX_SUITE_MTA") != "stalwart",
        reason="S23 requires Stalwart native people submission (Postfix remains supported)",
    ),
]


def _policy_event_boundary(store):
    return store.rows("SELECT COALESCE(MAX(sequence), 0) AS sequence FROM policy_events")[0][
        "sequence"
    ]


def _assert_owner_grant_journaled(store, after_sequence):
    # Plain-address human EOD events have no task/agent yet: LMTP assigns the task.
    # Use the policy sequence, not the later task token, to isolate this submission.
    rows = store.rows(
        "SELECT detail FROM policy_events WHERE sequence > ? AND stage='eod'",
        (after_sequence,),
    )
    assert any(
        re.search(r"(?:\[|; )grant=owner trust=high can_open_tasks=true\]", row["detail"])
        for row in rows
    ), "current submission's complete owner grant must be journaled"


def _message(sender, recipient):
    message = EmailMessage(policy=policy.SMTP)
    message["From"] = sender
    message["To"] = recipient
    message["Message-ID"] = f"<s23-{uuid.uuid4().hex}@contoso.test>"
    message["Subject"] = "S23 [reply] person-first task"
    message.set_content("Could you help with this ordinary human request?")
    return message


@pytest.mark.parametrize("port", [1465, 1587])
def test_s23_signed_in_person_gets_same_thread_answer(port):
    owner = "ops@contoso.test"
    recipient = "intake@agents.contoso.test"
    message = _message(owner, recipient)
    store = Store(CT_DB)

    context = ssl.create_default_context(cafile=str(DEV_TLS_CA))
    if port == 1465:
        smtp = smtplib.SMTP_SSL("localhost", port, context=context, timeout=10)
    else:
        smtp = smtplib.SMTP("localhost", port, timeout=10)
        smtp.ehlo()
        assert not smtp.has_extn("auth"), "no plaintext AUTH before TLS"
        smtp.starttls(context=context)
    with smtp:
        smtp.ehlo()
        smtp.login(owner, "dev-ops")  # source-controlled synthetic dev account only
        forged = _message("forged@contoso.test", recipient)
        with pytest.raises(smtplib.SMTPDataError) as error:
            smtp.sendmail(owner, [recipient], forged.as_bytes())
        assert error.value.smtp_code == 550
        policy_boundary = _policy_event_boundary(store)
        assert not smtp.send_message(message)
    message_id = str(message["Message-ID"])
    invoked = wait_for_handler(message_id)[-1]
    task = invoked["task"]
    assert valid_token(task)
    assert invoked["lane"] == "human" and not invoked["tainted"]
    delivered = wait_for_message(
        "127.0.0.1",
        recipient,
        "dev-intake",
        lambda msg: msg.get("Message-ID") == message_id,
        port=1432,
    )
    assert delivered["Agent-Trust"] == "high"
    assert delivered["Agent-Grant-Role"] == "owner"
    assert delivered["Agent-Grant-Can-Open-Tasks"] == "true"
    assert delivered["Agent-Task-Assigned"] == task
    answer = wait_for_message(
        "127.0.0.1",
        owner,
        "dev-ops",
        lambda msg: msg.get("In-Reply-To") == message_id,
        port=1432,
    )
    assert answer["Agent-Task"] == task
    assert message_id in str(answer["References"]).split()
    assert "Thanks, intake received your note." in answer.get_body().get_content()
    assert store.task(task, "intake")["state"] == "working"
    _assert_owner_grant_journaled(store, policy_boundary)
    # Same claimed local From on public25 is still a low-trust stranger, not owner.
    public = _message(owner, recipient)
    public.replace_header("Subject", "S23 public ingress cannot open a task")
    code, _ = smtp_transaction("127.0.0.1", owner, recipient, public.as_bytes(), port=2526)
    assert code == 250
    public_copy = wait_for_message(
        "127.0.0.1",
        recipient,
        "dev-intake",
        lambda msg: msg.get("Message-ID") == public["Message-ID"],
        port=1432,
    )
    assert public_copy["Agent-Trust"] == "low"
    assert public_copy["Agent-Grant-Can-Open-Tasks"] == "false"
    assert public_copy["Agent-Grant-Role"] is None
    assert public_copy["Agent-Task-Assigned"] is None
    print(f"S23 native submission {port}: owner task assigned, same-thread answer, public25 low")
