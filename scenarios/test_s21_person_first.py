"""SH-01: an eligible person writes first; ctx.reply answers in the same thread."""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime
from email import policy
from email.message import EmailMessage

import pytest
import yaml

from amx.store import Store
from amx.tasks import valid_token
from amx.testkit import smtp_transaction, wait_for_message
from scenarios.support import CT_DB, ROOT, compose, wait_for_handler


def _wait_reload(since: str) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if "config reloaded" in compose("logs", "--since", since, "gateway-ct").stdout:
            return
        time.sleep(0.25)
    raise TimeoutError("gateway-ct did not reload the S21 human-lane fixture")


@pytest.mark.integration
def test_s21_person_first_gets_same_thread_answer() -> None:
    # Explicit test-only eligibility, not SH-12 owner authentication. Restore the
    # shipped low-trust/replies-only human grant even if the assertion/send fails.
    path = ROOT / "deploy" / "gateway" / "contoso.yaml"
    original = path.read_text()
    configured = yaml.safe_load(original)
    human_grants = [grant for grant in configured["trust"] if grant.get("lane") == "human"]
    assert len(human_grants) == 1
    human_grants[0]["can_open_tasks"] = True
    suffix = uuid.uuid4().hex
    message_id = f"<s21-{suffix}@plainmail.test>"
    recipient = "intake@agents.contoso.test"
    message = EmailMessage(policy=policy.SMTP)
    message["From"] = "pat@plainmail.test"
    message["To"] = recipient
    message["Message-ID"] = message_id
    message["Subject"] = f"S21 [reply] {suffix}"
    message.set_content("Could you help with this ordinary human request?")
    try:
        since = datetime.now(UTC).isoformat()
        path.write_text(yaml.safe_dump(configured, sort_keys=False))
        _wait_reload(since)
        code, detail = smtp_transaction(
            "127.0.0.1", "pat@plainmail.test", recipient, message.as_bytes(), port=2526
        )
        assert code == 250, (code, detail)
        invoked = wait_for_handler(message_id)[-1]
        task = invoked["task"]
        assert task and valid_token(task)
        assert invoked["task_state"] is None
        assert invoked["lane"] == "human"
        answer = wait_for_message(
            "127.0.0.1",
            "pat@plainmail.test",
            "dev-pat",
            lambda msg: msg.get("In-Reply-To") == message_id,
            port=1433,
        )
        assert answer["Agent-Task"] == task
        assert message_id in str(answer["References"]).split()
        assert answer["Subject"] == f"Re: {message['Subject']}"
        assert "Thanks, intake received your note." in answer.get_body().get_content()
        delivered = wait_for_message(
            "127.0.0.1",
            recipient,
            "dev-intake",
            lambda msg: msg.get("Message-ID") == message_id,
            port=1432,
        )
        assert delivered["Agent-Task-Assigned"] == task
        assert delivered["Agent-Trust"] == "low"
        assert Store(CT_DB).task(task)["state"] == "working"
        print(f"S21 person-first same-thread answer task={task}")
    finally:
        since = datetime.now(UTC).isoformat()
        path.write_text(original)
        _wait_reload(since)
