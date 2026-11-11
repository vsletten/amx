from __future__ import annotations

import time
import uuid
from email import policy
from email.message import EmailMessage

import pytest

from amx.sdk import Agent
from amx.testkit import smtp_transaction, wait_for_message
from scenarios.support import (
    CT_JUDGE_DOWN,
    DEV_TLS_CA,
    postfix_log,
    queued_at,
    wait_for_handler,
)


def _wait(predicate, timeout: float, what: str) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.25)
    raise TimeoutError(what)


@pytest.mark.integration
def test_s16_judge_outage_defers_agent_mail_and_taints_human_mail() -> None:
    started = time.monotonic()
    suffix = uuid.uuid4().hex[:10]
    agent_task = f"t_s16a_{suffix}"
    human_task = f"t_s16h_{suffix}"
    human_id = f"<s16-human-{suffix}@plainmail.test>"
    CT_JUDGE_DOWN.write_text("stopped by S16\n", encoding="utf-8")
    try:
        sent = Agent(
            "scheduler@agents.northwind.test",
            "smtp://127.0.0.1:2587",
            "dev-scheduler-token",
            tls_ca_file=str(DEV_TLS_CA),
        ).send(
            to="intake@agents.contoso.test",
            subject=f"S16 judge outage {agent_task}",
            intent="request",
            task=agent_task,
            text="Please process this request once your content check is back.",
        )
        _wait(
            lambda: any(
                agent_task in line and "451 4.7.0 content check unavailable" in line
                for line in postfix_log("mailhost-nw").splitlines()
            ),
            timeout=20,
            what="northwind never logged the 451 4.7.0 deferral",
        )
        deferred = time.monotonic() - started
        assert queued_at("mailhost-nw", agent_task)

        human = EmailMessage(policy=policy.SMTP)
        human["From"] = "pat@plainmail.test"
        human["To"] = f"intake+{human_task}@agents.contoso.test"
        human["Subject"] = f"S16 human while the judge is down {suffix}"
        human["Message-ID"] = human_id
        human.set_content("Hello intake, is Thursday still on?")
        code, response = smtp_transaction(
            "127.0.0.1",
            "pat@plainmail.test",
            f"intake+{human_task}@agents.contoso.test",
            human.as_bytes(policy=policy.SMTP),
            port=2526,
        )
        assert code == 250, (code, response)
    finally:
        CT_JUDGE_DOWN.unlink(missing_ok=True)
    restored = time.monotonic() - started

    handled = wait_for_handler(sent.message_id, timeout=90)[-1]
    drained = time.monotonic() - started
    assert handled["tainted"] is False
    human_handled = wait_for_handler(human_id)[-1]
    assert human_handled["tainted"] is True
    assert human_handled["taint_reasons"] == ["judge-unavailable"]
    delivered = wait_for_message(
        "127.0.0.1",
        "intake@agents.contoso.test",
        "dev-intake",
        lambda m: m.get("Message-ID") == human_id,
        port=1432,
    )
    assert delivered.get("Agent-Taint") == "judge-unavailable"
    print(
        f"S16 TIMING: 451-at-nw={deferred:.1f}s judge-restored={restored:.1f}s "
        f"agent-mail-delivered={drained:.1f}s; human mail accepted tainted (judge-unavailable)"
    )
