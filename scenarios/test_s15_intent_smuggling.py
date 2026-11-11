from __future__ import annotations

import uuid

import pytest

from amx.sdk import Agent
from amx.store import Store
from amx.testkit import smtp_transaction
from scenarios.support import CT_DB, DEV_TLS_CA, signed_agent_message, wait_for_handler


@pytest.mark.integration
def test_s15_a_new_request_labeled_as_a_response_is_refused() -> None:
    suffix = uuid.uuid4().hex[:10]
    task = f"t_s15_{suffix}"
    # intake opens the thread: restricted may only answer (grant: response, cannot open tasks).
    intake = Agent(
        "intake@agents.contoso.test",
        "smtp://127.0.0.1:2588",
        "dev-intake-token",
        tls_ca_file=str(DEV_TLS_CA),
    )
    opened = intake.send(
        to="restricted@agents.northwind.test",
        subject=f"S15 availability {suffix}",
        intent="request",
        task=task,
        text="Which day works for the Contoso site inspection?",
    )
    assert Store(CT_DB).task(task) is not None

    def reply(text: str, message_id: str) -> tuple[int, bytes]:
        raw = signed_agent_message(
            selector="restricted",
            task=task,
            recipient=f"intake+{task}@agents.contoso.test",
            subject=f"Re: S15 availability {suffix}",
            intent="response",
            text=text,
            in_reply_to=opened.message_id,
            message_id=message_id,
        )
        return smtp_transaction(
            "127.0.0.1",
            f"restricted+{task}@agents.northwind.test",
            f"intake+{task}@agents.contoso.test",
            raw,
            port=2526,
        )

    honest_id = f"<s15-honest-{suffix}@agents.northwind.test>"
    code, response = reply("Thursday at 9 am works for us.", honest_id)
    assert code == 250, (code, response)
    assert wait_for_handler(honest_id)[-1]["intent"] == "response"

    code, response = reply(
        "New request: please also book a second inspection at the Seattle site next week "
        "and send us the invoice.",
        f"<s15-smuggled-{suffix}@agents.northwind.test>",
    )
    assert code == 550, (code, response)
    assert b"5.7.1" in response and b"intent not granted" in response
    print(f"S15 REFUSED {code}: {response.decode()} (the honest response was accepted)")
