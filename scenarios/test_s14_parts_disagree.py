from __future__ import annotations

import uuid

import pytest

from amx.store import Store
from amx.testkit import smtp_transaction
from scenarios.support import CT_DB, signed_agent_message


@pytest.mark.integration
def test_s14_text_and_machine_parts_that_disagree_are_refused() -> None:
    task = f"t_s14_{uuid.uuid4().hex[:10]}"
    raw = signed_agent_message(
        selector="scheduler",
        task=task,
        recipient=f"intake+{task}@agents.contoso.test",
        subject=f"S14 inspection {task}",
        text="Can we confirm the site inspection for Tuesday at 9 am?",
        payload={
            "action": "confirm_inspection",
            "arguments": {"day": "Thursday", "time": "09:00", "site": "Contoso HQ"},
        },
    )
    code, response = smtp_transaction(
        "127.0.0.1",
        f"scheduler+{task}@agents.northwind.test",
        f"intake+{task}@agents.contoso.test",
        raw,
        port=2526,
    )
    assert code == 550, (code, response)
    assert b"5.6.0" in response and b"text and machine parts disagree" in response
    [event] = Store(CT_DB).rows(
        "SELECT detail FROM policy_events WHERE task = ? AND stage = 'eod'", (task,)
    )
    print(f"S14 REFUSED {code}: {response.decode()} judgment {event['detail']}")
