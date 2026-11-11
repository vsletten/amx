from __future__ import annotations

import uuid

import pytest

from amx.store import Store
from amx.testkit import smtp_transaction, wait_for_message
from scenarios.support import CT_DB, ordinary_message, wait_for_handler


@pytest.mark.integration
def test_s12_unsigned_human_lane_is_low_trust_and_cannot_open_tasks() -> None:
    suffix = uuid.uuid4().hex[:10]
    task = f"t_s12_{suffix}"
    message_id = f"<s12-{suffix}@plainmail.test>"
    raw = ordinary_message(message_id, task)
    code, response = smtp_transaction(
        "127.0.0.1",
        "pat@plainmail.test",
        f"intake+{task}@agents.contoso.test",
        raw,
        port=2526,
    )
    assert code == 250, (code, response)
    matches = wait_for_handler(message_id)
    assert len(matches) == 1
    assert matches[0]["intent"] == "response"

    delivered = wait_for_message(
        "127.0.0.1",
        "intake@agents.contoso.test",
        "dev-intake",
        lambda message: message.get("Message-ID") == message_id,
        port=1432,
    )
    assert delivered.get("Agent-Lane") == "human"
    assert delivered.get("Agent-Trust") == "low"
    assert delivered.get("Agent-Grant-Can-Open-Tasks") == "false"
    assert Store(CT_DB).task(task) is None
    print(f"S12 ACCEPT {code}: lane=human trust=low can_open_tasks=false")


@pytest.mark.integration
def test_s12_unsigned_human_cannot_supply_verified_agent_results() -> None:
    suffix = uuid.uuid4().hex[:10]
    task = f"t_s12_spoof_{suffix}"
    message_id = f"<s12-spoof-{suffix}@plainmail.test>"
    raw = ordinary_message(
        message_id,
        task,
        transport_headers={
            "Agent-Lane": "agent",
            "Agent-Trust": "verified",
            "Agent-Verified-Domain": "agents.northwind.test",
            "Agent-Verified-Selector": "scheduler",
            "Agent-Grant-Can-Open-Tasks": "true",
        },
    )
    code, response = smtp_transaction(
        "127.0.0.1",
        "pat@plainmail.test",
        f"intake+{task}@agents.contoso.test",
        raw,
        port=2526,
    )
    assert code == 250, (code, response)
    delivered = wait_for_message(
        "127.0.0.1",
        "intake@agents.contoso.test",
        "dev-intake",
        lambda message: message.get("Message-ID") == message_id,
        port=1432,
    )
    assert delivered.get_all("Agent-Lane") == ["human"]
    assert delivered.get_all("Agent-Trust") == ["low"]
    assert delivered.get("Agent-Verified-Domain") is None
    assert delivered.get("Agent-Verified-Selector") is None
    assert delivered.get_all("Agent-Grant-Can-Open-Tasks") == ["false"]
    assert Store(CT_DB).task(task) is None
