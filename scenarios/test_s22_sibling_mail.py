"""SH-02: native sibling delivery and refusal of the identical signed port-25 replay."""

from __future__ import annotations

import uuid

import pytest

from amx.journal import Journal
from amx.sdk import Agent
from amx.store import Store
from amx.testkit import smtp_transaction, wait_for_message
from scenarios.support import CT_DB, DEV_TLS_CA, wait_for_handler


@pytest.mark.integration
def test_s22_sibling_delivery_and_port25_replay_refusal() -> None:
    agent = Agent(
        "intake@agents.contoso.test",
        "smtp://127.0.0.1:2588",
        "dev-intake-token",
        tls_ca_file=str(DEV_TLS_CA),
    )
    recipient = "intake-off@agents.contoso.test"  # no auto-reply/LLM/runner needed
    sent = agent.send(
        to=recipient,
        intent="request",
        subject=f"S22 sibling {uuid.uuid4().hex}",
        text="Please confirm this local sibling request.",
    )
    invoked = wait_for_handler(sent.message_id)
    assert len(invoked) == 1
    assert invoked[0]["agent"] == "intake-off"
    assert invoked[0]["task"] == sent.task
    assert invoked[0]["lane"] == "agent"
    delivered = wait_for_message(
        "127.0.0.1",
        recipient,
        "dev-intake-off",
        lambda message: message.get("Message-ID") == sent.message_id,
        port=1432,
    )
    assert delivered["Agent-Task"] == sent.task
    assert delivered["Agent-Task-Assigned"] is None
    assert delivered["Agent-Lane"] == "agent"
    assert delivered["Agent-Trust"] == "verified"
    assert delivered["Agent-Verified-Domain"] == "agents.contoso.test"
    assert delivered["Agent-Verified-Selector"] == "intake"
    store = Store(CT_DB)
    assert store.task(sent.task, "intake")["state"] == "submitted"
    assert store.task(sent.task, "intake-off")["state"] == "submitted"
    [outbound] = store.rows(
        "SELECT raw_sha256 FROM journal WHERE message_id = ? AND event = 'submission'",
        (sent.message_id,),
    )
    # Replay the exact signed pre-ingress bytes, not the delivered copy whose transport
    # headers would be stripped. The signature is valid; listener provenance is not.
    raw = Journal(CT_DB.parent, store).raw_path(outbound["raw_sha256"]).read_bytes()
    code, detail = smtp_transaction(
        "127.0.0.1", f"intake+{sent.task}@agents.contoso.test", recipient, raw, port=2526
    )
    assert code == 550, (code, detail)
    assert b"trusted sibling" in detail, detail
    refused = store.rows(
        "SELECT rule FROM policy_events WHERE stage = 'eod' AND action = 'reject' "
        "ORDER BY sequence DESC LIMIT 1"
    )
    assert refused[0]["rule"] == "own-agent-ingress"
    assert len(wait_for_handler(sent.message_id)) == 1
    print(f"S22 sibling delivered task={sent.task}; identical port-25 replay refused")
