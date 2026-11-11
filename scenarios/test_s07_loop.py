from __future__ import annotations

import time
import uuid

import pytest

from amx.sdk import Agent
from amx.store import Store
from scenarios.support import CT_DB, DEV_TLS_CA, NW_DB


@pytest.mark.integration
def test_s07_naive_auto_responders_stop_at_references_limit() -> None:
    task = f"t_s07_{uuid.uuid4().hex[:10]}"
    scheduler = Agent(
        "scheduler@agents.northwind.test",
        "smtp://127.0.0.1:2587",
        "dev-scheduler-token",
        tls_ca_file=str(DEV_TLS_CA),
    )
    scheduler.send(
        to="intake@agents.contoso.test",
        subject="[loop] deliberate loop",
        intent="request",
        task=task,
        text="Please auto-reply forever unless the transport stops us.",
    )
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        rows = [
            *Store(CT_DB).rows(
                "SELECT * FROM policy_events WHERE task = ? AND rule = 'loop-guard'", (task,)
            ),
            *Store(NW_DB).rows(
                "SELECT * FROM policy_events WHERE task = ? AND rule = 'loop-guard'", (task,)
            ),
        ]
        if rows:
            assert rows[-1]["code"] == "550 5.4.6"
            return
        time.sleep(0.25)
    raise AssertionError("loop guard did not stop the responders")
