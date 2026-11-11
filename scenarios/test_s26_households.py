"""SH-47: throwaway agents share one lane, but not another household's authority.

Hosted Compose acceptance only, under `make suite` on its disposable engine. Reuse S19's
registration paths; no real person, external recipient, runner, or DNS change is needed.
"""

from __future__ import annotations

import json
import smtplib
import uuid
from datetime import UTC, datetime

import pytest

from amx.sdk import Agent
from amx.store import Store
from amx.testkit import wait_for_message
from scenarios.support import CT_DB, DEV_TLS_CA
from scenarios.test_s19_agent_registration import (
    CONTOSO,
    CT_REGISTRY,
    IMAP,
    SUBMISSION,
    _amx,
    _ct,
    _rcpt,
    _reloaded,
    _submission_login,
    _wait,
)


@pytest.mark.integration
def test_s26_households_refuse_both_directions_and_reload_policy(tmp_path):
    suffix = uuid.uuid4().hex[:8]
    names = [f"hh-{suffix}-{label}" for label in ("a", "b", "c")]
    addresses = [f"{name}@agents.contoso.test" for name in names]
    bundles = []
    clients = []
    try:
        for index, name in enumerate(names):
            path = tmp_path / f"{name}.json"
            added = _ct(
                "agent",
                "add",
                name,
                "--live",
                "--bundle",
                str(path),
                "--imap",
                f"{IMAP[0]}:{IMAP[1]}",
                "--submission",
                f"smtp://{SUBMISSION[0]}:{SUBMISSION[1]}",
                *(
                    []
                    if index == 0
                    else ["--household", "fixture", "--accept-from", "owner@example.com"]
                ),
            )
            # Never include captured stdout/stderr in an assertion: bundle custody is private.
            assert added.returncode == 0, "household fixture registration failed"
            bundle = json.loads(path.read_text())
            bundles.append(bundle)
            _wait(
                lambda name=name, bundle=bundle: _submission_login(name, bundle["token"]),
                30,
                "agent did not reload",
            )
            _wait(
                lambda address=addresses[index]: _rcpt(address)[0] == 250,
                30,
                "recipient did not reload",
            )
            clients.append(
                Agent(
                    addresses[index],
                    f"smtp://{SUBMISSION[0]}:{SUBMISSION[1]}",
                    bundle["token"],
                    tls_ca_file=str(DEV_TLS_CA),
                )
            )

        def send(sender, to, *, task=None):
            return clients[sender].send(
                to=to,
                intent="request",
                subject="S26 household fixture",
                text="Please confirm this local request.",
                task=task,
            )

        store = Store(CT_DB)
        for index, (sender, to) in enumerate(
            ((0, addresses[1]), (1, addresses[0]), (1, [addresses[2], addresses[0]]))
        ):
            task = f"t_s26_{suffix}_refused_{index}"
            with pytest.raises(smtplib.SMTPResponseException) as refused:
                send(sender, to, task=task)
            assert refused.value.smtp_code == 550
            assert b"5.7.1" in refused.value.smtp_error
            assert b"agent-household" in refused.value.smtp_error
            assert store.rows("SELECT * FROM journal WHERE task = ?", (task,)) == []
        # A positive control crosses actual sibling ingress and LMTP, not just submission.
        sent = send(1, addresses[2])
        delivered = wait_for_message(
            IMAP[0],
            addresses[2],
            bundles[2]["password"],
            lambda message: message.get("Message-ID") == sent.message_id,
            port=IMAP[1],
        )
        assert delivered["Agent-Trust"] == "verified"
        assert delivered["Agent-Verified-Selector"] == names[1]

        since = datetime.now(UTC).isoformat()
        changed = _ct("agent", "set", names[2], "--household", "different")
        assert changed.returncode == 0, "household fixture policy update failed"
        _wait(lambda: _reloaded("gateway-ct", since), 15, "new household policy never applied")
        with pytest.raises(smtplib.SMTPResponseException) as refused:
            send(1, addresses[2])
        assert refused.value.smtp_code == 550 and b"agent-household" in refused.value.smtp_error
        listing = _amx(
            "agent", "list", "--config", str(CONTOSO), "--registry-dir", str(CT_REGISTRY)
        )
        assert listing.returncode == 0
        assert "household=different" in listing.stdout and "owner@example.com" in listing.stdout
        print(
            "S26 households: both directions and mixed recipients refused; "
            "same household delivered; policy reloaded"
        )
    finally:
        for name in names:
            if (CT_REGISTRY / "agents" / f"{name}.yaml").exists():
                assert _ct("agent", "remove", name).returncode == 0
                assert _ct("agent", "remove", name, "--purge", "--now").returncode == 0
