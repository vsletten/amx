from __future__ import annotations

import smtplib
import time
import uuid
from email import policy
from email.parser import BytesParser

import pytest

from amx.identity import sign
from amx.sdk import Agent
from amx.testkit import drop_zone_record, set_zone_record, smtp_transaction
from scenarios.support import (
    DEV_TLS_CA,
    GENERATED,
    INTAKE_KEY,
    compose_exec,
    signed_request,
    trace_task,
)


def _dns_has_scheduler_key() -> bool:
    script = """
import dns.exception, dns.resolver
r = dns.resolver.Resolver(configure=False)
r.nameservers = ['172.30.0.53']
try:
    r.resolve('scheduler._domainkey.agents.northwind.test', 'TXT', lifetime=2)
except dns.exception.DNSException:
    print('false')
else:
    print('true')
"""
    result = compose_exec("gateway-ct", "/app/.venv/bin/python", "-c", script)
    return result.stdout.strip() == "true"


def _wait_dns(expected: bool, timeout: float = 10) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _dns_has_scheduler_key() is expected:
            return
        time.sleep(0.25)
    raise TimeoutError(f"scheduler DKIM DNS presence did not become {expected}")


@pytest.mark.integration
def test_s05a_unsigned_and_wrong_selector_are_rejected() -> None:
    suffix = uuid.uuid4().hex[:10]
    task = f"t_s05a_{suffix}"
    raw = signed_request(task, f"<s05a-{suffix}@agents.northwind.test>")
    message = BytesParser(policy=policy.SMTP).parsebytes(raw)
    del message["DKIM-Signature"]
    unsigned = message.as_bytes(policy=policy.SMTP)
    code, response = smtp_transaction(
        "127.0.0.1",
        f"scheduler+{task}@agents.northwind.test",
        f"intake+{task}@agents.contoso.test",
        unsigned,
        port=2526,
    )
    assert code == 550 and b"5.7.1" in response
    wrong = sign(
        unsigned,
        selector="intake",
        domain="agents.northwind.test",
        private_key=INTAKE_KEY,
    )
    code, response = smtp_transaction(
        "127.0.0.1",
        f"scheduler+{task}@agents.northwind.test",
        f"intake+{task}@agents.contoso.test",
        wrong,
        port=2526,
    )
    assert code == 550 and b"5.7.1" in response


@pytest.mark.integration
def test_s05b_dns_key_revocation_rejects_and_traces_no_key() -> None:
    suffix = uuid.uuid4().hex[:10]
    task = f"t_s05b_{suffix}"
    zone = GENERATED / "zones" / "agents.northwind.test.zone"
    record = drop_zone_record(zone, "scheduler._domainkey")
    try:
        _wait_dns(False)
        code, response = smtp_transaction(
            "127.0.0.1",
            f"scheduler+{task}@agents.northwind.test",
            f"intake+{task}@agents.contoso.test",
            signed_request(task, f"<s05b-{suffix}@agents.northwind.test>"),
            port=2526,
        )
        assert code == 550 and b"5.7.1" in response
        assert "dkim fail: no key" in response.decode()
        assert "dkim fail: no key" in trace_task(task)
    finally:
        set_zone_record(zone, record)
        _wait_dns(True)


@pytest.mark.integration
def test_s05c_response_only_local_identity_cannot_submit_request() -> None:
    task = f"t_s05c_{uuid.uuid4().hex[:10]}"
    restricted = Agent(
        "restricted@agents.northwind.test",
        "smtp://127.0.0.1:2587",
        "dev-restricted-token",
        tls_ca_file=str(DEV_TLS_CA),
    )
    with pytest.raises(smtplib.SMTPDataError) as error:
        restricted.send(
            to="intake@agents.contoso.test",
            subject="Not granted request",
            intent="request",
            task=task,
            text="This request is outside the grant.",
        )
    assert error.value.smtp_code == 550
    assert b"intent or schema is not granted" in error.value.smtp_error
