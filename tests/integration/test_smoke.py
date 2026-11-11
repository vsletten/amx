from __future__ import annotations

import base64
import email
import imaplib
import json
import os
import smtplib
import subprocess
import time
import urllib.request
import uuid
from email.message import EmailMessage, Message

import pytest

ACCOUNTS = {
    "northwind.test": ("mail.northwind.test", "victor@northwind.test", "dev-victor"),
    "contoso.test": ("mail.contoso.test", "ops@contoso.test", "dev-ops"),
    "plainmail.test": ("mail.plainmail.test", "pat@plainmail.test", "dev-pat"),
}


def _send(origin_host: str, sender: str, recipient: str, subject: str) -> None:
    message = EmailMessage()
    message["From"] = sender
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(f"amx M0 smoke message {subject}\n")
    with smtplib.SMTP(origin_host, 25, timeout=10) as smtp:
        smtp.send_message(message, from_addr=sender, to_addrs=[recipient])


def _wait_for_message(
    host: str, username: str, password: str, subject: str, timeout: float = 30.0
) -> Message:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with imaplib.IMAP4(host, 143, timeout=10) as imap:
            imap.login(username, password)
            status, _ = imap.select("INBOX")
            assert status == "OK"
            status, data = imap.search(None, "ALL")
            assert status == "OK"
            for message_id in reversed(data[0].split()):
                status, fetched = imap.fetch(message_id, "(RFC822)")
                assert status == "OK"
                raw = next(item[1] for item in fetched if isinstance(item, tuple))
                message = email.message_from_bytes(raw)
                if message.get("Subject") == subject:
                    return message
        time.sleep(0.5)
    pytest.fail(f"message {subject!r} did not arrive at {username}")


def _compose_container(service: str) -> str:
    result = subprocess.run(
        [
            "docker",
            "ps",
            "--filter",
            "label=com.docker.compose.project=amx",
            "--filter",
            f"label=com.docker.compose.service={service}",
            "--format",
            "{{.ID}}",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    container_id = result.stdout.strip()
    assert container_id, f"no running amx container for {service}"
    return container_id


def _is_stalwart(service: str) -> bool:
    """M6: contoso's mailhost may be Stalwart (make up MTA_CT=stalwart)."""
    result = subprocess.run(
        ["docker", "inspect", "--format", "{{.Config.Image}}", _compose_container(service)],
        check=True,
        capture_output=True,
        text=True,
    )
    return "stalwart" in result.stdout


def _stalwart_queue(host: str) -> list[str]:
    """Stalwart's queued message ids, from its JMAP management API (dev admin, port 8080)."""
    request = urllib.request.Request(
        f"http://{host}:8080/jmap",
        data=json.dumps(
            {
                "using": ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"],
                "methodCalls": [["x:QueuedMessage/query", {}, "0"]],
            }
        ).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": "Basic " + base64.b64encode(b"admin:dev-admin").decode(),
        },
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)["methodResponses"][0][1]["ids"]


def _assert_queue_empty(service: str) -> None:
    if _is_stalwart(service):
        host = ACCOUNTS["contoso.test"][0]
        assert _stalwart_queue(host) == []
        return
    result = subprocess.run(
        ["docker", "exec", _compose_container(service), "postqueue", "-p"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert "Mail queue is empty" in result.stdout, result.stdout


def _assert_real_domain_rejected(origin_host: str, *, stalwart: bool = False) -> None:
    with smtplib.SMTP(origin_host, 25, timeout=10) as smtp:
        mail_code, _ = smtp.mail("victor@northwind.test")
        assert mail_code == 250
        recipient_code, recipient_message = smtp.rcpt("nobody@example.com")
        if stalwart:  # Stalwart's relay refusal (docs/findings-stalwart.md)
            assert (recipient_code, recipient_message) == (550, b"5.1.2 Relay not allowed.")
            return
        assert recipient_code == 554
        assert b"isolated .test domains" in recipient_message


@pytest.mark.integration
def test_cross_domain_delivery_uses_mx_and_leaves_empty_queues() -> None:
    run_id = os.environ.get("AMX_SMOKE_ID", uuid.uuid4().hex[:10])
    routes = [
        ("northwind.test", "victor@northwind.test", "ops@contoso.test", "contoso.test"),
        ("contoso.test", "ops@contoso.test", "pat@plainmail.test", "plainmail.test"),
        ("plainmail.test", "pat@plainmail.test", "victor@northwind.test", "northwind.test"),
    ]

    for index, (origin_domain, sender, recipient, target_domain) in enumerate(routes, start=1):
        subject = f"amx-M0-smoke-{run_id}-{index}"
        origin_host = ACCOUNTS[origin_domain][0]
        target_host, target_user, target_password = ACCOUNTS[target_domain]
        _send(origin_host, sender, recipient, subject)
        delivered = _wait_for_message(target_host, target_user, target_password, subject)
        received = "\n".join(delivered.get_all("Received", []))
        assert f"mail.{origin_domain}" in received, received
        assert f"mail.{target_domain}" in received, received
        print(f"{sender} -> {recipient}: {subject}")
        print(received)

    for service in ("mailhost-nw", "mailhost-ct", "mailhost-pm"):
        _assert_queue_empty(service)

    for domain, (origin_host, _, _) in ACCOUNTS.items():
        stalwart = domain == "contoso.test" and _is_stalwart("mailhost-ct")
        _assert_real_domain_rejected(origin_host, stalwart=stalwart)
