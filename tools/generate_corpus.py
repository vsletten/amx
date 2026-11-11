"""Regenerate the checked-in AMX profile conformance corpus."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from email.message import EmailMessage
from email.policy import SMTP
from pathlib import Path
from typing import Any

from amx.profile import DEFAULT_CONTEXT, PROTOCOL, build

ROOT = Path(__file__).parents[1]
CORPUS = ROOT / "spec" / "corpus"
DATE = datetime(2026, 9, 23, 19, 0, tzinfo=UTC)
REQUEST = "https://evtmail.ai/schema/0.1/request.json"
RESPONSE = "https://evtmail.ai/schema/0.1/response.json"
UPDATE = "https://evtmail.ai/schema/0.1/update.json"
ACK = "https://evtmail.ai/schema/0.1/ack.json"
ERROR = "https://evtmail.ai/schema/0.1/error.json"
APPOINTMENT = "https://evtmail.ai/schema/0.1/appointment-request.json"
CONTROL = "https://evtmail.ai/schema/0.1/control.json"


def expected_result(
    *,
    intent: str,
    task: str | None,
    task_state: str | None,
    text: str,
    sender: str,
    lane: str,
    message_id: str,
    schema: str | None = None,
    payload: dict[str, Any] | None = None,
    in_reply_to: str | None = None,
    references: list[str] | None = None,
    report: dict[str, Any] | None = None,
    card: str | None = None,
    reply_by: str | None = None,
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    return {
        "intent": intent,
        "task": task,
        "task_state": task_state,
        "schema": schema,
        "payload": payload,
        "text": text,
        "sender": {
            "address": sender,
            "display_name": None,
            "dkim_domain": None,
            "dkim_selector": None,
        },
        "lane": lane,
        "trust": None,
        "thread": {
            "message_id": message_id,
            "in_reply_to": in_reply_to,
            "references": references or [],
        },
        "report": report,
        "protocol": PROTOCOL if lane == "agent" else None,
        "card": card,
        "reply_by": reply_by,
        "idempotency_key": idempotency_key,
    }


def write_pair(name: str, raw: bytes, expected: dict[str, Any]) -> None:
    (CORPUS / f"{name}.eml").write_bytes(raw)
    (CORPUS / f"{name}.expected.json").write_text(
        json.dumps(expected, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8"
    )


def profile(
    name: str,
    *,
    intent: str,
    state: str,
    text: str,
    schema: str | None,
    payload: dict[str, Any] | None,
    task: str | None = None,
    sender: str = "scheduler@agents.northwind.test",
    recipient: str = "intake@agents.contoso.test",
    in_reply_to: str | None = None,
    references: list[str] | None = None,
    subject: str | None = None,
    cc: str | None = None,
    card: str | None = None,
    reply_by: datetime | None = None,
    message_id: str | None = None,
    date: datetime = DATE,
) -> EmailMessage:
    task = task or f"t_{name.replace('-', '_')}"
    message_id = message_id or f"<{name}@agents.northwind.test>"
    if intent == "response" and in_reply_to is None:
        in_reply_to = f"<request-for-{name}@agents.northwind.test>"
    if intent == "response" and references is None:
        assert in_reply_to is not None
        references = [in_reply_to]
    message = build(
        sender=sender,
        to=recipient,
        cc=cc,
        subject=subject or name.replace("-", " ").title(),
        intent=intent,  # type: ignore[arg-type]
        task=task,
        task_state=state,  # type: ignore[arg-type]
        text=text,
        payload=payload,
        schema=schema,
        card=card,
        reply_by=reply_by,
        date=date,
        message_id=message_id,
        in_reply_to=in_reply_to,
        references=references or (),
    )
    normalized = None if payload is None else {"@context": DEFAULT_CONTEXT, **payload}
    if message.is_multipart():
        message.set_boundary(f"amx-{name}")
    write_pair(
        name,
        message.as_bytes(policy=SMTP),
        {
            "result": expected_result(
                intent=intent,
                task=task,
                task_state=state,
                schema=schema,
                payload=normalized,
                text=text if text.endswith("\n") else f"{text}\n",
                sender=sender,
                lane="agent",
                message_id=message_id,
                in_reply_to=in_reply_to,
                references=references,
                card=card,
                reply_by=str(message["Agent-Reply-By"]) if reply_by is not None else None,
            )
        },
    )
    return message


def error_pair(name: str, message: EmailMessage, error_type: str, contains: str) -> None:
    write_pair(
        name,
        message.as_bytes(policy=SMTP),
        {"error": {"type": error_type, "contains": contains}},
    )


def main() -> None:
    CORPUS.mkdir(parents=True, exist_ok=True)
    for old in CORPUS.iterdir():
        if old.suffix in {".eml", ".json"}:
            old.unlink()

    profile(
        "01-request",
        intent="request",
        state="submitted",
        text="Please inspect Harbor Road.",
        schema=REQUEST,
        payload={"action": "inspect", "arguments": {"site": "Harbor Road"}},
    )
    profile(
        "02-response",
        intent="response",
        state="completed",
        text="Inspection completed.",
        schema=RESPONSE,
        payload={"result": {"condition": "good"}},
    )
    profile(
        "03-update",
        intent="update",
        state="working",
        text="Inspection is halfway complete.",
        schema=UPDATE,
        payload={"status": "on site", "progress": 0.5},
    )
    profile(
        "04-ack",
        intent="ack",
        state="working",
        text="Request received.",
        schema=ACK,
        payload={"received": True},
    )
    profile(
        "05-error",
        intent="error",
        state="failed",
        text="The location could not be found.",
        schema=ERROR,
        payload={"code": "location-not-found", "message": "No matching site", "retryable": False},
    )
    profile(
        "06-proposal-example-request",
        intent="request",
        state="submitted",
        text=(
            "Hello,\n\nVictor Sletten would like a site inspection at 1200 Harbor Rd during "
            "the week of October 5. Any weekday morning works. Please reply with two or "
            "three proposed slots. Victor is copied and can answer questions directly.\n\n"
            "-- scheduler, an agent acting for Victor Sletten (northwind.test)"
        ),
        schema=APPOINTMENT,
        payload={
            "@type": "Reservation",
            "reservationStatus": "https://schema.org/ReservationPending",
            "underName": {"@type": "Person", "name": "Victor Sletten"},
            "reservationFor": {
                "@type": "Service",
                "name": "Site inspection",
                "location": {"@type": "Place", "address": "1200 Harbor Rd"},
            },
            "amx:window": {
                "start": "2026-10-05",
                "end": "2026-10-09",
                "preferred": "morning",
            },
            "amx:ask": "propose_slots",
            "amx:count": 3,
        },
        task="t_8f3a2c",
        sender="scheduler+t_8f3a2c@agents.northwind.test",
        subject="Request: site inspection, week of 2026-10-05",
        cc="victor@northwind.test",
        card="https://northwind.test/.well-known/agents/scheduler.json",
        reply_by=datetime.fromisoformat("2026-09-23T17:00:00-07:00"),
        message_id="<t_8f3a2c.1@agents.northwind.test>",
        date=datetime.fromisoformat("2026-09-21T14:02:11-07:00"),
    )
    profile(
        "07-profile-text-only",
        intent="ack",
        state="working",
        text="Received; work will begin shortly.",
        schema=None,
        payload=None,
    )

    gmail = b"""From: pat@plainmail.test\r
To: Scheduler <scheduler+t_gmail@agents.northwind.test>\r
Subject: Re: quote request\r
Date: Wed, 23 Sep 2026 12:10:00 -0700\r
Message-ID: <gmail-reply@plainmail.test>\r
In-Reply-To: <quote-request@agents.northwind.test>\r
References: <root@agents.northwind.test> <quote-request@agents.northwind.test>\r
Content-Type: text/plain; charset=utf-8\r
\r
Friday morning works.\r
"""
    write_pair(
        "08-gmail-stripped-reply",
        gmail,
        {
            "result": expected_result(
                intent="response",
                task="t_gmail",
                task_state=None,
                text="Friday morning works.\n",
                sender="pat@plainmail.test",
                lane="human",
                message_id="<gmail-reply@plainmail.test>",
                in_reply_to="<quote-request@agents.northwind.test>",
                references=[
                    "<root@agents.northwind.test>",
                    "<quote-request@agents.northwind.test>",
                ],
            )
        },
    )

    delivered = b"""From: human@forwarder.test\r
To: scheduler@agents.northwind.test\r
Delivered-To: scheduler+t_delivered@agents.northwind.test\r
Subject: Forwarded answer\r
Date: Wed, 23 Sep 2026 12:11:00 -0700\r
Message-ID: <delivered-to@forwarder.test>\r
Content-Type: text/plain; charset=utf-8\r
\r
Forwarded confirmation.\r
"""
    write_pair(
        "09-delivered-to-reply",
        delivered,
        {
            "result": expected_result(
                intent="response",
                task="t_delivered",
                task_state=None,
                text="Forwarded confirmation.\n",
                sender="human@forwarder.test",
                lane="human",
                message_id="<delivered-to@forwarder.test>",
            )
        },
    )

    dsn = b"""From: mailer-daemon@contoso.test\r
To: scheduler+t_dsn@agents.northwind.test\r
Subject: Delivery failed\r
Date: Wed, 23 Sep 2026 12:12:00 -0700\r
Message-ID: <dsn@contoso.test>\r
MIME-Version: 1.0\r
Content-Type: multipart/report; report-type=delivery-status; boundary=dsn\r
\r
--dsn\r
Content-Type: text/plain; charset=utf-8\r
\r
Delivery failed.\r
--dsn\r
Content-Type: message/delivery-status\r
\r
Reporting-MTA: dns; mail.contoso.test\r
\r
Final-Recipient: rfc822; missing@agents.contoso.test\r
Action: failed\r
Status: 5.1.1\r
Diagnostic-Code: smtp; 550 5.1.1 unknown agent\r
\r
--dsn--\r
"""
    write_pair(
        "10-dsn-failed",
        dsn,
        {
            "result": expected_result(
                intent="error",
                task="t_dsn",
                task_state="failed",
                text="Delivery failed.",
                sender="mailer-daemon@contoso.test",
                lane="system",
                message_id="<dsn@contoso.test>",
                report={
                    "action": "failed",
                    "status": "5.1.1",
                    "recipient": "missing@agents.contoso.test",
                    "diagnostic": "smtp; 550 5.1.1 unknown agent",
                },
            )
        },
    )

    mdn = b"""From: pat@plainmail.test\r
To: scheduler+t_mdn@agents.northwind.test\r
Subject: Read receipt\r
Date: Wed, 23 Sep 2026 12:13:00 -0700\r
Message-ID: <mdn@plainmail.test>\r
MIME-Version: 1.0\r
Content-Type: multipart/report; report-type=disposition-notification; boundary=mdn\r
\r
--mdn\r
Content-Type: text/plain; charset=utf-8\r
\r
Displayed.\r
--mdn\r
Content-Type: message/disposition-notification\r
\r
Final-Recipient: rfc822; pat@plainmail.test\r
Original-Message-ID: <request@agents.northwind.test>\r
Disposition: manual-action/MDN-sent-manually; displayed\r
\r
--mdn--\r
"""
    write_pair(
        "11-mdn-displayed",
        mdn,
        {
            "result": expected_result(
                intent="ack",
                task="t_mdn",
                task_state=None,
                text="Displayed.",
                sender="pat@plainmail.test",
                lane="system",
                message_id="<mdn@plainmail.test>",
                report={
                    "recipient": "pat@plainmail.test",
                    "original_message_id": "<request@agents.northwind.test>",
                    "disposition": "manual-action/MDN-sent-manually; displayed",
                },
            )
        },
    )

    profile(
        "12-unicode-request",
        intent="request",
        state="submitted",
        text="Réservez une visite à Montréal.",
        schema=REQUEST,
        payload={"action": "réserver", "arguments": {"city": "Montréal"}},
    )
    profile(
        "13-threaded-response",
        intent="response",
        state="completed",
        text="Tuesday at nine is confirmed.",
        schema=RESPONSE,
        payload={"result": {"slot": "2026-10-06T09:00:00-07:00"}},
        task="t_thread",
        sender="intake@agents.contoso.test",
        recipient="scheduler+t_thread@agents.northwind.test",
        in_reply_to="<thread-request@agents.northwind.test>",
        references=[
            "<thread-root@agents.northwind.test>",
            "<thread-request@agents.northwind.test>",
        ],
    )

    malformed = profile(
        "temporary-malformed-source",
        intent="request",
        state="submitted",
        text="Malformed payload follows.",
        schema=REQUEST,
        payload={"action": "inspect"},
    )
    machine = next(
        part for part in malformed.walk() if part.get_content_type() == "application/ld+json"
    )
    del machine["Content-Transfer-Encoding"]
    machine.set_payload("{not json")
    error_pair("14-malformed-json", malformed, "MachinePartError", "valid JSON")

    invalid = profile(
        "temporary-invalid-source",
        intent="request",
        state="submitted",
        text="Invalid request payload follows.",
        schema=REQUEST,
        payload={"action": "inspect"},
    )
    machine = next(
        part for part in invalid.walk() if part.get_content_type() == "application/ld+json"
    )
    machine.set_content(
        b'{"@context":"https://schema.org","not-action":true}',
        maintype="application",
        subtype="ld+json",
        cte="8bit",
    )
    machine["Content-Purpose"] = "Machine-readable"
    error_pair("15-invalid-schema", invalid, "SchemaValidationError", "action")

    unknown = profile(
        "temporary-unknown-source",
        intent="request",
        state="submitted",
        text="Unknown schema.",
        schema=REQUEST,
        payload={"action": "inspect"},
    )
    unknown.replace_header("Agent-Schema", "https://schemas.invalid/not-local.json")
    error_pair("16-unknown-schema", unknown, "UnknownSchemaError", "local registry")

    missing_text = profile(
        "temporary-missing-text-source",
        intent="request",
        state="submitted",
        text="This text part will be removed.",
        schema=REQUEST,
        payload={"action": "inspect"},
    )
    missing_text_payload = missing_text.get_payload()
    assert isinstance(missing_text_payload, list)
    missing_text_payload.pop(0)
    error_pair("17-no-text-plain", missing_text, "ProfileError", "text/plain")

    timeout_dsn = b"""From: mailer-daemon@northwind.test\r
To: scheduler+t_timeout@agents.northwind.test\r
Subject: Delivery timed out\r
Date: Wed, 23 Sep 2026 12:14:00 -0700\r
Message-ID: <dsn-timeout@northwind.test>\r
MIME-Version: 1.0\r
Content-Type: multipart/report; report-type=delivery-status; boundary=timeout\r
\r
--timeout\r
Content-Type: text/plain; charset=utf-8\r
\r
Delivery timed out after repeated attempts.\r
--timeout\r
Content-Type: message/delivery-status\r
\r
Reporting-MTA: dns; mail.northwind.test\r
\r
Final-Recipient: rfc822; intake@unreachable.test\r
Action: failed\r
Status: 4.4.1\r
Diagnostic-Code: smtp; connection timed out\r
\r
--timeout--\r
"""
    write_pair(
        "18-dsn-timeout",
        timeout_dsn,
        {
            "result": expected_result(
                intent="error",
                task="t_timeout",
                task_state="failed",
                text="Delivery timed out after repeated attempts.",
                sender="mailer-daemon@northwind.test",
                lane="system",
                message_id="<dsn-timeout@northwind.test>",
                report={
                    "action": "failed",
                    "status": "4.4.1",
                    "recipient": "intake@unreachable.test",
                    "diagnostic": "smtp; connection timed out",
                },
            )
        },
    )

    deep_references = [f"<hop-{index:03d}@agents.northwind.test>" for index in range(101)]
    profile(
        "19-references-101-deep",
        intent="response",
        state="completed",
        text="This reply carries the loop-limit boundary corpus case.",
        schema=RESPONSE,
        payload={"result": {"accepted": True}},
        task="t_deep_thread",
        sender="intake@agents.contoso.test",
        recipient="scheduler+t_deep_thread@agents.northwind.test",
        in_reply_to=deep_references[-1],
        references=deep_references,
    )

    # PLAN §5.10: an agent's declaration to its own gateway's control address. It parses as an
    # ordinary profile event; the gateway's submission is what refuses to relay it.
    profile(
        "20-control-pause",
        intent="event",
        state="completed",
        text="A control declaration for this agent's gateway: pause.",
        schema=CONTROL,
        payload={"command": "pause", "until": "2026-09-23T19:30:00Z", "reason": "maintenance"},
        task="t_control_pause",
        sender="outpost@agents.contoso.test",
        recipient="control@agents.contoso.test",
    )

    for temporary in CORPUS.glob("temporary-*"):
        temporary.unlink()


if __name__ == "__main__":
    main()
