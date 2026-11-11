from __future__ import annotations

import base64
from datetime import UTC, datetime
from email.message import EmailMessage
from email.policy import SMTP

import pytest

from amx.profile import (
    DEFAULT_CONTEXT,
    DeliveryReport,
    DispositionReport,
    MachinePartError,
    ProfileError,
    SchemaValidationError,
    UnknownSchemaError,
    build,
    parse,
)

SCHEMA = "https://evtmail.ai/schema/0.1/request.json"
NOW = datetime(2026, 9, 23, 19, 0, tzinfo=UTC)


def _profile(**overrides: object) -> EmailMessage:
    values: dict[str, object] = {
        "sender": "Scheduler <scheduler+t_alpha@agents.northwind.test>",
        "to": ["intake@agents.contoso.test"],
        "subject": "Inspect the site",
        "intent": "request",
        "task": "t_alpha",
        "task_state": "submitted",
        "text": "Please inspect the site.\n",
        "payload": {"action": "inspect", "arguments": {"site": "Harbor Road"}},
        "schema": SCHEMA,
        "date": NOW,
        "message_id": "<t_alpha.1@agents.northwind.test>",
    }
    values.update(overrides)
    return build(**values)  # type: ignore[arg-type]


def test_build_and_parse_round_trip_defaults_json_ld_context() -> None:
    message = _profile()

    assert message["Agent-Protocol"] == "amx/0.1"
    assert message["Auto-Submitted"] == "auto-generated"
    assert message.get_content_type() == "multipart/mixed"
    machine = next(
        part for part in message.walk() if part.get_content_type() == "application/ld+json"
    )
    assert machine["Content-Purpose"] == "Machine-readable"
    assert machine.get_content_disposition() == "inline"
    assert machine.get_filename() == "payload.json"

    inbound = parse(message.as_bytes(policy=SMTP))

    assert inbound.intent == "request"
    assert inbound.task == "t_alpha"
    assert inbound.task_state == "submitted"
    assert inbound.schema == SCHEMA
    assert inbound.text == "Please inspect the site.\n"
    assert inbound.payload == {
        "@context": DEFAULT_CONTEXT,
        "action": "inspect",
        "arguments": {"site": "Harbor Road"},
    }
    assert inbound.sender is not None
    assert inbound.sender.address == "scheduler+t_alpha@agents.northwind.test"
    assert inbound.sender.display_name == "Scheduler"
    assert inbound.lane == "agent"
    assert inbound.thread.message_id == "<t_alpha.1@agents.northwind.test>"
    assert inbound.raw


def test_build_sets_threading_optional_headers_and_multiple_recipients() -> None:
    message = _profile(
        to=["intake@agents.contoso.test", "ops@contoso.test"],
        cc="victor@northwind.test",
        reply_to="scheduler+t_alpha@agents.northwind.test",
        card="https://northwind.test/.well-known/agents/scheduler.json",
        reply_by=NOW,
        idempotency_key="idem-1",
        in_reply_to="<previous@agents.contoso.test>",
        references=["<root@agents.contoso.test>", "<previous@agents.contoso.test>"],
    )

    assert message.get_all("To") == ["intake@agents.contoso.test, ops@contoso.test"]
    assert message["Cc"] == "victor@northwind.test"
    assert message["Reply-To"] == "scheduler+t_alpha@agents.northwind.test"
    assert message["Agent-Card"] == "https://northwind.test/.well-known/agents/scheduler.json"
    assert message["Agent-Idempotency-Key"] == "idem-1"
    assert message["In-Reply-To"] == "<previous@agents.contoso.test>"

    inbound = parse(message.as_bytes(policy=SMTP))
    assert inbound.protocol == "amx/0.1"
    assert inbound.card == "https://northwind.test/.well-known/agents/scheduler.json"
    assert inbound.reply_by == str(message["Agent-Reply-By"])
    assert inbound.idempotency_key == "idem-1"
    assert inbound.thread.in_reply_to == "<previous@agents.contoso.test>"
    assert inbound.thread.references == (
        "<root@agents.contoso.test>",
        "<previous@agents.contoso.test>",
    )


def test_optional_profile_headers_round_trip_without_value_normalization() -> None:
    card = "https://northwind.test/.well-known/agents/scheduler.json?version=1#profile"
    reply_by = "25 Sep 2026 17:30:00 -0700"

    message = _profile(card=card, reply_by=reply_by)
    inbound = parse(message.as_bytes(policy=SMTP))

    assert str(message["Agent-Card"]) == card
    assert str(message["Agent-Reply-By"]) == reply_by
    assert inbound.card == card
    assert inbound.reply_by == reply_by


@pytest.mark.parametrize("card", ["/agents/scheduler.json", "mailto:scheduler@example.test"])
def test_build_rejects_non_http_absolute_agent_card(card: str) -> None:
    with pytest.raises(ValueError, match=r"card must be an absolute HTTP\(S\) URI"):
        _profile(card=card)


@pytest.mark.parametrize("card", ["/agents/scheduler.json", "mailto:scheduler@example.test"])
def test_parse_rejects_non_http_absolute_agent_card(card: str) -> None:
    message = _profile(card="https://northwind.test/agents/scheduler.json")
    message.replace_header("Agent-Card", card)

    with pytest.raises(ProfileError, match=r"Agent-Card must be an absolute HTTP\(S\) URI"):
        parse(message.as_bytes(policy=SMTP))


@pytest.mark.parametrize("reply_by", ["not a date", "Fri, 99 Sep 2026 17:30:00 -0700"])
def test_build_rejects_malformed_agent_reply_by(reply_by: str) -> None:
    with pytest.raises(ValueError, match="reply_by must be an RFC 5322 date-time"):
        _profile(reply_by=reply_by)


@pytest.mark.parametrize("reply_by", ["not a date", "Fri, 99 Sep 2026 17:30:00 -0700"])
def test_parse_rejects_malformed_agent_reply_by(reply_by: str) -> None:
    message = _profile(reply_by=NOW)
    message.replace_header("Agent-Reply-By", reply_by)

    with pytest.raises(ProfileError, match="Agent-Reply-By must be an RFC 5322 date-time"):
        parse(message.as_bytes(policy=SMTP))


def test_build_plain_profile_without_payload_is_not_multipart() -> None:
    message = _profile(payload=None, schema=None, intent="ack", task_state="working")

    assert message.get_content_type() == "text/plain"
    assert message["Agent-Schema"] is None
    inbound = parse(message.as_bytes(policy=SMTP))
    assert inbound.payload is None


@pytest.mark.parametrize("text", ["", " \t\r\n"])
def test_build_rejects_empty_text(text: str) -> None:
    with pytest.raises(ValueError, match="text must not be empty"):
        _profile(text=text)


def test_human_reply_correlates_from_to_subaddress() -> None:
    raw = b"""From: Pat <pat@plainmail.test>\r
To: Scheduler <scheduler+t_quote_7@agents.northwind.test>\r
Subject: Re: quote\r
Date: Wed, 23 Sep 2026 12:00:00 -0700\r
Message-ID: <human-reply@plainmail.test>\r
In-Reply-To: <ask@agents.northwind.test>\r
References: <root@agents.northwind.test> <ask@agents.northwind.test>\r
Content-Type: text/plain; charset=utf-8\r
\r
Tuesday works.\r
"""

    inbound = parse(raw)

    assert inbound.intent == "response"
    assert inbound.task == "t_quote_7"
    assert inbound.task_state is None
    assert inbound.payload is None
    assert inbound.schema is None
    assert inbound.text == "Tuesday works.\n"
    assert inbound.lane == "human"
    assert inbound.thread.references == (
        "<root@agents.northwind.test>",
        "<ask@agents.northwind.test>",
    )


def test_parse_rejects_unknown_text_charset_as_profile_error() -> None:
    raw = b"""From: Pat <pat@plainmail.test>\r
To: Scheduler <scheduler+t_quote_7@agents.northwind.test>\r
Subject: Re: quote\r
Content-Type: text/plain; charset=not-a-real-charset\r
\r
Tuesday works.\r
"""

    with pytest.raises(ProfileError, match="invalid charset or encoding"):
        parse(raw)


def test_human_reply_uses_delivered_to_when_to_has_no_token() -> None:
    raw = b"""From: Pat <pat@plainmail.test>\r
To: scheduler@agents.northwind.test\r
Delivered-To: scheduler+t_forwarded@agents.northwind.test\r
Subject: Fwd reply\r
Date: Wed, 23 Sep 2026 12:00:00 -0700\r
Message-ID: <forwarded@plainmail.test>\r
\r
Forwarded answer.\r
"""

    assert parse(raw).task == "t_forwarded"


def test_profile_task_header_wins_over_recipient_token() -> None:
    message = _profile(task="canonical", to="intake+different@agents.contoso.test")

    assert parse(message.as_bytes(policy=SMTP)).task == "canonical"


def test_parse_delivery_status_notification() -> None:
    raw = b"""From: Mail Delivery System <mailer-daemon@contoso.test>\r
To: scheduler+t_dsn@agents.northwind.test\r
Subject: Undelivered Mail Returned to Sender\r
Date: Wed, 23 Sep 2026 12:02:00 -0700\r
Message-ID: <dsn-1@contoso.test>\r
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
Original-Envelope-Id: t_dsn\r
\r
Final-Recipient: rfc822; missing@agents.contoso.test\r
Action: failed\r
Status: 5.1.1\r
Diagnostic-Code: smtp; 550 5.1.1 unknown agent\r
\r
--dsn--\r
"""

    inbound = parse(raw)

    assert inbound.intent == "error"
    assert inbound.task == "t_dsn"
    assert inbound.task_state == "failed"
    assert inbound.lane == "system"
    assert inbound.text == "Delivery failed."
    assert inbound.report == DeliveryReport(
        action="failed",
        status="5.1.1",
        recipient="missing@agents.contoso.test",
        diagnostic="smtp; 550 5.1.1 unknown agent",
    )


def test_parse_message_disposition_notification() -> None:
    raw = b"""From: Pat <pat@plainmail.test>\r
To: scheduler+t_mdn@agents.northwind.test\r
Subject: Read: inspection\r
Date: Wed, 23 Sep 2026 12:05:00 -0700\r
Message-ID: <mdn-1@plainmail.test>\r
MIME-Version: 1.0\r
Content-Type: multipart/report; report-type=disposition-notification; boundary=mdn\r
\r
--mdn\r
Content-Type: text/plain; charset=utf-8\r
\r
Your message was displayed.\r
--mdn\r
Content-Type: message/disposition-notification\r
\r
Final-Recipient: rfc822; pat@plainmail.test\r
Original-Message-ID: <ask@agents.northwind.test>\r
Disposition: manual-action/MDN-sent-manually; displayed\r
\r
--mdn--\r
"""

    inbound = parse(raw)

    assert inbound.intent == "ack"
    assert inbound.task == "t_mdn"
    assert inbound.task_state is None
    assert inbound.lane == "system"
    assert inbound.report == DispositionReport(
        recipient="pat@plainmail.test",
        original_message_id="<ask@agents.northwind.test>",
        disposition="manual-action/MDN-sent-manually; displayed",
    )


def test_parse_rejects_malformed_machine_json() -> None:
    message = _profile()
    machine = next(
        part for part in message.walk() if part.get_content_type() == "application/ld+json"
    )
    del machine["Content-Transfer-Encoding"]
    machine.set_payload("{not json")

    with pytest.raises(MachinePartError, match="valid JSON"):
        parse(message.as_bytes(policy=SMTP))


def test_parse_rejects_non_object_machine_json() -> None:
    message = _profile()
    machine = next(
        part for part in message.walk() if part.get_content_type() == "application/ld+json"
    )
    machine.set_content(b"[]", maintype="application", subtype="ld+json", cte="8bit")
    machine["Content-Purpose"] = "Machine-readable"

    with pytest.raises(MachinePartError, match="JSON object"):
        parse(message.as_bytes(policy=SMTP))


def test_parse_rejects_unknown_schema_without_network_resolution() -> None:
    message = _profile()
    message.replace_header("Agent-Schema", "https://invalid.test/never-fetch.json")

    with pytest.raises(UnknownSchemaError, match="not in the local registry"):
        parse(message.as_bytes(policy=SMTP))


def test_build_and_parse_validate_schema() -> None:
    with pytest.raises(SchemaValidationError, match="action"):
        _profile(payload={"not-action": True})

    message = _profile()
    machine = next(
        part for part in message.walk() if part.get_content_type() == "application/ld+json"
    )
    machine.set_content(
        b'{"not-action": true}', maintype="application", subtype="ld+json", cte="8bit"
    )
    machine["Content-Purpose"] = "Machine-readable"

    with pytest.raises(SchemaValidationError, match="action"):
        parse(message.as_bytes(policy=SMTP))


def test_parse_rejects_duplicate_machine_parts() -> None:
    message = _profile()
    message.add_attachment(
        b'{"@context":"https://schema.org","action":"again"}',
        maintype="application",
        subtype="ld+json",
        disposition="inline",
        filename="second.json",
    )
    message.get_payload()[-1]["Content-Purpose"] = "Machine-readable"  # type: ignore[index]

    with pytest.raises(MachinePartError, match="at most one"):
        parse(message.as_bytes(policy=SMTP))


@pytest.mark.parametrize(
    ("header", "value", "match"),
    [
        ("Agent-Protocol", "amx/9.9", "unsupported"),
        ("Agent-Intent", "invented", "Agent-Intent"),
        ("Agent-Task-State", "mystery", "Agent-Task-State"),
    ],
)
def test_parse_rejects_invalid_profile_header_values(header: str, value: str, match: str) -> None:
    message = _profile()
    message.replace_header(header, value)

    with pytest.raises(ProfileError, match=match):
        parse(message.as_bytes(policy=SMTP))


def test_build_rejects_header_injection() -> None:
    with pytest.raises(ValueError, match="newline"):
        _profile(subject="safe\nBcc: attacker@example.test")


def test_parse_requires_task_for_profile_mail() -> None:
    message = _profile()
    del message["Agent-Task"]

    with pytest.raises(ProfileError, match="Agent-Task"):
        parse(message.as_bytes(policy=SMTP))


def test_profile_headers_prevent_report_type_from_becoming_system_lane() -> None:
    message = _profile()
    message.set_boundary("profile-report-boundary")
    message.replace_header(
        "Content-Type",
        'multipart/report; report-type="delivery-status"; boundary="profile-report-boundary"',
    )

    inbound = parse(message.as_bytes(policy=SMTP))

    assert inbound.lane == "agent"
    assert inbound.protocol == "amx/0.1"
    assert inbound.intent == "request"


def test_attached_message_cannot_supply_outer_machine_part() -> None:
    outer = _profile(payload=None, schema=None)
    outer["Agent-Schema"] = SCHEMA
    outer.add_attachment(_profile())

    with pytest.raises(MachinePartError, match="requires a machine-readable part"):
        parse(outer.as_bytes(policy=SMTP))


def test_attached_message_cannot_supply_outer_text_part() -> None:
    outer = _profile(payload=None, schema=None)
    outer.add_attachment(_profile())
    payload = outer.get_payload()
    assert isinstance(payload, list)
    payload.pop(0)

    with pytest.raises(ProfileError, match="text/plain"):
        parse(outer.as_bytes(policy=SMTP))


def test_response_requires_standard_thread_correlation() -> None:
    with pytest.raises(ValueError, match="in_reply_to"):
        _profile(intent="response", task_state="completed")

    message = _profile(
        intent="response",
        task_state="completed",
        in_reply_to="<request@agents.contoso.test>",
    )
    del message["In-Reply-To"]

    with pytest.raises(ProfileError, match="In-Reply-To"):
        parse(message.as_bytes(policy=SMTP))


def test_machine_part_must_declare_utf8() -> None:
    message = _profile()
    machine = next(
        part for part in message.walk() if part.get_content_type() == "application/ld+json"
    )
    encoded = '{"action":"r\u00e9server"}'.encode("iso-8859-1")
    machine.set_payload(base64.b64encode(encoded).decode("ascii"))
    machine.replace_header("Content-Transfer-Encoding", "base64")
    machine.replace_header("Content-Type", "application/ld+json; charset=iso-8859-1")

    with pytest.raises(MachinePartError, match="UTF-8"):
        parse(message.as_bytes(policy=SMTP))
