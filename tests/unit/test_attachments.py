from email import policy
from io import BytesIO
from zipfile import ZipFile

import pytest

from amx.attachments import EXECUTABLE_TYPES, Attachment, safe_filename, sniff_type
from amx.profile import SCHEMA_BASE, build, parse
from amx.sdk import Agent, PreparedSubmission

PDF = b"%PDF-1.4\nexample\n%%EOF"


def office(directory):
    output = BytesIO()
    with ZipFile(output, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        if directory:
            archive.writestr(directory + "/document.xml", "<document/>")
    return output.getvalue()


@pytest.mark.parametrize(
    "content,name,expected",
    [
        (PDF, "fake.exe", "application/pdf"),
        (b"\x89PNG\r\n\x1a\n", "a", "image/png"),
        (b"\xff\xd8\xff", "a", "image/jpeg"),
        (b"GIF87a", "a", "image/gif"),
        (b"GIF89a", "a", "image/gif"),
        (b"RIFF1234WEBP", "a", "image/webp"),
        (office(None), "a", "application/zip"),
        (
            office("word"),
            "a",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ),
        (office("xl"), "a", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        (
            office("ppt"),
            "a",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        ),
        (b"PK\x03\x04broken", "a", "application/zip"),
        (b"hello", "a", "text/plain"),
        (b"a,b\n1,2", "a.csv", "text/csv"),
        ("caf\u00e9".encode(), "a.md", "text/markdown"),
        (b"{}", "a.json", "application/json"),
        (b"MZ123", "fake.pdf", "application/vnd.microsoft.portable-executable"),
        (b"\x7fELF", "fake.pdf", "application/x-executable"),
        *[
            (magic, "fake.pdf", "application/x-mach-binary")
            for magic in (
                b"\xfe\xed\xfa\xce",
                b"\xce\xfa\xed\xfe",
                b"\xfe\xed\xfa\xcf",
                b"\xcf\xfa\xed\xfe",
            )
        ],
        (b"#!/bin/sh\ntrue", "fake.pdf", "text/x-script"),
        (b"\x00\xff", "a.pdf", "application/octet-stream"),
        (b"", "a.txt", "application/octet-stream"),
        (b"abc\x00", "a.txt", "application/octet-stream"),
    ],
)
def test_sniffer(content, name, expected):
    assert sniff_type(content, name) == expected


@pytest.mark.parametrize(
    "name,expected",
    [
        ("../../a.pdf", "a.pdf"),
        ("..\\..\\a.pdf", "a.pdf"),
        ("a\x00\n\x7fb.pdf", "ab.pdf"),
        ("..", "attachment"),
        ("r\u00e9sum\u00e9.pdf", "r\u00e9sum\u00e9.pdf"),
    ],
)
def test_safe_names(name, expected):
    assert safe_filename(name) == expected


def test_bounded_filename():
    assert len(safe_filename("\u00e9" * 300 + ".pdf").encode()) <= 180


def message(**kwargs):
    return build(
        sender="a@agents.example.test",
        to="b@agents.example.test",
        subject="file",
        intent="request",
        task="t_file",
        task_state="submitted",
        text="See file.",
        **kwargs,
    )


def test_mime_roundtrip_keeps_payload_separate_and_encodes_unicode():
    built = message(
        attachments=[Attachment("../r\u00e9sum\u00e9.pdf", PDF, "text/plain")],
        payload={"action": "read"},
        schema=SCHEMA_BASE + "request.json",
    )
    raw = built.as_bytes(policy=policy.SMTP)
    assert b"filename*=utf-8''" in raw
    incoming = parse(raw)
    assert incoming.payload["action"] == "read"
    assert len(incoming.attachments) == 1
    attached = incoming.attachments[0]
    assert attached.metadata() == {
        "index": 0,
        "filename": "r\u00e9sum\u00e9.pdf",
        "type": "application/pdf",
        "declared_type": "text/plain",
        "size": len(PDF),
    }
    assert attached.content == PDF
    part = list(built.iter_attachments())[-1]
    assert part["Content-Transfer-Encoding"] == "base64"
    assert part.get_content_disposition() == "attachment"


def test_sdk_send_reply_and_encoded_size_boundary(monkeypatch):
    captured = []
    agent = Agent("a@agents.example.test", "smtp://localhost", "unused", max_bytes=2000)
    monkeypatch.setattr(agent, "_transmit", lambda *args: captured.append(args[-1]) or "ok")
    agent.send(
        to="b@agents.example.test",
        subject="pdf",
        intent="request",
        text="read",
        attachments=[Attachment("a.pdf", PDF)],
    )
    incoming = agent.parse(captured[-1])
    incoming.reply(text="attached", attachments=[Attachment("b.pdf", PDF)])
    assert parse(captured[-1]).attachments[0].content == PDF
    raw = captured[-1]
    agent.max_bytes = len(raw)
    agent.submit_prepared(PreparedSubmission("a", ("b",), raw))
    agent.max_bytes -= 1
    with pytest.raises(ValueError, match=f"max_bytes={len(raw) - 1}"):
        agent.submit_prepared(PreparedSubmission("a", ("b",), raw))
    count = len(captured)
    with pytest.raises(ValueError, match="max_bytes"):
        agent.send(
            to="b@agents.example.test",
            subject="large",
            intent="request",
            text="read",
            attachments=[Attachment("large.pdf", PDF * 300)],
        )
    assert len(captured) == count


@pytest.mark.parametrize("content", [b"MZ", b"\x7fELF", b"\xfe\xed\xfa\xcf", b"#!/bin/sh"])
def test_sdk_refuses_disguised_executable_before_prepare_or_transmit(monkeypatch, content):
    agent = Agent("a@agents.example.test", "smtp://localhost", "unused")

    def unexpected(*args):
        pytest.fail("submission/preparation must not happen")

    monkeypatch.setattr(agent, "_transmit", unexpected)
    assert sniff_type(content) in EXECUTABLE_TYPES
    with pytest.raises(ValueError, match="executable"):
        agent.send(
            to="b@agents.example.test",
            subject="bad",
            intent="request",
            text="read",
            attachments=[Attachment("a.pdf", content, "application/pdf")],
            prepare=unexpected,
        )
