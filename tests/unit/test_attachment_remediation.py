"""Regressions for the single SH-42 cold review; all boundaries are fixture-local."""

from __future__ import annotations

import asyncio
import os
import struct
from dataclasses import replace
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_attachment_surfaces import tools_at
from test_attachments import PDF, message
from test_ax_delivery import offer, setup
from test_milter import _agent_request as gateway_request
from test_milter import _feed, _milter, _verified
from test_remote_agent import _agent_request
from test_submission import _config

from amx.adapters.ax import AxError
from amx.adapters.submission import SubmissionHandler, SubmissionService
from amx.attachment_files import load_files, save_file
from amx.attachments import Attachment, ReceivedAttachment, security_parts, sniff_type
from amx.config import load_config
from amx.journal import Journal
from amx.mcp_server import Fetched
from amx.profile import parse
from amx.runner import delivery_key
from amx.sdk import Agent, PreparedSubmission
from amx.store import Store


def fat_macho(endian, wide):
    """One x86_64 MH_EXECUTE slice, in each of the four exact fat-header formats."""
    magic = 0xCAFEBABF if wide else 0xCAFEBABE
    header = struct.pack(endian + "II", magic, 1)
    arch = struct.pack(
        endian + ("IIQQII" if wide else "IIIII"),
        *((0x01000007, 3, 4096, 32, 12, 0) if wide else (0x01000007, 3, 4096, 32, 12)),
    )
    thin = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x01000007, 3, 2, 0, 0, 0, 0)
    return (header + arch).ljust(4096, b"\0") + thin


FAT_FILES = [fat_macho(endian, wide) for wide in (False, True) for endian in (">", "<")]


def bypass(kind):
    # Human mail matters: profile parsing must not be needed for security refusal.
    mail = EmailMessage(policy=policy.SMTP)
    mail["From"] = "owner@people.test"
    mail["To"] = "intake+t_1@agents.example.test"
    mail["Subject"] = "A file"
    mail["Message-ID"] = "<bypass@people.test>"
    mail["Agent-Task"] = "t_file"  # submission's required task, not an AMX declaration
    mail["Agent-Intent"] = "request"
    mail.set_content("Please read the file.")
    if kind == "container":
        container = EmailMessage()
        container.make_mixed()
        container.add_header("Content-Disposition", "attachment", filename="bundle.mime")
        container.add_attachment(
            b"\x7fELFfixture", maintype="application", subtype="pdf", filename="safe.pdf"
        )
        mail.make_mixed()
        mail.attach(container)
    elif kind == "machine-headers":
        mail.add_attachment(
            b"\x7fELFfixture",
            maintype="application",
            subtype="ld+json",
            disposition="inline",
            filename="payload.json",
        )
        mail.get_payload()[-1]["Content-Purpose"] = "Machine-readable"
    elif kind == "forwarded":
        inner = EmailMessage()
        inner.set_content("Forwarded executable")
        inner.add_attachment(
            b"\x7fELFfixture", maintype="application", subtype="pdf", filename="safe.pdf"
        )
        mail.add_attachment(inner, filename="forward.eml")
    return mail.as_bytes(policy=policy.SMTP)


def submission_refused(tmp_path, raw, limits=None):
    config = _config(tmp_path)
    if limits is not None:
        config = replace(config, limits=limits)
    store = Store(tmp_path / "journal.sqlite")
    service = SubmissionService(
        config,
        Journal(tmp_path, store),
        reinject=lambda *args: pytest.fail("blocked mail reinjected"),
    )
    result = asyncio.run(
        SubmissionHandler(service).handle_DATA(
            None,
            SimpleNamespace(auth_data=("scheduler", "secret-scheduler-token")),
            SimpleNamespace(original_content=raw),
        )
    )
    assert result.startswith("552 5.3.4 size-or-attachment")
    for table in ("journal", "holds", "tasks"):
        assert store.rows(f"SELECT * FROM {table}") == []
    assert not list(tmp_path.rglob("*.eml"))


@pytest.mark.parametrize("kind", ["container", "machine-headers", "forwarded"])
def test_review_mime_bypasses_refused_at_submission(tmp_path, kind):
    submission_refused(tmp_path, bypass(kind))


@pytest.mark.parametrize("kind", ["container", "machine-headers", "forwarded"])
def test_review_mime_bypasses_refused_at_eod(tmp_path, monkeypatch, kind):
    import Milter

    _verified(monkeypatch)
    make, registry, replies = _milter(tmp_path)
    milter = make("<owner@people.test>")
    assert milter.envrcpt("<intake+t_1@agents.example.test>") == Milter.CONTINUE
    _feed(milter, bypass(kind))
    assert milter.eom() == Milter.REJECT
    assert replies[-1][:2] == ("552", "5.3.4")
    assert not milter.quarantined
    assert registry.depth("intake") == 0
    store = Store(tmp_path / "journal.sqlite")
    assert store.rows("SELECT * FROM holds") == []
    assert store.rows("SELECT * FROM tasks") == []
    assert not list(tmp_path.rglob("*.eml"))


def test_security_scan_does_not_treat_plain_shebang_body_as_attachment(monkeypatch):
    mail = EmailMessage(policy=policy.SMTP)
    mail.set_content("#!/bin/sh\nThis is ordinary message text, not an attached script.\n")
    assert security_parts(mail) == ()

    agent = Agent("a@agents.example.test", "smtp://localhost", "fixture")
    transmitted = []
    monkeypatch.setattr(
        agent,
        "_transmit",
        lambda sender, recipients, raw: transmitted.append(raw) or "2.0.0 accepted",
    )
    agent.send(
        to="b@agents.example.test",
        subject="plain shebang prose",
        intent="request",
        text="#!/bin/sh\nThis is ordinary message text, not an attached script.",
    )
    assert len(transmitted) == 1


@pytest.mark.parametrize("content", FAT_FILES, ids=["fat-be", "fat-le", "fat64-be", "fat64-le"])
def test_review_fat_macho_sdk_and_gateway(tmp_path, monkeypatch, content):
    assert sniff_type(content, "safe.pdf") == "application/x-mach-binary"
    agent = Agent("a@agents.example.test", "smtp://localhost", "fixture")

    def unexpected(*args):
        pytest.fail("executable prepared or transmitted")

    monkeypatch.setattr(agent, "_transmit", unexpected)
    with pytest.raises(ValueError, match="executable"):
        agent.send(
            to="b@agents.example.test",
            subject="file",
            intent="request",
            text="file",
            attachments=[Attachment("safe.pdf", content, "application/pdf")],
            prepare=unexpected,
        )
    raw = message(attachments=[Attachment("safe.pdf", content, "application/pdf")]).as_bytes()
    with pytest.raises(ValueError, match="executable"):
        agent.submit_prepared(PreparedSubmission("a", ("b",), raw))
    submission_refused(tmp_path, raw)


@pytest.mark.parametrize("declared", ["application/x-msdownload", "application/pdf"])
def test_review_old_yaml_still_blocks_pe_true_bytes(tmp_path, declared):
    old = tmp_path / "gateway.yaml"
    old.write_text(
        "domain: example.test\nagent_domain: agents.example.test\nagents: {}\n"
        "limits:\n  blocked_attachment_types: [application/x-msdownload]\n"
    )
    limits = load_config(old).limits
    raw = message(attachments=[Attachment("safe.pdf", b"MZfixture", declared)]).as_bytes()
    submission_refused(tmp_path, raw, limits)


def test_review_old_yaml_alias_does_not_block_benign_declared_pe(tmp_path):
    old = tmp_path / "gateway.yaml"
    old.write_text(
        "domain: example.test\nagent_domain: agents.example.test\nagents: {}\n"
        "limits:\n  blocked_attachment_types: [application/x-msdownload]\n"
    )
    limits = load_config(old).limits
    assert "application/vnd.microsoft.portable-executable" in limits.blocked_attachment_types
    assert sniff_type(PDF, "a.exe") not in limits.blocked_attachment_types


@pytest.mark.parametrize("operation", ["load", "save"])
@pytest.mark.parametrize("swap_at", ["parent", "leaf", "file"])
def test_review_descriptor_traversal_rejects_parent_swap(tmp_path, monkeypatch, operation, swap_at):
    working, private = tmp_path / "working", tmp_path / "private"
    working.mkdir()
    private.mkdir()
    (working / "downloads").mkdir()
    (private / "downloads").mkdir()
    (working / "file.pdf").write_bytes(PDF)
    (private / "file.pdf").write_bytes(b"SYNTHETIC PRIVATE CONTENT")
    real_open = os.open
    swapped = False

    def raced_open(path, flags, *args, **kwargs):
        nonlocal swapped
        path = Path(path)
        target = (
            "working"
            if swap_at == "parent"
            else (
                "file.pdf"
                if operation == "load"
                else ("saved.pdf" if swap_at == "file" else "downloads")
            )
        )
        if not swapped and path.name == target:
            swapped = True
            working.rename(tmp_path / "original-working")
            working.symlink_to(private, target_is_directory=True)
        return real_open(path, flags, *args, **kwargs)

    # The new implementation must not need /proc, including on macOS.
    real_exists = Path.exists
    monkeypatch.setattr(
        Path, "exists", lambda path: False if str(path).startswith("/proc/") else real_exists(path)
    )
    monkeypatch.setattr(os, "open", raced_open)
    real_link = os.link

    def raced_link(source, destination, **kwargs):
        nonlocal swapped
        if operation == "save" and swap_at == "file":
            # Publication, not opening the staging file, is now the final-name seam.
            swapped = True
            working.rename(tmp_path / "original-working")
            working.symlink_to(private, target_is_directory=True)
        return real_link(source, destination, **kwargs)

    monkeypatch.setattr(os, "link", raced_link)
    with pytest.raises((ValueError, OSError)):
        if operation == "load":
            load_files([str(working / "file.pdf")], max_bytes=100, forbidden=(private,))
        else:
            raw = message(attachments=[Attachment("saved.pdf", PDF)]).as_bytes()
            part = parse(raw).attachments[0]
            save_file(part, working / "downloads")
    assert swapped
    assert list((private / "downloads").iterdir()) == []
    assert (private / "file.pdf").read_bytes() == b"SYNTHETIC PRIVATE CONTENT"


def test_review_safe_absolute_relative_and_created_paths_without_proc(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    real_exists = Path.exists
    monkeypatch.setattr(
        Path, "exists", lambda path: False if str(path).startswith("/proc/") else real_exists(path)
    )
    (tmp_path / "file.pdf").write_bytes(PDF)
    for path in ("file.pdf", str(tmp_path / "file.pdf")):
        assert load_files([path], max_bytes=100)[0].content == PDF
    part = parse(message(attachments=[Attachment("saved.pdf", PDF)]).as_bytes()).attachments[0]
    for path in (Path("relative/a/b"), tmp_path / "absolute/a/b"):
        saved = save_file(part, path)
        assert saved.read_bytes() == PDF
        assert saved.stat().st_mode & 0o777 == 0o600


def forwarded():
    inner = EmailMessage(policy=policy.SMTP)
    inner["From"] = "sender@example.test"
    inner["To"] = "recipient@example.test"
    inner["Subject"] = "Forwarded fixture"
    inner.set_content("Preserve this forwarded body.\n")
    outer = BytesParser(policy=policy.SMTP).parsebytes(_agent_request())
    outer.add_attachment(inner, filename="forward.eml")
    return inner.as_bytes(policy=policy.SMTP), outer.as_bytes(policy=policy.SMTP)


def test_review_structured_forward_parse_and_mcp_save(tmp_path):
    expected, raw = forwarded()
    part = parse(raw).attachments[0]
    assert part.content == expected
    assert part.size == len(expected)
    tools, mailbox = tools_at(tmp_path)
    mailbox.folders["INBOX"] = [Fetched("INBOX", 1, raw, False)]
    result = tools.save_attachment(parse(raw).thread.message_id, 0)
    assert Path(result["path"]).read_bytes() == expected


def test_review_structured_forward_ax_save(tmp_path):
    expected, raw = forwarded()
    runner, _, mailbox, _, _ = setup(tmp_path / "runner")
    _, record = offer(runner, mailbox, raw)
    part = record["data"]["attachments"][0]
    assert part["size"] == len(expected)
    assert Path(part["path"]).read_bytes() == expected


def test_review_builder_explicit_rfc822_declaration():
    expected, _ = forwarded()
    built = message(attachments=[Attachment("forward.eml", expected, "message/rfc822")])
    part = parse(built.as_bytes(policy=policy.SMTP)).attachments[0]
    assert part.declared_type == "message/rfc822"
    assert part.content == expected


def test_review_unsupported_structured_payload_is_not_silently_empty():
    part = EmailMessage()
    part.set_type("message/unsupported")
    child = EmailMessage()
    child.set_content("meaningful structured content")
    part.set_payload([child])
    assert (
        b"meaningful structured content"
        in ReceivedAttachment(0, "unknown.mime", "message/unsupported", part).content
    )


def test_review_ax_parent_failure_does_not_materialize_duplicate_files(tmp_path, monkeypatch):
    runner, delivery, mailbox, endpoint, _ = setup(tmp_path / "runner")
    offer(runner, mailbox)
    incoming = BytesParser(policy=policy.SMTP).parsebytes(_agent_request())
    incoming.replace_header("Message-ID", "<followup@agents.sender.test>")
    incoming.add_attachment(PDF, maintype="application", subtype="pdf", filename="in.pdf")
    raw = incoming.as_bytes(policy=policy.SMTP)
    uid = str(mailbox.add(raw))
    real_status = endpoint.delivery_status

    def unavailable(*args):
        raise AxError("temporary broker outage")

    monkeypatch.setattr(endpoint, "delivery_status", unavailable)
    for _ in range(3):
        assert delivery.offer(mailbox, uid, raw) is False
        assert list(runner.handled.path.parent.rglob("*.pdf")) == []
        assert runner.handled.ax_record(delivery_key(raw)) is None
    monkeypatch.setattr(endpoint, "delivery_status", real_status)
    assert delivery.offer(mailbox, uid, raw) is True
    assert delivery.offer(mailbox, uid, raw) is True
    assert len(list(runner.handled.path.parent.rglob("*.pdf"))) == 1


@pytest.mark.parametrize("content", FAT_FILES, ids=["fat-be", "fat-le", "fat64-be", "fat64-le"])
def test_review_fat_macho_eod(tmp_path, monkeypatch, content):
    import Milter

    _verified(monkeypatch)
    make, _, replies = _milter(tmp_path)
    milter = make()
    assert milter.envrcpt("<intake+t_1@agents.example.test>") == Milter.CONTINUE
    incoming = BytesParser(policy=policy.SMTP).parsebytes(
        gateway_request(["intake+t_1@agents.example.test"])
    )
    incoming.add_attachment(content, maintype="application", subtype="pdf", filename="safe.pdf")
    _feed(milter, incoming.as_bytes(policy=policy.SMTP))
    assert milter.eom() == Milter.REJECT
    assert replies[-1][:2] == ("552", "5.3.4")


@pytest.mark.parametrize("content,expected", [(b"MZfixture", "reject"), (PDF, "accept")])
def test_review_old_yaml_eod_true_type_wins(tmp_path, monkeypatch, content, expected):
    import Milter

    old = tmp_path / "gateway.yaml"
    old.write_text(
        "domain: example.test\nagent_domain: agents.example.test\nagents: {}\n"
        "limits:\n  blocked_attachment_types: [application/x-msdownload]\n"
    )
    _verified(monkeypatch)
    make, _, replies = _milter(tmp_path, limits=load_config(old).limits)
    milter = make()
    assert milter.envrcpt("<intake+t_1@agents.example.test>") == Milter.CONTINUE
    incoming = BytesParser(policy=policy.SMTP).parsebytes(
        gateway_request(["intake+t_1@agents.example.test"])
    )
    incoming.add_attachment(
        content, maintype="application", subtype="x-msdownload", filename="file.exe"
    )
    _feed(milter, incoming.as_bytes(policy=policy.SMTP))
    assert milter.eom() == (Milter.REJECT if expected == "reject" else Milter.ACCEPT)
    if expected == "reject":
        assert replies[-1][:2] == ("552", "5.3.4")


@pytest.mark.parametrize("operation", ["load", "save"])
def test_review_descriptor_io_unavailable_fails_closed(tmp_path, monkeypatch, operation):
    import amx.attachment_files as files

    source = tmp_path / "file.pdf"
    source.write_bytes(PDF)
    part = parse(message(attachments=[Attachment("saved.pdf", PDF)]).as_bytes()).attachments[0]
    monkeypatch.setattr(files, "_SAFE_DIR_FD", False)
    with pytest.raises(ValueError, match=r"descriptor-relative.*unavailable"):
        if operation == "load":
            load_files([str(source)], max_bytes=100)
        else:
            save_file(part, tmp_path / "new-directory")
    assert not (tmp_path / "new-directory").exists()


@pytest.mark.parametrize("kind", ["container", "machine-headers", "forwarded"])
def test_review_sdk_prepared_scans_nested_and_machine_parts(monkeypatch, kind):
    agent = Agent("a@agents.example.test", "smtp://localhost", "fixture")
    monkeypatch.setattr(agent, "_transmit", lambda *args: pytest.fail("executable transmitted"))
    with pytest.raises(ValueError, match="executable"):
        agent.submit_prepared(PreparedSubmission("a", ("b",), bypass(kind)))


def test_review_sdk_structured_file_scanned_before_prepare(monkeypatch):
    inner = EmailMessage(policy=policy.SMTP)
    inner.set_content("File")
    inner.add_attachment(b"MZfixture", maintype="application", subtype="pdf", filename="safe.pdf")
    agent = Agent("a@agents.example.test", "smtp://localhost", "fixture")

    def unexpected(*args):
        pytest.fail("executable prepared or transmitted")

    monkeypatch.setattr(agent, "_transmit", unexpected)
    with pytest.raises(ValueError, match="executable"):
        agent.send(
            to="b@agents.example.test",
            subject="file",
            intent="request",
            text="file",
            attachments=[Attachment("forward.eml", inner.as_bytes(), "message/rfc822")],
            prepare=unexpected,
        )


@pytest.mark.parametrize("declared", ["message/unsupported", "multipart/mixed"])
def test_review_builder_refuses_unsupported_structured_declarations(declared):
    with pytest.raises(ValueError, match="unsupported structured"):
        message(attachments=[Attachment("unknown.mime", b"payload", declared)])
