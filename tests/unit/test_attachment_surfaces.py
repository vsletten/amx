"""SH-42 host-local surfaces, transport refusal, and durable attachment custody."""

from __future__ import annotations

import asyncio
import smtplib
from dataclasses import replace
from email import policy
from email.parser import BytesParser
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_attachments import PDF, message
from test_ax_delivery import offer, restart, setup
from test_mcp_server import ADDRESS, FakeMailbox
from test_submission import _config, _held_id, _hold_service

from amx.adapters.submission import SubmissionHandler, SubmissionService
from amx.attachment_files import load_files
from amx.attachments import DEFAULT_BLOCKED_TYPES, Attachment
from amx.config import LimitsConfig
from amx.custody import Custody
from amx.journal import Journal
from amx.mcp_server import AgentTools, Fetched, build_server
from amx.profile import parse
from amx.sdk import Agent
from amx.store import Store


def tools_at(tmp_path):
    mailbox = FakeMailbox({"INBOX": []})
    tools = AgentTools(
        Agent(ADDRESS, "smtp://localhost", "unused"),
        mailbox,
        custody=Custody(ADDRESS, directory=tmp_path / "custody"),
        state_directory=tmp_path / "state",
    )
    return tools, mailbox


def test_mcp_send_reply_list_read_save_roundtrip(tmp_path, monkeypatch):
    tools, mailbox = tools_at(tmp_path)
    pdf = tmp_path / "report.pdf"
    pdf.write_bytes(PDF)
    submitted = []
    monkeypatch.setattr(tools.agent, "_transmit", lambda *args: submitted.append(args[-1]) or "ok")
    result = tools.send(["b@agents.example.test"], "file", "read", attachments=[str(pdf)])
    assert result["attachments"] == [
        {"filename": "report.pdf", "type": "application/pdf", "size": len(PDF)}
    ]
    incoming = parse(submitted[-1])
    mailbox.folders["INBOX"] = [Fetched("INBOX", 1, submitted[-1], False)]
    summary = tools.list_inbox()[0]
    assert summary["attachments"][0]["type"] == "application/pdf"
    assert tools.read_thread(incoming.task)[0]["attachments"] == summary["attachments"]
    tools.reply(incoming.thread.message_id, "attached", attachments=[str(pdf)])
    assert parse(submitted[-1]).attachments[0].content == PDF
    assert parse(submitted[-1]).thread.in_reply_to == incoming.thread.message_id
    before = mailbox.flagged.copy()
    saved = tools.save_attachment(incoming.thread.message_id, 0)
    assert Path(saved["path"]).read_bytes() == PDF
    assert Path(saved["path"]).parent == tmp_path / "state" / "attachments" / incoming.task
    assert mailbox.flagged == before


@pytest.mark.parametrize(
    "kind", ["missing", "directory", "state", "symlink", "credentials", "too-big", "executable"]
)
def test_host_path_refusals(tmp_path, kind, monkeypatch):
    tools, _ = tools_at(tmp_path)
    private = tools.state_directory
    private.mkdir()
    secret = private / "token"
    secret.write_bytes(b"private fixture")
    candidate = tmp_path / "file.pdf"
    if kind == "directory":
        candidate.mkdir()
    elif kind == "state":
        candidate = secret
    elif kind == "symlink":
        candidate.symlink_to(secret)
    elif kind == "credentials":
        credential_dir = tmp_path / "credentials"
        credential_dir.mkdir()
        tools.credential_directories = (credential_dir,)
        candidate = credential_dir / "bundle.json"
        candidate.write_bytes(b"fixture")
    elif kind == "too-big":
        tools.agent.max_bytes = 5
        candidate.write_bytes(PDF)
    elif kind == "executable":
        candidate.write_bytes(b"\x7fELFfake")
    monkeypatch.setattr(
        tools.agent, "send", lambda **kwargs: pytest.fail("must refuse before send")
    )
    with pytest.raises(ValueError):
        tools.send(["b@agents.example.test"], "bad", "read", attachments=[str(candidate)])


def test_default_private_directories_and_symlink_are_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    secret = tmp_path / "amx" / "host" / "credentials.json"
    secret.parent.mkdir(parents=True)
    secret.write_bytes(b"fixture")
    with pytest.raises(ValueError, match="state or credential"):
        load_files([str(secret)], max_bytes=100)
    alias = tmp_path / "alias"
    alias.symlink_to(secret)
    with pytest.raises(ValueError, match="state or credential"):
        load_files([str(alias)], max_bytes=100)


def test_save_is_observational_confined_exclusive_even_for_symlinks(tmp_path):
    tools, mailbox = tools_at(tmp_path)
    raw = message(attachments=[Attachment("../../outside.pdf", PDF)]).as_bytes(policy=policy.SMTP)
    # Use a hostile inbound name too: do not rely on the builder's sanitizer.
    raw = raw.replace(b'filename="outside.pdf"', b'filename="../../outside.pdf"')
    mid = parse(raw).thread.message_id
    mailbox.folders["INBOX"] = [Fetched("INBOX", 1, raw, True)]  # runner owns Seen-only mail
    directory = tmp_path / "saved"
    directory.mkdir()
    untouched = tmp_path / "outside.pdf"
    untouched.write_bytes(b"original")
    (directory / "outside.pdf").symlink_to(untouched)
    first = tools.save_attachment(mid, 0, str(directory))
    second = tools.save_attachment(mid, 0, str(directory))
    assert first["path"] != second["path"]
    for saved in (first, second):
        assert Path(saved["path"]).parent == directory
        assert Path(saved["path"]).read_bytes() == PDF
        assert Path(saved["path"]).stat().st_mode & 0o777 == 0o600
    assert untouched.read_bytes() == b"original"
    assert mailbox.flagged == []
    with tools.custody.locked() as state:
        assert state["claims"] == {}
    with pytest.raises(ValueError, match="index"):
        tools.save_attachment(mid, -1)


def test_save_registered_in_mcp_schema(tmp_path):
    tools, _ = tools_at(tmp_path)
    discovered = asyncio.run(build_server(tools).list_tools())
    schema = {tool.name: tool.inputSchema for tool in discovered}
    assert "save_attachment" in schema
    assert "attachments" in schema["send"]["properties"]
    assert "attachments" in schema["reply"]["properties"]


def test_ax_inbound_files_are_saved_and_outbound_retry_keeps_original_bytes(tmp_path):
    from test_remote_agent import _agent_request

    runner, delivery, mailbox, endpoint, submissions = setup(tmp_path / "runner")
    incoming = BytesParser(policy=policy.SMTP).parsebytes(_agent_request())
    incoming.add_attachment(PDF, maintype="application", subtype="pdf", filename="in.pdf")
    _, record = offer(runner, mailbox, incoming.as_bytes(policy=policy.SMTP))
    attached = record["data"]["attachments"][0]
    assert attached["type"] == "application/pdf"
    assert attached["size"] == len(PDF)
    assert Path(attached["path"]).read_bytes() == PDF
    assert attached["path"] in record["text"]
    # Outbound file is outside the runner's private state.
    outgoing = tmp_path / "reply.pdf"
    outgoing.write_bytes(PDF)
    endpoint.reply(record["message_id"], data={"attachments": [str(outgoing)]})
    attempted = []

    def disconnected(sender, recipients, raw):
        attempted.append(raw)
        raise smtplib.SMTPServerDisconnected("fixture loss")

    runner.agent._transmit = disconnected
    with pytest.raises(Exception, match="uncertain SMTP"):
        delivery.step()
    assert parse(attempted[0]).attachments[0].content == PDF
    outgoing.unlink()
    runner.agent._transmit = lambda sender, recipients, raw: submissions.append(raw) or "ok"
    recovered = restart(delivery)
    recovered.step()
    assert submissions == attempted
    assert endpoint.acked == ["reply1"]


@pytest.mark.parametrize("content", [b"MZfake", b"\x7fELFfake", b"#!/bin/sh"])
def test_submission_refuses_true_type_before_side_effects(tmp_path, content):
    config = _config(tmp_path)
    store = Store(tmp_path / "journal.sqlite")
    service = SubmissionService(
        config,
        Journal(tmp_path, store),
        reinject=lambda *args: pytest.fail("reinjected blocked file"),
    )
    raw = message(attachments=[Attachment("a.pdf", content, "application/pdf")]).as_bytes(
        policy=policy.SMTP
    )
    handler = SubmissionHandler(service)
    result = asyncio.run(
        handler.handle_DATA(
            None,
            SimpleNamespace(auth_data=("scheduler", "secret-scheduler-token")),
            SimpleNamespace(original_content=raw),
        )
    )
    assert result.startswith("552 5.3.4 size-or-attachment")
    assert store.rows("SELECT * FROM journal") == []
    assert store.rows("SELECT * FROM holds") == []


def test_submission_exact_limit_and_one_over(tmp_path):
    config = _config(tmp_path)
    raw = message(attachments=[Attachment("a.pdf", PDF)]).as_bytes(policy=policy.SMTP)
    service = SubmissionService(
        replace(config, limits=replace(config.limits, max_bytes=len(raw))),
        Journal(tmp_path, Store(tmp_path / "journal.sqlite")),
        reinject=lambda *args: None,
    )
    assert service.submit("scheduler", "secret-scheduler-token", raw)
    service.config = replace(service.config, limits=replace(config.limits, max_bytes=len(raw) - 1))
    result = asyncio.run(
        SubmissionHandler(service).handle_DATA(
            None,
            SimpleNamespace(auth_data=("scheduler", "secret-scheduler-token")),
            SimpleNamespace(original_content=raw),
        )
    )
    assert result.startswith("552 5.3.4 size-or-attachment")


def test_default_blocked_list():
    assert LimitsConfig().blocked_attachment_types == DEFAULT_BLOCKED_TYPES
    assert "application/x-msdownload" in DEFAULT_BLOCKED_TYPES
    assert len(DEFAULT_BLOCKED_TYPES) == 5


def test_submission_true_type_wins_over_declared_blocked_type(tmp_path):
    config = _config(tmp_path)
    service = SubmissionService(
        config, Journal(tmp_path, Store(tmp_path / "journal.sqlite")), reinject=lambda *args: None
    )
    raw = message(attachments=[Attachment("a.exe", PDF, "application/x-msdownload")]).as_bytes()
    assert service.submit("scheduler", "secret-scheduler-token", raw)


def test_held_release_keeps_attachment_bytes_and_roundcube_copy(tmp_path):
    service, _store, reinjected, mailbox = _hold_service(tmp_path)
    raw = message(
        attachments=[Attachment("a.pdf", PDF)],
    ).as_bytes(policy=policy.SMTP)
    parsed = BytesParser(policy=policy.SMTP).parsebytes(raw)
    parsed.replace_header("To", "pat@plainmail.test")
    held = service.submit(
        "scheduler", "secret-scheduler-token", parsed.as_bytes(policy=policy.SMTP)
    )
    assert held.held
    assert parse(mailbox.appended[0][1]).attachments[0].content == PDF
    released = service.release("scheduler", _held_id(held))
    assert released is not None
    assert parse(reinjected[0][-1]).attachments[0].content == PDF
