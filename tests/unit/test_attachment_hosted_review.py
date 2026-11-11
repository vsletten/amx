"""Regressions for the supplied Sourcery findings, with fixture-local I/O only."""

from __future__ import annotations

import os
from dataclasses import replace
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path

import pytest
from test_attachment_remediation import bypass, submission_refused
from test_attachment_surfaces import tools_at
from test_attachments import PDF, message
from test_ax_delivery import setup
from test_mcp_server import _raw
from test_milter import _agent_request as gateway_request
from test_milter import _feed, _milter, _verified
from test_remote_agent import _agent_request

from amx.adapters.ax import Contract, _size, envelope
from amx.attachment_files import load_files, save_file
from amx.attachments import Attachment, ReceivedAttachment, security_parts
from amx.mcp_server import Fetched
from amx.profile import parse
from amx.runner import bind, delivery_key
from amx.sdk import Agent, PreparedSubmission


def test_hosted_hard_link_private_alias_is_refused(tmp_path):
    private = tmp_path / "private"
    private.mkdir()
    secret = private / "credentials.json"
    secret.write_bytes(b"synthetic private fixture")
    alias = tmp_path / "public.pdf"
    alias.hardlink_to(secret)
    with pytest.raises(ValueError, match="hard link"):
        load_files([str(alias)], max_bytes=1000, forbidden=(private,))


def test_hosted_runner_denies_resolved_credential_target(tmp_path, monkeypatch):
    import amx.runner as runner

    target = tmp_path / "elsewhere" / "bundle.json"
    target.parent.mkdir()
    target.write_bytes(b"synthetic credential fixture")
    configured = tmp_path / "configured" / "login.json"
    configured.parent.mkdir()
    configured.symlink_to(target)
    captured = {}
    monkeypatch.setattr(
        runner,
        "read_bundle",
        lambda path: {
            "address": "a@agents.example.test",
            "password": "fixture",
            "token": "fixture",
            "imap": "imap://localhost:143",
            "submission": "smtp://localhost:2587",
        },
    )
    monkeypatch.setattr(runner.Runner, "run", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner.AxPresence, "run", lambda *args: None)
    monkeypatch.setattr(runner.signal, "signal", lambda *args: None)
    import amx.ax_delivery as ax

    real_init = ax.AxDelivery.__init__

    def capture(self, *args, **kwargs):
        captured.update(kwargs)
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(ax.AxDelivery, "__init__", capture)
    runner.main(
        [
            "--credentials",
            str(configured),
            "--state",
            str(tmp_path / "state"),
            "--ax",
            "live",
            "--ax-home",
            str(tmp_path / "ax"),
        ]
    )
    for path in (configured, target, configured.parent / "other.json"):
        if not path.exists():
            path.write_bytes(b"fixture")
        with pytest.raises(ValueError, match="state or credential"):
            load_files([str(path)], max_bytes=1000, forbidden=captured["credential_directories"])


def unnamed_executable():
    mail = BytesParser(policy=policy.SMTP).parsebytes(bypass("none"))
    mail.add_attachment(b"\x7fELFfixture", maintype="application", subtype="pdf")
    part = mail.get_payload()[-1]
    del part["Content-Disposition"]
    return mail.as_bytes(policy=policy.SMTP)


def test_hosted_unnamed_binary_sdk_and_submission(tmp_path, monkeypatch):
    raw = unnamed_executable()
    agent = Agent("a@agents.example.test", "smtp://localhost", "fixture")
    monkeypatch.setattr(agent, "_transmit", lambda *args: pytest.fail("executable transmitted"))
    with pytest.raises(ValueError, match="executable"):
        agent.submit_prepared(PreparedSubmission("a", ("b",), raw))
    submission_refused(tmp_path, raw)


def test_hosted_unnamed_binary_milter(tmp_path, monkeypatch):
    import Milter

    _verified(monkeypatch)
    make, _, replies = _milter(tmp_path)
    milter = make("<owner@people.test>")
    assert milter.envrcpt("<intake+t_1@agents.example.test>") == Milter.CONTINUE
    _feed(milter, unnamed_executable())
    assert milter.eom() == Milter.REJECT
    assert replies[-1][:2] == ("552", "5.3.4")


@pytest.mark.parametrize("failure", ["size", "intent", "parse"])
@pytest.mark.parametrize("taken", [False, True])
def test_hosted_invalid_mcp_reply_preserves_exact_custody(tmp_path, monkeypatch, failure, taken):
    tools, mailbox = tools_at(tmp_path)
    raw = _raw("t_a", "<incoming@fixture>")
    mailbox.folders["INBOX"] = [Fetched("INBOX", 1, raw, False, taken=taken)]
    with tools.custody.locked() as state:
        if taken:
            state["claims"][delivery_key(raw)] = "mcp"
        before = dict(state["claims"])
    original = mailbox.folders["INBOX"].copy()
    file = tmp_path / "file.pdf"
    file.write_bytes(PDF)
    if failure == "size":
        tools.agent.max_bytes = 500
    if failure == "parse":
        monkeypatch.setattr(
            tools.agent, "parse", lambda raw: (_ for _ in ()).throw(ValueError("invalid"))
        )
    monkeypatch.setattr(
        tools.agent, "_transmit", lambda *args: pytest.fail("invalid reply submitted")
    )
    with pytest.raises(ValueError):
        tools.reply(
            "<incoming@fixture>",
            "reply",
            intent="invalid" if failure == "intent" else "response",
            attachments=[str(file)],
        )
    assert mailbox.folders["INBOX"] == original
    assert mailbox.flagged == []
    with tools.custody.locked() as state:
        assert state["claims"] == before


def structured_mail():
    # Unknown message types are parsed by email as structured lists, including nested shapes.
    raw = _agent_request()
    mail = BytesParser(policy=policy.SMTP).parsebytes(raw)
    part = BytesParser(policy=policy.SMTP).parsebytes(
        b"Content-Type: message/unsupported\r\n"
        b'Content-Disposition: attachment; filename="unknown.mime"\r\n\r\n'
        b"Content-Type: message/unsupported\r\n\r\nSubject: nested\r\n\r\nMeaningful body\r\n"
    )
    if mail.get_content_type() != "multipart/mixed":
        mail.make_mixed()
    mail.attach(part)
    return mail.as_bytes(policy=policy.SMTP)


def test_hosted_unknown_nested_mime_metadata_mcp_ax_gateway(tmp_path, monkeypatch):
    raw = structured_mail()
    attachment = parse(raw).attachments[0]
    assert b"Meaningful body" in attachment.content
    assert attachment.metadata()["size"] == len(attachment.content)
    tools, mailbox = tools_at(tmp_path / "mcp")
    mailbox.folders["INBOX"] = [Fetched("INBOX", 1, raw, False)]
    assert tools.list_inbox()[0]["attachments"][0]["size"] > 0
    saved = tools.save_attachment(parse(raw).thread.message_id, 0)
    assert Path(saved["path"]).read_bytes() == attachment.content
    runner, delivery, mb, _, _ = setup(tmp_path / "ax")
    uid = str(mb.add(raw))
    assert delivery.offer(mb, uid, raw) is True
    record = runner.handled.ax_record(delivery_key(raw))
    assert Path(record["data"]["attachments"][0]["path"]).read_bytes() == attachment.content
    assert all(isinstance(part.type, str) for part in security_parts(BytesParser().parsebytes(raw)))
    import Milter

    _verified(monkeypatch)
    make, _, _ = _milter(tmp_path / "gateway")
    milter = make()
    assert milter.envrcpt("<intake+t_1@agents.example.test>") == Milter.CONTINUE
    gateway_mail = BytesParser(policy=policy.SMTP).parsebytes(
        gateway_request(["intake+t_1@agents.example.test"])
    )
    gateway_mail.make_mixed()
    gateway_mail.attach(BytesParser(policy=policy.SMTP).parsebytes(raw).get_payload()[-1])
    _feed(milter, gateway_mail.as_bytes(policy=policy.SMTP))
    assert milter.eom() == Milter.ACCEPT


@pytest.mark.parametrize("failure", ["envelope", "ax_save", "second_file"])
def test_hosted_ax_failed_offer_cleans_only_new_files(tmp_path, monkeypatch, failure):
    import amx.ax_delivery as ax

    runner, delivery, mailbox, endpoint, _ = setup(tmp_path)
    mail = BytesParser(policy=policy.SMTP).parsebytes(_agent_request())
    for name in ("one.pdf", "two.pdf"):
        mail.add_attachment(PDF, maintype="application", subtype="pdf", filename=name)
    raw = mail.as_bytes(policy=policy.SMTP)
    uid = str(mailbox.add(raw))
    prior = tmp_path / "attachments" / parse(raw).task / "one.pdf"
    prior.parent.mkdir(parents=True)
    prior.write_bytes(b"preexisting")
    original = (
        ax.envelope
        if failure == "envelope"
        else (runner.handled.ax_save if failure == "ax_save" else ax.save_file)
    )

    def fail(*args, **kwargs):
        if failure == "second_file" and args[0].filename != "two.pdf":
            return original(*args, **kwargs)
        raise OSError("injected after materialization")

    with monkeypatch.context() as patcher:
        if failure == "ax_save":
            patcher.setattr(runner.handled, "ax_save", fail)
        else:
            patcher.setattr(ax, "envelope" if failure == "envelope" else "save_file", fail)
        with pytest.raises(OSError, match="injected"):
            delivery.offer(mailbox, uid, raw)
    assert list((tmp_path / "attachments").rglob("*.pdf")) == [prior]
    assert prior.read_bytes() == b"preexisting"
    assert endpoint.calls == []
    assert delivery.offer(mailbox, uid, raw) is True
    assert delivery.offer(mailbox, uid, raw) is True
    assert len(list((tmp_path / "attachments").rglob("*.pdf"))) == 3


@pytest.mark.parametrize("contract", [Contract.V1, Contract.INTERIM])
def test_hosted_ax_envelope_bounded_retains_complete_paths(tmp_path, contract):
    inbound = replace(bind(_agent_request()), text="<&😀" * 40000)
    paths = []
    for index in range(180):
        path = tmp_path / (str(index) + "長" * 50 + ".pdf")
        path.write_bytes(PDF)
        paths.append(
            {
                "filename": "<&" * 500,
                "declared_type": "x" * 500,
                "type": "application/pdf",
                "size": len(PDF),
                "index": index,
                "path": str(path),
            }
        )
    text, data, _ = envelope(inbound, "outpost@agents.contoso.test", contract, attachments=paths)
    if contract == Contract.V1:
        assert _size(data) <= 32 * 1024
        retained = data["attachments"]
        assert retained
        assert data["attachments_omitted"] == len(paths) - len(retained)
        for item in retained:
            assert Path(item["path"]).read_bytes() == PDF
    else:
        assert len(text.encode()) <= 64 * 1024
        assert "attachments omitted:" in text
        assert str(paths[0]["path"]) in text
        # No partial path for the first excluded item is rendered.
        assert not text.endswith(str(paths[-1]["path"])[:10])


@pytest.mark.parametrize("failure", ["write", "fsync", "publish"])
def test_hosted_atomic_save_failure_leaves_no_partial_final(tmp_path, monkeypatch, failure):
    part = parse(message(attachments=[Attachment("file.pdf", PDF)]).as_bytes()).attachments[0]
    real_fdopen = os.fdopen

    class BrokenWrite:
        def __init__(self, fd, mode):
            self.stream = real_fdopen(fd, mode)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()

        def write(self, content):
            self.stream.write(content[:3])
            self.stream.flush()
            raise OSError("injected write")

    def fail(*args, **kwargs):
        raise OSError("injected " + failure)

    monkeypatch.setattr(
        os,
        "fdopen" if failure == "write" else "fsync" if failure == "fsync" else "link",
        BrokenWrite if failure == "write" else fail,
    )
    with pytest.raises(OSError, match="injected"):
        save_file(part, tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_hosted_filename_text_excluded_from_judge_body():
    mail = EmailMessage()
    mail.make_mixed()
    file = EmailMessage()
    file.set_content("attachment instructions")
    file.set_param("name", "notes.txt", header="Content-Type")
    mail.attach(file)
    body = EmailMessage()
    body.set_content("genuine message")
    mail.attach(body)
    assert parse(mail.as_bytes()).text == "genuine message\n"


def test_hosted_claimed_machine_file_listed_and_saveable(tmp_path):
    mail = BytesParser(policy=policy.SMTP).parsebytes(message().as_bytes())
    mail.add_attachment(
        b'{"user":"file"}',
        maintype="application",
        subtype="ld+json",
        filename="user.json",
        disposition="inline",
    )
    mail.get_payload()[-1]["Content-Purpose"] = "machine-readable"
    raw = mail.as_bytes(policy=policy.SMTP)
    inbound = parse(raw)
    assert [part.filename for part in inbound.attachments] == ["user.json"]
    tools, mailbox = tools_at(tmp_path)
    mailbox.folders["INBOX"] = [Fetched("INBOX", 1, raw, False)]
    saved = tools.save_attachment(inbound.thread.message_id, 0)
    assert Path(saved["path"]).read_bytes() == b'{"user":"file"}'


@pytest.mark.parametrize("nested_file", [False, True])
def test_hosted_forwarded_shebang_body_not_file_but_nested_script_is(monkeypatch, nested_file):
    inner = EmailMessage()
    inner.set_content("#!/bin/sh\nordinary forwarded prose\n")
    if nested_file:
        inner.add_attachment(
            b"#!/bin/sh\necho bad", maintype="text", subtype="plain", filename="script.txt"
        )
    mail = message()
    mail.add_attachment(inner, filename="forward.eml")
    raw = mail.as_bytes(policy=policy.SMTP)
    agent = Agent("a@agents.example.test", "smtp://localhost", "fixture")
    submitted = []
    monkeypatch.setattr(agent, "_transmit", lambda *args: submitted.append(args[-1]) or "ok")
    if nested_file:
        with pytest.raises(ValueError, match="executable"):
            agent.submit_prepared(PreparedSubmission("a", ("b",), raw))
        assert not submitted
    else:
        agent.submit_prepared(PreparedSubmission("a", ("b",), raw))
        assert submitted == [raw]


@pytest.mark.parametrize(
    "declared", ["message/unsupported", "application/unsupported", "text/plain"]
)
def test_hosted_arbitrary_structured_content_is_total_and_preserves_children(declared):
    children = []
    for text in ("first meaningful bytes", "last meaningful bytes"):
        child = EmailMessage()
        child.set_content(text)
        children.append(child)
    nested = EmailMessage()
    nested.set_type(declared)
    nested.set_payload(children)
    outer = EmailMessage()
    outer.set_type("message/unsupported")
    outer.set_payload([nested])
    attachment = ReceivedAttachment(0, "structure.mime", "message/unsupported", outer)
    assert b"first meaningful bytes" in attachment.content
    assert b"last meaningful bytes" in attachment.content
    assert attachment.metadata()["size"] == len(attachment.content)


def test_hosted_ax_committed_save_error_keeps_durable_files(tmp_path, monkeypatch):
    runner, delivery, mailbox, _, _ = setup(tmp_path)
    mail = BytesParser(policy=policy.SMTP).parsebytes(_agent_request())
    mail.add_attachment(PDF, maintype="application", subtype="pdf", filename="saved.pdf")
    raw = mail.as_bytes(policy=policy.SMTP)
    uid = str(mailbox.add(raw))
    real_save = runner.handled.ax_save

    def committed_then_error(record, **kwargs):
        real_save(record, **kwargs)
        raise OSError("injected after commit")

    with monkeypatch.context() as patcher:
        patcher.setattr(runner.handled, "ax_save", committed_then_error)
        with pytest.raises(OSError, match="after commit"):
            delivery.offer(mailbox, uid, raw)
    record = runner.handled.ax_record(delivery_key(raw))
    assert Path(record["data"]["attachments"][0]["path"]).read_bytes() == PDF
    assert delivery.offer(mailbox, uid, raw) is True
    assert len(list((tmp_path / "attachments").rglob("*.pdf"))) == 1


def test_hosted_true_payload_excluded_but_inline_user_file_saved(tmp_path):
    from test_profile import _profile

    mail = _profile()
    mail.add_attachment(
        b'{"user":"file"}',
        maintype="application",
        subtype="ld+json",
        filename="user.json",
        disposition="inline",
    )
    mail.get_payload()[-1]["Content-Purpose"] = "machine-readable"
    raw = mail.as_bytes(policy=policy.SMTP)
    inbound = parse(raw)
    assert inbound.payload is not None
    assert [part.filename for part in inbound.attachments] == ["user.json"]
    tools, mailbox = tools_at(tmp_path)
    mailbox.folders["INBOX"] = [Fetched("INBOX", 1, raw, False)]
    saved = tools.save_attachment(inbound.thread.message_id, 0)
    assert Path(saved["path"]).read_bytes() == b'{"user":"file"}'


def test_hosted_unsupported_structure_submission_and_sdk(tmp_path, monkeypatch):
    from test_submission import _config

    from amx.adapters.submission import SubmissionService
    from amx.journal import Journal
    from amx.store import Store

    mail = message()
    if mail.get_content_type() != "multipart/mixed":
        mail.make_mixed()
    mail.attach(BytesParser(policy=policy.SMTP).parsebytes(structured_mail()).get_payload()[-1])
    raw = mail.as_bytes(policy=policy.SMTP)
    submissions = []
    agent = Agent("a@agents.example.test", "smtp://localhost", "fixture")
    monkeypatch.setattr(agent, "_transmit", lambda *args: submissions.append(args[-1]) or "ok")
    agent.submit_prepared(PreparedSubmission("a", ("b",), raw))
    assert submissions == [raw]
    service = SubmissionService(
        _config(tmp_path),
        Journal(tmp_path, Store(tmp_path / "journal.sqlite")),
        reinject=lambda *args: None,
    )
    assert service.submit("scheduler", "secret-scheduler-token", raw)
