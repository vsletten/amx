"""Boundary regressions for SH-42's shared helpers and trusted size headroom."""

from __future__ import annotations

import os
from email import policy
from email.message import EmailMessage
from types import SimpleNamespace

import pytest
from test_attachments import PDF, message
from test_ax_delivery import offer, setup

from amx.adapters.ax import parse_reply
from amx.attachment_files import attachment_directory, load_files, save_file
from amx.attachments import Attachment, ReceivedAttachment
from amx.profile import parse


@pytest.mark.parametrize("paths", ["/tmp/x", {}, 0, [None], [1]])
def test_ax_rejects_malformed_attachment_paths(paths):
    with pytest.raises(ValueError, match="attachments"):
        parse_reply({"text": "file", "data": {"attachments": paths}})


def test_file_size_is_checked_before_read(tmp_path, monkeypatch):
    path = tmp_path / "large.pdf"
    path.write_bytes(PDF)
    opened = os.fdopen

    class Guard:
        def __init__(self, fd, mode):
            self.stream = opened(fd, mode)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()

        def fileno(self):
            return self.stream.fileno()

        def read(self, *args):
            pytest.fail("oversize file was read before size check")

    monkeypatch.setattr(os, "fdopen", Guard)
    with pytest.raises(ValueError, match="max_bytes=5"):
        load_files([str(path)], max_bytes=5)


def test_file_growth_read_is_bounded(tmp_path, monkeypatch):
    path = tmp_path / "growing.pdf"
    path.write_bytes(PDF * 100)
    real_fstat = os.fstat
    monkeypatch.setattr(
        os,
        "fstat",
        lambda fd: SimpleNamespace(
            st_mode=real_fstat(fd).st_mode,
            st_size=1,
            st_ino=real_fstat(fd).st_ino,
            st_dev=real_fstat(fd).st_dev,
            st_nlink=real_fstat(fd).st_nlink,
        ),
    )
    real_fdopen = os.fdopen

    class Guard:
        def __init__(self, fd, mode):
            self.stream = real_fdopen(fd, mode)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()

        def fileno(self):
            return self.stream.fileno()

        def read(self, size=-1):
            assert size == 6
            return self.stream.read(size)

    monkeypatch.setattr(os, "fdopen", Guard)
    with pytest.raises(ValueError, match="max_bytes=5"):
        load_files([str(path)], max_bytes=5)


def test_save_helper_alone_confines_hostile_names_and_task(tmp_path):
    part = EmailMessage()
    part.set_content(PDF, maintype="application", subtype="pdf")
    attached = ReceivedAttachment(0, "../../outside.pdf", "application/pdf", part)
    directory = tmp_path / "safe"
    saved = save_file(attached, directory)
    assert saved.parent == directory
    assert saved.read_bytes() == PDF
    assert not (tmp_path.parent / "outside.pdf").exists()
    assert attachment_directory(tmp_path, "../../escape") == tmp_path / "attachments" / "escape"


def test_encoded_attachments_do_not_enter_body_or_json_snapshot():
    inbound = parse(message(attachments=[Attachment("secret.txt", b"ATTACHMENT ONLY")]).as_bytes())
    assert "ATTACHMENT ONLY" not in inbound.text
    snapshot = inbound.as_dict()
    assert snapshot["attachments"] == [inbound.attachments[0].metadata()]
    assert "content" not in snapshot["attachments"][0]


@pytest.mark.parametrize("boundary", ["temporary", "uncertain"])
def test_ax_attachment_retry_replays_prepared_bytes(tmp_path, boundary):
    import smtplib

    from test_ax_delivery import restart

    from amx.adapters.ax import AxError

    runner, delivery, mailbox, endpoint, submissions = setup(tmp_path / "runner")
    _, record = offer(runner, mailbox)
    file = tmp_path / "file.pdf"
    file.write_bytes(PDF)
    endpoint.reply(record["message_id"], data={"attachments": [str(file)]})
    attempts = []

    def fail(sender, recipients, raw):
        attempts.append(raw)
        if boundary == "temporary":
            raise smtplib.SMTPDataError(450, b"later")
        raise smtplib.SMTPServerDisconnected("lost")

    runner.agent._transmit = fail
    with pytest.raises(AxError):
        delivery.step()
    file.write_bytes(b"MZchanged after prepare")
    runner.agent._transmit = lambda sender, recipients, raw: submissions.append(raw) or "ok"
    restart(delivery).step()
    assert submissions == attempts
    assert parse(submissions[0]).attachments[0].content == PDF


@pytest.mark.parametrize("kind", ["missing", "directory", "state", "link", "executable", "large"])
def test_ax_attachment_paths_use_same_refusals(tmp_path, kind):
    runner, delivery, mailbox, endpoint, submissions = setup(tmp_path / "runner")
    _, record = offer(runner, mailbox)
    file = tmp_path / "file.pdf"
    if kind == "directory":
        file.mkdir()
    elif kind in {"state", "link"}:
        forbidden = runner.handled.path.parent / "private-fixture"
        forbidden.write_bytes(b"fixture, not credentials")
        if kind == "link":
            file.symlink_to(forbidden)
        else:
            file = forbidden
    elif kind == "executable":
        file.write_bytes(b"\x7fELFfake")
    elif kind == "large":
        file.write_bytes(PDF)
        runner.agent.max_bytes = 5
    endpoint.reply(record["message_id"], data={"attachments": [str(file)]})
    delivery.step()
    assert submissions == []
    assert "reply1" in endpoint.acked
    assert runner.handled.ax_reply("reply1")["error"]


def test_ordinary_human_mail_exposes_attachment():
    human = EmailMessage(policy=policy.SMTP)
    human["From"] = "owner@example.test"
    human["To"] = "agent@example.test"
    human.set_content("Body only.")
    human.add_attachment(PDF, maintype="application", subtype="pdf", filename="report.pdf")
    inbound = parse(human.as_bytes())
    assert inbound.lane == "human"
    assert inbound.attachments[0].content == PDF


def test_valid_declared_type_required():
    with pytest.raises(ValueError, match="MIME type"):
        message(attachments=[Attachment("a.pdf", PDF, "application/pdf\r\nX-Evil: yes")])


def test_prepared_submission_also_refuses_executable(monkeypatch):
    from amx.sdk import Agent, PreparedSubmission

    agent = Agent("a@agents.example.test", "smtp://localhost", "fixture")
    raw = message(attachments=[Attachment("a.pdf", b"MZfixture", "application/pdf")]).as_bytes()
    monkeypatch.setattr(agent, "_transmit", lambda *args: pytest.fail("executable transmitted"))
    with pytest.raises(ValueError, match="executable"):
        agent.submit_prepared(PreparedSubmission("a", ("b",), raw))


def test_ax_sender_only_rebuild_preserves_original_attachment_after_cc_refusal(tmp_path):
    import smtplib

    from test_owner_named_recipients import _owner_ax_mail

    runner, delivery, mailbox, endpoint, submissions = setup(tmp_path / "runner")
    _, record = offer(runner, mailbox, _owner_ax_mail("dana@acme.test"))
    file = tmp_path / "file.pdf"
    file.write_bytes(PDF)
    endpoint.reply(record["message_id"], data={"attachments": [str(file)]})

    def transmit(sender, recipients, raw):
        if len(recipients) > 1:
            file.unlink()
            raise smtplib.SMTPDataError(550, b"fixture Cc refusal")
        submissions.append(raw)
        return "ok"

    runner.agent._transmit = transmit
    delivery.step()
    assert len(submissions) == 1
    assert parse(submissions[0]).attachments[0].content == PDF
