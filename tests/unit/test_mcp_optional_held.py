"""An uncreated hold queue must not break ordinary MCP mailbox reads (S27)."""

from __future__ import annotations

import imaplib
from copy import deepcopy
from email import policy
from pathlib import Path

import pytest
from test_attachments import PDF, message
from test_mcp_server import ADDRESS, SHARED_HELD, FakeMailbox, _raw

from amx.attachments import Attachment
from amx.custody import Custody
from amx.holds import HELD_FOLDER
from amx.mcp_server import INBOX, SENT, AgentTools, Fetched, ImapAccount, Mailbox
from amx.profile import parse
from amx.sdk import Agent


class FailingMailbox(FakeMailbox):
    def __init__(self, folder, error):
        super().__init__({INBOX: [], SENT: []})
        self.failing_folder = folder
        self.error = error
        self.fetched = []

    def fetch(self, folder, *, unseen_only=False, limit=None):
        self.fetched.append(folder)
        if folder == self.failing_folder:
            # Mailbox.fetch raises this RuntimeError when SELECT rejects the folder.
            raise self.error
        return super().fetch(folder, unseen_only=unseen_only, limit=limit)


@pytest.fixture(params=[HELD_FOLDER, SHARED_HELD])
def tools(tmp_path, request):
    held_folder = request.param
    return AgentTools(
        Agent(ADDRESS, "smtp://localhost", "unused"),
        FailingMailbox(held_folder, RuntimeError(f"cannot open {held_folder}")),
        held_folder=held_folder,
        custody=Custody(ADDRESS, directory=tmp_path / "custody"),
        state_directory=tmp_path / "state",
    )


@pytest.mark.parametrize(
    "seen,taken,handled",
    [(False, False, False), (True, False, False), (False, True, False), (True, True, True)],
)
def test_save_inbox_pdf_with_absent_hold_queue_preserves_custody(tools, seen, taken, handled):
    raw = message(attachments=[Attachment("report.pdf", PDF)]).as_bytes(policy=policy.SMTP)
    inbound = parse(raw)
    original = Fetched(INBOX, 1, raw, seen, taken=taken, handled=handled)
    tools.mailbox.folders[INBOX] = [original]
    with tools.custody.locked() as state:
        state["claims"]["existing-delivery"] = "runner"
        before = deepcopy(state)

    saved = tools.save_attachment(inbound.thread.message_id, 0)

    assert Path(saved["path"]).read_bytes() == PDF
    assert Path(saved["path"]).parent == tools.state_directory / "attachments" / inbound.task
    assert tools.mailbox.fetched == [INBOX, SENT, tools.held_folder]
    assert tools.mailbox.folders[INBOX] == [original]
    assert tools.mailbox.flagged == []
    with tools.custody.locked() as state:
        assert state == before


def test_read_thread_with_absent_hold_queue_returns_inbox_and_sent(tools):
    tools.mailbox.folders[INBOX] = [Fetched(INBOX, 1, _raw("t_a", "<reply@x>"), False)]
    tools.mailbox.folders[SENT] = [Fetched(SENT, 1, _raw("t_a", "<sent@x>"), True)]

    thread = tools.read_thread("t_a")

    assert {(item["folder"], item["message_id"]) for item in thread} == {
        (INBOX, "<reply@x>"),
        (SENT, "<sent@x>"),
    }
    assert all("text" in item for item in thread)
    # Keep read_thread's existing custody semantics, unlike observational save_attachment.
    assert tools.mailbox.flagged == [(INBOX, 1, "$AmxTaken")]


def test_list_held_with_absent_hold_queue_is_empty(tools):
    assert tools.list_held() == []
    assert tools.mailbox.fetched == [tools.held_folder]
    assert tools.mailbox.flagged == []


CALLS = [("save_attachment", ("<pdf@x>", 0)), ("read_thread", ("t_a",)), ("list_held", ())]


@pytest.mark.parametrize("method,args", CALLS[:2])
@pytest.mark.parametrize("folder", [INBOX, SENT])
def test_mandatory_folder_select_errors_propagate(tools, method, args, folder):
    error = RuntimeError(f"cannot open {folder}")
    tools.mailbox = FailingMailbox(folder, error)

    with pytest.raises(RuntimeError) as caught:
        getattr(tools, method)(*args)

    assert caught.value is error
    assert tools.mailbox.flagged == []


@pytest.mark.parametrize("method,args", CALLS)
@pytest.mark.parametrize("failure", ["connection", "auth", "protocol", "search", "other-folder"])
def test_optional_folder_real_failures_propagate(tools, method, args, failure):
    error = {
        "connection": OSError("connection lost"),
        "auth": imaplib.IMAP4.error("authentication failed"),
        "protocol": imaplib.IMAP4.abort("protocol failure"),
        "search": RuntimeError(f"cannot search {tools.held_folder}"),
        "other-folder": RuntimeError("cannot open Other"),
    }[failure]
    tools.mailbox.error = error

    with pytest.raises(type(error)) as caught:
        getattr(tools, method)(*args)

    assert caught.value is error
    assert tools.mailbox.flagged == []


@pytest.mark.parametrize("method,args", CALLS)
@pytest.mark.parametrize("folder", [INBOX, SENT])
def test_configured_hold_folder_cannot_make_mandatory_folder_optional(tools, method, args, folder):
    tools.held_folder = folder
    error = RuntimeError(f"cannot open {folder}")
    tools.mailbox = FailingMailbox(folder, error)

    with pytest.raises(RuntimeError) as caught:
        getattr(tools, method)(*args)

    assert caught.value is error


def test_mailbox_fetch_select_failure_matches_fake(monkeypatch):
    class RejectedSelect:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def select(self, folder, *, readonly):
            assert folder == HELD_FOLDER
            assert readonly is True
            return "NO", [b"Mailbox does not exist"]

    mailbox = Mailbox(ImapAccount("localhost", 143, ADDRESS, "unused"))
    monkeypatch.setattr(mailbox, "_connect", RejectedSelect)
    with pytest.raises(RuntimeError) as caught:
        mailbox.fetch(HELD_FOLDER)
    assert caught.value.args == (f"cannot open {HELD_FOLDER}",)
