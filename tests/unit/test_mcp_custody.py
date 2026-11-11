"""SH-24a: cooperative MCP custody, completion, refusal and fail-closed reads."""

from __future__ import annotations

import smtplib
from dataclasses import replace

import pytest
from test_mcp_server import AGENT_LANE, FakeMailbox, _raw, _tools

from amx.mcp_server import Fetched
from amx.sdk import Agent, Declared, Sent


@pytest.fixture(autouse=True)
def forbid_unmocked_submission(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("unit tests must never connect to a submission service")

    monkeypatch.setattr(Agent, "_transmit", forbidden)


def mailbox():
    return FakeMailbox(
        {
            "INBOX": [
                Fetched(
                    "INBOX",
                    1,
                    _raw(
                        "t_a",
                        "<m@x>",
                        headers={
                            **AGENT_LANE,
                            "Delivered-To": "scheduler+t_a@agents.northwind.test",
                        },
                    ),
                    False,
                )
            ]
        }
    )


@pytest.mark.parametrize("tool", ["list_inbox", "read_thread", "reply"])
def test_each_read_or_reply_claims_before_exposing_or_submitting(tool, monkeypatch):
    box = mailbox()
    tools = _tools(box)

    def transmit(self, *args):
        assert box.flagged == [("INBOX", 1, "$AmxTaken")]
        return "2.0.0 sent"

    monkeypatch.setattr(Agent, "_transmit", transmit)
    if tool == "list_inbox":
        assert tools.list_inbox()[0]["taken"]
    elif tool == "read_thread":
        assert tools.read_thread("t_a")[0]["taken"]
    else:
        tools.reply("<m@x>", "Yes")
    assert box.flagged == [("INBOX", 1, "$AmxTaken")]
    assert not box.folders["INBOX"][0].seen


@pytest.mark.parametrize("tool", ["list_inbox", "read_thread"])
@pytest.mark.parametrize("taken", [False, True])
def test_seen_inbox_reads_preserve_legacy_custody_and_revisit_mcp(tool, taken):
    box = mailbox()
    original = replace(box.folders["INBOX"][0], seen=True, taken=taken)
    box.folders["INBOX"] = [original]
    tools = _tools(box)

    items = tools.list_inbox() if tool == "list_inbox" else tools.read_thread("t_a")

    assert len(items) == 1  # Legacy work stays visible, but observational only.
    assert items[0]["seen"] and not items[0]["handled"]
    assert items[0]["taken"] is taken
    if tool == "read_thread":
        assert items[0]["text"] == "Thursday at 9 works."
    assert not box.flagged
    assert box.folders["INBOX"] == [original]
    assert tools.list_inbox(unread_only=True) == []


@pytest.mark.parametrize("tool", ["reply", "done", "refuse"])
@pytest.mark.parametrize("taken", [False, True])
def test_seen_inbox_actions_reject_legacy_custody_but_allow_mcp(tool, taken, monkeypatch):
    box = mailbox()
    original = replace(
        box.folders["INBOX"][0],
        seen=True,
        taken=taken,
        raw=b"Agent-Taint: unjudged\r\n" + box.folders["INBOX"][0].raw,
    )
    box.folders["INBOX"] = [original]
    calls = []

    def send(self, **fields):
        calls.append("reply")
        return Sent("t_a", "<reply@x>")

    def refuse(self, recipient, message_id, **fields):
        calls.append("refuse")
        return Declared("t_ctl", "<ctl@x>", "refuse dsn=sent why=verified")

    monkeypatch.setattr(Agent, "send", send)
    monkeypatch.setattr(Agent, "refuse", refuse)
    tools = _tools(box)

    def act():
        if tool == "reply":
            return tools.reply("<m@x>", "Yes")
        return getattr(tools, tool)("<m@x>")

    if not taken:
        with pytest.raises(ValueError, match="legacy runner"):
            act()
        assert not calls and not box.flagged
        assert box.folders["INBOX"] == [original]  # Keep the runner's taint window open.
    else:
        result = act()
        assert calls == ([] if tool == "done" else [tool])
        if tool == "reply":
            assert result["message_id"] == "<reply@x>"
            assert not box.flagged
            assert not box.folders["INBOX"][0].handled
        else:
            assert result["status"] == ("handled" if tool == "done" else "refused")
            flags = "$AmxHandled" if tool == "done" else "$AmxHandled $AmxRefused"
            assert box.flagged == [("INBOX", 1, flags)]
        assert box.folders["INBOX"][0].seen and box.folders["INBOX"][0].taken
        assert box.folders["INBOX"][0].raw == original.raw


@pytest.mark.parametrize("taken", [False, True])
def test_wait_never_offers_seen_copies_even_with_mcp_custody(taken):
    box = mailbox()
    original = replace(box.folders["INBOX"][0], seen=True, taken=taken)
    box.folders["INBOX"] = [original]
    assert _tools(box).wait_for_reply("t_a", 0) == {"status": "timeout", "task": "t_a"}
    assert not box.flagged
    assert box.folders["INBOX"] == [original]


def test_done_is_idempotent_and_does_not_close_task():
    box = mailbox()
    tools = _tools(box)
    tools.list_inbox()
    assert tools.done("<m@x>") == {"message_id": "<m@x>", "status": "handled"}
    tools.done("<m@x>")
    assert box.flagged == [("INBOX", 1, "$AmxTaken"), ("INBOX", 1, "$AmxHandled")]
    assert tools.wait_for_reply("t_a", 0)["status"] == "timeout"
    with pytest.raises(LookupError):
        tools.done("<missing@x>")


def test_refuse_reports_original_recipient_before_ack_and_retries_safely(monkeypatch):
    box = mailbox()
    tools = _tools(box)
    calls = []

    def refuse(self, recipient, message_id, **fields):
        assert box.folders["INBOX"][0].taken
        assert not box.folders["INBOX"][0].handled
        calls.append((recipient, message_id, fields))
        if len(calls) == 1:
            raise smtplib.SMTPDataError(451, b"4.3.0 retry")
        return Declared("t_ctl", "<ctl@x>", "refuse dsn=sent why=verified")

    monkeypatch.setattr(Agent, "refuse", refuse)
    with pytest.raises(RuntimeError, match="451"):
        tools.refuse("<m@x>", status="5.6.0", reason="content")
    assert not box.folders["INBOX"][0].handled
    assert tools.refuse("<m@x>", status="5.6.0", reason="content")["status"] == "refused"
    assert calls[-1] == (
        "scheduler+t_a@agents.northwind.test",
        "<m@x>",
        {
            "status": "5.6.0",
            "reason": "content",
        },
    )
    assert box.flagged[-1] == ("INBOX", 1, "$AmxHandled $AmxRefused")
    assert tools.refuse("<m@x>")["status"] == "refused"
    assert tools.done("<m@x>")["status"] == "refused"
    assert len(calls) == 2


def test_refusal_keeps_custody_when_final_store_fails_and_retries(monkeypatch):
    box = mailbox()
    tools = _tools(box)
    flag = box.flag
    calls = []

    def fail_final_once(folder, uid, flags):
        if "$AmxHandled" in flags:
            box.flag = flag
            raise RuntimeError("final STORE failed")
        flag(folder, uid, flags)

    def refuse(self, recipient, message_id, **fields):
        calls.append((recipient, message_id, fields))
        return Declared("t_ctl", "<ctl@x>", "refuse dsn=sent why=verified")

    box.flag = fail_final_once
    monkeypatch.setattr(Agent, "refuse", refuse)
    with pytest.raises(RuntimeError, match="final STORE failed"):
        tools.refuse("<m@x>")
    [item] = box.folders["INBOX"]
    assert item.taken and not item.handled and not item.refused and not item.seen
    assert tools.wait_for_reply("t_a", 0)["status"] == "timeout"
    assert tools.refuse("<m@x>")["status"] == "refused"
    assert len(calls) == 2 and calls[0] == calls[1]
    assert box.flagged == [("INBOX", 1, "$AmxTaken"), ("INBOX", 1, "$AmxHandled $AmxRefused")]
    assert tools.refuse("<m@x>")["status"] == "refused"
    assert len(calls) == 2


@pytest.mark.parametrize("outcome", ["done", "refuse"])
@pytest.mark.parametrize("seen", [False, True])
def test_reply_rejects_finished_message_before_parse_or_submission(outcome, seen, monkeypatch):
    box = mailbox()
    tools = _tools(box)
    monkeypatch.setattr(
        Agent, "refuse", lambda *a, **kw: Declared("t_ctl", "<ctl@x>", "refuse dsn=sent")
    )
    getattr(tools, outcome)("<m@x>")
    box.folders["INBOX"] = [replace(box.folders["INBOX"][0], seen=seen)]
    before = box.folders["INBOX"][:]
    flags_before = box.flagged[:]

    def unexpected(*args, **kwargs):
        pytest.fail("finished messages must not be parsed or submitted")

    monkeypatch.setattr(Agent, "parse", unexpected)
    monkeypatch.setattr(Agent, "send", unexpected)
    with pytest.raises(ValueError, match="already handled"):
        tools.reply("<m@x>", "Too late")
    assert box.folders["INBOX"] == before and box.flagged == flags_before


@pytest.mark.parametrize("tool", ["reply", "done", "refuse"])
@pytest.mark.parametrize("newest_state", ["unclaimed", "handled", "legacy"])
def test_duplicate_message_ids_reject_all_actions_before_any_side_effect(
    tool, newest_state, monkeypatch
):
    box = mailbox()
    box.folders["INBOX"].append(
        replace(
            box.folders["INBOX"][0],
            uid=2,
            raw=_raw("t_other", "<m@x>", headers={"Delivered-To": "other@agents.northwind.test"}),
            handled=newest_state == "handled",
            seen=newest_state == "legacy",
        )
    )
    before = box.folders["INBOX"][:]

    def unexpected(*args, **kwargs):
        pytest.fail("ambiguous copies must not be parsed, submitted or flagged")

    monkeypatch.setattr(Agent, "parse", unexpected)
    monkeypatch.setattr(Agent, "refuse", unexpected)
    monkeypatch.setattr(Agent, "send", unexpected)
    box.flag = unexpected
    tools = _tools(box)
    with pytest.raises(ValueError, match="ambiguous"):
        if tool == "reply":
            tools.reply(" <m@x> ", "No")
        else:
            getattr(tools, tool)(" <m@x> ")
    assert box.folders["INBOX"] == before and not box.flagged


def test_refusal_without_gateway_recipient_never_submits_or_acknowledges(monkeypatch):
    box = FakeMailbox({"INBOX": [Fetched("INBOX", 1, _raw("t_a", "<m@x>"), False)]})

    def unexpected(*args, **kwargs):
        pytest.fail("must not submit without Delivered-To")

    monkeypatch.setattr(Agent, "refuse", unexpected)
    with pytest.raises(ValueError, match="Delivered-To"):
        _tools(box).refuse("<m@x>")
    assert not box.folders["INBOX"][0].handled


@pytest.mark.parametrize("tool", ["list_inbox", "read_thread", "reply", "wait_for_reply", "done"])
def test_failed_flag_is_not_reported_as_success(tool):
    box = mailbox()

    def fail(*args):
        raise RuntimeError("STORE failed")

    box.flag = fail
    tools = _tools(box)
    with pytest.raises(RuntimeError, match="STORE failed"):
        if tool == "list_inbox":
            tools.list_inbox()
        elif tool == "read_thread":
            tools.read_thread("t_a")
        elif tool == "wait_for_reply":
            tools.wait_for_reply("t_a", 0)
        elif tool == "reply":
            tools.reply("<m@x>", "Yes")
        else:
            tools.done("<m@x>")


def test_sent_held_and_finished_copies_are_never_reclaimed():
    raw = _raw("t_a", "<m@x>")
    box = FakeMailbox(
        {
            "INBOX": [Fetched("INBOX", 1, raw, False, handled=True)],
            "Sent": [Fetched("Sent", 2, raw, True)],
            "Outbox/Held": [Fetched("Outbox/Held", 3, raw, False)],
        }
    )
    tools = _tools(box)
    tools.list_inbox()
    tools.read_thread("t_a")
    tools.list_held()
    assert not box.flagged
    with pytest.raises(ValueError, match="already handled"):
        tools.refuse("<m@x>")


@pytest.mark.parametrize("tool", ["flag", "refuse"])
@pytest.mark.parametrize("failure", ["select", "store", "missing", "not-persisted", None])
def test_mailbox_flag_checks_store_and_exact_uid_readback(monkeypatch, failure, tool):
    from amx.mcp_server import AgentTools, ImapAccount, Mailbox

    commands = []

    class Imap:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def select(self, folder):
            assert folder == "INBOX"
            return ("NO" if failure == "select" else "OK"), [b""]

        def uid(self, command, *args):
            commands.append((command, args))
            assert args[0] == "7"
            if command == "STORE":
                assert args[1:] == ("+FLAGS.SILENT", "($AmxTaken)")
                return ("NO" if failure == "store" else "OK"), [b""]
            assert command == "FETCH" and args[1] == "(FLAGS)"
            if failure == "missing":
                return "OK", [None]
            flags = "" if failure == "not-persisted" else "$amxtaken"
            return "OK", [f"1 (UID 7 FLAGS ({flags}))".encode()]

    monkeypatch.setattr(Mailbox, "_connect", lambda self: Imap())
    box = Mailbox(ImapAccount("unused.invalid", 143, "fixture", "fixture"))
    calls = []

    def refuse(self, recipient, message_id, **fields):
        assert not failure
        assert [command for command, _ in commands] == ["STORE", "FETCH"]
        calls.append(message_id)
        raise smtplib.SMTPDataError(451, b"retry after verified claim")

    monkeypatch.setattr(Agent, "refuse", refuse)
    original = replace(mailbox().folders["INBOX"][0], uid=7)
    monkeypatch.setattr(box, "fetch", lambda *args, **kwargs: [original])

    def act():
        if tool == "flag":
            box.flag("INBOX", 7, "$AmxTaken")
        else:
            AgentTools(_tools(mailbox()).agent, box).refuse("<m@x>")

    if failure:
        with pytest.raises(RuntimeError):
            act()
        assert not calls
    elif tool == "refuse":
        with pytest.raises(RuntimeError, match="451"):
            act()
        assert calls == ["<m@x>"]
    else:
        act()
        assert len(commands) == 2


def test_mailbox_reads_keywords_sent_after_the_body_literal(monkeypatch):
    from amx.mcp_server import ImapAccount, Mailbox

    class Imap:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def select(self, folder, readonly=False):
            assert folder == "INBOX" and readonly
            return "OK", [b"1"]

        def uid(self, command, *args):
            if command == "SEARCH":
                return "OK", [b"7"]
            assert args == ("7", "(FLAGS BODY.PEEK[])")
            return "OK", [
                (b"1 (UID 7 BODY[] {3}", b"raw"),
                b" FLAGS ($amxtaken $AMXHANDLED $AmxRefused \\Seen))",
            ]

    monkeypatch.setattr(Mailbox, "_connect", lambda self: Imap())
    box = Mailbox(ImapAccount("unused.invalid", 143, "fixture", "fixture"))
    [item] = box.fetch("INBOX")
    assert (item.uid, item.raw, item.seen, item.taken, item.handled, item.refused) == (
        7,
        b"raw",
        True,
        True,
        True,
        True,
    )
