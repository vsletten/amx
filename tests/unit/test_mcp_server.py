from __future__ import annotations

import asyncio
import smtplib
from dataclasses import replace
from email import policy

import pytest

from amx import mcp_server
from amx.mcp_server import AgentTools, Fetched, summarize
from amx.profile import build
from amx.sdk import Agent, Declared, Sent

ADDRESS = "scheduler@agents.northwind.test"


def _raw(
    task: str,
    message_id: str,
    *,
    sender: str = "intake+{task}@agents.contoso.test",
    text: str = "Thursday at 9 works.",
    headers: dict[str, str] | None = None,
    payload: dict[str, object] | None = None,
) -> bytes:
    message = build(
        sender=sender.format(task=task),
        to=f"scheduler+{task}@agents.northwind.test",
        cc="victor@northwind.test",
        subject="Re: Site inspection",
        intent="response",
        task=task,
        task_state="working",
        text=text,
        payload=payload,
        schema="https://evtmail.ai/schema/0.1/response.json" if payload else None,
        message_id=message_id,
        in_reply_to="<request@x>",
    )
    for name, value in (headers or {}).items():
        message[name] = value
    return message.as_bytes(policy=policy.SMTP)


AGENT_LANE = {
    "Agent-Lane": "agent",
    "Agent-Trust": "verified",
    "Agent-Verified-Domain": "agents.contoso.test",
    "Agent-Verified-Selector": "intake",
}


class FakeMailbox:
    def __init__(self, folders: dict[str, list[Fetched]]) -> None:
        self.folders = folders
        self.flagged: list[tuple[str, int, str]] = []

    def fetch(self, folder, *, unseen_only=False, limit=None):
        items = sorted(self.folders.get(folder, []), key=lambda item: item.uid, reverse=True)
        items = [item for item in items if not (unseen_only and item.seen)]
        return items[:limit] if limit is not None else items

    def flag(self, folder, uid, flags):
        self.flagged.append((folder, uid, flags))
        self.folders[folder] = [
            replace(
                item,
                taken=item.taken or "$AmxTaken" in flags,
                handled=item.handled or "$AmxHandled" in flags,
                refused=item.refused or "$AmxRefused" in flags,
            )
            if item.uid == uid
            else item
            for item in self.folders[folder]
        ]


def _tools(mailbox: FakeMailbox, **kwargs) -> AgentTools:
    return AgentTools(Agent(ADDRESS, "smtp://127.0.0.1:2587", "token"), mailbox, **kwargs)


def test_summary_reports_profile_fields_and_the_receiving_gateways_verdicts() -> None:
    raw = _raw(
        "t_a",
        "<m1@agents.contoso.test>",
        headers={**AGENT_LANE, "Agent-Taint": "directs_recipient"},
        payload={"result": {"action": "confirm", "slot": "thu-09"}},
    )
    summary = summarize(Fetched("INBOX", 7, raw, False), full=True)
    assert summary["message_id"] == "<m1@agents.contoso.test>"
    assert summary["from"] == "intake+t_a@agents.contoso.test"
    assert summary["cc"] == ["victor@northwind.test"]
    assert (summary["intent"], summary["task"], summary["task_state"]) == (
        "response",
        "t_a",
        "working",
    )
    assert summary["lane"] == "agent"
    assert summary["verified"] == "agents.contoso.test/intake"
    assert summary["tainted"] is True
    assert summary["taint_reasons"] == "directs_recipient"
    assert summary["text"] == "Thursday at 9 works."
    assert summary["payload"]["result"]["slot"] == "thu-09"


def test_verdict_fields_are_reported_only_for_delivered_mail() -> None:
    # Sent and Held copies were written by this agent, so no gateway verdict applies to them.
    raw = _raw("t_a", "<m1@x>", headers={**AGENT_LANE, "Agent-Hold-Rule": "tainted-input"})
    held = summarize(Fetched("Outbox/Held", 1, raw, False))
    assert "lane" not in held and "tainted" not in held
    assert held["hold_rule"] == "tainted-input"
    assert "lane" not in summarize(Fetched("Sent", 1, raw, False))


def test_wait_for_reply_returns_oldest_unread_untaken_message_without_seen() -> None:
    mailbox = FakeMailbox(
        {
            "INBOX": [
                Fetched("INBOX", 1, _raw("t_a", "<old@x>"), True),
                Fetched("INBOX", 2, _raw("t_other", "<other@x>"), False),
                Fetched("INBOX", 3, _raw("t_a", "<first@x>"), False),
                Fetched("INBOX", 4, _raw("t_a", "<second@x>"), False),
            ]
        }
    )
    tools = _tools(mailbox)
    first = tools.wait_for_reply("t_a", 0)
    assert first["status"] == "received"
    assert first["message"]["message_id"] == "<first@x>"
    assert first["message"]["seen"] is False
    assert first["message"]["taken"] is True
    assert tools.wait_for_reply("t_a", 0)["message"]["message_id"] == "<second@x>"
    assert tools.wait_for_reply("t_a", 0) == {"status": "timeout", "task": "t_a"}
    assert mailbox.flagged == [("INBOX", 3, "$AmxTaken"), ("INBOX", 4, "$AmxTaken")]


def test_wait_for_reply_polls_until_a_message_arrives() -> None:
    mailbox = FakeMailbox({"INBOX": []})
    now = [0.0]

    def sleep(seconds: float) -> None:
        now[0] += seconds
        if now[0] >= 3:
            mailbox.folders["INBOX"] = [Fetched("INBOX", 9, _raw("t_a", "<late@x>"), False)]

    tools = _tools(mailbox, clock=lambda: now[0], sleep=sleep, poll_seconds=1.0)
    assert tools.wait_for_reply("t_a", 10)["message"]["message_id"] == "<late@x>"
    assert now[0] == 3.0


def test_wait_for_reply_caps_the_wait() -> None:
    now = [0.0]

    def sleep(seconds: float) -> None:
        now[0] += seconds

    tools = _tools(FakeMailbox({}), clock=lambda: now[0], sleep=sleep, poll_seconds=50.0)
    assert tools.wait_for_reply("t_a", 10_000)["status"] == "timeout"
    assert now[0] == mcp_server.MAX_WAIT_SECONDS


def test_read_thread_merges_folders_oldest_first_and_skips_other_tasks() -> None:
    sent = _raw("t_a", "<request@x>", sender="scheduler+{task}@agents.northwind.test")
    mailbox = FakeMailbox(
        {
            "Sent": [Fetched("Sent", 1, sent, True)],
            "INBOX": [
                Fetched("INBOX", 5, _raw("t_a", "<reply@x>"), False),
                Fetched("INBOX", 6, _raw("t_b", "<elsewhere@x>"), False),
            ],
        }
    )
    thread = _tools(mailbox).read_thread("t_a")
    assert {message["message_id"] for message in thread} == {"<request@x>", "<reply@x>"}
    assert all("text" in message for message in thread)


def test_read_thread_orders_a_same_second_reply_after_its_request() -> None:
    request = build(
        sender="scheduler+t_a@agents.northwind.test",
        to="intake+t_a@agents.contoso.test",
        subject="Inspection",
        intent="request",
        task="t_a",
        task_state="submitted",
        text="Please inspect.",
        message_id="<request@x>",
    )
    reply = build(
        sender="intake+t_a@agents.contoso.test",
        to="scheduler+t_a@agents.northwind.test",
        subject="Re: Inspection",
        intent="response",
        task="t_a",
        task_state="completed",
        text="Done.",
        message_id="<reply@x>",
        in_reply_to="<request@x>",
        references=("<request@x>",),
    )
    same_second = "Fri, 25 Sep 2026 22:24:10 +0000"
    for message in (request, reply):
        del message["Date"]
        message["Date"] = same_second
    mailbox = FakeMailbox(
        {
            "INBOX": [Fetched("INBOX", 1, reply.as_bytes(policy=policy.SMTP), False)],
            "Sent": [Fetched("Sent", 1, request.as_bytes(policy=policy.SMTP), True)],
        }
    )
    thread = _tools(mailbox).read_thread("t_a")
    assert [message["message_id"] for message in thread] == ["<request@x>", "<reply@x>"]


def test_read_thread_compares_dates_across_time_zones() -> None:
    early = _raw("t_a", "<early@x>")
    late = _raw("t_a", "<late@x>")
    early = early.replace(b"Date: ", b"X-Old-Date: ", 1).replace(
        b"\r\n\r\n", b"\r\nDate: Fri, 25 Sep 2026 23:00:00 +0000\r\n\r\n", 1
    )
    late = late.replace(b"Date: ", b"X-Old-Date: ", 1).replace(
        b"\r\n\r\n", b"\r\nDate: Fri, 25 Sep 2026 17:00:00 -0700\r\n\r\n", 1
    )
    # 17:00 -0700 is 00:00 UTC the next day, after 23:00 UTC, though "17:00" sorts first as text.
    mailbox = FakeMailbox(
        {"INBOX": [Fetched("INBOX", 1, late, False), Fetched("INBOX", 2, early, False)]}
    )
    thread = _tools(mailbox).read_thread("t_a")
    assert [message["message_id"] for message in thread] == ["<early@x>", "<late@x>"]


def test_reply_answers_the_named_message_in_its_task(monkeypatch) -> None:
    mailbox = FakeMailbox({"INBOX": [Fetched("INBOX", 1, _raw("t_a", "<m1@x>"), False)]})
    calls: list[dict[str, object]] = []

    def fake_send(self, **message):
        calls.append(message)
        return Sent(message["task"], "<reply@agents.northwind.test>", "tainted-input")

    monkeypatch.setattr(Agent, "send", fake_send)
    result = _tools(mailbox).reply("<m1@x>", "Confirmed.", cc=["victor@northwind.test"])
    assert result == {
        "task": "t_a",
        "message_id": "<reply@agents.northwind.test>",
        "held": "tainted-input",
    }
    assert calls[0]["to"] == "intake+t_a@agents.contoso.test"
    assert calls[0]["cc"] == ["victor@northwind.test"]
    assert calls[0]["in_reply_to"] == "<m1@x>"
    with pytest.raises(LookupError):
        _tools(mailbox).reply("<missing@x>", "No.")


def test_gateway_refusals_become_readable_tool_errors(monkeypatch) -> None:
    def refused(self, **_message):
        raise smtplib.SMTPDataError(550, b"5.7.1 intent or schema is not granted")

    monkeypatch.setattr(Agent, "send", refused)
    with pytest.raises(RuntimeError, match=r"550 5\.7\.1 intent or schema is not granted"):
        _tools(FakeMailbox({})).send(["pat@plainmail.test"], "Hi", "Hello.")


def test_the_server_exposes_exactly_the_planned_tools() -> None:
    server = mcp_server.build_server(_tools(FakeMailbox({})))
    names = {tool.name for tool in asyncio.run(server.list_tools())}
    assert names == {
        "list_inbox",
        "read_thread",
        "send",
        "reply",
        "wait_for_reply",
        "list_held",
        "declare_state",  # PLAN §5.10
        "save_attachment",  # SH-42
        "done",
        "refuse",
    }


def test_declare_state_sends_the_agents_declaration_through_the_sdk(monkeypatch) -> None:
    calls: list[tuple[str, dict[str, object]]] = []

    def declare(self, command, **fields):
        calls.append((command, fields))
        return Declared("t_ctl", "<ctl@agents.contoso.test>", f"{command} applied")

    monkeypatch.setattr(Agent, "declare", declare)
    tools = _tools(FakeMailbox({}))
    assert tools.declare_state("resume") == {"applied": "resume applied", "task": "t_ctl"}
    tools.declare_state("capacity", max_messages=1, ttl_seconds=60)
    tools.declare_state("pause", seconds=30, reason="overloaded")
    assert [command for command, _fields in calls] == ["resume", "capacity", "pause"]
    assert calls[1][1] == {"max": 1, "ttl_seconds": 60}
    assert calls[2][1]["reason"] == "overloaded" and str(calls[2][1]["until"]).endswith("Z")
    with pytest.raises(ValueError, match="pause \\(with seconds\\)"):
        tools.declare_state("pause")
    with pytest.raises(ValueError):
        tools.declare_state("refuse")


def test_a_refused_declaration_becomes_a_readable_tool_error(monkeypatch) -> None:
    def refused(self, command, **_fields):
        raise smtplib.SMTPDataError(550, b"5.7.1 until is more than 3600 s ahead")

    monkeypatch.setattr(Agent, "declare", refused)
    with pytest.raises(RuntimeError, match=r"550 5\.7\.1 until is more than 3600 s ahead"):
        _tools(FakeMailbox({})).declare_state("pause", seconds=7200)


def test_main_requires_credentials_from_the_environment(monkeypatch) -> None:
    monkeypatch.delenv("AMX_IMAP_PASSWORD", raising=False)
    monkeypatch.delenv("AMX_SUBMIT_TOKEN", raising=False)
    with pytest.raises(SystemExit):
        mcp_server.main(["--agent", ADDRESS])


SHARED_HELD = "Shared Folders/holds@contoso.test/Holds/intake/Held"


def test_list_held_and_read_thread_use_the_configured_hold_folder() -> None:
    # On Stalwart the agent's hold queue is another account's folder, shared read-only.
    raw = _raw("t_a", "<held@x>", headers={"Agent-Hold-Rule": "tainted-input"})
    mailbox = FakeMailbox(
        {
            "Outbox/Held": [Fetched("Outbox/Held", 1, _raw("t_a", "<stale@x>"), False)],
            SHARED_HELD: [Fetched(SHARED_HELD, 5, raw, False)],
        }
    )
    tools = _tools(mailbox, held_folder=SHARED_HELD)
    [held] = tools.list_held()
    assert (held["message_id"], held["folder"], held["hold_rule"]) == (
        "<held@x>",
        SHARED_HELD,
        "tainted-input",
    )
    assert [item["message_id"] for item in tools.read_thread("t_a")] == ["<held@x>"]
    assert [item["message_id"] for item in _tools(mailbox).list_held()] == ["<stale@x>"]


def test_main_passes_the_hold_folder_through(monkeypatch) -> None:
    served: list[AgentTools] = []

    class Server:
        def run(self) -> None:
            pass

    def build(tools: AgentTools) -> Server:
        served.append(tools)
        return Server()

    monkeypatch.setenv("AMX_IMAP_PASSWORD", "pw")
    monkeypatch.setenv("AMX_SUBMIT_TOKEN", "token")
    monkeypatch.setattr(mcp_server, "build_server", build)
    mcp_server.main(["--agent", "intake@agents.contoso.test", "--held-folder", SHARED_HELD])
    mcp_server.main(["--agent", ADDRESS])
    assert [tools.held_folder for tools in served] == [SHARED_HELD, "Outbox/Held"]
    assert served[0].mailbox.account.port == 1432  # type: ignore[attr-defined]


def test_the_instructions_name_the_hold_folder() -> None:
    server = mcp_server.build_server(_tools(FakeMailbox({}), held_folder=SHARED_HELD))
    assert f"it waits in {SHARED_HELD} until a person" in server.instructions


def test_mailbox_fetch_quotes_a_shared_folder(monkeypatch) -> None:
    import imaplib

    selected: list[tuple[str, bool]] = []

    class FakeImap:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def login(self, _user: str, _password: str) -> None:
            return None

        def select(self, folder: str, readonly: bool = False):
            selected.append((folder, readonly))
            return "OK", [b"0"]

        def uid(self, *_args):
            return "OK", [b""]

    monkeypatch.setattr(imaplib, "IMAP4", FakeImap)
    account = mcp_server.ImapAccount("127.0.0.1", 1432, "intake@agents.contoso.test", "pw")
    assert mcp_server.Mailbox(account).fetch(SHARED_HELD) == []
    assert selected == [(f'"{SHARED_HELD}"', True)]
