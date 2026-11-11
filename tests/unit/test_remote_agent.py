"""PLAN §5.9: the remote agent runner and the gateway's reads of a remote agent's INBOX."""

from __future__ import annotations

import imaplib
import re
import threading
import time
from email import policy
from email.message import EmailMessage

import pytest

from amx import mailbox as mailbox_module
from amx import runner as runner_module
from amx.adapters.lmtp import system_event
from amx.config import MailboxConfig
from amx.mailbox import HANDLED_KEYWORD, TAKEN_KEYWORD, MailboxAppender
from amx.profile import SCHEMA_BASE, Inbound, Thread, build
from amx.runner import REFUSED_KEYWORD, HandledLog, ImapLogin, Runner, bind, delivery_key
from amx.runtime import Context, Refuse, TryLater
from amx.sdk import Agent, Declared

ADDRESS = "outpost@agents.contoso.test"


class FakeImap:
    """One IMAP mailbox (UID → flags, raw) speaking only what the remote path uses."""

    def __init__(self) -> None:
        self.messages: dict[int, tuple[set[str], bytes]] = {}
        self.filed: dict[int, float] = {}  # INTERNALDATE, as epoch seconds
        self.logins: list[tuple[str, str]] = []
        self.selected: list[tuple[str, bool]] = []
        self.stored: list[tuple[str, str]] = []
        self.fail_store: str | None = None
        self.untagged_responses: dict[str, list[bytes]] = {}
        self.noops = 0
        self.announce_on_noop = False  # Stalwart: mail filed mid-pass is announced only by NOOP
        self.chatty = False

    def add(self, raw: bytes, *flags: str, filed: float | None = None) -> int:
        uid = max(self.messages, default=0) + 1
        self.messages[uid] = (set(flags), raw)
        self.filed[uid] = time.time() if filed is None else filed
        return uid

    def flags(self, uid: int) -> set[str]:
        return self.messages[uid][0]

    def __enter__(self) -> FakeImap:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def login(self, user: str, password: str) -> tuple[str, list[bytes]]:
        self.logins.append((user, password))
        return "OK", [b""]

    def noop(self) -> tuple[str, list[bytes]]:
        self.noops += 1
        if self.announce_on_noop or self.chatty:
            # A chatty server repeats EXISTS on every NOOP, grown or not (RFC 3501 allows it).
            self.untagged_responses["EXISTS"] = [str(len(self.messages)).encode()]
            self.announce_on_noop = False
        return "OK", [b"NOOP completed"]

    def select(self, folder: str, readonly: bool = False) -> tuple[str, list[bytes]]:
        self.selected.append((folder, readonly))
        return "OK", [str(len(self.messages)).encode()]

    def uid(self, command: str, *raw_args: object) -> tuple[str, list[object]]:
        args = [value.decode() if isinstance(value, bytes) else value for value in raw_args]
        if command == "SEARCH":
            criteria = [str(value) for value in args if value is not None]
            matches = [
                uid for uid, (flags, _raw) in self.messages.items() if _match(flags, criteria)
            ]
            return "OK", [" ".join(map(str, matches)).encode()]
        if command == "FETCH":
            uids, spec = str(args[0]), str(args[1])
            if spec == "(FLAGS)":
                return "OK", [
                    f"{uid} (UID {uid} FLAGS ({' '.join(sorted(self.flags(int(uid))))}))".encode()
                    for uid in uids.split(",")
                ]
            if spec == "(FLAGS INTERNALDATE)":
                return "OK", [
                    f"{uid} (UID {uid} FLAGS ({' '.join(sorted(self.flags(int(uid))))}) "
                    f"INTERNALDATE {imaplib.Time2Internaldate(self.filed[int(uid)])})".encode()
                    for uid in uids.split(",")
                ]
            fields = re.search(r"HEADER\.FIELDS \(([^)]*)\)", spec)
            data: list[object] = []
            for uid in uids.split(","):
                raw = self.messages[int(uid)][1]
                body = _header_fields(raw, fields[1].split()) if fields else raw
                data += [(f"{uid} (UID {uid} BODY[] {{{len(body)}}}".encode(), body), b")"]
            return "OK", data
        if command == "STORE":
            uid, operation, flags = str(args[0]), str(args[1]), str(args[2])
            assert operation in {"+FLAGS", "-FLAGS"}
            if self.fail_store and self.fail_store in flags:
                self.fail_store = None
                return "NO", [b"connection lost"]
            names = flags.strip("()").split()
            if operation == "+FLAGS":
                self.messages[int(uid)][0].update(names)
                self.stored.append((uid, flags))
            else:
                self.messages[int(uid)][0].difference_update(names)
                self.stored.append((uid, f"-{flags}"))
            return "OK", [b""]
        raise AssertionError(command)


def _match(flags: set[str], criteria: list[str]) -> bool:
    index, matched = 0, True
    while index < len(criteria):
        if criteria[index] == "OR":
            assert criteria[index + 1 : index + 3] == ["SEEN", "KEYWORD"]
            matched &= "\\Seen" in flags or criteria[index + 3] in flags
            index += 4
        elif criteria[index] == "UNKEYWORD":
            matched &= criteria[index + 1] not in flags
            index += 2
        elif criteria[index] == "SEEN":
            matched &= "\\Seen" in flags
            index += 1
        elif criteria[index] == "UNDELETED":
            matched &= "\\Deleted" not in flags
            index += 1
        else:
            raise AssertionError(criteria)
    return matched


def _header_fields(raw: bytes, names: list[str]) -> bytes:
    wanted = {name.casefold() for name in names}
    head = raw.split(b"\r\n\r\n", 1)[0].split(b"\r\n")
    kept = [line for line in head if line.split(b":", 1)[0].decode().casefold() in wanted]
    return b"".join(line + b"\r\n" for line in kept) + b"\r\n"


def _agent_request(task: str = "t_remote", message_id: str = "<r1@agents.northwind.test>") -> bytes:
    """An INBOX copy of a verified agent's request, as the gateway files it for outpost."""
    message = build(
        sender=f"scheduler+{task}@agents.northwind.test",
        to=f"outpost+{task}@agents.contoso.test",
        subject="Site inspection",
        intent="request",
        task=task,
        task_state="submitted",
        text="Please confirm Tuesday.",
        payload={"action": "confirm"},
        schema=f"{SCHEMA_BASE}request.json",
        message_id=message_id,
    )
    message["Agent-Lane"] = "agent"
    message["Agent-Trust"] = "verified"
    message["Agent-Verified-Domain"] = "agents.northwind.test"
    message["Agent-Verified-Selector"] = "scheduler"
    stamp = f"Delivered-To: outpost+{task}@agents.contoso.test\r\n".encode()
    return stamp + message.as_bytes(policy=policy.SMTP)


def _human_reply(*, taint: str | None = None) -> bytes:
    """A person's reply that names no task in its headers; the gateway's stamp carries it."""
    message = EmailMessage(policy=policy.SMTP)
    message["From"] = "pat@plainmail.test"
    message["To"] = ADDRESS
    message["Subject"] = "Re: quote"
    message["Message-ID"] = "<pat-1@plainmail.test>"
    message["Agent-Lane"] = "human"
    message["Agent-Trust"] = "low"
    if taint:
        message["Agent-Taint"] = taint
    message.set_content("Thursday works for me.")
    stamp = b"Delivered-To: outpost+t_quote@agents.contoso.test\r\n"
    return stamp + message.as_bytes(policy=policy.SMTP)


def _runner(tmp_path, handler, **kwargs) -> tuple[Runner, list[dict[str, object]]]:
    agent = Agent(ADDRESS, "smtp://gateway-ct:2587", "dev-outpost-token")
    sent: list[dict[str, object]] = []
    agent.send = lambda **message: sent.append(message)  # type: ignore[method-assign]
    # The gateway takes each refusal (PLAN §5.11); test_refuse.py covers its other answers.
    refusals: list[dict[str, object]] = []
    agent.refusals = refusals  # type: ignore[attr-defined]

    def refuse(recipient: str, message_id: str, **fields: object) -> Declared:
        refusals.append({"recipient": recipient, "message_id": message_id, **fields})
        return Declared("t_ctl", "<ctl@x>", "refuse dsn=sent why=verified")

    agent.refuse = refuse  # type: ignore[method-assign]
    runner = Runner(
        agent,
        ImapLogin("mailhost-ct", 143, ADDRESS, "dev-outpost"),
        handler,
        HandledLog(tmp_path / "runner.sqlite"),
        **kwargs,
    )
    return runner, sent


def test_bind_reads_the_milters_verdicts_and_the_gateways_recipient_stamp() -> None:
    agent = bind(_agent_request())
    assert (agent.lane, agent.trust, agent.task, agent.intent) == (
        "agent",
        "verified",
        "t_remote",
        "request",
    )
    assert agent.sender is not None
    assert (agent.sender.dkim_domain, agent.sender.dkim_selector) == (
        "agents.northwind.test",
        "scheduler",
    )
    human = bind(_human_reply(taint="directs-recipient"))
    assert (human.lane, human.trust, human.task) == ("human", "low", "t_quote")
    assert human.tainted and human.taint_reasons == ("directs-recipient",)


def test_bind_turns_the_gateways_event_back_into_a_system_lane_inbound() -> None:
    event = Inbound(
        intent="update",
        task="t_held",
        task_state="canceled",
        schema=None,
        payload=None,
        text="A person rejected held message <h@agents.contoso.test>. It was not sent.",
        sender=None,
        lane="system",
        trust=None,
        thread=Thread(message_id="<h@agents.contoso.test>", in_reply_to=None, references=()),
        raw=b"",
    )
    bound = bind(system_event(ADDRESS, "agents.contoso.test", event))
    assert (bound.lane, bound.intent, bound.task, bound.task_state) == (
        "system",
        "update",
        "t_held",
        "canceled",
    )
    assert bound.sender is None and bound.trust is None
    assert bound.thread.message_id == "<h@agents.contoso.test>", "the held message, as in-process"
    assert not bound.tainted
    assert "rejected held message" in bound.text


def test_bind_adds_the_tasks_taint_to_a_clean_message() -> None:
    raw = b"Agent-Task-Taint: directs-recipient\r\n" + _human_reply(taint="unjudged")
    bound = bind(raw)
    assert bound.tainted and bound.taint_reasons == ("unjudged", "directs-recipient")
    clean = bind(b"Agent-Task-Taint: directs-recipient\r\n" + _human_reply())
    assert clean.tainted and clean.taint_reasons == ("directs-recipient",)


def test_taint_reasons_keep_only_reason_tokens() -> None:
    from amx.mailbox import taint_reasons

    assert taint_reasons(["directs-recipient, unjudged", "unjudged", " parts-agree "]) == (
        "directs-recipient",
        "unjudged",
        "parts-agree",
    )
    assert taint_reasons(["bad\r\nInjected: header", "ok", "", "a b"]) == ("ok",)
    assert taint_reasons(["=?utf-8?q?x?="]) == ("tainted-input",), "present but unreadable"
    assert taint_reasons([]) == ()


def test_bind_refuses_a_forged_lane_it_cannot_trust() -> None:
    forged = _agent_request().replace(b"Agent-Lane: agent", b"Agent-Lane: robot")
    with pytest.raises(ValueError, match="invalid Agent-Lane"):
        bind(forged)


def test_delivery_key_is_the_gateways_recipient_and_message_id() -> None:
    assert delivery_key(_agent_request()) == (
        "outpost+t_remote@agents.contoso.test <r1@agents.northwind.test>"
    )
    unnamed = b"Subject: no id\r\n\r\nbody"
    assert delivery_key(unnamed).startswith(" <sha256-")


def test_runner_takes_runs_records_and_finishes_each_message_oldest_first(tmp_path) -> None:
    seen: list[tuple[str | None, Context]] = []

    def handle(message: Inbound, context: Context) -> None:
        seen.append((message.task, context))
        context.reply(text="Tuesday is booked.", task_state="completed")

    runner, sent = _runner(tmp_path, handle)
    imap = FakeImap()
    first = imap.add(_agent_request("t_a", "<a@agents.northwind.test>"))
    second = imap.add(_agent_request("t_b", "<b@agents.northwind.test>"))

    assert runner.drain(imap) == 0  # type: ignore[arg-type]
    assert [task for task, _context in seen] == ["t_a", "t_b"]
    uids = [first, second]
    for uid in uids:
        assert {"\\Seen", HANDLED_KEYWORD} <= imap.flags(uid)
        assert REFUSED_KEYWORD not in imap.flags(uid)
    # Taken before the handler ran, finished after it.
    assert [flags for _uid, flags in imap.stored] == [
        "(\\Seen)",
        f"({HANDLED_KEYWORD})",
        "(\\Seen)",
        f"({HANDLED_KEYWORD})",
    ]
    context = seen[0][1]
    assert context.agent == "outpost"
    assert context.metadata["remote"] is True
    assert str(context.metadata["recipient"]).startswith("outpost+t_")
    assert [message["task"] for message in sent] == [task for task, _context in seen]
    assert [message["to"] for message in sent] == [
        "scheduler+t_a@agents.northwind.test",
        "scheduler+t_b@agents.northwind.test",
    ]
    assert runner.drain(imap) == 0, "a finished message is never handled again"  # type: ignore[arg-type]
    assert len(seen) == 2


def test_runner_handles_by_numeric_uid_order(tmp_path) -> None:
    order: list[str | None] = []
    runner, _sent = _runner(tmp_path, lambda message, _context: order.append(message.task))
    imap = FakeImap()
    imap.messages[10] = (set(), _agent_request("t_ten", "<ten@agents.northwind.test>"))
    imap.messages[9] = (set(), _agent_request("t_nine", "<nine@agents.northwind.test>"))
    runner.drain(imap)  # type: ignore[arg-type]
    assert order == ["t_nine", "t_ten"]


def test_try_later_and_crashes_leave_the_message_waiting_and_retry_it(tmp_path) -> None:
    attempts: list[str] = []

    def flaky(_message: Inbound, _context: Context) -> None:
        attempts.append("try")
        if len(attempts) == 1:
            raise TryLater("model is busy")
        if len(attempts) == 2:
            raise RuntimeError("handler bug")

    runner, _sent = _runner(tmp_path, flaky)
    imap = FakeImap()
    uid = imap.add(_agent_request())
    assert runner.drain(imap) == 1  # type: ignore[arg-type]
    assert imap.flags(uid) == set(), "waiting again: not taken, not finished, still counted"
    assert imap.stored == [(str(uid), "(\\Seen)"), (str(uid), "-(\\Seen)")]
    assert runner.drain(imap) == 1  # type: ignore[arg-type]
    assert runner.drain(imap) == 0  # type: ignore[arg-type]
    assert imap.flags(uid) == {"\\Seen", HANDLED_KEYWORD}
    assert len(attempts) == 3


def test_a_failing_tainted_message_does_not_hold_the_runners_other_work(
    tmp_path, monkeypatch
) -> None:
    imap = FakeImap()
    gateway = _gateway_view(monkeypatch, imap)
    seen_by_gateway: list[str | None] = []

    def handle(message: Inbound, _context: Context) -> None:
        if message.tainted:
            raise RuntimeError("the tainted message breaks the handler")
        # What submission reads while the runner answers the clean message.
        seen_by_gateway.append(gateway.tainted_in_progress(ADDRESS))

    runner, _sent = _runner(tmp_path, handle)
    imap.add(_human_reply(taint="directs-recipient"))
    imap.add(_agent_request())
    assert runner.drain(imap) == 1  # type: ignore[arg-type]
    assert seen_by_gateway == [None], "the failed tainted message is not in progress any more"


def test_a_handler_that_always_fails_is_finished_after_four_attempts(tmp_path) -> None:
    def replies_then_crashes(_message: Inbound, context: Context) -> None:
        context.reply(text="Working on it.")
        raise RuntimeError("handler bug after the reply")

    runner, sent = _runner(tmp_path, replies_then_crashes)
    imap = FakeImap()
    uid = imap.add(_agent_request())
    assert [runner.drain(imap) for _ in range(3)] == [1, 1, 1]  # type: ignore[arg-type]
    assert runner.drain(imap) == 0  # type: ignore[arg-type]
    assert imap.flags(uid) == {"\\Seen", HANDLED_KEYWORD, REFUSED_KEYWORD}
    assert runner.handled.outcome(delivery_key(_agent_request())) == (
        "refused after 4 failed attempts"
    )
    assert runner.drain(imap) == 0  # type: ignore[arg-type]
    assert len(sent) == 4, "four attempts, four replies, and no more"


def test_an_unexpected_parse_error_finishes_the_copy_instead_of_wedging(
    tmp_path, monkeypatch
) -> None:
    def broken(_raw: bytes) -> Inbound:
        raise RuntimeError("parser bug")

    monkeypatch.setattr(runner_module, "bind", broken)
    runner, _sent = _runner(tmp_path, lambda _message, _context: None)
    imap = FakeImap()
    first, second = imap.add(_agent_request("t_a", "<a@x>")), imap.add(_agent_request())
    assert runner.drain(imap) == 0  # type: ignore[arg-type]
    assert REFUSED_KEYWORD in imap.flags(first) and REFUSED_KEYWORD in imap.flags(second)


def test_mail_after_an_expunge_still_counts_as_new(tmp_path) -> None:
    runner, _sent = _runner(tmp_path, lambda _message, _context: None)
    imap = FakeImap()
    runner._exists = 3
    imap.untagged_responses["EXPUNGE"] = [b"2"]  # the mailbox went down to 2...
    imap.untagged_responses["EXISTS"] = [b"3"]  # ...and a new message brought it back to 3
    assert runner._arrived(imap)  # type: ignore[arg-type]
    imap.untagged_responses["EXISTS"] = [b"3"]
    assert not runner._arrived(imap), "the same size again is not new mail"  # type: ignore[arg-type]


def test_refuse_finishes_the_message_as_refused(tmp_path) -> None:
    def refuse(_message: Inbound, _context: Context) -> None:
        raise Refuse("5.7.1", "not a request this agent takes")

    runner, _sent = _runner(tmp_path, refuse)
    imap = FakeImap()
    uid = imap.add(_agent_request())
    assert runner.drain(imap) == 0  # type: ignore[arg-type]
    assert imap.flags(uid) == {"\\Seen", HANDLED_KEYWORD, REFUSED_KEYWORD}
    outcome = runner.handled.outcome(delivery_key(_agent_request()))
    assert outcome == "refused 5.7.1 not a request this agent takes"


def test_an_unreadable_copy_is_finished_as_refused_not_retried_forever(tmp_path) -> None:
    calls: list[Inbound] = []
    runner, _sent = _runner(tmp_path, lambda message, _context: calls.append(message))
    imap = FakeImap()
    uid = imap.add(b"Delivered-To: outpost@agents.contoso.test\r\nSubject: x\r\n\r\nno lane")
    assert runner.drain(imap) == 0  # type: ignore[arg-type]
    assert calls == []
    assert REFUSED_KEYWORD in imap.flags(uid)


def test_a_connection_lost_after_the_handler_never_runs_it_twice(tmp_path) -> None:
    calls: list[str | None] = []
    runner, _sent = _runner(tmp_path, lambda message, _context: calls.append(message.task))
    imap = FakeImap()
    uid = imap.add(_agent_request())
    imap.fail_store = HANDLED_KEYWORD
    with pytest.raises(imaplib.IMAP4.error, match="connection lost"):
        runner.drain(imap)  # type: ignore[arg-type]
    assert imap.flags(uid) == {"\\Seen"}
    # A restart reads the same state file and only finishes the message.
    restarted = Runner(
        runner.agent, runner.login, runner.handler, HandledLog(tmp_path / "runner.sqlite")
    )
    assert restarted.drain(imap) == 0  # type: ignore[arg-type]
    assert calls == ["t_remote"]
    assert imap.flags(uid) == {"\\Seen", HANDLED_KEYWORD}


def test_run_logs_in_as_the_agent_and_reconnects_after_a_failure(tmp_path, monkeypatch) -> None:
    calls: list[str | None] = []
    runner, _sent = _runner(
        tmp_path, lambda message, _context: calls.append(message.task), retry_seconds=0
    )
    imap = FakeImap()
    imap.add(_agent_request())
    attempts = iter([OSError("mailhost unreachable"), imap])
    stop = threading.Event()

    def connect() -> FakeImap:
        attempt = next(attempts)
        if isinstance(attempt, Exception):
            raise attempt
        return attempt

    def one_idle(_client: object, seconds: float) -> bool:
        assert seconds == runner.idle_seconds
        stop.set()
        return False

    runner._connect = connect  # type: ignore[assignment]
    monkeypatch.setattr(runner_module, "idle", one_idle)
    runner.run(stop)
    assert imap.logins == [(ADDRESS, "dev-outpost")], "the agent's own login, not a master user"
    assert imap.selected == [("INBOX", False)]
    assert calls == ["t_remote"]


def test_mail_announced_during_a_pass_is_drained_before_idling(tmp_path, monkeypatch) -> None:
    imap = FakeImap()
    handled: list[str | None] = []

    def handle(message: Inbound, _context: Context) -> None:
        handled.append(message.task)
        if len(handled) == 1:
            # Filed while the runner works; the server says so in a STORE response, not in IDLE.
            imap.add(_agent_request("t_late", "<late@agents.northwind.test>"))
            imap.untagged_responses["EXISTS"] = [b"2"]

    runner, _sent = _runner(tmp_path, handle, retry_seconds=0)
    imap.add(_agent_request())
    stop = threading.Event()
    idles: list[list[str | None]] = []

    def one_idle(_client: object, _seconds: float) -> bool:
        idles.append(list(handled))
        stop.set()
        return False

    runner._connect = lambda: imap  # type: ignore[assignment]
    monkeypatch.setattr(runner_module, "idle", one_idle)
    runner.run(stop)
    assert idles == [["t_remote", "t_late"]], "both handled before the first IDLE"


def test_mail_announced_only_by_noop_is_drained_before_idling(tmp_path, monkeypatch) -> None:
    imap = FakeImap()
    handled: list[str | None] = []

    def handle(message: Inbound, _context: Context) -> None:
        handled.append(message.task)
        if len(handled) == 1:
            imap.add(_agent_request("t_late", "<late@agents.northwind.test>"))
            imap.announce_on_noop = True  # silent in STORE, silent at IDLE start

    runner, _sent = _runner(tmp_path, handle, retry_seconds=0)
    imap.add(_agent_request())
    stop = threading.Event()
    idles: list[list[str | None]] = []

    def one_idle(_client: object, _seconds: float) -> bool:
        idles.append(list(handled))
        stop.set()
        return False

    runner._connect = lambda: imap  # type: ignore[assignment]
    monkeypatch.setattr(runner_module, "idle", one_idle)
    runner.run(stop)
    assert idles == [["t_remote", "t_late"]]
    assert imap.noops == 2, "one NOOP found the late mail, the next found nothing"


def test_a_server_repeating_exists_does_not_keep_the_runner_from_idling(
    tmp_path, monkeypatch
) -> None:
    imap = FakeImap()
    imap.chatty = True
    runner, _sent = _runner(tmp_path, lambda _message, _context: None)
    imap.add(_agent_request())
    stop = threading.Event()
    runner._connect = lambda: imap  # type: ignore[assignment]
    monkeypatch.setattr(runner_module, "idle", lambda _client, _seconds: stop.set() or False)
    runner.run(stop)
    assert imap.noops == 1, "an unchanged EXISTS is not new mail"


def test_a_stop_finishes_the_message_in_hand_and_takes_no_other(tmp_path) -> None:
    stop = threading.Event()
    busy: list[bool] = []

    def handle(message: Inbound, _context: Context) -> None:
        busy.append(runner.busy)
        stop.set()  # SIGTERM arrives mid-handler

    runner, _sent = _runner(tmp_path, handle)
    imap = FakeImap()
    first = imap.add(_agent_request("t_a", "<a@agents.northwind.test>"))
    second = imap.add(_agent_request("t_b", "<b@agents.northwind.test>"))
    assert runner.drain(imap, stop) == 0  # type: ignore[arg-type]
    assert busy == [True] and not runner.busy
    assert HANDLED_KEYWORD in imap.flags(first), "finished, flags and all, before leaving"
    assert imap.flags(second) == set(), "not taken"


def test_main_requires_the_agents_own_credentials(monkeypatch) -> None:
    monkeypatch.delenv("AMX_IMAP_PASSWORD", raising=False)
    monkeypatch.delenv("AMX_SUBMIT_TOKEN", raising=False)
    with pytest.raises(SystemExit):
        runner_module.main(
            [
                "--agent",
                ADDRESS,
                "--imap",
                "mailhost-ct:143",
                "--submit",
                "smtp://gateway-ct:2587",
                "--handler",
                "amx.examples.intake:handle",
            ]
        )


def _gateway_view(monkeypatch, imap: FakeImap) -> MailboxAppender:
    monkeypatch.setattr(mailbox_module.imaplib, "IMAP4", lambda *_args, **_kwargs: imap)
    return MailboxAppender(MailboxConfig(host="mailhost-ct", master_password="dev-gateway"))


def test_backlog_counts_what_the_runner_has_not_finished(monkeypatch) -> None:
    imap = FakeImap()
    imap.add(_agent_request("t_a"))
    imap.add(_agent_request("t_b"), "\\Seen")
    imap.add(_agent_request("t_c"), "\\Seen", HANDLED_KEYWORD)
    imap.add(_agent_request("t_d"), "\\Deleted")
    appender = _gateway_view(monkeypatch, imap)
    assert appender.backlog(ADDRESS) == 2, "waiting plus running, not deleted"
    assert imap.logins == [(f"{ADDRESS}*gateway", "dev-gateway")]
    assert imap.selected == [("INBOX", True)], "EXAMINE: the gateway changes no flags"


def test_backlog_state_ages_the_oldest_message_nobody_has_taken(monkeypatch) -> None:
    from amx.runtime import Backlog

    imap = FakeImap()
    appender = _gateway_view(monkeypatch, imap)
    assert appender.backlog_state(ADDRESS) == Backlog(0), "an empty INBOX costs one SEARCH"
    now = 1_790_510_400.0
    imap.add(_agent_request("t_a"), "\\Seen", filed=now - 500)  # taken: running
    imap.add(_agent_request("t_b"), filed=now - 40)  # waiting
    imap.add(_agent_request("t_c"), filed=now - 5)  # waiting, newer
    imap.add(_agent_request("t_d"), "\\Seen", HANDLED_KEYWORD, filed=now - 900)  # finished
    imap.add(_agent_request("t_e"), "\\Deleted", filed=now - 800)
    state = appender.backlog_state(ADDRESS, clock=lambda: now)
    assert state.count == 3, "waiting plus running"
    assert state.oldest_untaken == pytest.approx(40, abs=1), "a taken message is not waiting"
    imap.flags(2).add("\\Seen")
    imap.flags(3).add("\\Seen")
    assert appender.backlog_state(ADDRESS, clock=lambda: now) == Backlog(3), "all taken"
    # The age is observation only: a FETCH that fails leaves it unknown, never the INBOX full.
    fetch = imap.uid
    imap.uid = lambda command, *args: (  # type: ignore[method-assign]
        ("NO", [b"message expunged"]) if command == "FETCH" else fetch(command, *args)
    )
    assert appender.backlog_state(ADDRESS, clock=lambda: now) == Backlog(3)


def test_tainted_in_progress_sees_only_tainted_mail_the_agent_has_taken(monkeypatch) -> None:
    imap = FakeImap()
    unread = imap.add(_human_reply(taint="directs-recipient"))
    imap.add(_agent_request(), "\\Seen")  # clean and in progress
    imap.add(_human_reply(taint="parts-disagree"), "\\Seen", HANDLED_KEYWORD)  # finished
    appender = _gateway_view(monkeypatch, imap)
    assert appender.tainted_in_progress(ADDRESS) is None, "unread mail steered nothing yet"
    imap.flags(unread).add("\\Seen")
    imap.add(_human_reply(taint="directs-recipient, unjudged"), "\\Seen")
    assert appender.tainted_in_progress(ADDRESS) == "directs-recipient, unjudged"
    # A clean message in a tainted task counts too, as an in-process context would; a deleted
    # message does not.
    imap.messages = {}
    imap.add(b"Agent-Task-Taint: parts-agree\r\n" + _agent_request(), "\\Seen")
    imap.add(_human_reply(taint="directs-recipient"), "\\Seen", "\\Deleted")
    assert appender.tainted_in_progress(ADDRESS) == "parts-agree"
    # A clean copy whose task was tainted after it was filed: looked up at send time.
    imap.messages = {}
    imap.add(_agent_request("t_later"), "\\Seen")
    human = imap.add(_human_reply(), "\\Seen")  # its task comes from the Delivered-To stamp
    stored = {"t_later": "directs-recipient", "t_quote": "unjudged"}
    assert appender.tainted_in_progress(ADDRESS, stored.get) == "directs-recipient, unjudged"
    imap.flags(human).add(HANDLED_KEYWORD)
    assert appender.tainted_in_progress(ADDRESS, {}.get) is None


def test_mcp_custody_opens_taint_window_and_done_drains_backlog(monkeypatch) -> None:
    imap = FakeImap()
    uid = imap.add(_human_reply(taint="directs-recipient"), TAKEN_KEYWORD)
    appender = _gateway_view(monkeypatch, imap)
    assert appender.backlog(ADDRESS) == 1
    assert appender.backlog_state(ADDRESS).oldest_untaken is None
    assert appender.tainted_in_progress(ADDRESS) == "directs-recipient"
    imap.flags(uid).add(HANDLED_KEYWORD)
    assert appender.backlog(ADDRESS) == 0
    assert appender.tainted_in_progress(ADDRESS) is None
    assert "\\Seen" not in imap.flags(uid)


def test_a_remote_handler_declares_through_the_runners_own_submission(tmp_path) -> None:
    declared: list[tuple[str, dict[str, object]]] = []

    def pauses(_message: Inbound, context: Context) -> None:
        context.declare("pause", until="2026-09-27T12:10:00Z", reason="upstream-unavailable")

    runner, _sent = _runner(tmp_path, pauses)
    runner.agent.declare = lambda command, **fields: declared.append((command, fields))  # type: ignore[method-assign]
    imap = FakeImap()
    imap.add(_agent_request())
    assert runner.drain(imap) == 0  # type: ignore[arg-type]
    assert declared == [
        ("pause", {"until": "2026-09-27T12:10:00Z", "reason": "upstream-unavailable"})
    ]


def test_the_runner_takes_its_credentials_from_the_operators_bundle(tmp_path, monkeypatch) -> None:
    from amx import runner as runner_module
    from amx.credentials import write_bundle

    write_bundle(
        tmp_path / "probe.json",
        {
            "address": "probe@agents.example.test",
            "imap": "imaps://mail.example.test",
            "submission": "smtp://mail.example.test:2588",
            "password": "the-password",
            "token": "the-token",
        },
    )
    built: dict = {}

    class FakeRunner:
        busy = False

        def __init__(self, agent, login, handler, log, *, idle_seconds) -> None:
            built.update(agent=agent, login=login)

        def run(self, _stop) -> None:
            return None

    monkeypatch.delenv("AMX_IMAP_PASSWORD", raising=False)
    monkeypatch.delenv("AMX_SUBMIT_TOKEN", raising=False)
    monkeypatch.setattr(runner_module, "Runner", FakeRunner)
    runner_module.main(
        [
            "--credentials",
            str(tmp_path / "probe.json"),
            "--handler",
            "amx.examples.echo:handle",
            "--state",
            str(tmp_path / "state"),
        ]
    )
    agent, login = built["agent"], built["login"]
    assert agent.address == "probe@agents.example.test" and agent.token == "the-token"
    assert (login.host, login.port, login.tls, login.username, login.password) == (
        "mail.example.test",
        993,
        True,
        "probe@agents.example.test",
        "the-password",
    )


def test_the_runner_without_a_bundle_still_needs_its_environment(monkeypatch, capsys) -> None:
    from amx import runner as runner_module

    monkeypatch.delenv("AMX_IMAP_PASSWORD", raising=False)
    monkeypatch.delenv("AMX_SUBMIT_TOKEN", raising=False)
    with pytest.raises(SystemExit):
        runner_module.main(
            [
                "--agent",
                "a@agents.example.test",
                "--imap",
                "h:1",
                "--submit",
                "smtp://h:2",
                "--handler",
                "amx.examples.echo:handle",
            ]
        )
    assert "AMX_IMAP_PASSWORD" in capsys.readouterr().err
