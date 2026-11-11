from __future__ import annotations

import socket
from email import policy
from email.message import EmailMessage
from pathlib import Path

import pytest

from amx.adapters.holdwatch import DONE_KEYWORD, FolderWatcher, idle
from amx.config import MailboxConfig


def _raw(message_id: str) -> bytes:
    message = EmailMessage(policy=policy.SMTP)
    message["Message-ID"] = message_id
    message["Subject"] = "held"
    message.set_content("body")
    return message.as_bytes()


class FakeFolder:
    """The subset of imaplib.IMAP4 a FolderWatcher drain uses."""

    def __init__(self, messages: dict[bytes, bytes], flagged: set[bytes] | None = None) -> None:
        self.messages = messages
        self.flagged = flagged or set()
        self.commands: list[tuple[str, ...]] = []

    def uid(self, command: str, *args: object):
        self.commands.append((command, *(str(arg) for arg in args if arg is not None)))
        if command == "SEARCH":
            assert args[1:] == ("UNKEYWORD", DONE_KEYWORD)
            pending = [uid for uid in self.messages if uid not in self.flagged]
            return "OK", [b" ".join(pending)]
        uid = args[0]
        assert isinstance(uid, bytes)
        if command == "FETCH":
            return "OK", [(b"1 (UID 1 BODY[] {3}", self.messages[uid]), b")"]
        if command == "MOVE":
            del self.messages[uid]
            return "OK", [b""]
        if command == "STORE":
            self.flagged.add(uid)
            return "OK", [b""]
        raise AssertionError(command)


def _watcher(action) -> FolderWatcher:
    return FolderWatcher(
        MailboxConfig(host="mail.test"), "scheduler@agents.test", "Outbox/Approved", action
    )


def test_drain_moves_released_flags_ignored_and_retries_failures() -> None:
    folder = FakeFolder(
        {b"1": _raw("<release@test>"), b"2": _raw("<unknown@test>"), b"3": _raw("<boom@test>")}
    )

    def action(raw: bytes) -> str | None:
        if b"<boom@test>" in raw:
            raise OSError("postfix down")
        return "Sent" if b"<release@test>" in raw else None

    assert _watcher(action).drain(folder) == 2  # type: ignore[arg-type]
    assert ("MOVE", "b'1'", "Sent") in folder.commands
    assert folder.flagged == {b"2"}
    assert list(folder.messages) == [b"2", b"3"], "the failed message stays for the next cycle"
    assert _watcher(lambda _raw: None).drain(folder) == 1  # type: ignore[arg-type]
    assert folder.flagged == {b"2", b"3"}


class FakeIdleServer:
    """Scripted server lines behind imaplib's documented send/readline/socket methods."""

    def __init__(self, lines: list[bytes], *, readable: bool) -> None:
        self.lines = lines
        self.sent: list[bytes] = []
        self._ours, self._theirs = socket.socketpair()
        if readable:
            self._theirs.send(b"x")

    def send(self, data: bytes) -> None:
        self.sent.append(data)

    def readline(self) -> bytes:
        return self.lines.pop(0) if self.lines else b""

    def socket(self) -> socket.socket:
        return self._ours

    def close(self) -> None:
        self._ours.close()
        self._theirs.close()


def test_idle_wakes_on_an_untagged_response_and_ends_with_done() -> None:
    server = FakeIdleServer(
        [b"+ idling\r\n", b"* 1 EXISTS\r\n", b"* 1 RECENT\r\n", b"AMXIDLE OK Idle completed\r\n"],
        readable=True,
    )
    assert idle(server, 5) is True  # type: ignore[arg-type]
    assert server.sent == [b"AMXIDLE IDLE\r\n", b"DONE\r\n"]
    server.close()


def test_idle_times_out_quietly_and_rejects_refusal_or_failure() -> None:
    quiet = FakeIdleServer([b"+ idling\r\n", b"AMXIDLE OK done\r\n"], readable=False)
    assert idle(quiet, 0.01) is False  # type: ignore[arg-type]
    quiet.close()
    import imaplib

    refused = FakeIdleServer([b"AMXIDLE BAD no idle\r\n"], readable=False)
    with pytest.raises(imaplib.IMAP4.error, match="IDLE refused"):
        idle(refused, 0.01)  # type: ignore[arg-type]
    refused.close()
    closed = FakeIdleServer([b"+ idling\r\n"], readable=False)
    with pytest.raises(imaplib.IMAP4.abort):
        idle(closed, 0.01)  # type: ignore[arg-type]
    closed.close()


def _gateway(mailbox: MailboxConfig):
    from amx.config import GatewayConfig, LimitsConfig

    return GatewayConfig(
        domain="contoso.test",
        agent_domain="agents.contoso.test",
        data_dir=Path("/nonexistent"),
        agents={},
        trust=(),
        limits=LimitsConfig(),
        mailbox=mailbox,
    )


class RecordingService:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, bytes]] = []

    def approve(self, agent: str, raw: bytes) -> None:
        self.calls.append(("approve", agent, raw))

    def reject(self, agent: str, raw: bytes) -> None:
        self.calls.append(("reject", agent, raw))


def test_watchers_open_each_agents_queue_where_it_lives() -> None:
    from amx.adapters.holdwatch import watchers_for

    service = RecordingService()
    own = watchers_for(_gateway(MailboxConfig(host="mail")), ["intake"], service)  # type: ignore[arg-type]
    assert [(w.address, w.folder) for w in own] == [
        ("intake@agents.contoso.test", "Outbox/Approved"),
        ("intake@agents.contoso.test", "Outbox/Rejected"),
    ]
    shared = MailboxConfig(
        host="mail", hold_owner="holds@contoso.test", hold_prefix="Holds/{agent}/"
    )
    watchers = watchers_for(_gateway(shared), ["intake", "inspections"], service)  # type: ignore[arg-type]
    assert [(w.address, w.folder) for w in watchers] == [
        ("holds@contoso.test", "Holds/intake/Approved"),
        ("holds@contoso.test", "Holds/intake/Rejected"),
        ("holds@contoso.test", "Holds/inspections/Approved"),
        ("holds@contoso.test", "Holds/inspections/Rejected"),
    ]
    # Each watcher still decides for its own agent, although they share one mailbox.
    for watcher in watchers:
        watcher.action(b"raw")
    assert [call[:2] for call in service.calls[-4:]] == [
        ("approve", "intake"),
        ("reject", "intake"),
        ("approve", "inspections"),
        ("reject", "inspections"),
    ]
    assert not any(watcher.is_alive() for watcher in own + watchers), "built, not started"


def test_drain_quotes_a_destination_with_a_space() -> None:
    folder = FakeFolder({b"1": _raw("<release@test>")})
    _watcher(lambda _raw: "Shared Folders/x/Held").drain(folder)  # type: ignore[arg-type]
    assert ("MOVE", "b'1'", '"Shared Folders/x/Held"') in folder.commands
