from __future__ import annotations

import smtplib
import subprocess
from email import policy
from email.parser import BytesParser
from pathlib import Path

import pytest

from amx.adapters.submission import SubmissionService
from amx.config import AgentConfig, GatewayConfig, LimitsConfig, MailboxConfig, TrustGrant
from amx.journal import Journal
from amx.profile import SCHEMA_BASE, build
from amx.sdk import Agent
from amx.store import Store


def _config(tmp_path, port: int) -> GatewayConfig:
    keys = tmp_path / "keys"
    keys.mkdir()
    subprocess.run(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:1024",
            "-out",
            str(keys / "scheduler.private.pem"),
        ],
        check=True,
        capture_output=True,
    )
    return GatewayConfig(
        domain="northwind.test",
        agent_domain="agents.northwind.test",
        data_dir=tmp_path,
        agents={"scheduler": AgentConfig("mailbox-only", submit_token="submit-secret")},
        trust=(
            TrustGrant(
                d="agents.northwind.test",
                s="scheduler",
                intents=frozenset({"*"}),
                schemas=frozenset({"*"}),
                can_open_tasks=True,
            ),
        ),
        limits=LimitsConfig(),
        mailbox=MailboxConfig("unused"),
        keys_dir=keys,
        submission_host="127.0.0.1",
        submission_port=port,
    )


def test_agent_send_and_reply_use_authenticated_submission(tmp_path, monkeypatch) -> None:
    port = 2587
    config = _config(tmp_path, port)
    reinjected: list[tuple[str, tuple[str, ...], bytes]] = []
    service = SubmissionService(
        config,
        Journal(tmp_path, Store(tmp_path / "journal.sqlite")),
        reinject=lambda sender, recipients, raw: reinjected.append((sender, recipients, raw)),
    )

    class LocalSMTP:
        def __init__(self, host: str, actual_port: int, timeout: int) -> None:
            assert (host, actual_port, timeout) == ("127.0.0.1", port, 15)
            self.credentials: tuple[str, str] | None = None

        def __enter__(self):
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def login(self, agent: str, token: str) -> None:
            self.credentials = (agent, token)

        def starttls(self, *, context) -> None:
            assert context is not None

        def mail(self, _sender: str) -> tuple[int, bytes]:
            return 250, b"2.1.0 ok"

        def rcpt(self, _recipient: str) -> tuple[int, bytes]:
            return 250, b"2.1.5 ok"

        def rset(self) -> None:
            return None

        def data(self, raw: bytes) -> tuple[int, bytes]:
            assert self.credentials is not None
            result = service.submit(*self.credentials, raw)
            detail = f"2.0.0 held rule={result.held}" if result.held else "2.0.0 submitted"
            return 250, detail.encode()

    monkeypatch.setattr(smtplib, "SMTP", LocalSMTP)
    agent = Agent(
        "scheduler@agents.northwind.test",
        f"smtp://127.0.0.1:{port}",
        "submit-secret",
    )
    sent = agent.send(
        to="intake@agents.contoso.test",
        subject="Need a quote",
        intent="request",
        payload={"action": "quote"},
        schema=f"{SCHEMA_BASE}request.json",
        text="Please quote this work.",
        cc="victor@northwind.test",
    )
    assert sent.task.startswith("t_")
    assert sent.message_id.startswith("<")
    assert sent.held is None
    assert len(reinjected) == 1
    envelope_from, recipients, _raw = reinjected[0]
    assert envelope_from == f"scheduler+{sent.task}@agents.northwind.test"
    assert recipients == (
        f"intake+{sent.task}@agents.contoso.test",
        "victor@northwind.test",
    )

    inbound_raw = build(
        sender=f"intake+{sent.task}@agents.contoso.test",
        to=f"scheduler+{sent.task}@agents.northwind.test",
        subject="Quote response",
        intent="response",
        task=sent.task,
        task_state="working",
        text="The quote is ready.",
        in_reply_to=sent.message_id,
        references=(sent.message_id,),
        message_id="<reply@agents.contoso.test>",
    ).as_bytes(policy=policy.SMTP)
    received = agent.parse(inbound_raw)
    replied = received.reply(intent="response", text="Accepted.", task_state="completed")
    assert replied.task == sent.task
    reply_message = BytesParser(policy=policy.default).parsebytes(reinjected[-1][2])
    assert reply_message["In-Reply-To"] == "<reply@agents.contoso.test>"
    assert reply_message["References"] == f"{sent.message_id} <reply@agents.contoso.test>"


def test_agent_parse_maps_dsn_to_failed_task_state() -> None:
    agent = Agent("scheduler@agents.northwind.test", "smtp://127.0.0.1:2587", "unused")
    received = agent.parse(Path("spec/corpus/10-dsn-failed.eml").read_bytes())
    assert received.intent == "error"
    assert received.task_state == "failed"
    assert received.task is not None
    assert agent.task_state(received.task) == "failed"
    assert received.diagnostic


def test_agent_send_preserves_every_recipient_in_comma_separated_string(monkeypatch) -> None:
    captured: list[list[str]] = []

    class CapturingSMTP:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def login(self, _agent: str, _token: str) -> None:
            return None

        def starttls(self, *, context) -> None:
            assert context is not None

        def mail(self, _sender: str) -> tuple[int, bytes]:
            captured.append([])
            return 250, b"2.1.0 ok"

        def rcpt(self, recipient: str) -> tuple[int, bytes]:
            captured[-1].append(recipient)
            return 250, b"2.1.5 ok"

        def data(self, _raw: bytes) -> tuple[int, bytes]:
            return 250, b"2.0.0 submitted"

    monkeypatch.setattr(smtplib, "SMTP", CapturingSMTP)
    agent = Agent("scheduler@agents.northwind.test", "smtp://127.0.0.1:2587", "secret")

    sent = agent.send(
        to="a@agents.contoso.test, b@agents.contoso.test",
        subject="Both recipients",
        intent="request",
        text="Send to both.",
    )

    assert captured == [
        [
            f"a+{sent.task}@agents.contoso.test",
            f"b+{sent.task}@agents.contoso.test",
        ]
    ]


class _ReplySMTP:
    """A submission port that answers DATA with a fixed reply (and optionally refuses RCPTs)."""

    reply: tuple[int, bytes] = (250, b"2.0.0 submitted")
    refuse: frozenset[str] = frozenset()

    def __init__(self, *_args, **_kwargs) -> None:
        self.reset = 0

    def __enter__(self):
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def login(self, _agent: str, _token: str) -> None:
        return None

    def starttls(self, *, context) -> None:
        assert context is not None

    def mail(self, _sender: str) -> tuple[int, bytes]:
        return 250, b"2.1.0 ok"

    def rcpt(self, recipient: str) -> tuple[int, bytes]:
        if recipient.split("+")[0].split("@")[0] in self.refuse:
            return 550, b"5.1.1 no such agent"
        return 250, b"2.1.5 ok"

    def rset(self) -> None:
        self.reset += 1

    def data(self, _raw: bytes) -> tuple[int, bytes]:
        return self.reply


def test_agent_send_reports_a_gateway_hold(monkeypatch) -> None:
    class Held(_ReplySMTP):
        reply = (250, b"2.0.0 held rule=tainted-input folder=Outbox/Held")

    monkeypatch.setattr(smtplib, "SMTP", Held)
    agent = Agent("scheduler@agents.northwind.test", "smtp://127.0.0.1:2587", "secret")
    sent = agent.send(to="pat@plainmail.test", subject="Hi", intent="request", text="Hello.")
    assert sent.held == "tainted-input"


def test_agent_send_raises_when_every_recipient_is_refused(monkeypatch) -> None:
    class Refusing(_ReplySMTP):
        refuse = frozenset({"a", "b"})

    monkeypatch.setattr(smtplib, "SMTP", Refusing)
    agent = Agent("scheduler@agents.northwind.test", "smtp://127.0.0.1:2587", "secret")
    with pytest.raises(smtplib.SMTPRecipientsRefused):
        agent.send(
            to="a@agents.contoso.test, b@agents.contoso.test",
            subject="Nobody",
            intent="request",
            text="Refused.",
        )


def test_agent_send_raises_on_a_data_refusal(monkeypatch) -> None:
    class Refusing(_ReplySMTP):
        reply = (550, b"5.7.1 not authorized for this intent")

    monkeypatch.setattr(smtplib, "SMTP", Refusing)
    agent = Agent("scheduler@agents.northwind.test", "smtp://127.0.0.1:2587", "secret")
    with pytest.raises(smtplib.SMTPDataError):
        agent.send(to="pat@plainmail.test", subject="No", intent="request", text="Refused.")


def test_a_refusal_is_not_hidden_by_a_disconnect_during_rset(monkeypatch) -> None:
    class Hangup(_ReplySMTP):
        reply = (554, b"5.7.1 refused")

        def rset(self) -> None:
            raise smtplib.SMTPServerDisconnected("gone")

    monkeypatch.setattr(smtplib, "SMTP", Hangup)
    agent = Agent("scheduler@agents.northwind.test", "smtp://127.0.0.1:2587", "secret")
    with pytest.raises(smtplib.SMTPDataError):
        agent.send(to="pat@plainmail.test", subject="No", intent="request", text="Refused.")
