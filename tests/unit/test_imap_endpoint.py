"""IMAP endpoints for an agent's own client: plain on the dev network, IMAPS to a live host."""

from __future__ import annotations

import imaplib
import ssl
from pathlib import Path

import pytest

from amx import mcp_server, runner
from amx.config import load_config
from amx.mailbox import ImapEndpoint


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("edge-ct:143", ImapEndpoint("edge-ct", 143, False)),
        ("imap://mailhost-ct:1143", ImapEndpoint("mailhost-ct", 1143, False)),
        ("imaps://mail.example.com", ImapEndpoint("mail.example.com", 993, True)),
        ("imaps://localhost:12993/", ImapEndpoint("localhost", 12993, True)),
    ],
)
def test_endpoints_parse(value: str, expected: ImapEndpoint) -> None:
    assert ImapEndpoint.parse(value) == expected


@pytest.mark.parametrize("value", ["edge-ct", "pop3://host:110", "imaps://:993", "host:x"])
def test_bad_endpoints_fail(value: str) -> None:
    with pytest.raises(ValueError):
        ImapEndpoint.parse(value)


def test_imaps_verifies_the_certificate_and_the_name(monkeypatch, tmp_path: Path) -> None:
    opened: list[tuple[str, int, ssl.SSLContext]] = []

    class FakeSSL:
        def __init__(self, host, port, *, ssl_context, timeout):
            opened.append((host, port, ssl_context))

    monkeypatch.setattr(imaplib, "IMAP4_SSL", FakeSSL)
    ImapEndpoint("mail.example.com", 993, True).connect()
    host, port, context = opened[0]
    assert (host, port) == ("mail.example.com", 993)
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname


def test_the_runner_and_mcp_server_take_imaps(monkeypatch) -> None:
    captured: dict[str, object] = {}

    class StopRunner(Exception):
        pass

    def fake_runner(agent, login, handler, handled, **_kwargs):
        captured["login"] = login
        raise StopRunner

    monkeypatch.setattr(runner, "Runner", fake_runner)
    monkeypatch.setenv("AMX_IMAP_PASSWORD", "pw")
    monkeypatch.setenv("AMX_SUBMIT_TOKEN", "token")
    with pytest.raises(StopRunner):
        runner.main(
            [
                "--agent=outpost@agents.example.com",
                "--imap=imaps://mail.example.com",
                "--submit=smtp://mail.example.com:587",
                "--ca=/tmp/ca.pem",
                "--handler=amx.examples.intake:handle",
                "--state=/tmp/unused-runner-state",
            ]
        )
    login = captured["login"]
    assert (login.host, login.port, login.tls, login.ca_file) == (
        "mail.example.com",
        993,
        True,
        "/tmp/ca.pem",
    )

    def fake_server(tools):
        captured["account"] = tools.mailbox.account
        raise StopRunner

    monkeypatch.setattr(mcp_server, "build_server", fake_server)
    with pytest.raises(StopRunner):
        mcp_server.main(
            [
                "--agent=outpost@agents.example.com",
                "--imap=imaps://mail.example.com:993",
                "--submit=smtp://mail.example.com:587",
            ]
        )
    account = captured["account"]
    assert (account.host, account.port, account.tls) == ("mail.example.com", 993, True)


def test_role_addresses_and_the_submission_client_host_load(tmp_path: Path) -> None:
    base = "domain: example.test\nagents: {intake: {handler: mailbox-only}}\n"
    path = tmp_path / "gateway.yaml"
    path.write_text(base, encoding="utf-8")
    config = load_config(path)
    assert config.role_addresses == frozenset() and config.submission_client_host == "127.0.0.1"
    path.write_text(
        base + "role_addresses: [Postmaster, abuse]\n"
        "listeners: {submission_client_host: mail.example.test}\n",
        encoding="utf-8",
    )
    config = load_config(path)
    assert config.role_addresses == frozenset({"postmaster", "abuse"})
    assert config.submission_client_host == "mail.example.test"
    for bad, message in (
        ("[intake]", "name agents"),
        ("[postmaster@x.test]", "bare local"),
        ("[control]", "also a role address"),
    ):
        path.write_text(base + f"role_addresses: {bad}\n", encoding="utf-8")
        with pytest.raises(ValueError, match=message):
            load_config(path)
