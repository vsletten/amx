"""The native acceptance peer is exercised without installing services or sending mail."""

from __future__ import annotations

import imaplib
import importlib.util
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "native_host_acceptance", Path(__file__).parents[2] / "tools/native_host_acceptance.py"
)
assert _SPEC is not None and _SPEC.loader is not None
fixture_tool = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(fixture_tool)


@pytest.mark.parametrize(
    ("state", "expected"),
    [("false", True), ("enabled", True), ("true", False), ("disabled", False)],
)
def test_launchctl_enablement_output(state, expected):
    assert fixture_tool.launch_enabled(f'"ai.amx.runner.fixture" => {state}') is expected


def test_native_tool_requires_explicit_opt_in(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("native test invoked a real manager/network")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(
        sys,
        "argv",
        ["native_host_acceptance", "--output", str(tmp_path / "no"), "--source-sha", "a" * 40],
    )
    with pytest.raises(SystemExit) as stopped:
        fixture_tool.main()
    assert stopped.value.code == 2
    assert not (tmp_path / "no").exists()


def test_loopback_peer_drives_real_runner_without_smtp(tmp_path, monkeypatch):
    from amx.runner import HandledLog, ImapLogin, Runner
    from amx.sdk import Agent

    # Only this explicitly-created loopback listener may be reached.
    fixture = fixture_tool.Fixture("fixture@agents.example.invalid", "fixture-password")
    thread = threading.Thread(target=fixture.serve_forever, daemon=True)
    thread.start()
    received = []

    def receive(message, context):
        received.append(message)

    def forbidden(*args, **kwargs):
        pytest.fail("fixture runner tried SMTP or a service-manager command")

    import smtplib

    monkeypatch.setattr(smtplib, "SMTP", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    port = fixture.server_address[1]
    runner = Runner(
        Agent(fixture.address, "smtp://127.0.0.1:1", "fixture-token"),
        ImapLogin("127.0.0.1", port, fixture.address, fixture.password),
        receive,
        HandledLog(tmp_path / "handled.sqlite"),
    )
    try:
        fixture.add("unit-fixture")
        with imaplib.IMAP4("127.0.0.1", port, timeout=5) as client:
            client.login(fixture.address, fixture.password)
            client.select("INBOX")
            assert runner.drain(client) == 0
            assert runner.drain(client) == 0
        assert len(received) == 1
        assert received[0].text.strip() == "unit-fixture"
        assert fixture.handled == {1}
    finally:
        fixture.shutdown()
        fixture.server_close()
        thread.join(timeout=5)
