"""Hosted-review regressions: exercise authenticated submission and approved release retries."""

import smtplib
from dataclasses import replace
from email import policy
from email.parser import BytesParser
from types import SimpleNamespace

import pytest

from amx.adapters.submission import SubmissionError, SubmissionService
from amx.config import AgentConfig, GatewayConfig, HoldRule, LimitsConfig, MailboxConfig, TrustGrant
from amx.journal import Journal
from amx.profile import build
from amx.provision import generate_dkim_key
from amx.store import Store


def _service(tmp_path, *, held=False):
    keys = tmp_path / "keys"
    keys.mkdir(exist_ok=True)
    if not (keys / "alpha.private.pem").exists():
        generate_dkim_key(keys / "alpha.private.pem", bits=1024)
    config = GatewayConfig(
        domain="home.arpa",
        agent_domain="agents.home.arpa",
        data_dir=tmp_path,
        keys_dir=keys,
        limits=LimitsConfig(),
        agents={"alpha": AgentConfig(handler="mailbox-only", submit_token="fixture-token")},
        trust=(
            TrustGrant(
                d="agents.home.arpa",
                s="alpha",
                intents=frozenset({"*"}),
                schemas=frozenset({"*"}),
                can_open_tasks=True,
            ),
        ),
        mailbox=MailboxConfig(host="unused.invalid"),
        postfix_host="unused.invalid",
        sibling_port=10027,
        hold_rules=(HoldRule(name="approval", agents=frozenset({"alpha"})),) if held else (),
    )
    store = Store(tmp_path / "store.sqlite")
    return SubmissionService(
        config, Journal(tmp_path, store), mailbox=SimpleNamespace(append=lambda *a, **kw: None)
    )


def _raw(*, identity=True):
    message = build(
        sender="alpha@agents.home.arpa",
        to="beta@agents.home.arpa",
        subject="Split retry",
        intent="request",
        task="t_retry",
        task_state="completed",
        text="Please help.",
        message_id="<retry@agents.home.arpa>",
    )
    message["Cc"] = "pat@home.arpa"
    message["Received"] = "from runner; Thu, 15 Oct 2026 10:00:00 -0700"
    if not identity:
        del message["Message-ID"]
    return message.as_bytes(policy=policy.SMTP)


@pytest.mark.parametrize("held", [False, True])
def test_partial_acceptance_restarts_only_remaining_group_with_original_bytes(
    tmp_path, monkeypatch, held
):
    service = _service(tmp_path, held=held)
    calls = []
    failing = True

    def send(sender, recipients, raw, port):
        calls.append((sender, recipients, raw, port))
        if port == 10025 and failing:
            raise smtplib.SMTPDataError(451, b"retry later")

    monkeypatch.setattr(service, "_smtp_send", send)
    raw = _raw()
    if held:
        service.submit("alpha", "fixture-token", raw)
    with pytest.raises(smtplib.SMTPDataError):
        if held:
            service.release("alpha", "<retry@agents.home.arpa>")
        else:
            service.submit("alpha", "fixture-token", raw)
    assert [x[3] for x in calls] == [10027, 10025]
    original = calls[0][2]
    if held:
        assert service.store.hold("<retry@agents.home.arpa>")["state"] == "releasing"
        assert service.reject("alpha", "<retry@agents.home.arpa>") is None
    # Restart loses all in-process state; the next SMTP Received stamp and line endings differ.
    restarted = SubmissionService(
        service.config, Journal(tmp_path, Store(service.store.path)), mailbox=service.mailbox
    )
    monkeypatch.setattr(restarted, "_smtp_send", send)
    failing = False
    retry = raw.replace(b"10:00:00", b"10:03:00").replace(b"\r\n", b"\n")
    result = (
        restarted.release("alpha", "<retry@agents.home.arpa>")
        if held
        else restarted.submit("alpha", "fixture-token", retry)
    )
    assert [x[3] for x in calls] == [10027, 10025, 10025]
    assert result.raw == original == calls[-1][2]
    assert result.recipients == ("beta@agents.home.arpa", "pat@home.arpa")
    assert restarted.store.task("t_retry", "alpha")["state"] == "completed"
    if held:
        assert restarted.store.hold("<retry@agents.home.arpa>")["state"] == "released"
    else:
        revision = restarted.store.task("t_retry", "alpha")["revision"]
        assert restarted.submit("alpha", "fixture-token", retry).raw == original
        assert len(calls) == 3
        assert restarted.store.task("t_retry", "alpha")["revision"] == revision
    assert restarted.journal.verify().valid


def test_retry_identity_cannot_change_payload_or_recipients(tmp_path, monkeypatch):
    service = _service(tmp_path)
    monkeypatch.setattr(service, "_smtp_send", lambda *a: None)
    service.submit("alpha", "fixture-token", _raw())
    for raw in (
        _raw().replace(b"Please help.", b"Different body."),
        _raw().replace(b"pat@home.arpa", b"other@home.arpa"),
    ):
        with pytest.raises(SubmissionError, match="replay"):
            service.submit("alpha", "fixture-token", raw)


@pytest.mark.parametrize("held", [False, True])
def test_reload_between_groups_retains_accepted_custody(tmp_path, monkeypatch, held):
    service = _service(tmp_path, held=held)
    original = service.config
    raw = _raw().replace(b"pat@home.arpa", b"pat@example.test")
    calls = []

    def send(sender, recipients, signed, port):
        calls.append((port, signed))
        if port == 10027:
            service.config = replace(original, outbound="local-only")

    monkeypatch.setattr(service, "_smtp_send", send)
    if held:
        service.submit("alpha", "fixture-token", raw)
    with pytest.raises(SubmissionError, match="outbound allowlist"):
        if held:
            service.release("alpha", "<retry@agents.home.arpa>")
        else:
            service.submit("alpha", "fixture-token", raw)
    assert [port for port, _ in calls] == [10027]
    kind = "released" if held else "submission"
    progress = service.store.outbound_progress("alpha", "<retry@agents.home.arpa>", kind)
    assert progress["accepted"] == "[0]" and not progress["completed"]
    assert not progress["claim"]
    if held:
        assert service.store.hold("<retry@agents.home.arpa>")["state"] == "releasing"
        assert service.reject("alpha", "<retry@agents.home.arpa>") is None
    service.config = original
    result = (
        service.release("alpha", "<retry@agents.home.arpa>")
        if held
        else service.submit("alpha", "fixture-token", raw)
    )
    assert [port for port, _ in calls] == [10027, 10025]
    assert result.raw == calls[0][1] == calls[1][1]
    if held:
        assert service.store.hold("<retry@agents.home.arpa>")["state"] == "released"


def test_no_message_id_is_not_inferred_to_be_a_duplicate(tmp_path, monkeypatch):
    service = _service(tmp_path)
    sent = []
    monkeypatch.setattr(service, "_smtp_send", lambda *a: sent.append(a))
    first = service.submit("alpha", "fixture-token", _raw(identity=False))
    second = service.submit("alpha", "fixture-token", _raw(identity=False))
    assert len(sent) == 4
    parse = BytesParser(policy=policy.default).parsebytes
    assert parse(first.raw)["Message-ID"] != parse(second.raw)["Message-ID"]


@pytest.mark.parametrize("ambiguous", [False, True])
def test_real_submission_smtp_receipt_boundary(tmp_path, monkeypatch, ambiguous):
    service = _service(tmp_path)
    submitted = _raw()
    calls = []
    first = True

    class SMTP:
        def __init__(self, host, port, **kw):
            self.port = port

        def __enter__(self):
            return self

        def __exit__(self, *args):
            if not ambiguous:
                raise smtplib.SMTPServerDisconnected("QUIT reply lost after DATA 250")

        def ehlo_or_helo_if_needed(self):
            pass

        def mail(self, sender):
            return 250, b"ok"

        def rcpt(self, recipient):
            return 250, b"ok"

        def data(self, raw):
            nonlocal first
            calls.append((self.port, raw))
            if ambiguous and first:
                first = False
                raise smtplib.SMTPServerDisconnected("DATA reply lost; custody unknown")
            return 250, b"queued as fixture-receipt"

    monkeypatch.setattr(smtplib, "SMTP", SMTP)
    if ambiguous:
        with pytest.raises(smtplib.SMTPServerDisconnected):
            service.submit("alpha", "fixture-token", submitted)
    result = service.submit("alpha", "fixture-token", submitted)
    assert [port for port, raw in calls] == ([10027, 10027, 10025] if ambiguous else [10027, 10025])
    assert all(raw == result.raw for port, raw in calls)
    service.submit("alpha", "fixture-token", submitted)
    assert len(calls) == (3 if ambiguous else 2)


def test_concurrent_release_cannot_reopen_hold_for_rejection(tmp_path, monkeypatch):
    from amx.adapters.submission import HoldUnavailable

    service = _service(tmp_path, held=True)
    service.submit("alpha", "fixture-token", _raw())

    def send(*args):
        with pytest.raises(HoldUnavailable, match="being sent"):
            service.release("alpha", "<retry@agents.home.arpa>")
        assert service.reject("alpha", "<retry@agents.home.arpa>") is None

    monkeypatch.setattr(service, "_smtp_send", send)
    assert service.release("alpha", "<retry@agents.home.arpa>") is not None


def test_partial_release_retains_approval_but_rechecks_current_authority(tmp_path, monkeypatch):
    from amx.adapters.submission import HoldUnavailable

    service = _service(tmp_path, held=True)
    service.submit("alpha", "fixture-token", _raw())
    ports = []

    def send(sender, recipients, raw, port):
        ports.append(port)
        if port == 10025:
            raise smtplib.SMTPDataError(451, b"temporary failure")

    monkeypatch.setattr(service, "_smtp_send", send)
    with pytest.raises(smtplib.SMTPDataError):
        service.release("alpha", "<retry@agents.home.arpa>")
    enabled = service.config
    service.config = replace(
        enabled, agents={"alpha": replace(enabled.agents["alpha"], enabled=False)}
    )
    with pytest.raises(HoldUnavailable, match="no longer authorized"):
        service.release("alpha", "<retry@agents.home.arpa>")
    assert ports == [10027, 10025]
    assert service.reject("alpha", "<retry@agents.home.arpa>") is None
    service.config = enabled
    monkeypatch.setattr(service, "_smtp_send", lambda *a: ports.append(a[-1]))
    assert service.release("alpha", "<retry@agents.home.arpa>") is not None
    assert ports == [10027, 10025, 10025]
