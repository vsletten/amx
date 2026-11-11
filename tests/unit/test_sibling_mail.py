"""SH-02 sibling routing and listener-bound trust regression tests."""

import asyncio
import sqlite3
from dataclasses import replace
from email import policy
from email.parser import BytesParser
from types import SimpleNamespace

import pytest

from amx.adapters.submission import SubmissionError, SubmissionService
from amx.config import (
    AgentConfig,
    GatewayConfig,
    LimitsConfig,
    MailboxConfig,
    TrustGrant,
    load_config,
)
from amx.dsn import build_dsn
from amx.identity import sign
from amx.journal import Journal
from amx.policy import AgentState, Stage, State, TxnContext, evaluate
from amx.profile import build
from amx.provision import generate_dkim_key
from amx.runtime import HandlerRegistry
from amx.store import Store


def _config(tmp_path):
    return GatewayConfig(
        domain="home.arpa",
        agent_domain="agents.home.arpa",
        data_dir=tmp_path,
        agents={},
        trust=(),
        limits=LimitsConfig(),
        mailbox=MailboxConfig(host="unused.invalid"),
        postfix_host="unused.invalid",
        sibling_port=10027,
        role_addresses=frozenset({"postmaster"}),
    )


@pytest.mark.parametrize("enabled", [True, False])
def test_reinjection_splits_only_local_agent_envelopes(tmp_path, monkeypatch, enabled):
    config = _config(tmp_path)
    if not enabled:
        config = replace(config, sibling_port=0)
    service = SubmissionService(config, Journal(tmp_path, Store(tmp_path / "journal.sqlite")))
    calls = []
    monkeypatch.setattr(service, "_smtp_send", lambda *args: calls.append(args))
    recipients = (
        "beta@agents.home.arpa",
        '"gamma+t_same"@AGENTS.HOME.ARPA.',
        "pat@home.arpa",
        "postmaster@agents.home.arpa",
        "beta@agents.foreign.test",
    )
    service._smtp_reinject("alpha+t_same@agents.home.arpa", recipients, b"signed bytes")
    sender = "alpha+t_same@agents.home.arpa"
    assert calls == (
        [
            (sender, recipients[:2], b"signed bytes", 10027),
            (sender, recipients[2:], b"signed bytes", 10025),
        ]
        if enabled
        else [(sender, recipients, b"signed bytes", 10025)]
    )


def test_submitted_report_cannot_select_trusted_system_reinjection(tmp_path, monkeypatch):
    keys = tmp_path / "keys"
    keys.mkdir()
    generate_dkim_key(keys / "alpha.private.pem", bits=1024)
    config = replace(
        _config(tmp_path),
        keys_dir=keys,
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
    )
    report = build_dsn(
        original=_request(),
        envelope_from="beta+t_same@agents.home.arpa",
        recipient="alpha+t_same@agents.home.arpa",
        status="5.7.1",
        reason="policy",
        domain=config.agent_domain,
        reporting_mta=config.agent_domain,
        message_id="<submitted-report@agents.home.arpa>",
    )
    # Neither null MAIL FROM, report MIME type, auto-replied nor a forged system stamp
    # can choose the gateway-only route. Submission still normalizes and signs it.
    raw = b"Agent-Task: t_same\r\nAgent-Intent: error\r\nAgent-Lane: system\r\n" + report
    service = SubmissionService(config, Journal(tmp_path, Store(tmp_path / "store.sqlite")))
    calls = []
    monkeypatch.setattr(service, "_smtp_send", lambda *args: calls.append(args))
    result = service.submit("alpha", "fixture-token", raw, envelope_from="")
    [(sender, recipients, signed, port)] = calls
    assert (sender, recipients, port) == (
        "alpha+t_same@agents.home.arpa",
        ("beta+t_same@agents.home.arpa",),
        config.sibling_port,
    )
    headers = BytesParser(policy=policy.default).parsebytes(signed)
    assert headers.get_content_type() == "multipart/report"
    assert str(headers["Auto-Submitted"]) == "auto-generated"
    assert headers["DKIM-Signature"] is not None
    assert headers["Agent-Lane"] is None
    assert signed == result.raw


def test_sibling_route_is_explicitly_configured_and_can_be_disabled(tmp_path, monkeypatch):
    path = tmp_path / "gateway.yaml"
    path.write_text("domain: home.arpa\npostfix_sibling_port: 10027\n")
    assert load_config(path).sibling_port == 10027
    monkeypatch.setenv("AMX_POSTFIX_SIBLING_PORT", "0")
    assert load_config(path).sibling_port == 0


@pytest.mark.parametrize("revision", [None, 7])
def test_legacy_task_migration_preserves_every_column_and_is_idempotent(tmp_path, revision):
    path = tmp_path / "legacy.sqlite"
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE tasks (token TEXT PRIMARY KEY, agent TEXT NOT NULL, state TEXT NOT NULL, "
            "created_at TEXT NOT NULL, updated_at TEXT NOT NULL"
            + (", revision INTEGER NOT NULL DEFAULT 0" if revision is not None else "")
            + ")"
        )
        values = ("t_same", "alpha", "completed", "created", "updated")
        if revision is not None:
            values = (*values, revision)
        connection.execute(
            "INSERT INTO tasks VALUES (" + ",".join("?" for _ in values) + ")", values
        )
    store = Store(path)
    before = dict(store.task("t_same", "alpha"))
    assert before == dict(
        token="t_same",
        agent="alpha",
        state="completed",
        created_at="created",
        updated_at="updated",
        revision=revision or 0,
    )
    store.put_task("t_same", "beta", "working")
    assert dict(Store(path).task("t_same", "alpha")) == before
    assert Store(path).task("t_same", "beta")["state"] == "working"


def test_task_lifecycle_and_revision_guards_are_agent_scoped(tmp_path):
    store = Store(tmp_path / "store.sqlite")
    store.put_task("t_same", "alpha", "completed")
    assert store.put_task_unless_changed("t_same", "beta", "submitted", None)
    assert store.put_task_unless_changed("t_same", "beta", "working", 0)
    assert not store.put_task_unless_changed("t_same", "beta", "submitted", 0)
    assert not store.put_task("t_same", "alpha", "working")
    assert store.task("t_same", "alpha")["state"] == "completed"
    assert store.task("t_same", "beta")["state"] == "working"
    assert store.task_keys(closed=True) == frozenset({("alpha", "t_same")})
    with pytest.raises(ValueError, match="specify agent"):
        store.task("t_same")


def test_submission_cannot_borrow_another_agents_task(tmp_path):
    config = replace(
        _config(tmp_path),
        agents={"beta": AgentConfig(handler="mailbox-only", submit_token="fixture-token")},
        trust=(TrustGrant(d="agents.home.arpa", s="beta", intents=frozenset({"request"})),),
    )
    store = Store(tmp_path / "store.sqlite")
    store.put_task("t_same", "alpha", "working")
    service = SubmissionService(
        config, Journal(tmp_path, store), reinject=lambda *args: pytest.fail("unexpected send")
    )
    with pytest.raises(SubmissionError, match="not allowed to open tasks"):
        service.submit("beta", "fixture-token", _request())


@pytest.mark.parametrize("live", [False, True])
def test_postfix_sibling_listeners_are_gateway_and_loopback_only(live):
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    path = root / (
        "deploy/live/mailhost/master.cf.template" if live else "deploy/mailhost/master.cf"
    )
    services = {}
    current = None
    for line in path.read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        if not line.startswith(" "):
            current = line.split()[0]
            services[current] = []
        else:
            services[current].append(line.strip())
    admission = services["${MAILHOST_IP}:10027" if live else "10027"]
    filtered = services["127.0.0.1:10028"]
    assert "-o mynetworks=${GATEWAY_IP}/32" in admission
    assert "-o smtpd_client_restrictions=permit_mynetworks,reject" in admission
    assert "-o smtpd_milters=" in admission
    assert "-o content_filter=sibling-out:[127.0.0.1]:10028" in admission
    assert "-o mynetworks=127.0.0.1/32" in filtered
    assert "-o smtpd_client_restrictions=permit_mynetworks,reject" in filtered
    assert "-o milter_macro_daemon_name=amx-sibling" in filtered
    assert "-o smtpd_milters=" not in filtered, "inherits the gateway milter, fail closed"
    assert "-o content_filter=" in filtered, "does not loop again"


def _request():
    return build(
        sender="alpha+t_same@agents.home.arpa",
        to="beta@agents.home.arpa",
        subject="Sibling request",
        intent="request",
        task="t_same",
        task_state="submitted",
        text="Please help.",
        message_id="<sibling@agents.home.arpa>",
    ).as_bytes(policy=policy.SMTP)


@pytest.mark.parametrize(
    "edge", ["valid", "port25", "tampered", "disabled", "no-grant", "forged-header"]
)
@pytest.mark.parametrize("mta", ["postfix", "stalwart"])
def test_real_milter_local_signature_listener_grant_and_lmtp_delivery(
    tmp_path, monkeypatch, edge, mta
):
    Milter = pytest.importorskip("Milter")
    import dns.resolver

    from amx.adapters.lmtp import LmtpHandler
    from amx.adapters.milter import build_milter

    keys = tmp_path / "keys"
    keys.mkdir()
    key = keys / "alpha.private.pem"
    generate_dkim_key(key, bits=1024)
    config = replace(
        _config(tmp_path),
        keys_dir=keys,
        agents={
            "alpha": AgentConfig(handler="mailbox-only", enabled=edge != "disabled"),
            "beta": AgentConfig(handler="mailbox-only"),
        },
        trust=()
        if edge == "no-grant"
        else (
            TrustGrant(
                d="agents.home.arpa",
                s="alpha",
                intents=frozenset({"request"}),
                schemas=frozenset({"*"}),
                can_open_tasks=True,
            ),
        ),
    )
    raw = sign(_request(), selector="alpha", domain=config.agent_domain, private_key=key)
    if edge == "tampered":
        raw = raw.replace(b"Please help.", b"Forged body.")
    elif edge == "forged-header":
        raw = b"Agent-Sibling: yes\r\n" + raw
    monkeypatch.setattr(dns.resolver, "Resolver", lambda *a, **kw: pytest.fail("unexpected DNS"))
    store = Store(tmp_path / "store.sqlite")
    registry = HandlerRegistry()
    registry.register("beta", "mailbox-only")
    trusted = edge not in {"port25", "forged-header"}
    milter = build_milter(
        config,
        store,
        registry,
        listener_sibling=(lambda _handle: trusted) if mta == "stalwart" else None,
    )()
    added, replies = [], []
    milter.getsymval = lambda name: (
        (
            "Stalwart v0.16.25"
            if mta == "stalwart"
            else "amx-sibling"
            if trusted
            else "mail.home.arpa"
        )
        if name == "{daemon_name}"
        else None
    )
    milter.setreply = lambda *args: replies.append(args)
    milter.addheader = lambda *args: added.append(args)
    assert milter.connect("mailhost", 2, ("127.0.0.1", 40000)) == Milter.CONTINUE
    assert milter.envfrom("<alpha+t_same@agents.home.arpa>") == Milter.CONTINUE
    assert milter.envrcpt("<beta@agents.home.arpa>") == Milter.CONTINUE
    for name, value in BytesParser(policy=policy.SMTP).parsebytes(raw).raw_items():
        milter.header(name, value.encode())
    milter.body(raw if mta == "stalwart" else raw.partition(b"\r\n\r\n")[2])
    verdict = milter.eom()
    if edge != "valid":
        assert verdict == Milter.REJECT, replies
        assert not added
        milter.close()
        return
    assert verdict == Milter.ACCEPT, replies
    delivered = b"".join(f"{name}: {value}\r\n".encode() for name, value in added) + raw
    copies = []
    mailbox = SimpleNamespace(append=lambda *args, **kwargs: copies.append(args))
    handler = LmtpHandler(config, store, Journal(tmp_path, store), registry, mailbox)
    envelope = SimpleNamespace(
        original_content=delivered,
        rcpt_tos=["beta@agents.home.arpa"],
        mail_from="alpha+t_same@agents.home.arpa",
    )
    status = asyncio.run(handler.handle_DATA(None, None, envelope))
    assert status.values[0].startswith("250"), status
    assert copies[0][0] == "beta@agents.home.arpa"
    assert store.task("t_same", "beta")["state"] == "submitted"
    assert b"Agent-Task-Assigned:" not in copies[0][1]
    milter.close()


def test_bare_and_tokenized_recipients_check_each_agents_task_and_capability():
    grant = TrustGrant(
        d="agents.home.arpa",
        s="alpha",
        intents=frozenset({"request"}),
        schemas=frozenset({"*"}),
        can_open_tasks=False,
    )
    state = State(
        agent_domain="agents.home.arpa",
        agents={"alpha": AgentState(), "beta": AgentState()},
        households={"alpha": None, "beta": None},
        grants=(grant,),
        known_tasks=frozenset({("alpha", "t_same")}),
        closed_tasks=frozenset({("alpha", "t_same")}),
    )
    context = TxnContext(
        raw=_request(),
        dkim_verified=True,
        dkim_domain="agents.home.arpa",
        dkim_selector="alpha",
        from_domain="agents.home.arpa",
        sibling=True,
        recipient_agents=("beta",),
        recipient_task_tokens=(None,),
    )
    assert evaluate(Stage.EOD, context, state).rule == "grant", "alpha's task is not beta's"
    state = replace(state, known_tasks=frozenset({("beta", "t_same")}))
    assert evaluate(Stage.EOD, context, state).accepted, "alpha's closed task does not close beta's"
    mismatch = replace(context, recipient_task_tokens=("t_other",))
    assert evaluate(Stage.EOD, mismatch, state).rule == "task-token-mismatch"
    closed = replace(state, closed_tasks=frozenset({("beta", "t_same")}))
    assert evaluate(Stage.EOD, context, closed).rule == "closed-task"
    assert evaluate(Stage.EOD, replace(context, message_accepted=(True,)), closed).accepted
    multi = replace(
        context, recipient_agents=("beta", "alpha"), recipient_task_tokens=(None, "t_same")
    )
    assert evaluate(Stage.EOD, multi, closed).rule == "closed-task"
