"""SH-47: household boundaries use verified agents, never a task owner's naming."""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from types import SimpleNamespace

import pytest
import yaml
from test_submission import RecordingMailbox, _request
from typer.testing import CliRunner

from amx import domain_dkim
from amx import registration as reg
from amx.adapters.milter import _policy_state, build_milter
from amx.adapters.submission import SubmissionError, SubmissionHandler, SubmissionService
from amx.cli import app
from amx.config import load_config
from amx.credentials import hash_token
from amx.identity import sign
from amx.journal import Journal
from amx.policy import AgentState, Stage, State, TxnContext, evaluate
from amx.registration import generate_key
from amx.registry import Registration, read_registrations, registration_from, write_registration
from amx.reload import ConfigWatcher
from amx.runtime import HandlerRegistry
from amx.store import Store

DOMAIN = "agents.home.test"
OPERATOR = "operator@parent.test"
CHILD = "child@son.test"


@pytest.fixture
def lane(tmp_path):
    path = tmp_path / "gateway.yaml"
    raw = {
        "domain": DOMAIN,
        "agent_domain": DOMAIN,
        "data_dir": str(tmp_path / "data"),
        "keys_dir": str(tmp_path / "keys"),
        "registry_dir": str(tmp_path / "registry"),
        "accounts_file": str(tmp_path / "accounts"),
        "accept_from": [OPERATOR],
        "outbound_allowlist": [OPERATOR],
        "mailbox": {"host": "unused.invalid"},
        "agents": {
            "alpha": {"handler": "mailbox-only", "submit_token": "fixture"},
            "beta": {
                "handler": "mailbox-only",
                "submit_token": "fixture",
                "household": "son",
                "accept_from": [CHILD],
            },
            "gamma": {
                "handler": "mailbox-only",
                "submit_token": "fixture",
                "household": "son",
                "accept_from": [CHILD],
            },
            "delta": {
                "handler": "mailbox-only",
                "submit_token": "fixture",
                "household": "other",
                "accept_from": ["other@other.test"],
            },
            "epsilon": {"handler": "mailbox-only", "submit_token": "fixture"},
        },
        "trust": [
            {"d": DOMAIN, "s": name, "intents": ["*"], "schemas": ["*"], "can_open_tasks": True}
            for name in ("alpha", "beta", "gamma", "delta", "epsilon")
        ]
        + [{"d": "agents.foreign.test", "s": "beta", "intents": ["*"], "can_open_tasks": True}],
    }
    path.write_text(yaml.safe_dump(raw))
    return path, raw


def _load(lane):
    path, raw = lane
    path.write_text(yaml.safe_dump(raw))
    return load_config(path)


def _state(config, tmp_path):
    registry = HandlerRegistry()
    store = Store(tmp_path / "state.sqlite")
    return _policy_state(config, store, registry)


def _mail(sender, recipients, *, agent_lane=True):
    message = EmailMessage(policy=policy.SMTP)
    message["From"] = f"{sender}+t_same@{DOMAIN}"
    message["To"] = ", ".join(f"{name}@{DOMAIN}" for name in recipients)
    message["Subject"] = "Hello"
    message["Date"] = "Sat, 24 Oct 2026 12:00:00 +0000"
    message["Message-ID"] = "<household@home.test>"
    message["Auto-Submitted"] = "auto-generated"
    if agent_lane:
        message["Agent-Protocol"] = "amx/0.1"
        message["Agent-Intent"] = "request"
        message["Agent-Task"] = "t_same"
        message["Agent-Task-State"] = "submitted"
    message.set_content("Please inspect this.")
    return message.as_bytes()


def _context(sender, recipients, *, agent_lane=True):
    return TxnContext(
        raw=_mail(sender, recipients, agent_lane=agent_lane),
        mail_from=f"{sender}@{DOMAIN}",
        recipient_agent=recipients[0],
        recipient_agents=recipients,
        recipient_task_tokens=tuple(None for _ in recipients),
        sibling=True,
        dkim_verified=True,
        dkim_domain=DOMAIN,
        dkim_selector=sender,
        from_domain=DOMAIN,
        sender_verified=f"{sender}+t_same@{DOMAIN}",
    )


@pytest.mark.parametrize(
    "sender,recipients",
    [
        ("alpha", ("beta",)),
        ("beta", ("alpha",)),
        ("beta", ("delta",)),
        ("beta", ("gamma", "alpha")),
        ("alpha", ("epsilon", "beta")),
    ],
)
@pytest.mark.parametrize("agent_lane", [True, False])
def test_eod_refuses_cross_household_in_either_lane(lane, tmp_path, sender, recipients, agent_lane):
    state = _state(_load(lane), tmp_path)
    verdict = evaluate(Stage.EOD, _context(sender, recipients, agent_lane=agent_lane), state)
    assert (verdict.rule, verdict.code) == ("agent-household", "550 5.7.1"), verdict


@pytest.mark.parametrize("sender,recipient", [("alpha", "epsilon"), ("beta", "gamma")])
def test_eod_accepts_same_household_agent_mail(lane, tmp_path, sender, recipient):
    verdict = evaluate(Stage.EOD, _context(sender, (recipient,)), _state(_load(lane), tmp_path))
    assert verdict.accepted, verdict
    assert ("Agent-Trust", "verified") in verdict.headers


@pytest.mark.parametrize("missing_households", [False, True])
def test_foreign_agents_still_use_their_grants(lane, tmp_path, missing_households):
    context = replace(
        _context("beta", ("alpha", "beta")),
        dkim_domain="agents.foreign.test",
        from_domain="agents.foreign.test",
        sender_verified="beta@agents.foreign.test",
        raw=_mail("beta", ("alpha", "beta")).replace(DOMAIN.encode(), b"agents.foreign.test", 1),
        sibling=False,
    )
    state = _state(_load(lane), tmp_path)
    if missing_households:
        state = replace(state, households={})
    assert evaluate(Stage.EOD, context, state).accepted
    assert evaluate(Stage.EOD, replace(context, dkim_selector="unknown"), state).rule == "grant"


@pytest.mark.parametrize(
    "households",
    [None, {}, {"beta": None}, {"alpha": None}, {"epsilon": None}],
    ids=["omitted", "empty", "recipient-missing", "sender-missing", "both-missing"],
)
@pytest.mark.parametrize("agent_lane", [True, False])
def test_eod_missing_household_policy_fails_closed(lane, households, agent_lane):
    config = _load(lane)
    # Direct callers must not silently downgrade beta's configured household to default.
    state = State(
        agent_domain=config.agent_domain,
        agents={name: AgentState() for name in config.agents},
        grants=config.trust,
        **({"households": households} if households is not None else {}),
    )
    verdict = evaluate(Stage.EOD, _context("beta", ("alpha",), agent_lane=agent_lane), state)
    assert (verdict.action, verdict.rule, verdict.code) == (
        "reject",
        "agent-household",
        "550 5.7.1",
    ), verdict


@pytest.mark.parametrize("agent_lane", [True, False])
def test_eod_explicit_default_households_remain_compatible(lane, agent_lane):
    config = _load(lane)
    state = State(
        agent_domain=config.agent_domain,
        agents={name: AgentState() for name in config.agents},
        grants=config.trust,
        # Unrelated agents need not have household data for this transaction.
        households={"alpha": None, "epsilon": None},
    )
    assert evaluate(
        Stage.EOD, _context("alpha", ("epsilon",), agent_lane=agent_lane), state
    ).accepted


@pytest.mark.parametrize(
    "sender,recipients,accepted",
    [
        (CHILD, ("beta",), True),
        (OPERATOR, ("beta",), False),
        (CHILD, ("alpha", "beta"), False),
        (OPERATOR, ("alpha",), True),
    ],
)
def test_people_are_owners_only_of_agents_that_list_them(
    lane, tmp_path, sender, recipients, accepted
):
    message = BytesParser(policy=policy.SMTP).parsebytes(
        _mail("beta", recipients, agent_lane=False)
    )
    message.replace_header("From", sender)
    context = replace(
        _context("beta", recipients, agent_lane=False),
        raw=message.as_bytes(),
        sender_verified=sender,
        dkim_domain=sender.split("@")[1],
        from_domain=sender.split("@")[1],
    )
    verdict = evaluate(Stage.EOD, context, _state(_load(lane), tmp_path))
    assert verdict.accepted == accepted, verdict
    if accepted:
        assert ("Agent-Trust", "high") in verdict.headers
    else:
        assert verdict.rule == "sender-not-accepted"


@pytest.mark.parametrize("accept_from", [None, []])
def test_config_refuses_household_without_own_nonempty_list(lane, accept_from):
    lane[1]["agents"]["beta"]["accept_from"] = accept_from
    with pytest.raises(ValueError, match=r"household.*accept_from"):
        _load(lane)


@pytest.mark.parametrize("household", ["", "Son", "bad.label", "bad\n", "x" * 64, 1])
def test_config_refuses_invalid_household(lane, household):
    lane[1]["agents"]["beta"]["household"] = household
    with pytest.raises(ValueError, match="household"):
        _load(lane)


def _service(lane, tmp_path):
    config = _load(lane)
    config.keys_dir.mkdir(exist_ok=True)
    for name in config.agents:
        generate_key(config.keys_dir / f"{name}.private.pem", 1024)
    store = Store(tmp_path / "journal.sqlite")
    sent = []
    mailbox = RecordingMailbox()
    service = SubmissionService(
        config, Journal(tmp_path, store), reinject=lambda *args: sent.append(args), mailbox=mailbox
    )
    return service, store, sent, mailbox


@pytest.mark.parametrize(
    "sender,recipients",
    [
        ("alpha", ("beta",)),
        ("beta", ("alpha",)),
        ("beta", ("gamma", "alpha")),
        ("beta", ("delta",)),
    ],
)
def test_submission_refuses_before_sign_journal_hold_or_send(
    lane, tmp_path, monkeypatch, sender, recipients
):
    service, store, sent, mailbox = _service(lane, tmp_path)
    addresses = tuple(f"{name}@{DOMAIN}" for name in recipients)
    store.name_recipients(sender, "t_hold", addresses)
    monkeypatch.setattr(service, "_sign", lambda *_: pytest.fail("signed a refused message"))
    with pytest.raises(SubmissionError, match="agent-household"):
        service.submit(sender, "fixture", _request(", ".join(addresses)))
    assert sent == [] and mailbox.appended == []
    assert store.rows("SELECT * FROM journal") == []
    assert store.rows("SELECT * FROM holds") == []
    assert store.rows("SELECT rule, code FROM policy_events")[-1]["rule"] == "agent-household"


@pytest.mark.parametrize(
    "address",
    [
        f"alpha+t_other@{DOMAIN}",
        f'"alpha+t_other"@{DOMAIN.upper()}',
    ],
)
def test_submission_normalizes_local_recipient_before_comparing(lane, tmp_path, address):
    service, _, sent, _ = _service(lane, tmp_path)
    with pytest.raises(SubmissionError, match="agent-household"):
        service.submit("beta", "fixture", _request(address))
    assert sent == []


def test_smtp_reports_household_refusal_as_550_571(lane, tmp_path):
    service, _, sent, _ = _service(lane, tmp_path)
    result = asyncio.run(
        SubmissionHandler(service).handle_DATA(
            None,
            SimpleNamespace(auth_data=("beta", "fixture")),
            SimpleNamespace(
                original_content=_request(f"alpha@{DOMAIN}"),
                mail_from=f"beta@{DOMAIN}",
                rcpt_tos=[f"alpha@{DOMAIN}"],
            ),
        )
    )
    assert result.startswith("550 5.7.1") and "agent-household" in result
    assert sent == []


@pytest.mark.parametrize("sender,recipient", [("alpha", "epsilon"), ("beta", "gamma")])
def test_submission_accepts_same_household(lane, tmp_path, sender, recipient):
    service, _, sent, _ = _service(lane, tmp_path)
    assert service.submit(sender, "fixture", _request(f"{recipient}@{DOMAIN}")).held is None
    assert len(sent) == 1


@pytest.mark.parametrize(
    "allowlist,recipient,allowed",
    [
        (None, CHILD, True),
        (None, OPERATOR, False),
        (["friend@elsewhere.test"], "friend@elsewhere.test", True),
        (["friend@elsewhere.test"], CHILD, False),
        ([], "anyone@elsewhere.test", True),
        (None, "friend@son.test", False),
    ],
)
def test_household_outbound_uses_own_list_or_accept_from(
    lane, tmp_path, allowlist, recipient, allowed
):
    if allowlist is not None:
        lane[1]["agents"]["beta"]["outbound_allowlist"] = allowlist
    service, _, sent, _ = _service(lane, tmp_path)
    if allowed:
        service.submit("beta", "fixture", _request(recipient))
        assert len(sent) == 1
    else:
        with pytest.raises(SubmissionError, match="outbound allowlist"):
            service.submit("beta", "fixture", _request(recipient))
        assert sent == []


def test_own_accept_from_is_not_first_contact_but_no_domain_widening(lane, tmp_path):
    lane[1]["agents"]["beta"]["outbound_allowlist"] = []
    lane[1]["hold_rules"] = [{"name": "first", "when": {"recipient_domain_seen": False}}]
    service, store, sent, _ = _service(lane, tmp_path)
    assert service.submit("beta", "fixture", _request(CHILD)).held is None
    assert "son.test" not in store.contacted_domains("beta")
    assert (
        service.submit("beta", "fixture", _request("friend@son.test", task="t_friend")).held
        == "first"
    )
    assert len(sent) == 1


def test_default_household_effective_accept_from_is_not_first_contact(lane, tmp_path):
    lane[1]["outbound_allowlist"] = []
    lane[1]["hold_rules"] = [{"name": "first", "when": {"recipient_domain_seen": False}}]
    service, store, sent, _ = _service(lane, tmp_path)
    assert service.config.agents["alpha"].accept_from is None
    assert service.submit("alpha", "fixture", _request(OPERATOR)).held is None
    assert "parent.test" not in store.contacted_domains("alpha")
    assert (
        service.submit("alpha", "fixture", _request("friend@parent.test", task="t_friend")).held
        == "first"
    )
    assert len(sent) == 1


@pytest.mark.parametrize(
    "agent,accept_from,address,listed",
    [
        ("alpha", None, OPERATOR, True),
        ("alpha", [], OPERATOR, False),
        ("alpha", [CHILD], OPERATOR, False),
        ("alpha", [CHILD], CHILD, True),
        ("beta", [CHILD], OPERATOR, False),
        ("beta", [CHILD], CHILD, True),
        ("unknown", None, OPERATOR, False),
    ],
)
def test_first_contact_uses_only_effective_sender_list(lane, agent, accept_from, address, listed):
    if agent in lane[1]["agents"]:
        lane[1]["agents"][agent]["accept_from"] = accept_from
    assert _load(lane).own_sender_listed(agent, address) is listed


@pytest.mark.parametrize("constraint", ["taint", "hold", "daily", "local-only"])
def test_household_owners_still_obey_other_outbound_gates(lane, tmp_path, constraint):
    if constraint == "hold":
        lane[1]["hold_rules"] = [{"name": "all-requests", "when": {"intents": ["request"]}}]
    if constraint == "daily":
        lane[1]["limits"] = {"external_per_day": 0}
    if constraint == "local-only":
        lane[1]["outbound"] = "local-only"
    service, store, sent, _ = _service(lane, tmp_path)
    if constraint == "taint":
        store.taint_task("beta", "t_hold", ("untrusted",))
    if constraint in {"taint", "hold"}:
        assert service.submit("beta", "fixture", _request(CHILD)).held is not None
    else:
        with pytest.raises(SubmissionError):
            service.submit("beta", "fixture", _request(CHILD))
    assert sent == []


def test_named_person_is_allowed_but_not_another_households_agent(lane, tmp_path):
    service, store, sent, _ = _service(lane, tmp_path)
    store.name_recipients("beta", "t_hold", ("friend@elsewhere.test", f"alpha@{DOMAIN}"))
    assert service.submit("beta", "fixture", _request("friend@elsewhere.test")).held is None
    with pytest.raises(SubmissionError, match="agent-household"):
        service.submit("beta", "fixture", _request(f"alpha@{DOMAIN}"))
    assert len(sent) == 1


def test_release_rechecks_household_after_registry_change(lane, tmp_path, monkeypatch):
    service, store, sent, _ = _service(lane, tmp_path)
    store.taint_task("beta", "t_hold", ("untrusted",))
    held = service.submit("beta", "fixture", _request(f"gamma@{DOMAIN}"))
    message_id = str(BytesParser(policy=policy.default).parsebytes(held.raw)["Message-ID"])
    service.config = replace(
        service.config,
        agents={
            **service.config.agents,
            "gamma": replace(service.config.agents["gamma"], household="other"),
        },
    )
    monkeypatch.setattr(service, "_sign", lambda *_: pytest.fail("signed across households"))
    assert service.release("beta", message_id) is None
    assert store.hold(message_id)["state"] == "held" and sent == []
    assert store.rows("SELECT rule FROM policy_events")[-1]["rule"] == "agent-household"


def test_outbound_group_rechecks_household_after_earlier_group(lane, tmp_path, monkeypatch):
    service, _, sent, _ = _service(lane, tmp_path)
    service._custom_reinject = None
    monkeypatch.setattr(
        service, "_smtp_groups", lambda _: ((1, (CHILD,)), (2, (f"gamma@{DOMAIN}",)))
    )

    def send(_sender, recipients, _raw, _port):
        sent.append(recipients)
        service.config = replace(
            service.config,
            agents={
                **service.config.agents,
                "gamma": replace(service.config.agents["gamma"], household="other"),
            },
        )

    monkeypatch.setattr(service, "_smtp_send", send)
    with pytest.raises(SubmissionError, match="agent-household"):
        service.submit("beta", "fixture", _request(f"{CHILD}, gamma@{DOMAIN}"))
    assert sent == [(CHILD,)]


@pytest.mark.parametrize("accept_from", [None, frozenset()])
def test_registration_refuses_household_without_own_list(accept_from):
    with pytest.raises(ValueError, match=r"household.*accept_from"):
        Registration(
            name="probe",
            submit_token_hash=hash_token("fixture"),
            household="son",
            accept_from=accept_from,
        )


def test_registry_roundtrip_and_merge_keep_absent_and_empty_distinct(lane):
    config = _load(lane)
    registration = registration_from(
        {
            "name": "probe",
            "submit_token_hash": hash_token("fixture"),
            "household": "son",
            "accept_from": ["Child@Son.test", "*@family.test"],
            "outbound_allowlist": [],
        },
        "fixture",
    )
    write_registration(config.registry_dir, registration)
    assert read_registrations(config.registry_dir)["probe"] == registration
    loaded = load_config(lane[0])
    assert loaded.agents["probe"].household == "son"
    assert loaded.accept_from_for("probe") == {CHILD, "family.test"}
    assert loaded.agents["probe"].outbound_allowlist == frozenset()
    old = registration_from({"name": "old", "submit_token_hash": hash_token("fixture")}, "old")
    assert old.household is None and old.accept_from is None and old.outbound_allowlist is None


@pytest.mark.parametrize("live_cli", [False, True])
def test_cli_add_set_list_and_reload_without_reissuing_keys(lane, tmp_path, monkeypatch, live_cli):
    config = _load(lane)
    site = reg.Site(
        config.domain,
        config.agent_domain,
        config.registry_dir,
        config.keys_dir,
        config.accounts_file,
        validate=lambda: load_config(lane[0]),
        dkim_bits=1024,
    )
    params = SimpleNamespace(
        gateway_config=lane[0],
        registry_dir=site.registry_dir,
        keys_dir=site.keys_dir,
        accounts_file=site.accounts_file,
        dkim_bits=1024,
        tls_mode="acme",
    )
    monkeypatch.setattr("amx.cli._live_site", lambda *a, **kw: (params, config, site, lambda s: s))
    prefix = ["live", "agent"] if live_cli else ["agent"]
    common = [] if live_cli else ["--config", str(lane[0])]
    result = CliRunner().invoke(
        app,
        [
            *prefix,
            "add",
            "probe",
            *common,
            *([] if live_cli else ["--live"]),
            "--bundle",
            str(tmp_path / "bundle.json"),
            "--imap",
            "imaps://mail.home.test",
            "--submission",
            "smtp://mail.home.test:587",
            "--household",
            "son",
            "--accept-from",
            CHILD,
            "--accept-from",
            "*@family.test",
            "--outbound-allowlist",
            "friend@elsewhere.test",
        ],
    )
    assert result.exit_code == 0, result.output
    before = read_registrations(site.registry_dir)["probe"]
    key = site.key_path("probe").read_bytes()
    accounts = site.accounts_file.read_bytes()
    current = [load_config(lane[0])]
    watcher = ConfigWatcher(
        lane[0], lambda: current[0], lambda config: current.__setitem__(0, config)
    )
    result = CliRunner().invoke(
        app,
        [
            *prefix,
            "set",
            "probe",
            *common,
            "--household",
            "other",
            "--accept-from",
            "new@owner.test",
            "--outbound-allowlist",
            "new@out.test",
        ],
    )
    assert result.exit_code == 0, result.output
    after = read_registrations(site.registry_dir)["probe"]
    assert after.household == "other" and after.accept_from == {"new@owner.test"}
    assert after.outbound_allowlist == {"new@out.test"}
    assert (
        replace(
            after,
            household=before.household,
            accept_from=before.accept_from,
            outbound_allowlist=before.outbound_allowlist,
        )
        == before
    )
    assert (
        site.key_path("probe").read_bytes() == key and site.accounts_file.read_bytes() == accounts
    )
    watcher.check()
    assert current[0].agents["probe"].household == "other"
    result = CliRunner().invoke(app, [*prefix, "list", *common])
    assert result.exit_code == 0 and "household=other" in result.output
    assert "new@owner.test" in result.output
    bundle = json.loads((tmp_path / "bundle.json").read_text())
    assert bundle["token"] not in result.output and bundle["password"] not in result.output


@pytest.mark.parametrize("agent_lane", [True, False])
def test_real_milter_verifies_signed_from_not_domain_key_selector(lane, tmp_path, agent_lane):
    Milter = pytest.importorskip("Milter")
    lane[1]["agents"].pop("beta")
    write_registration(
        tmp_path / "registry",
        Registration(
            name="beta",
            submit_token_hash=hash_token("fixture"),
            household="son",
            accept_from=frozenset({CHILD}),
        ),
    )
    domain_dkim.write(tmp_path / "registry", DOMAIN, domain_dkim.DomainDkim(active="amx.2026-10"))
    config = _load(lane)
    config.keys_dir.mkdir()
    generate_key(config.keys_dir / "amx.2026-10.private.pem", 1024)
    raw = sign(
        _mail("beta", ("alpha",), agent_lane=agent_lane),
        selector="amx.2026-10",
        domain=DOMAIN,
        private_key=config.keys_dir / "amx.2026-10.private.pem",
    )
    registry = HandlerRegistry()
    cls = build_milter(
        config, Store(tmp_path / "milter.sqlite"), registry, listener_sibling=lambda _: True
    )
    milter = cls()
    replies = []
    milter.setreply = lambda *args: replies.append(args)
    milter.addheader = lambda *_: None
    milter.getsymval = lambda _: ""
    milter.connect("fixture", 2, ("127.0.0.1", 12345))
    milter.envfrom(f"<beta@{DOMAIN}>")
    assert milter.envrcpt(f"<alpha@{DOMAIN}>") == Milter.CONTINUE
    headers, body = raw.split(b"\r\n\r\n", 1)
    parsed = BytesParser(policy=policy.compat32).parsebytes(headers + b"\r\n\r\n")
    for name, value in parsed.raw_items():
        milter.header(name, value.encode())
    milter.body(body)
    assert milter.eom() == Milter.REJECT
    assert replies[-1][:2] == ("550", "5.7.1")
    assert "household" in replies[-1][2]
    assert registry.depth("alpha") == 0
    milter.close()
