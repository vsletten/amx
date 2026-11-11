"""SH-47 management, rollback and remaining outbound gates; no Docker or real accounts."""

from dataclasses import replace
from email import policy
from email.parser import BytesParser

import pytest
from test_households import CHILD, DOMAIN, OPERATOR, _context, _load, _service, _state
from test_households import lane as lane  # pytest fixture
from test_submission import _request
from typer.testing import CliRunner

from amx import registration as reg
from amx.adapters.submission import SubmissionError
from amx.cli import app
from amx.credentials import hash_token
from amx.policy import Stage, evaluate
from amx.registry import Registration, read_registrations, registration_from, write_registration


@pytest.fixture
def registered(lane, tmp_path):
    config = _load(lane)
    site = reg.Site(
        config.domain,
        config.agent_domain,
        config.registry_dir,
        config.keys_dir,
        config.accounts_file,
        dkim_bits=1024,
        validate=lambda: _load(lane),
    )
    registration = Registration(
        name="probe",
        submit_token_hash=hash_token("fixture"),
        household="son",
        accept_from=frozenset({CHILD}),
    )
    write_registration(site.registry_dir, registration)
    return site, registration


@pytest.mark.parametrize(
    "field,value",
    [
        ("household", "bad\n"),
        ("household", "Son"),
        ("household", ""),
        ("household", 1),
        ("accept_from", None),
        ("accept_from", []),
        ("accept_from", "child@son.test"),
        ("accept_from", ["not an address"]),
        ("outbound_allowlist", "child@son.test"),
        ("outbound_allowlist", ["*"]),
    ],
)
def test_registry_parser_refuses_invalid_household_policy(field, value):
    raw = {
        "name": "probe",
        "submit_token_hash": hash_token("fixture"),
        "household": "son",
        "accept_from": [CHILD],
    }
    with pytest.raises(ValueError):
        registration_from({**raw, field: value}, "fixture")


def test_default_registry_preserves_an_explicit_empty_sender_list(lane, tmp_path):
    config = _load(lane)
    write_registration(
        config.registry_dir,
        Registration(name="open", submit_token_hash=hash_token("fixture"), accept_from=frozenset()),
    )
    config = _load(lane)
    assert config.accept_from_for("open") == frozenset()
    assert config.agents["open"].household is None
    assert config.agents["open"].outbound_allowlist is None
    assert config.outbound_allowlist_for("open") == {OPERATOR}


@pytest.mark.parametrize("accept_from", [None, []])
def test_registration_add_refuses_before_creating_bundle_keys_or_account(
    lane, tmp_path, accept_from
):
    config = _load(lane)
    site = reg.Site(
        config.domain,
        config.agent_domain,
        config.registry_dir,
        config.keys_dir,
        config.accounts_file,
        dkim_bits=1024,
    )
    bundle = tmp_path / "private-bundle.json"
    with pytest.raises(ValueError, match=r"household.*accept_from"):
        reg.add(
            site,
            "probe",
            bundle=bundle,
            imap="imaps://mail.home.test",
            submission="smtp://mail.home.test:587",
            household="son",
            accept_from=accept_from,
        )
    assert not bundle.exists() and not site.key_path("probe").exists()
    assert not site.accounts_file.exists()
    assert read_registrations(site.registry_dir) == {}


@pytest.mark.parametrize("changes", [{"accept_from": []}, {"inherit_accept_from": True}])
def test_policy_set_cannot_clear_a_households_owner_list(registered, changes):
    site, before = registered
    with pytest.raises(ValueError, match=r"household.*accept_from"):
        reg.set_policy(site, "probe", **changes)
    assert read_registrations(site.registry_dir)["probe"] == before


def test_policy_set_restores_registry_if_gateway_validation_fails(registered):
    site, before = registered
    path = site.registry_dir / "agents" / "probe.yaml"
    original = path.read_bytes()
    site = replace(site, validate=lambda: (_ for _ in ()).throw(ValueError("fixture validation")))
    with pytest.raises(reg.RegistrationError, match="nothing changed"):
        reg.set_policy(site, "probe", accept_from=["new@owner.test"])
    assert path.read_bytes() == original
    assert read_registrations(site.registry_dir)["probe"] == before


@pytest.mark.parametrize(
    "changes",
    [
        {},
        {"household": "son", "default_household": True},
        {"accept_from": [CHILD], "inherit_accept_from": True},
        {"outbound_allowlist": [], "inherit_outbound_allowlist": True},
    ],
)
def test_policy_set_refuses_ambiguous_or_empty_updates(registered, changes):
    site, before = registered
    with pytest.raises(ValueError):
        reg.set_policy(site, "probe", **changes)
    assert read_registrations(site.registry_dir)["probe"] == before


def test_cli_reset_and_explicit_empty_lists_remain_distinct(registered, lane):
    site, _ = registered

    def run(*options):
        result = CliRunner().invoke(
            app, ["agent", "set", "probe", "--config", str(lane[0]), *options]
        )
        assert result.exit_code == 0, result.output
        return read_registrations(site.registry_dir)["probe"]

    assert run("--outbound-any").outbound_allowlist == frozenset()
    assert run("--inherit-outbound-allowlist").outbound_allowlist is None
    changed = run("--default-household", "--inherit-accept-from")
    assert changed.household is None and changed.accept_from is None
    assert run("--accept-any").accept_from == frozenset()
    config = _load(lane)
    assert config.accept_from_for("probe") == frozenset()
    assert config.outbound_allowlist_for("probe") == {OPERATOR}


@pytest.mark.parametrize(
    "flags",
    [
        ["--accept-any"],
        ["--inherit-accept-from"],
        ["--household", "son", "--default-household"],
        ["--outbound-any", "--outbound-allowlist", CHILD],
        ["--accept-any", "--accept-from", CHILD],
        ["--outbound-any", "--inherit-outbound-allowlist"],
    ],
)
def test_cli_refuses_insecure_or_conflicting_updates(registered, lane, flags):
    site, before = registered
    result = CliRunner().invoke(app, ["agent", "set", "probe", "--config", str(lane[0]), *flags])
    assert result.exit_code != 0
    assert read_registrations(site.registry_dir)["probe"] == before


def test_same_household_still_needs_an_intent_grant(lane, tmp_path):
    config = _load(lane)
    grants = tuple(
        replace(grant, intents=frozenset({"response"})) if grant.s == "beta" else grant
        for grant in config.trust
    )
    state = _state(replace(config, trust=grants), tmp_path)
    assert evaluate(Stage.EOD, _context("beta", ("gamma",)), state).rule == "grant"


def test_a_person_can_own_recipients_in_two_households_if_both_list_them(lane, tmp_path):
    lane[1]["agents"]["alpha"]["accept_from"] = [CHILD]
    message = BytesParser(policy=policy.SMTP).parsebytes(
        _context("beta", ("alpha", "beta"), agent_lane=False).raw
    )
    message.replace_header("From", CHILD)
    context = replace(
        _context("beta", ("alpha", "beta"), agent_lane=False),
        raw=message.as_bytes(),
        sender_verified=CHILD,
        own_agent_verified=None,
    )
    verdict = evaluate(Stage.EOD, context, _state(_load(lane), tmp_path))
    assert verdict.accepted and ("Agent-Trust", "high") in verdict.headers


def test_a_forged_agent_from_on_human_lane_does_not_claim_verified_identity(lane, tmp_path):
    lane[1]["accept_from"] = []
    context = replace(
        _context("beta", ("alpha",), agent_lane=False),
        sender_verified=None,
        own_agent_verified=None,
        dkim_verified=False,
    )
    verdict = evaluate(Stage.EOD, context, _state(_load(lane), tmp_path))
    assert verdict.accepted and ("Agent-Trust", "low") in verdict.headers


@pytest.mark.parametrize("sender,to", [("alpha", "beta"), ("beta", "alpha")])
def test_cross_household_refusal_precedes_even_a_tainted_hold(lane, tmp_path, sender, to):
    service, store, sent, mailbox = _service(lane, tmp_path)
    store.taint_task(sender, "t_hold", ("fixture",))
    with pytest.raises(SubmissionError, match="agent-household"):
        service.submit(sender, "fixture", _request(f"{to}@{DOMAIN}"))
    assert store.rows("SELECT * FROM journal") == []
    assert store.rows("SELECT * FROM holds") == []
    assert sent == [] and mailbox.appended == []


def test_default_household_own_outbound_override_wins(lane, tmp_path):
    lane[1]["agents"]["alpha"]["outbound_allowlist"] = ["friend@elsewhere.test"]
    service, _, sent, _ = _service(lane, tmp_path)
    service.submit("alpha", "fixture", _request("friend@elsewhere.test"))
    with pytest.raises(SubmissionError, match="outbound allowlist"):
        service.submit("alpha", "fixture", _request(OPERATOR))
    assert len(sent) == 1


@pytest.mark.parametrize("entry", ["son.test", "*@son.test"])
def test_household_outbound_domain_lists_use_the_same_parser(lane, tmp_path, entry):
    lane[1]["agents"]["beta"]["accept_from"] = [entry]
    service, _, sent, _ = _service(lane, tmp_path)
    service.submit("beta", "fixture", _request("friend@son.test"))
    with pytest.raises(SubmissionError, match="outbound allowlist"):
        service.submit("beta", "fixture", _request("friend@sub.son.test"))
    assert len(sent) == 1


def test_release_rechecks_per_agent_outbound_override(lane, tmp_path):
    service, store, sent, _ = _service(lane, tmp_path)
    store.taint_task("beta", "t_hold", ("fixture",))
    held = service.submit("beta", "fixture", _request(CHILD))
    message_id = str(BytesParser(policy=policy.default).parsebytes(held.raw)["Message-ID"])
    service.config = replace(
        service.config,
        agents={
            **service.config.agents,
            "beta": replace(
                service.config.agents["beta"], outbound_allowlist=frozenset({"not@allowed.test"})
            ),
        },
    )
    assert service.release("beta", message_id) is None
    assert store.hold(message_id)["state"] == "held" and sent == []


def test_outbound_group_rechecks_per_agent_outbound_override(lane, tmp_path, monkeypatch):
    lane[1]["agents"]["beta"]["outbound_allowlist"] = [CHILD, "friend@elsewhere.test"]
    service, _, sent, _ = _service(lane, tmp_path)
    service._custom_reinject = None
    monkeypatch.setattr(
        service, "_smtp_groups", lambda _: ((1, (CHILD,)), (2, ("friend@elsewhere.test",)))
    )

    def send(_sender, recipients, _raw, _port):
        sent.append(recipients)
        service.config = replace(
            service.config,
            agents={
                **service.config.agents,
                "beta": replace(
                    service.config.agents["beta"], outbound_allowlist=frozenset({CHILD})
                ),
            },
        )

    monkeypatch.setattr(service, "_smtp_send", send)
    with pytest.raises(SubmissionError, match="outbound allowlist"):
        service.submit("beta", "fixture", _request(f"{CHILD}, friend@elsewhere.test"))
    assert sent == [(CHILD,)]
