"""SH-10 validator orchestration and refusal tests; no Docker or mail is used."""

import importlib.util
import json
import signal
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def validator(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "tools"))
    spec = importlib.util.spec_from_file_location(
        "stalwart_validator", ROOT / "tools/live_validate_stalwart.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_existing_resources_refuse_without_install_or_cleanup(validator, monkeypatch, tmp_path):
    monkeypatch.setattr(validator, "require_lock_custody", lambda: None)
    monkeypatch.setattr(validator, "inventory", lambda: ["foreign-resource"])
    monkeypatch.setattr(validator, "cli", lambda *_a, **_kw: pytest.fail("mutation on refusal"))
    assert validator.validate_stalwart(SimpleNamespace(state=tmp_path, keep=False)) == 2
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("failure", [False, True])
def test_up_and_checks_have_cleanup_inside_the_lease(validator, monkeypatch, tmp_path, failure):
    monkeypatch.setattr(validator, "require_lock_custody", lambda: None)
    calls = []
    monkeypatch.setattr(validator, "inventory", lambda: [])

    def cli(_state, *args, **kwargs):
        calls.append((args, kwargs))
        if failure and args[0] == "up":
            raise RuntimeError("fixture up failed")
        return ""

    monkeypatch.setattr(validator, "cli", cli)
    monkeypatch.setattr(validator, "functional_checks", lambda *_: None)
    monkeypatch.setattr(validator, "stage_webui", lambda *_: None)
    monkeypatch.setattr(
        validator.subprocess, "run", lambda *_a, **_kw: SimpleNamespace(stdout="", stderr="")
    )
    handlers = {
        sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
    }
    assert validator.validate_stalwart(SimpleNamespace(state=tmp_path, keep=False)) == int(failure)
    assert {sig: signal.getsignal(sig) for sig in handlers} == handlers
    assert [args[0] for args, _kw in calls] == ["install", "up", "down"]
    assert calls[-1] == (("down",), {"timeout": 60})
    results = json.loads((tmp_path / "validation.json").read_text())
    assert any(not result["passed"] for result in results) == failure
    overlay = json.loads((tmp_path / "sealed.json").read_text())
    assert overlay["networks"]["live"]["internal"] is True
    assert overlay["services"]["mailhost"]["dns"] == ["127.0.0.1"]


@pytest.mark.parametrize("outcome", ["mail-refused", "auth-refused", "accepted", "relay-refused"])
def test_native_agent_probe_requires_auth_or_mail_policy_refusal(validator, monkeypatch, outcome):
    attempts = []
    agent = {"address": "intake@agents.home.arpa", "password": "synthetic-mailbox-secret"}
    owner = "alice@home.arpa"
    context = object()

    class SMTP:
        def __init__(self, host, port, **kwargs):
            assert (host, port, kwargs) == (
                "mail.home.arpa",
                465,
                {"context": context, "timeout": 10},
            )

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def ehlo(self):
            pass

        def login(self, user, password):
            assert (user, password) == (agent["address"], agent["password"])
            if outcome == "auth-refused":
                raise validator.smtplib.SMTPAuthenticationError(535, b"refused")

        def send_message(self, message):
            attempts.append((str(message["From"]), str(message["To"])))
            if outcome == "mail-refused":
                raise validator.smtplib.SMTPSenderRefused(550, b"refused", message["From"])
            if outcome == "relay-refused":
                raise validator.smtplib.SMTPRecipientsRefused({owner: (550, b"relay refused")})
            return {}

    monkeypatch.setattr(validator, "FixtureSMTP", SMTP)
    if outcome == "accepted":
        with pytest.raises(AssertionError, match="bypassed gateway"):
            validator.native_agent_submission_refused(agent, owner, context)
    elif outcome == "relay-refused":
        with pytest.raises(validator.smtplib.SMTPRecipientsRefused):
            validator.native_agent_submission_refused(agent, owner, context)
    else:
        ids = validator.native_agent_submission_refused(agent, owner, context)
        assert len(ids) == len(set(ids)) == 2
        if outcome == "mail-refused":
            assert attempts == [(agent["address"], owner), (owner, owner)]


def test_hosted_diagnostics_emit_only_allowlisted_stage_status_counts(validator):
    query = "amx: people stage=query status=ok records=8 desired=1"
    apply = "amx: people stage=apply status=ok desired=1"
    missing = "amx: accounts sync failed stage=snapshot type=FileNotFoundError status=n/a; retrying"
    refused = "amx: accounts sync failed stage=apply type=CalledProcessError status=7; retrying"
    detail = "amx: people stage=apply status=error code=invalidProperties property=credentialId"
    raw = "\n".join(
        [
            "service | " + query,
            "service | " + apply,
            "service | " + missing,
            "service | " + refused,
            "service | " + detail,
            "Authorization: Basic PRIVATE",
            "credentials: PRIVATE",
            query + " credentials=PRIVATE",
            "amx: accounts sync failed: PRIVATE",
            detail + " PRIVATE",
            detail.replace("credentialId", "PRIVATE"),
            detail.replace("invalidProperties", "PRIVATE"),
        ]
    )
    assert validator.safe_sync_diagnostics(raw) == [query, apply, missing, refused, detail]


def test_hosted_bootstrap_diagnostics_preserve_only_fixed_failure_fields(validator):
    stage = "amx: bootstrap stage=settings-apply status=management-error"
    detail = (
        "amx: bootstrap operation=upsert object=Certificate index=28 status=error "
        "code=invalidProperties property=filePath"
    )
    raw = "\n".join(
        [
            "service | " + stage,
            "service | " + detail,
            detail + " PRIVATE",
            detail.replace("filePath", "PRIVATE"),
            detail.replace("Certificate", "PRIVATE"),
            detail.replace("upsert", "PRIVATE"),
            detail.replace("28", "128"),
            detail.replace("error", "PRIVATE"),
            "credentials: PRIVATE",
        ]
    )
    assert validator.safe_bootstrap_diagnostics(raw) == [stage, detail]
