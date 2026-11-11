"""SH-11 local account state, credential secrecy and shared ACL contract."""

import json
import plistlib
import stat
from dataclasses import replace
from types import SimpleNamespace

import pytest
import yaml
from typer.testing import CliRunner

from amx import live, users
from amx.adapters import stalwart
from amx.cli import app
from amx.credentials import hash_password


@pytest.fixture
def site(tmp_path):
    path = tmp_path / "live.yaml"
    path.write_text(
        yaml.safe_dump(
            {"mta": "stalwart", "profile": "private", "state_dir": str(tmp_path / "state")}
        )
    )
    params = live.load_params(path)
    (params.secrets_dir / "stalwart").mkdir(parents=True)
    users.write_private(params.secrets_dir / "stalwart" / "people.json", "{}\n")
    return params


@pytest.mark.parametrize(
    "name",
    [
        "holds",
        "gateway",
        "approver",
        "admin",
        "postmaster",
        "abuse",
        "x@agents.home.arpa",
        "Alice",
        "a\n",
        "a%b",
        "a/b",
        "a..b",
        "a@home.arpa@evil",
        "-a",
        "a+task",
    ],
)
def test_identity_refuses_reserved_or_malformed(name):
    with pytest.raises(ValueError):
        users.identity(name, "home.arpa")


def invoke(site, *args):
    return CliRunner().invoke(app, ["user", *args, "--params", str(site.path)])


def test_add_rotate_remove_and_secretless_profile(site, tmp_path):
    secret = tmp_path / "app-password"
    result = invoke(site, "add", "alice", "--owner", "--password-out", str(secret))
    assert result.exit_code == 0, result.output
    token = secret.read_text().strip()
    assert token not in result.output
    assert stat.S_IMODE(secret.stat().st_mode) == 0o600
    path = users.state_path(site)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    people = users.read_people(path)
    assert people["alice@home.arpa"]["owner"] is True
    stored = people["alice@home.arpa"]["secret"]
    assert token not in json.dumps(people)
    assert hash_password(token, salt=stored.split("$")[2]).endswith(stored)
    assert invoke(site, "list").output.strip() == "alice@home.arpa owner"
    profile = tmp_path / "alice.mobileconfig"
    assert invoke(site, "profile", "alice", "--output", str(profile)).exit_code == 0
    payload = plistlib.loads(profile.read_bytes())
    mail = payload["PayloadContent"][0]
    assert payload["PayloadType"] == "Configuration"
    assert mail["PayloadType"] == "com.apple.mail.managed"
    assert mail["IncomingMailServerHostName"] == site.mx_host
    assert mail["IncomingMailServerUsername"] == "alice@home.arpa"
    assert "Password" not in {
        key
        for key in mail
        if key.endswith("Password") and key != "OutgoingPasswordSameAsIncomingPassword"
    }
    assert token.encode() not in profile.read_bytes()
    assert invoke(site, "add", "alice", "--password-out", str(tmp_path / "unused")).exit_code != 0
    assert not (tmp_path / "unused").exists()
    old = stored
    assert invoke(site, "passwd", "alice", "--password-out", str(tmp_path / "new")).exit_code == 0
    assert users.read_people(path)["alice@home.arpa"]["secret"] != old
    assert invoke(site, "remove", "alice").exit_code == 0
    assert invoke(site, "list").output == ""
    assert users.read_people(path)["alice@home.arpa"]["enabled"] is False


def test_secret_files_are_private_exclusive_and_never_echoed(site, tmp_path):
    secret = tmp_path / "secret"
    secret.write_text("sensitive-but-invalid")
    result = invoke(site, "add", "alice", "--password-file", str(secret))
    assert result.exit_code != 0
    assert "sensitive-but-invalid" not in result.output
    result = invoke(site, "add", "alice", "--password-out", str(secret))
    assert result.exit_code != 0
    assert secret.read_text() == "sensitive-but-invalid"
    assert users.read_people(users.state_path(site)) == {}


def test_owner_rights_cover_all_existing_and_future_agents():
    site = stalwart.Site(
        "home.arpa",
        "agents.home.arpa",
        "mail.home.arpa",
        "gateway",
        "172.30.0.20",
        approvers=("alice@home.arpa", "bob@home.arpa"),
    )
    for names in (("old",), ("old", "future")):
        _, grants, subscriptions = stalwart.hold_layout(
            site, [f"{name}@agents.home.arpa" for name in names]
        )
        for name in names:
            for kind, rights in stalwart.APPROVER_RIGHTS.items():
                folder = f"Holds/{name}/{kind}"
                assert grants[folder]["alice@home.arpa"] == rights
                assert grants[folder]["bob@home.arpa"] == rights
                assert grants[folder][f"{name}@agents.home.arpa"] == "lr"
                assert stalwart.shared_name(site, folder) in subscriptions["alice@home.arpa"]
    _, revoked, _ = stalwart.hold_layout(replace(site, approvers=()), ["old@agents.home.arpa"])
    assert "alice@home.arpa" not in revoked["Holds/old/Held"]


@pytest.mark.parametrize("changed", [False, True])
@pytest.mark.parametrize("collision", [None, "prefix", "token", "generation"])
def test_sync_preserves_native_app_password_except_on_rotation(
    site, monkeypatch, changed, collision
):
    user_state = {
        "alice@home.arpa": {
            "secret": "$6$hash",
            "generation": "new" if changed else "old",
            "ownership": "a" * 32,
            "generations": ["old", "new"] if changed else ["old"],
            "owner": True,
            "enabled": True,
        }
    }
    previous = {
        "id": "b",
        "emailAddress": "alice@home.arpa",
        "description": "amx managed person " + "a" * 32 + " old",
        "credentials": {"1": {"@type": "AppPassword", "credentialId": "b", "secret": "********"}},
    }
    if collision:
        previous["description"] = {
            "prefix": "amx managed person arbitrary",
            "token": "amx managed person " + "b" * 32 + " old",
            "generation": "amx managed person " + "a" * 32 + " unknown",
        }[collision]
    mail_site = stalwart.Site(
        "home.arpa", "agents.home.arpa", "mail.home.arpa", "gateway", "172.30.0.20"
    )
    monkeypatch.setattr(stalwart, "_site", lambda _: mail_site)
    monkeypatch.setattr(
        stalwart, "provisioning_inputs", lambda *_: ([], {"gateway": "fixture"}, [])
    )
    monkeypatch.setenv("STALWART_RECOVERY_ADMIN", "admin:fixture")
    plans, layouts = [], []

    def run(argv, **kwargs):
        assert kwargs["timeout"] == stalwart.CLI_TIMEOUT
        if "query" in argv:
            return SimpleNamespace(stdout=json.dumps(previous))
        plans.append([json.loads(line) for line in kwargs["input"].splitlines()])
        return SimpleNamespace(stdout="")

    monkeypatch.setattr(stalwart.subprocess, "run", run)
    monkeypatch.setattr(
        stalwart, "ensure_mailboxes", lambda *args, **kwargs: layouts.append(args) or {}
    )
    arguments = SimpleNamespace(
        url="http://fixture.invalid", cli="fixture-cli", imap_host="fixture.invalid", imap_port=143
    )
    if collision:
        with pytest.raises(ValueError, match="unmanaged principal"):
            stalwart.sync_accounts(
                arguments, snapshot=b"", people_snapshot=json.dumps(user_state).encode()
            )
        assert not plans and not layouts
        return
    stalwart.sync_accounts(arguments, snapshot=b"", people_snapshot=json.dumps(user_state).encode())
    account = plans[0][-1]["value"]["person-alice"]
    if changed:
        assert account["credentials"] == {"0": {"@type": "Password", "secret": "$6$hash"}}
    else:
        assert "credentials" not in account  # preserve native credentials server-side
    assert layouts[0][1].approvers == ("alice@home.arpa",)


def test_disabled_agent_acl_reconciles_without_logging_in_as_disabled(monkeypatch):
    mail_site = stalwart.Site(
        "home.arpa",
        "agents.home.arpa",
        "mail.home.arpa",
        "gateway",
        "172.30.0.20",
        approvers=("alice@home.arpa",),
    )
    sessions, grants = [], {}
    import contextlib

    @contextlib.contextmanager
    def session(_factory, user, _password):
        sessions.append(user)
        yield object()

    monkeypatch.setattr(stalwart, "_session", session)
    monkeypatch.setattr(stalwart, "_create_missing", lambda *_: [])
    monkeypatch.setattr(
        stalwart,
        "_set_acl",
        lambda _client, folder, expected, _owner: grants.update({folder: expected}),
    )
    monkeypatch.setattr(stalwart, "_subscribe", lambda *_: None)
    stalwart.ensure_mailboxes(
        lambda: None,
        mail_site,
        ["alice@home.arpa"],
        lambda user: user,
        "fixture",
        inactive=["old@agents.home.arpa"],
    )
    assert "old@agents.home.arpa" not in sessions
    assert grants["Holds/old/Held"]["alice@home.arpa"] == "lrswte"
