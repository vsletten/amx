"""Regressions for the hosted SH-11 repair; no sockets or engine required."""

import json
import ssl
from types import SimpleNamespace

import pytest
import test_users

from amx import mail_client, users
from amx.adapters import stalwart

site = test_users.site
invoke = test_users.invoke


def test_jmap_native_redirect_preserves_exact_auth_and_closes_connections():
    calls, closed = [], []
    auth = {"Authorization": "Basic fixture"}

    class Connection:
        def __init__(self, host, port, **kwargs):
            assert (host, port) == ("mail.home.arpa", 443)

        def request(self, method, path, **kwargs):
            assert kwargs["headers"] == auth
            calls.append((method, path))

        def getresponse(self):
            return SimpleNamespace(
                status=307 if len(calls) == 1 else 200,
                getheader=lambda *_: "/jmap/session",
                read=lambda _: b'{"primaryAccounts": {}}',
            )

        def close(self):
            closed.append(True)

    raw = mail_client.https_request(
        "mail.home.arpa",
        443,
        "/.well-known/jmap",
        ssl.create_default_context(),
        headers=auth,
        connection_factory=Connection,
    )
    assert json.loads(raw) == {"primaryAccounts": {}}
    assert calls == [("GET", "/.well-known/jmap"), ("GET", "/jmap/session")]
    assert len(closed) == 2


@pytest.mark.parametrize(
    "target",
    [
        "http://mail.home.arpa/jmap/session",
        "https://evil.test/",
        "https://mail.home.arpa:8443/",
        "https://user:secret@mail.home.arpa/",
    ],
)
def test_native_redirect_refuses_before_forwarding_auth(target):
    calls = []

    class Connection:
        def __init__(self, *args, **kwargs):
            calls.append(True)

        def request(self, *args, **kwargs):
            pass

        def getresponse(self):
            return SimpleNamespace(status=307, getheader=lambda *_: target)

        def close(self):
            pass

    with pytest.raises(ValueError, match="cross-origin"):
        mail_client.https_request(
            "mail.home.arpa", 443, "/.well-known/jmap", None, connection_factory=Connection
        )
    assert len(calls) == 1


def test_safe_session_diagnostic_does_not_echo_payload(tmp_path):
    def request(*args, **kwargs):
        raise mail_client.NativeHTTPError(403)

    params = SimpleNamespace(mx_host="mail.home.arpa", ports={"discovery": 443}, tls_mode="acme")
    with pytest.raises(OSError, match="stage=session status=403 attempts=1"):
        mail_client.issue_app_password(
            params, "alice@home.arpa", "secret", tmp_path / "app", request=request
        )


def test_passwd_owner_both_directions_and_default_retention(site, tmp_path):
    assert invoke(site, "add", "alice", "--password-out", str(tmp_path / "one")).exit_code == 0
    before = users.read_people(users.state_path(site))["alice@home.arpa"]
    for index, flags, expected in [
        (2, ["--owner"], True),
        (3, [], True),
        (4, ["--no-owner"], False),
    ]:
        result = invoke(
            site, "passwd", "alice", *flags, "--password-out", str(tmp_path / str(index))
        )
        assert result.exit_code == 0, result.output
        person = users.read_people(users.state_path(site))["alice@home.arpa"]
        assert person["enabled"] and person["owner"] is expected
        assert person["ownership"] == before["ownership"]
        assert before["generation"] in person["generations"]
        assert person["generation"] in person["generations"]


@pytest.mark.parametrize("failure", ["before", "replacement", "after"])
@pytest.mark.parametrize("action", ["add", "passwd"])
def test_generated_output_cleanup_only_definitely_uncommitted_owned_file(
    site, tmp_path, monkeypatch, failure, action
):
    if action == "passwd":
        assert (
            invoke(site, "add", "alice", "--password-out", str(tmp_path / "initial")).exit_code == 0
        )
    output = tmp_path / "generated"
    original_write = users.write_private

    def fail(path, data):
        if failure == "replacement":
            output.rename(tmp_path / "original-inode")
            output.write_text("foreign replacement")
        if failure == "after":
            original_write(path, data)
        raise OSError("fixture publication failure")

    monkeypatch.setattr(users, "write_private", fail)
    assert invoke(site, action, "alice", "--password-out", str(output)).exit_code != 0
    assert output.exists() is (failure != "before")
    if failure == "replacement":
        assert output.read_text() == "foreign replacement"
    if failure == "after":
        assert users.read_people(users.state_path(site))["alice@home.arpa"]["enabled"]


def test_optional_app_failure_keeps_committed_primary(site, tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        raise OSError("optional fixture failure")

    monkeypatch.setattr(mail_client, "issue_app_password", fail)
    output = tmp_path / "primary"
    result = invoke(
        site,
        "add",
        "alice",
        "--password-out",
        str(output),
        "--app-password-out",
        str(tmp_path / "app"),
    )
    assert result.exit_code != 0
    assert output.exists()
    assert users.read_people(users.state_path(site))["alice@home.arpa"]["enabled"]


def test_missing_people_direct_sync_and_user_change_refuse(site, tmp_path, monkeypatch):
    users.state_path(site).unlink()
    assert invoke(site, "add", "alice", "--password-out", str(tmp_path / "unused")).exit_code != 0
    assert not (tmp_path / "unused").exists()
    monkeypatch.setattr(stalwart, "_site", lambda _: SimpleNamespace())
    monkeypatch.setattr(stalwart, "provisioning_inputs", lambda *_: ([], {}, []))
    monkeypatch.setattr(stalwart, "site_users", lambda *_: [])
    monkeypatch.setattr(stalwart, "registered_accounts", lambda *_: [])
    monkeypatch.setattr(stalwart, "_cli_env", lambda *_: {})
    arguments = SimpleNamespace(url="http://fixture", people=str(users.state_path(site)))
    with pytest.raises(FileNotFoundError):
        stalwart.sync_accounts(arguments, snapshot=b"")


def test_missing_people_watch_never_receipts_failure_and_recovers(tmp_path, monkeypatch, capsys):
    people = tmp_path / "people.json"
    arguments = SimpleNamespace(watch=True, accounts=str(tmp_path / "accounts"), people=str(people))
    calls, ticks = [], []

    class StopWatch(BaseException):
        pass

    def tick(_seconds):
        ticks.append(True)
        if len(ticks) == 1:
            captured = capsys.readouterr()
            assert "accounts applied" not in captured.out
            assert "stage=snapshot type=FileNotFoundError" in captured.err
            assert not calls
            people.write_text("{}")
        else:
            raise StopWatch

    monkeypatch.setattr(stalwart.time, "sleep", tick)
    monkeypatch.setattr(stalwart, "sync_accounts", lambda *a, **kw: calls.append(kw))
    with pytest.raises(StopWatch):
        stalwart.sync(arguments)
    assert calls == [{"snapshot": b"", "people_snapshot": b"{}"}]
    assert "accounts applied" in capsys.readouterr().out


def test_sync_error_diagnostic_never_contains_cli_or_credential_payload(
    tmp_path, monkeypatch, capsys
):
    arguments = SimpleNamespace(watch=True, accounts=str(tmp_path / "accounts"))

    def fail(*args, **kwargs):
        raise stalwart.subprocess.CalledProcessError(
            7, ["fixture", "PRIVATE-COMMAND"], output="PRIVATE-CREDENTIAL", stderr="PRIVATE-HEADER"
        )

    class StopWatch(BaseException):
        pass

    def stop(_):
        raise StopWatch

    monkeypatch.setattr(stalwart, "sync_accounts", fail)
    monkeypatch.setattr(stalwart.time, "sleep", stop)
    with pytest.raises(StopWatch):
        stalwart.sync(arguments)
    captured = capsys.readouterr()
    assert "accounts applied" not in captured.out
    assert "stage=apply type=CalledProcessError status=7" in captured.err
    assert "PRIVATE" not in captured.out + captured.err
