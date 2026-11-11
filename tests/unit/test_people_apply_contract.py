"""Pinned Stalwart management wire contract, without a native engine."""

import argparse
import json
from types import SimpleNamespace

import pytest

from amx.adapters import stalwart


@pytest.mark.parametrize("previous_generation", [None, "old", "current"])
@pytest.mark.parametrize("apply_error", [False, True])
def test_people_apply_omits_server_set_credentials_and_preserves_by_omission(
    monkeypatch, capsys, previous_generation, apply_error
):
    site = stalwart.Site(
        "home.arpa", "agents.home.arpa", "mail.home.arpa", "gateway", "172.30.0.20"
    )
    person = {
        "secret": "$6$fixture",
        "generation": "current",
        "ownership": "a" * 32,
        "generations": ["old", "current"],
        "owner": True,
        "enabled": True,
    }
    previous = {
        "id": "b",
        "emailAddress": "alice@home.arpa",
        "description": f"amx managed person {'a' * 32} {previous_generation}",
        "credentials": {"1": {"@type": "AppPassword", "credentialId": "b", "secret": "********"}},
    }
    monkeypatch.setattr(stalwart, "_site", lambda _: site)
    monkeypatch.setattr(
        stalwart, "provisioning_inputs", lambda *_: ([], {"gateway": "fixture"}, [])
    )
    monkeypatch.setattr(stalwart, "_cli_env", lambda _: {})
    monkeypatch.setattr(stalwart, "ensure_mailboxes", lambda *_, **kwargs: {})
    plans = []

    def run(argv, **kwargs):
        assert kwargs["check"] and kwargs["timeout"] == stalwart.CLI_TIMEOUT
        assert kwargs["capture_output"]
        if "query" in argv:
            return SimpleNamespace(stdout=json.dumps(previous) if previous_generation else "")
        plans.extend(json.loads(line) for line in kwargs["input"].splitlines())
        if apply_error:
            raise stalwart.subprocess.CalledProcessError(
                1,
                ["PRIVATE"],
                output="PRIVATE",
                stderr=(
                    "error: invalidProperties | PRIVATE | Properties: /credentials/0/credentialId"
                ),
            )
        return SimpleNamespace(stdout="")

    monkeypatch.setattr(stalwart.subprocess, "run", run)
    arguments = argparse.Namespace(url="http://fixture", cli="fixture-cli")
    if apply_error:
        with pytest.raises(stalwart.subprocess.CalledProcessError):
            stalwart.sync_accounts(
                arguments,
                snapshot=b"",
                people_snapshot=json.dumps({"alice@home.arpa": person}).encode(),
            )
        captured = capsys.readouterr()
        assert captured.err == (
            "amx: people stage=apply status=error code=invalidProperties property=credentialId\n"
        )
        assert "stage=apply status=ok" not in captured.out
        assert "accounts applied" not in captured.out
        assert "PRIVATE" not in captured.out + captured.err
        return
    stalwart.sync_accounts(
        arguments, snapshot=b"", people_snapshot=json.dumps({"alice@home.arpa": person}).encode()
    )
    account = plans[-1]["value"]["person-alice"]
    assert plans[-1]["matchOn"] == ["name", "domainId"]
    assert account["permissions"]["disabledPermissions"] == {
        "impersonate": True,
        "authenticate": False,
    }
    if previous_generation == "current":
        # Omission preserves the actual server credentials; never replay masked secrets,
        # server-set IDs, or secondary credentials through management Account/set.
        assert "credentials" not in account
    else:
        assert account["credentials"] == {"0": {"@type": "Password", "secret": "$6$fixture"}}


@pytest.mark.parametrize(
    "stderr,expected",
    [
        (
            "✗ upsert Account: Account: create failed for `PRIVATE` (operation #2): "
            "error: invalidProperties | PRIVATE description | "
            "Properties: /credentials/0/credentialId",
            ("invalidProperties", "credentialId"),
        ),
        ("error: validationFailed | Properties: /permissions", ("validationFailed", "permissions")),
        ("error: PRIVATE | Properties: /PRIVATE", ("unknown", "unknown")),
        ("Authorization: PRIVATE\ncredentials: PRIVATE", ("unknown", "unknown")),
        (None, ("unknown", "unknown")),
    ],
)
def test_management_diagnostic_is_fixed_code_and_property_only(stderr, expected):
    error = stalwart.subprocess.CalledProcessError(1, ["PRIVATE"], stderr=stderr)
    assert stalwart.management_failure_fields(error) == expected
