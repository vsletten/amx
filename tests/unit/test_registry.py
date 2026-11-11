from __future__ import annotations

import stat
from datetime import UTC, datetime, timedelta

import pytest
import yaml

from amx.credentials import hash_token
from amx.registry import (
    Grant,
    Registration,
    RetiredSelector,
    atomic_write,
    check_name,
    check_selector,
    delete_grant,
    delete_registration,
    fingerprint,
    grant_from,
    locked,
    read_grants,
    read_registrations,
    registration_from,
    selector_agent,
    write_grant,
    write_registration,
)

NOW = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)


def _registration(**changes) -> Registration:
    return Registration(name="probe", submit_token_hash=hash_token("t"), **changes)


@pytest.mark.parametrize("name", ["probe", "a", "probe-2", "x" * 63])
def test_check_name_accepts_agent_names(name: str) -> None:
    assert check_name(name) == name


@pytest.mark.parametrize(
    "name", ["", "Probe", "-probe", "probe.k2", "probe_1", "pröbe", "x" * 64, "control", "abuse"]
)
def test_check_name_refuses_bad_and_reserved_names(name: str) -> None:
    with pytest.raises(ValueError):
        check_name(name)


def test_a_rotated_selector_belongs_to_its_agent() -> None:
    assert selector_agent("intake.k2") == "intake"
    assert selector_agent("intake") == "intake"
    assert check_selector("intake", "intake.k2") == "intake.k2"
    assert selector_agent("intake.mail") == "intake.mail"  # not a rotation label
    for bad in ("other.k2", "intake.", "intake.K2", "intake.k2.x", "intake.mail"):
        with pytest.raises(ValueError):
            check_selector("intake", bad)


def test_a_registration_round_trips_through_its_file(tmp_path) -> None:
    registration = _registration(
        pending_selector="probe.k2",
        retired_selectors=(RetiredSelector("probe.k1", NOW),),
        intents=("response",),
        can_open_tasks=False,
        imap_endpoint="mail.example.test:993",
        submission_endpoint="smtp://mail.example.test:587",
        created_at=NOW,
    )
    write_registration(tmp_path, registration)
    assert read_registrations(tmp_path) == {"probe": registration}
    text = (tmp_path / "agents" / "probe.yaml").read_text(encoding="utf-8")
    assert text.startswith("# Written by `amx agent`")


def test_a_registration_defaults_its_selector_to_its_name() -> None:
    assert _registration().selector == "probe"


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"mode": "remote", "handler": "amx.examples.echo:handle"}, "own host"),
        ({"mode": "batch"}, "mode must be"),
        ({"watermark": 0}, "at least 1"),
        ({"selector": "other"}, "is not 'probe'"),
    ],
)
def test_a_bad_registration_fails(changes, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        _registration(**changes)


def test_registration_from_refuses_unknown_keys_and_wrong_types() -> None:
    base = _registration().to_mapping()
    with pytest.raises(ValueError, match="unknown keys: token"):
        registration_from({**base, "token": "plaintext"}, "f")
    with pytest.raises(ValueError, match="enabled must be true or false"):
        registration_from({**base, "enabled": "no"}, "f")
    with pytest.raises(ValueError, match="submit_token_hash is required"):
        registration_from({**base, "submit_token_hash": None}, "f")


def test_a_file_must_be_named_for_its_agent(tmp_path) -> None:
    path = tmp_path / "agents" / "other.yaml"
    path.parent.mkdir()
    path.write_text(yaml.safe_dump(_registration().to_mapping()), encoding="utf-8")
    with pytest.raises(ValueError, match="holds agent 'probe'"):
        read_registrations(tmp_path)


def test_hidden_and_temporary_files_are_ignored(tmp_path) -> None:
    write_registration(tmp_path, _registration())
    (tmp_path / "agents" / ".probe.yaml.abc123").write_text("half a file", encoding="utf-8")
    (tmp_path / "agents" / "notes.txt").write_text("not yaml", encoding="utf-8")
    assert list(read_registrations(tmp_path)) == ["probe"]


def test_selectors_to_publish_include_staged_and_unexpired_retired_keys() -> None:
    registration = _registration(
        selector="probe.k3",
        pending_selector="probe.k4",
        retired_selectors=(
            RetiredSelector("probe", NOW - timedelta(days=1)),
            RetiredSelector("probe.k2", NOW + timedelta(days=1)),
        ),
    )
    selectors = registration.selectors(NOW)
    assert [selector for selector, _role in selectors] == ["probe.k3", "probe.k4", "probe.k2"]
    assert selectors[0][1] == "active" and selectors[1][1] == "pending"
    assert selectors[2][1].startswith("retiring until 2026-09-28")


def test_delete_registration(tmp_path) -> None:
    write_registration(tmp_path, _registration())
    assert delete_registration(tmp_path, "probe")
    assert not delete_registration(tmp_path, "probe")
    assert read_registrations(tmp_path) == {}


def test_grants_round_trip_and_delete(tmp_path) -> None:
    grant = Grant("agents.other.test", "scheduler", intents=("response",))
    path = write_grant(tmp_path, grant)
    assert path.name == "agents.other.test--scheduler.yaml"
    assert read_grants(tmp_path) == [grant]
    assert delete_grant(tmp_path, "agents.other.test", "scheduler")
    assert read_grants(tmp_path) == []


@pytest.mark.parametrize(
    "raw",
    [
        {"d": "*", "s": "scheduler"},
        {"d": "agents.other.test", "s": "*"},
        {"d": "agents.other.test", "s": "sched.k2"},
        {"d": "agents.other.test", "s": "scheduler", "lane": "human"},
        {"d": "agents.other.test", "s": "scheduler", "can_open_tasks": "yes"},
    ],
)
def test_a_grant_names_one_agent_of_one_domain(raw) -> None:
    with pytest.raises(ValueError):
        grant_from(raw, "f")


def test_fingerprint_follows_content(tmp_path) -> None:
    empty = fingerprint(tmp_path)
    write_registration(tmp_path, _registration())
    one = fingerprint(tmp_path)
    assert one != empty
    write_registration(tmp_path, _registration(enabled=False))
    assert fingerprint(tmp_path) != one
    write_grant(tmp_path, Grant("agents.other.test", "scheduler"))
    assert fingerprint(tmp_path) not in {empty, one}


def test_atomic_write_sets_the_mode_and_leaves_no_temporary(tmp_path) -> None:
    path = tmp_path / "sub" / "file"
    atomic_write(path, "content", mode=0o600)
    assert path.read_text(encoding="utf-8") == "content"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert [entry.name for entry in path.parent.iterdir()] == ["file"]


def test_locked_serializes_and_creates_the_directory(tmp_path) -> None:
    with locked(tmp_path / "registry"):
        assert (tmp_path / "registry" / ".lock").exists()
