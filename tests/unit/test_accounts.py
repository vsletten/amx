from __future__ import annotations

import stat

import pytest

from amx.accounts import (
    Account,
    new_generation,
    read_accounts,
    set_account,
    set_state,
    write_accounts,
)
from amx.credentials import hash_password

HASH = hash_password("a-password", salt="saltsalt")
GEN = "0123456789abcdef"


def test_accounts_round_trip_sorted_and_0600(tmp_path) -> None:
    path = tmp_path / "agents.passwd"
    write_accounts(
        path,
        {
            "zed@agents.example.test": Account("zed@agents.example.test", HASH, "enabled", GEN),
            "abe@agents.example.test": Account("abe@agents.example.test", HASH, "disabled", GEN),
        },
    )
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    lines = [line for line in path.read_text().splitlines() if not line.startswith("#")]
    assert lines == [
        f"abe@agents.example.test:{HASH}:disabled:{GEN}",
        f"zed@agents.example.test:{HASH}:enabled:{GEN}",
    ]
    assert read_accounts(path)["abe@agents.example.test"].state == "disabled"


def test_a_missing_file_has_no_accounts(tmp_path) -> None:
    assert read_accounts(tmp_path / "absent") == {}


def test_set_state_keeps_the_generation_and_purge_drops_the_hash(tmp_path) -> None:
    path = tmp_path / "agents.passwd"
    set_account(path, Account("probe@agents.example.test", HASH, "enabled", GEN))
    disabled = set_state(path, "probe@agents.example.test", "disabled")
    assert (disabled.password_hash, disabled.generation) == (HASH, GEN)
    purged = set_state(path, "probe@agents.example.test", "purge")
    assert purged.password_hash == "-"
    assert read_accounts(path)["probe@agents.example.test"].line().endswith(f":-:purge:{GEN}")
    with pytest.raises(KeyError):
        set_state(path, "other@agents.example.test", "disabled")


def test_each_registration_gets_a_new_generation() -> None:
    first, second = new_generation(), new_generation()
    assert first != second and len(first) == 16
    Account("probe@agents.example.test", HASH, "enabled", first)


@pytest.mark.parametrize(
    ("address", "password_hash", "state", "generation"),
    [
        ("Probe@agents.example.test", HASH, "enabled", GEN),
        ("probe", HASH, "enabled", GEN),
        ("pro:be@agents.example.test", HASH, "enabled", GEN),
        ("probe@agents.example.test", "plaintext", "enabled", GEN),
        ("probe@agents.example.test", HASH, "paused", GEN),
        ("probe@agents.example.test", HASH, "purge", GEN),
        ("probe@agents.example.test", HASH, "enabled", "short"),
        ("probe@agents.example.test", HASH, "enabled", "0123456789ABCDEF"),
    ],
)
def test_a_bad_account_line_fails(
    address: str, password_hash: str, state: str, generation: str
) -> None:
    with pytest.raises(ValueError):
        Account(address, password_hash, state, generation)


@pytest.mark.parametrize(
    "line",
    [
        f"probe@agents.example.test:{HASH}:enabled:{GEN}\n" * 2,
        f"probe@agents.example.test:{HASH}:enabled\n",
        # A home-directory injection the Dovecot passwd-file would read as fields.
        f"evil@agents.example.test:{HASH}:5000:5000::/var/mail/alice::x:enabled:{GEN}\n",
    ],
)
def test_a_malformed_file_fails(tmp_path, line: str) -> None:
    path = tmp_path / "agents.passwd"
    path.write_text(line, encoding="utf-8")
    with pytest.raises(ValueError):
        read_accounts(path)
