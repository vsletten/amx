from __future__ import annotations

import json
import stat

import pytest

from amx.credentials import (
    hash_password,
    hash_token,
    is_password_hash,
    is_token_hash,
    new_secret,
    read_bundle,
    verify_token,
    write_bundle,
)


def test_new_secret_is_random_and_url_safe() -> None:
    first, second = new_secret(), new_secret()
    assert first != second
    assert len(first) >= 43  # 32 bytes in base64url
    assert all(character.isalnum() or character in "-_" for character in first)


def test_a_token_verifies_against_its_hash_and_nothing_else() -> None:
    hashed = hash_token("the-token")
    assert is_token_hash(hashed)
    assert "the-token" not in hashed
    assert verify_token("the-token", hashed)
    assert not verify_token("the-token2", hashed)
    assert not verify_token("", hashed)


def test_each_token_hash_has_its_own_salt() -> None:
    assert hash_token("same") != hash_token("same")
    assert hash_token("same", salt=b"0123456789abcdef") == hash_token(
        "same", salt=b"0123456789abcdef"
    )


@pytest.mark.parametrize(
    "value",
    ["", "dev-token", "sha256$", "sha256$abc$", "md5$c2FsdHNhbHQ$AAAA", "sha256$!!$AAAA"],
)
def test_a_malformed_hash_is_not_a_hash_and_verifies_nothing(value: str) -> None:
    assert not is_token_hash(value)
    assert not verify_token("anything", value)


def test_password_hash_is_sha512_crypt_and_matches_the_spec_vector() -> None:
    # The SHA-crypt specification's test vector ("Hello world!", salt "saltstring").
    assert hash_password("Hello world!", salt="saltstring") == (
        "{SHA512-CRYPT}$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4"
        "OTLiBFdcbYEdFCoEOfaS35inz1"
    )
    hashed = hash_password("a-random-password")
    assert is_password_hash(hashed)
    assert "a-random-password" not in hashed


@pytest.mark.parametrize("password", ["", "two\nlines", "carriage\rreturn"])
def test_a_password_must_be_one_line(password: str) -> None:
    with pytest.raises(ValueError):
        hash_password(password)


def test_is_password_hash_rejects_other_schemes() -> None:
    assert not is_password_hash("$6$saltstring$abc")
    assert not is_password_hash("{PLAIN}secret")


def test_the_bundle_is_0600_written_once_and_read_back(tmp_path) -> None:
    path = tmp_path / "probe.json"
    write_bundle(
        path,
        {
            "address": "probe@agents.example.test",
            "imap": {"host": "mail.example.test", "port": 993},
            "submission": "smtp://mail.example.test:587",
            "password": "p",
            "token": "t",
        },
    )
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    bundle = read_bundle(path)
    assert bundle["token"] == "t" and bundle["amx_credentials"] == 1
    with pytest.raises(FileExistsError):
        write_bundle(path, {"address": "x"})


def test_read_bundle_refuses_other_files(tmp_path) -> None:
    path = tmp_path / "other.json"
    path.write_text(json.dumps({"address": "x"}), encoding="utf-8")
    with pytest.raises(ValueError, match="not an amx credentials bundle"):
        read_bundle(path)
    path.write_text(json.dumps({"amx_credentials": 1, "address": "x"}), encoding="utf-8")
    with pytest.raises(ValueError, match="lacks imap"):
        read_bundle(path)
