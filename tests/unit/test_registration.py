from __future__ import annotations

import json
import stat
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from amx import registration as reg
from amx.accounts import read_accounts
from amx.credentials import is_password_hash, verify_token
from amx.registry import RetiredSelector, read_registrations, write_registration

IMAP = "mail.example.test:1143"
SUBMISSION = "smtp://mail.example.test:2587"


@pytest.fixture
def site(tmp_path) -> reg.Site:
    return reg.Site(
        domain="example.test",
        agent_domain="agents.example.test",
        registry_dir=tmp_path / "registry",
        keys_dir=tmp_path / "keys",
        accounts_file=tmp_path / "accounts" / "agents.passwd",
        yaml_agents=frozenset({"intake"}),
    )


def _add(site: reg.Site, tmp_path, name: str = "probe", **options) -> reg.AddResult:
    return reg.add(
        site,
        name,
        bundle=tmp_path / f"{name}.json",
        imap=IMAP,
        submission=SUBMISSION,
        **options,
    )


def _secrets(tmp_path, name: str = "probe") -> tuple[str, str]:
    bundle = json.loads((tmp_path / f"{name}.json").read_text(encoding="utf-8"))
    return bundle["token"], bundle["password"]


def test_add_writes_a_key_an_account_a_registration_and_one_bundle(site, tmp_path) -> None:
    result = _add(site, tmp_path)
    assert stat.S_IMODE(result.key.stat().st_mode) == 0o600
    assert stat.S_IMODE(result.bundle.stat().st_mode) == 0o600
    token, password = _secrets(tmp_path)
    bundle = json.loads(result.bundle.read_text(encoding="utf-8"))
    assert bundle["address"] == "probe@agents.example.test"
    assert bundle["imap"] == IMAP
    assert bundle["submission"] == SUBMISSION
    registration = read_registrations(site.registry_dir)["probe"]
    assert registration.mode == "remote" and registration.selector == "probe"
    assert verify_token(token, registration.submit_token_hash)
    account = read_accounts(site.accounts_file)["probe@agents.example.test"]
    assert account.state == "enabled" and is_password_hash(account.password_hash)
    # The plaintext is in the bundle and nowhere on the server side.
    for path in (site.registry_dir / "agents" / "probe.yaml", site.accounts_file):
        text = path.read_text(encoding="utf-8")
        assert token not in text and password not in text


def test_add_refuses_a_second_add_and_changes_nothing(site, tmp_path) -> None:
    _add(site, tmp_path)
    (tmp_path / "probe.json").unlink()
    before = site.accounts_file.read_bytes()
    with pytest.raises(reg.RegistrationError, match="already registered"):
        _add(site, tmp_path)
    assert site.accounts_file.read_bytes() == before
    assert not (tmp_path / "probe.json").exists()


@pytest.mark.parametrize(
    ("existing", "message"),
    [("key", "key for selector probe"), ("bundle", "bundle path already exists")],
)
def test_add_never_overwrites_a_key_or_a_bundle(site, tmp_path, existing, message) -> None:
    path = site.key_path("probe") if existing == "key" else tmp_path / "probe.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("kept", encoding="utf-8")
    with pytest.raises(reg.RegistrationError, match=message):
        _add(site, tmp_path)
    assert path.read_text(encoding="utf-8") == "kept"
    assert not site.accounts_file.exists()


def test_add_refuses_an_agent_the_yaml_configures(site, tmp_path) -> None:
    with pytest.raises(reg.RegistrationError, match="gateway YAML"):
        _add(site, tmp_path, "intake")


def test_add_rolls_back_when_a_later_step_fails(site, tmp_path, monkeypatch) -> None:
    def broken(*_args, **_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(reg, "write_registration", broken)
    with pytest.raises(OSError, match="disk full"):
        _add(site, tmp_path)
    assert not (tmp_path / "probe.json").exists()
    assert not site.key_path("probe").exists()
    # The mailhost may already have made the account: a tombstone has it delete it.
    [account] = read_accounts(site.accounts_file).values()
    assert (account.address, account.state) == ("probe@agents.example.test", "purge")


def test_a_name_registered_again_gets_a_new_generation(site, tmp_path) -> None:
    _add(site, tmp_path)
    first = read_accounts(site.accounts_file)["probe@agents.example.test"].generation
    reg.disable(site, "probe")
    reg.purge(site, "probe", grace=timedelta(0))
    (tmp_path / "probe.json").unlink()
    _add(site, tmp_path)
    again = read_accounts(site.accounts_file)["probe@agents.example.test"]
    # The mailhost deletes the old agent's mailbox even if it never saw the tombstone.
    assert again.state == "enabled" and again.generation != first


def test_rotation_keeps_the_generation(site, tmp_path) -> None:
    _add(site, tmp_path)
    first = read_accounts(site.accounts_file)["probe@agents.example.test"].generation
    reg.rotate(site, "probe", dkim=False, bundle=tmp_path / "probe-2.json")
    assert read_accounts(site.accounts_file)["probe@agents.example.test"].generation == first


def test_a_missing_account_line_stops_before_anything_is_written(site, tmp_path) -> None:
    _add(site, tmp_path)
    site.accounts_file.unlink()
    before = (site.registry_dir / "agents" / "probe.yaml").read_bytes()
    with pytest.raises(reg.RegistrationError, match="no line in"):
        reg.disable(site, "probe")
    assert (site.registry_dir / "agents" / "probe.yaml").read_bytes() == before
    # A purge writes a tombstone instead, so the mailhost deletes whatever it has.
    registration = read_registrations(site.registry_dir)["probe"]
    write_registration(
        site.registry_dir, replace(registration, enabled=False, disabled_at=registration.created_at)
    )
    result = reg.purge(site, "probe", grace=timedelta(0))
    assert result.deleted_keys == (site.key_path("probe"),)
    assert read_accounts(site.accounts_file)["probe@agents.example.test"].state == "purge"


def test_activate_refuses_a_staged_key_other_than_the_one_checked(site, tmp_path) -> None:
    _add(site, tmp_path)
    reg.rotate(site, "probe", credentials=False)
    with pytest.raises(reg.RegistrationError, match=r"not the probe\.k9 that was checked"):
        reg.activate(site, "probe", overlap=timedelta(days=1), expected="probe.k9")
    assert reg.activate(site, "probe", overlap=timedelta(days=1), expected="probe.k2")


def test_disable_then_enable(site, tmp_path) -> None:
    _add(site, tmp_path)
    disabled = reg.disable(site, "probe")
    assert not disabled.enabled and disabled.disabled_at is not None
    assert read_accounts(site.accounts_file)["probe@agents.example.test"].state == "disabled"
    with pytest.raises(reg.RegistrationError, match="already disabled"):
        reg.disable(site, "probe")
    enabled = reg.enable(site, "probe")
    assert enabled.enabled and enabled.disabled_at is None
    assert read_accounts(site.accounts_file)["probe@agents.example.test"].state == "enabled"


def test_purge_needs_a_disabled_agent_and_its_grace(site, tmp_path) -> None:
    _add(site, tmp_path)
    with pytest.raises(reg.RegistrationError, match="disable probe first"):
        reg.purge(site, "probe", grace=timedelta(days=7))
    reg.disable(site, "probe")
    with pytest.raises(reg.RegistrationError, match="grace period ends"):
        reg.purge(site, "probe", grace=timedelta(days=7))
    result = reg.purge(site, "probe", grace=timedelta(days=7), force=True)
    assert read_registrations(site.registry_dir) == {}
    assert read_accounts(site.accounts_file)["probe@agents.example.test"].state == "purge"
    assert result.deleted_keys == (site.key_path("probe"),)
    assert "probe._domainkey.agents.example.test" in result.unpublish
    assert "probe._agents.agents.example.test" in result.unpublish


def test_operations_on_an_unknown_or_yaml_agent_fail(site) -> None:
    with pytest.raises(reg.RegistrationError, match="not registered"):
        reg.disable(site, "ghost")
    with pytest.raises(reg.RegistrationError, match="edit it there"):
        reg.disable(site, "intake")


def test_rotate_replaces_both_secrets_and_stages_a_key(site, tmp_path) -> None:
    _add(site, tmp_path)
    old_token, _old_password = _secrets(tmp_path)
    old_account = read_accounts(site.accounts_file)["probe@agents.example.test"]
    result = reg.rotate(site, "probe", bundle=tmp_path / "probe-2.json")
    new_token, _new_password = _secrets(tmp_path, "probe-2")
    registration = read_registrations(site.registry_dir)["probe"]
    assert verify_token(new_token, registration.submit_token_hash)
    assert not verify_token(old_token, registration.submit_token_hash)
    account = read_accounts(site.accounts_file)["probe@agents.example.test"]
    assert account.password_hash != old_account.password_hash
    assert result.staged_selector == registration.pending_selector == "probe.k2"
    assert registration.selector == "probe"  # still signing with the old key
    assert site.key_path("probe.k2").exists()
    with pytest.raises(reg.RegistrationError, match="already staged"):
        reg.rotate(site, "probe", credentials=False)


def test_rotate_keeps_a_disabled_accounts_state(site, tmp_path) -> None:
    _add(site, tmp_path)
    reg.disable(site, "probe")
    reg.rotate(site, "probe", dkim=False, bundle=tmp_path / "probe-2.json")
    assert read_accounts(site.accounts_file)["probe@agents.example.test"].state == "disabled"


def test_rotate_rolls_back_the_account_when_the_registry_write_fails(
    site, tmp_path, monkeypatch
) -> None:
    _add(site, tmp_path)
    before = site.accounts_file.read_bytes()

    def broken(*_args, **_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(reg, "write_registration", broken)
    with pytest.raises(OSError):
        reg.rotate(site, "probe", bundle=tmp_path / "probe-2.json")
    assert site.accounts_file.read_bytes() == before
    assert not (tmp_path / "probe-2.json").exists()
    assert not site.key_path("probe.k2").exists()


def test_rotate_needs_something_to_rotate_and_a_new_bundle(site, tmp_path) -> None:
    _add(site, tmp_path)
    with pytest.raises(reg.RegistrationError, match="nothing to rotate"):
        reg.rotate(site, "probe", credentials=False, dkim=False)
    with pytest.raises(reg.RegistrationError, match="--bundle"):
        reg.rotate(site, "probe", bundle=tmp_path / "probe.json")


def test_activate_switches_the_selector_and_retires_the_old_one(site, tmp_path) -> None:
    _add(site, tmp_path)
    with pytest.raises(reg.RegistrationError, match="no staged key"):
        reg.activate(site, "probe", overlap=timedelta(days=7))
    reg.rotate(site, "probe", credentials=False)
    result = reg.activate(site, "probe", overlap=timedelta(days=7))
    registration = read_registrations(site.registry_dir)["probe"]
    assert registration.selector == "probe.k2" and registration.pending_selector is None
    assert [item.selector for item in registration.retired_selectors] == ["probe"]
    assert result.retired == "probe"
    reg.rotate(site, "probe", credentials=False)
    assert read_registrations(site.registry_dir)["probe"].pending_selector == "probe.k3"


def test_activate_deletes_retired_keys_whose_overlap_ended(site, tmp_path) -> None:
    _add(site, tmp_path)
    reg.rotate(site, "probe", credentials=False)
    registration = read_registrations(site.registry_dir)["probe"]
    expired = datetime.now(UTC) - timedelta(minutes=1)
    reg.generate_key(site.key_path("probe.k1"))
    write_registration(
        site.registry_dir,
        replace(registration, retired_selectors=(RetiredSelector("probe.k1", expired),)),
    )
    result = reg.activate(site, "probe", overlap=timedelta(days=1))
    assert result.pruned == (site.key_path("probe.k1"),)
    assert not site.key_path("probe.k1").exists()
    remaining = read_registrations(site.registry_dir)["probe"].retired_selectors
    assert [item.selector for item in remaining] == ["probe"]


@pytest.mark.parametrize(
    ("text", "expected"),
    [("90s", timedelta(seconds=90)), ("30m", timedelta(minutes=30)), ("7d", timedelta(days=7))],
)
def test_parse_duration(text: str, expected: timedelta) -> None:
    assert reg.parse_duration(text) == expected


@pytest.mark.parametrize("text", ["7", "7w", "-1d", "d"])
def test_parse_duration_refuses_other_shapes(text: str) -> None:
    with pytest.raises(ValueError):
        reg.parse_duration(text)


def test_record_lines_give_the_zone_file_and_dns_host_forms() -> None:
    value = "v=DKIM1; k=rsa; p=" + "A" * 400
    zone, dns_host = reg.record_lines("intake._domainkey.agents.example.com", value, "example.com")
    assert zone.startswith("  zone file: intake._domainkey.agents.example.com. 3600 IN TXT ")
    assert zone.count('"') == 4  # two character-strings: 255 + the rest
    assert "DNS host:  Type TXT | Name intake._domainkey.agents |" in dns_host
    assert f"Value {value} |" in dns_host


def test_relative_name_outside_the_zone_is_left_whole() -> None:
    assert reg.relative_name("a._domainkey.agents.other.test", "example.com") == (
        "a._domainkey.agents.other.test"
    )


def test_dkim_matches_compares_the_published_key(tmp_path) -> None:
    key = tmp_path / "k.pem"
    reg.generate_key(key)
    value = reg.dkim_value(key)
    assert reg.dkim_matches([value], key) == "ok"
    # Whitespace a DNS host inserts inside p= does not matter.
    spaced = value[:40] + " " + value[40:]
    assert reg.dkim_matches(["some other txt", spaced], key) == "ok"
    assert reg.dkim_matches(None, key) == "missing"
    assert reg.dkim_matches(["v=DKIM1; k=rsa; p=AAAA"], key) == "mismatch"


def test_check_endpoints() -> None:
    reg.check_endpoints("mail.example.test:993", "smtp://mail.example.test:587")
    with pytest.raises(ValueError):
        reg.check_endpoints("mail.example.test", "smtp://mail.example.test:587")
    with pytest.raises(ValueError):
        reg.check_endpoints("mail.example.test:993", "mail.example.test:587")


def test_add_refuses_the_gateways_control_address(site, tmp_path) -> None:
    renamed = replace(site, reserved=frozenset({"gw-ctl"}))
    with pytest.raises(reg.RegistrationError, match="reserved on this gateway"):
        _add(renamed, tmp_path, "gw-ctl")


def _refusing(message: str):
    def validate() -> None:
        raise ValueError(message)

    return validate


def test_a_result_the_gateway_would_not_load_is_undone(site, tmp_path) -> None:
    _add(site, tmp_path)
    registration_file = site.registry_dir / "agents" / "probe.yaml"
    before = (registration_file.read_bytes(), site.accounts_file.read_bytes())
    reg.disable(site, "probe")
    disabled = (registration_file.read_bytes(), site.accounts_file.read_bytes())
    blocked = replace(site, validate=_refusing("hold_rules[0] names unknown agents: probe"))
    with pytest.raises(reg.RegistrationError, match="would not load"):
        reg.purge(blocked, "probe", grace=timedelta(0))
    # The registration, the account line, and the keys are all as they were.
    assert (registration_file.read_bytes(), site.accounts_file.read_bytes()) == disabled
    assert site.key_path("probe").exists()
    assert before != disabled


def test_an_add_the_gateway_would_not_load_leaves_a_tombstone_and_no_files(site, tmp_path) -> None:
    blocked = replace(site, validate=_refusing("role_addresses name agents: probe"))
    with pytest.raises(reg.RegistrationError, match="would not load"):
        _add(blocked, tmp_path)
    assert read_registrations(site.registry_dir) == {}
    assert not site.key_path("probe").exists() and not (tmp_path / "probe.json").exists()
    assert read_accounts(site.accounts_file)["probe@agents.example.test"].state == "purge"


def test_submission_must_be_smtp_not_smtps() -> None:
    with pytest.raises(ValueError, match="smtp://host:port"):
        reg.check_endpoints("imaps://mail.example.test", "smtps://mail.example.test:465")


@pytest.mark.parametrize(
    ("server", "nameservers", "port"),
    [("127.0.0.1:15353", ["127.0.0.1"], 15353), ("192.0.2.53", ["192.0.2.53"], 53)],
)
def test_the_dns_check_asks_a_resolver_on_any_port(monkeypatch, server, nameservers, port) -> None:
    """--dns-server takes ip or ip:port, as preflight's --resolver does (a CoreDNS on 15353)."""
    asked: list[tuple[list[str], int]] = []

    def resolve(self, _name, _rdtype, lifetime):
        asked.append((list(self.nameservers), self.port))
        raise reg.dns.resolver.NXDOMAIN

    monkeypatch.setattr(reg.dns.resolver.Resolver, "resolve", resolve)
    assert reg.lookup_txt("x._domainkey.agents.example.test", server) is None
    assert asked == [(nameservers, port)]


def test_a_site_makes_keys_of_its_own_size(site, tmp_path) -> None:
    small = replace(site, dkim_bits=1024)
    reg.add(small, "probe", bundle=tmp_path / "probe.json", imap=IMAP, submission=SUBMISSION)
    assert len(reg.public_key(small.key_path("probe"))) < 300  # 1024 bits; 2048 is ~392
    with pytest.raises(ValueError, match="2048"):
        reg.generate_key(tmp_path / "odd.pem", 4096)
