from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from amx import domain_dkim
from amx.config import AgentConfig, GatewayConfig, LimitsConfig, MailboxConfig, TrustGrant
from amx.identity import from_identity, sign, verify
from amx.registration import Site, dkim_value
from amx.registry import Registration, fingerprint, write_registration

DOMAIN = "agents.home.arpa"


@pytest.fixture
def site(tmp_path):
    return Site(
        "home.arpa",
        DOMAIN,
        tmp_path / "registry",
        tmp_path / "keys",
        tmp_path / "accounts",
        dkim_bits=1024,
    )


def test_fresh_domain_one_key_for_all_agents_and_reload_fingerprint(site):
    before = fingerprint(site.registry_dir)
    state = domain_dkim.ensure(site)
    assert state.active.startswith("amx.")
    assert fingerprint(site.registry_dir) != before
    assert domain_dkim.ensure(site) == state
    config = GatewayConfig(
        "home.arpa",
        DOMAIN,
        site.registry_dir,
        {
            "one": AgentConfig("mailbox-only", registered=True),
            "two": AgentConfig("mailbox-only", registered=True),
        },
        (),
        LimitsConfig(),
        MailboxConfig("localhost"),
        domain_selector=state.active,
    )
    assert config.selector_for("one") == config.selector_for("two") == state.active
    assert len(list(site.keys_dir.glob("*.private.pem"))) == 1


def test_migration_requires_published_key_and_preserves_overlap(site, monkeypatch):
    from amx.registration import generate_key

    generate_key(site.key_path("one"), 1024)
    write_registration(site.registry_dir, Registration("one", "fixture-only"))
    state = domain_dkim.ensure(site, migrating=True)
    assert state.active is None and state.pending
    before = fingerprint(site.registry_dir)
    monkeypatch.setattr("amx.registration.lookup_txt", lambda *a: None)
    with pytest.raises(ValueError, match="missing"):
        domain_dkim.activate(site, overlap=timedelta(days=7))
    assert fingerprint(site.registry_dir) == before
    monkeypatch.setattr(
        "amx.registration.lookup_txt", lambda *a: [dkim_value(site.key_path(state.pending))]
    )
    activated = domain_dkim.activate(site, overlap=timedelta(days=7))
    assert activated.active == state.pending and activated.pending is None
    assert [item.selector for item in activated.retiring] == ["one"]
    assert site.key_path("one").exists()
    assert domain_dkim.retire(site) == ()
    domain_dkim.write(
        site.registry_dir,
        DOMAIN,
        replace(
            activated,
            retiring=tuple(
                replace(item, until=datetime.now(UTC) - timedelta(seconds=1))
                for item in activated.retiring
            ),
        ),
    )
    assert domain_dkim.retire(site) == ("one",)
    assert not site.key_path("one").exists()


def test_rotation_never_overwrites_or_switches_before_dns(site, monkeypatch):
    original = domain_dkim.ensure(site)
    staged = domain_dkim.stage(site)
    assert staged.active == original.active and staged.pending != original.active
    with pytest.raises(ValueError, match="already staged"):
        domain_dkim.stage(site)
    monkeypatch.setattr(
        "amx.registration.lookup_txt", lambda *a: [dkim_value(site.key_path(staged.pending))]
    )
    active = domain_dkim.activate(site, overlap=timedelta(days=7))
    assert active.active == staged.pending
    assert active.retiring[0].selector == original.active


@pytest.mark.parametrize("selector", ["amx.2026-10", "scheduler", "scheduler.k2"])
@pytest.mark.parametrize("name", ["scheduler", "scheduler+t_example"])
def test_foreign_identity_is_signed_from_not_selector(site, monkeypatch, selector, name):
    state = domain_dkim.ensure(site)
    record = dkim_value(site.key_path(state.active)).encode()
    monkeypatch.setattr(
        "dns.resolver.Resolver.resolve",
        lambda self, host, *a, **kw: [
            SimpleNamespace(
                strings=(b"v=DMARC1; p=reject" if host.startswith("_dmarc") else record,)
            )
        ],
    )
    raw = sign(
        f"From: {name}@{DOMAIN}\r\n\r\nHello.\r\n".encode(),
        selector=selector,
        domain=DOMAIN,
        private_key=site.key_path(state.active),
    )
    result = verify(raw)
    assert result.verified and result.agent == "scheduler" and result.selector == selector
    assert TrustGrant(d=DOMAIN, s="scheduler").names(result.domain, result.agent)
    assert not TrustGrant(d=DOMAIN, s="other").names(result.domain, result.agent)


@pytest.mark.parametrize("status", ["enabled", "disabled", "unknown"])
def test_own_domain_shared_key_does_not_vouch_for_unknown_from(site, status):
    state = domain_dkim.ensure(site)
    if status != "unknown":
        write_registration(
            site.registry_dir,
            Registration("scheduler", "fixture-only", enabled=status == "enabled"),
        )
    raw = sign(
        f"From: scheduler+t_example@{DOMAIN}\r\n\r\nHello.\r\n".encode(),
        selector=state.active,
        domain=DOMAIN,
        private_key=site.key_path(state.active),
    )
    result = verify(
        raw, agent_domain=DOMAIN, registry_dir=site.registry_dir, keys_dir=site.keys_dir
    )
    assert result.verified is (status == "enabled")


@pytest.mark.parametrize(
    ("sender", "agent"),
    [
        ("scheduler+t_x@{d}", "scheduler"),
        ("Scheduler@{d}", "scheduler"),
        ("boss.k1@{d}", None),  # a sender-chosen suffix must not stand for "boss"
        ("planner.mail@{d}", None),
        ("@{d}", None),
        # Unicode case folding and RFC 2047 decoding must not turn a local part into "boss".
        ("bo\u017fs@{d}", None),
        ("bo\u00df@{d}", None),
        ("=?utf-8?q?boss?=@{d}", None),
        ('"=?utf-8?q?boss?="@{d}', None),
        # One parse decides both the aligned domain and the agent (round-3 review).
        ("bo(c)ss@{d}", None),
        ("(c)b(x)o(y)s(z)s@{d}", None),
        ("{d}<boss@\\", None),
        ('"boss@x =?utf-8?q?x=40{d}?=', None),
        ("boss@=?utf-8?q?{d}?=", None),
        ("<x@{d}> (<boss@{d}>)", "x"),
        ('"Boss" <boss+t_1@{d}>', "boss"),
    ],
)
def test_only_an_agent_name_is_an_identity(site, monkeypatch, sender, agent):
    state = domain_dkim.ensure(site)
    record = dkim_value(site.key_path(state.active)).encode()
    monkeypatch.setattr(
        "dns.resolver.Resolver.resolve",
        lambda self, host, *a, **kw: [
            SimpleNamespace(
                strings=(b"v=DMARC1; p=reject" if host.startswith("_dmarc") else record,)
            )
        ],
    )
    raw = sign(
        f"From: {sender.format(d=DOMAIN)}\r\n\r\nHello.\r\n".encode(),
        selector=state.active,
        domain=DOMAIN,
        private_key=site.key_path(state.active),
    )
    result = verify(raw)
    assert result.verified is (agent is not None) and result.agent == agent
    assert TrustGrant(d=DOMAIN, s="boss").names(result.domain, result.identity) is (agent == "boss")


def test_yaml_agents_keep_their_own_key_beside_the_domain_key(site):
    from amx.registration import generate_key

    state = domain_dkim.ensure(site)
    generate_key(site.key_path("ops"), 1024)
    config = GatewayConfig(
        "home.arpa",
        DOMAIN,
        site.registry_dir,
        {"ops": AgentConfig("mailbox-only"), "one": AgentConfig("mailbox-only", registered=True)},
        (),
        LimitsConfig(),
        MailboxConfig("localhost"),
        domain_selector=state.active,
    )
    assert config.selector_for("ops") == "ops"
    assert config.selector_for("one") == state.active
    raw = sign(
        f"From: ops+t_x@{DOMAIN}\r\n\r\nHello.\r\n".encode(),
        selector="ops",
        domain=DOMAIN,
        private_key=site.key_path("ops"),
    )
    result = verify(
        raw,
        agent_domain=DOMAIN,
        registry_dir=site.registry_dir,
        keys_dir=site.keys_dir,
        configured_selectors=frozenset({"ops"}),
    )
    assert result.verified and result.agent == "ops"
    # Without the YAML's say-so the per-agent key is no authority once the domain signs.
    assert not verify(
        raw, agent_domain=DOMAIN, registry_dir=site.registry_dir, keys_dir=site.keys_dir
    ).verified


@pytest.mark.parametrize(
    "value",
    [":+tboß;[BOSS\t", 'bosspartner.example],"', "boß\tss@[ ", "(c)::=?utf-8?q?x=40p?=;"],
)
def test_a_from_the_parser_chokes_on_names_no_one(value):
    # The stdlib header parser raises on some malformed input; that must fail closed, not crash.
    assert from_identity(f"From: {value}\r\n\r\nx\r\n".encode()) is None
