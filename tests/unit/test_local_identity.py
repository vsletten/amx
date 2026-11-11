from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import dns.resolver
import pytest

from amx.identity import sign, verify
from amx.provision import dkim_public_key, dkim_txt_value, generate_dkim_key
from amx.registry import Registration, RetiredSelector, write_registration

DOMAIN = "agents.home.arpa"


@pytest.fixture
def local(tmp_path):
    keys = tmp_path / "keys"
    keys.mkdir()
    key = keys / "scheduler.private.pem"
    generate_dkim_key(key, bits=1024)
    registry = tmp_path / "registry"
    registration = Registration(name="scheduler", submit_token_hash="fixture-only")
    write_registration(registry, registration)
    return SimpleNamespace(
        keys=keys,
        key=key,
        registry=registry,
        registration=registration,
        record=dkim_txt_value(dkim_public_key(key)).encode(),
    )


def signed(local, *, selector="scheduler", domain=DOMAIN, sender_domain=None):
    raw = (
        f"From: scheduler@{sender_domain or domain}\r\n"
        "To: intake+t_local@agents.home.arpa\r\n"
        "Subject: Local request\r\n"
        "Message-ID: <fixture@agents.home.arpa>\r\n"
        "Agent-Protocol: amx/1\r\n"
        "\r\nPlease help.\r\n"
    ).encode()
    return sign(raw, selector=selector, domain=domain, private_key=local.key)


def verify_local(local, raw):
    return verify(
        raw,
        agent_domain=DOMAIN,
        registry_dir=local.registry,
        keys_dir=local.keys,
    )


@pytest.mark.parametrize("dns_mode", ["empty", "raising"])
def test_local_identity_needs_no_dns_even_to_construct_resolver(local, monkeypatch, dns_mode):
    calls = []

    def resolve(*args, **kwargs):
        calls.append(args)
        raise dns.resolver.NXDOMAIN

    if dns_mode == "empty":
        monkeypatch.setattr(dns.resolver.Resolver, "resolve", resolve)
    else:

        def unavailable(*args, **kwargs):
            pytest.fail("local verification must not construct a DNS resolver")

        monkeypatch.setattr(dns.resolver, "Resolver", unavailable)
    result = verify_local(local, signed(local))
    assert result.verified and result.aligned
    assert result.domain == DOMAIN and result.selector == "scheduler"
    assert calls == []


@pytest.mark.parametrize(
    "state", ["disabled", "unregistered", "missing-key", "corrupt-key", "bad-registry"]
)
def test_local_revocation_never_falls_back_to_tempting_dns(local, monkeypatch, state):
    raw = signed(local)
    if state == "disabled":
        write_registration(local.registry, replace(local.registration, enabled=False))
    elif state == "unregistered":
        (local.registry / "agents/scheduler.yaml").unlink()
    elif state == "missing-key":
        local.key.unlink()
    elif state == "corrupt-key":
        local.key.write_bytes(b"not a key")
    else:
        (local.registry / "agents/scheduler.yaml").write_text("[broken yaml")

    def tempting(*args, **kwargs):
        pytest.fail("own-domain revocation must not consult DNS")

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", tempting)
    result = verify_local(local, raw)
    assert not result.verified and result.reason == "dkim fail: no key"


@pytest.mark.parametrize("role", ["active", "pending", "retiring", "expired", "unpublished"])
def test_selector_eligibility_uses_registry_publication_rules(local, monkeypatch, role):
    selector = "scheduler.k2"
    (local.keys / f"{selector}.private.pem").write_bytes(local.key.read_bytes())
    now = datetime.now(UTC)
    registration = local.registration
    if role == "active":
        registration = replace(registration, selector=selector)
    elif role == "pending":
        registration = replace(registration, pending_selector=selector)
    elif role in {"retiring", "expired"}:
        until = now + timedelta(days=1 if role == "retiring" else -1)
        registration = replace(registration, retired_selectors=(RetiredSelector(selector, until),))
    write_registration(local.registry, registration)
    monkeypatch.setattr(
        dns.resolver.Resolver,
        "resolve",
        lambda *a, **kw: pytest.fail("unexpected DNS"),
    )
    result = verify_local(local, signed(local, selector=selector))
    assert result.verified is (role in {"active", "pending", "retiring"})


@pytest.mark.parametrize(
    "selector",
    [
        "../scheduler",
        "/scheduler",
        "scheduler/../../key",
        "scheduler.other",
        "scheduler.k2.extra",
        "scheduler.k1234567890",
        "sched\nuler",
        "ghost",
    ],
)
def test_malformed_or_unregistered_selectors_cannot_read_arbitrary_keys(
    local, monkeypatch, selector
):
    raw = signed(local).replace(b"s=scheduler;", b"s=" + selector.encode() + b";")
    monkeypatch.setattr(
        dns.resolver.Resolver,
        "resolve",
        lambda *a, **kw: pytest.fail("unexpected DNS"),
    )
    # An invalid signature cannot pass either; more importantly, no key is eligible.
    result = verify_local(local, raw)
    assert not result.verified
    assert result.reason in {"dkim fail: no key", "dkim fail: malformed message"}


def test_key_symlink_outside_store_is_not_trusted(local, tmp_path, monkeypatch):
    raw = signed(local)
    outside = tmp_path / "outside.private.pem"
    local.key.rename(outside)
    local.key.symlink_to(outside)
    monkeypatch.setattr(
        dns.resolver.Resolver,
        "resolve",
        lambda *a, **kw: pytest.fail("unexpected DNS"),
    )
    assert verify_local(local, raw).reason == "dkim fail: no key"


@pytest.mark.parametrize("target", ["key-file", "keys-dir"])
@pytest.mark.parametrize("legacy_runtime_error", [False, True])
def test_local_symlink_loops_fail_closed(local, monkeypatch, target, legacy_runtime_error):
    raw = signed(local)
    if target == "key-file":
        loop = local.key
        loop.unlink()
    else:
        loop = local.keys.with_name("keys-loop")
        local.keys = loop
    loop.symlink_to(loop.name)
    if legacy_runtime_error:
        # Python versions differ: exercise the older pathlib failure with the same
        # real loop, even when this runtime returns an unresolved path or OSError.
        resolve = Path.resolve

        def resolve_loop(path, *args, **kwargs):
            if path == loop:
                raise RuntimeError(f"Symlink loop from {path}")
            return resolve(path, *args, **kwargs)

        monkeypatch.setattr(Path, "resolve", resolve_loop)
    monkeypatch.setattr(dns.resolver, "Resolver", lambda *a, **kw: pytest.fail("unexpected DNS"))
    result = verify_local(local, raw)
    assert not result.verified and result.reason == "dkim fail: no key"


def test_local_mixed_type_unknown_registry_keys_fail_closed(local, monkeypatch):
    raw = signed(local)
    registration = local.registry / "agents/scheduler.yaml"
    # Valid YAML, but sorting these unknown mapping keys raises TypeError before
    # registration_from's parser try block.
    with registration.open("a") as stream:
        stream.write("\n1: unknown integer key\nunknown: unknown string key\n")
    monkeypatch.setattr(dns.resolver, "Resolver", lambda *a, **kw: pytest.fail("unexpected DNS"))
    result = verify_local(local, raw)
    assert not result.verified and result.reason == "dkim fail: no key"


@pytest.mark.parametrize(
    "sender_domain", ["home.arpa", "sub.agents.home.arpa", "agents.home.arpa.evil.test"]
)
def test_local_identity_still_requires_exact_from_alignment(local, monkeypatch, sender_domain):
    monkeypatch.setattr(
        dns.resolver.Resolver,
        "resolve",
        lambda *a, **kw: pytest.fail("unexpected DNS"),
    )
    result = verify_local(local, signed(local, sender_domain=sender_domain))
    assert not result.verified and not result.aligned
    assert result.reason == "dmarc fail: unaligned From"


def test_local_identity_still_requires_valid_signature(local, monkeypatch):
    monkeypatch.setattr(
        dns.resolver.Resolver,
        "resolve",
        lambda *a, **kw: pytest.fail("unexpected DNS"),
    )
    result = verify_local(local, signed(local).replace(b"Please help.", b"Forged body."))
    assert not result.verified and result.reason == "dkim fail: bad signature"


@pytest.mark.parametrize("dmarc", [b"v=DMARC1; p=reject", None, b"not DMARC"])
def test_foreign_domain_keeps_dns_and_dmarc_requirements(local, monkeypatch, dmarc):
    foreign = "agents.foreign.test"
    calls = []

    def resolve(_self, name, kind, **kwargs):
        calls.append(name)
        value = local.record if name == f"scheduler._domainkey.{foreign}" else dmarc
        if value is None:
            raise dns.resolver.NXDOMAIN
        return [SimpleNamespace(strings=(value,))]

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", resolve)
    result = verify_local(local, signed(local, domain=foreign))
    assert result.verified is (dmarc == b"v=DMARC1; p=reject")
    assert calls == [f"scheduler._domainkey.{foreign}", f"_dmarc.{foreign}"]


def test_local_domain_case_insensitive_but_identity_is_not_a_grant(local, monkeypatch):
    monkeypatch.setattr(
        dns.resolver.Resolver,
        "resolve",
        lambda *a, **kw: pytest.fail("unexpected DNS"),
    )
    assert verify_local(local, signed(local, domain=DOMAIN.upper())).verified


def test_own_domain_without_local_store_fails_closed(local, monkeypatch):
    monkeypatch.setattr(
        dns.resolver.Resolver,
        "resolve",
        lambda *a, **kw: pytest.fail("unexpected DNS"),
    )
    assert not verify(signed(local), agent_domain=DOMAIN).verified


@pytest.mark.parametrize(
    "edge", ["valid", "disabled", "unregistered", "tampered", "unaligned", "no-grant"]
)
def test_production_milter_verifies_local_identity_and_preserves_policy(
    local, tmp_path, monkeypatch, edge
):
    Milter = pytest.importorskip("Milter")
    from email import policy
    from email.parser import BytesParser

    from amx.adapters.milter import build_milter
    from amx.config import AgentConfig, GatewayConfig, LimitsConfig, MailboxConfig, TrustGrant
    from amx.profile import build
    from amx.runtime import HandlerRegistry
    from amx.store import Store

    config = GatewayConfig(
        domain="home.arpa",
        agent_domain=DOMAIN,
        data_dir=tmp_path,
        agents={
            "intake": AgentConfig(handler="mailbox-only", mode="queued"),
            "scheduler": AgentConfig(handler="mailbox-only", registered=True),
        },
        trust=()
        if edge == "no-grant"
        else (
            TrustGrant(
                d=DOMAIN,
                s="scheduler",
                intents=frozenset({"request"}),
                schemas=frozenset({"*"}),
                can_open_tasks=True,
            ),
        ),
        limits=LimitsConfig(),
        mailbox=MailboxConfig(host="fixture.invalid"),
        registry_dir=local.registry,
        keys_dir=local.keys,
    )
    handlers = HandlerRegistry()
    handlers.register("intake", "mailbox-only", mode="queued", watermark=2)
    cls = build_milter(config, Store(tmp_path / "fixture.sqlite"), handlers)
    message = build(
        sender=f"scheduler@{'other.test' if edge == 'unaligned' else DOMAIN}",
        to=f"intake+t_local@{DOMAIN}",
        subject="Local request",
        intent="request",
        task="t_local",
        task_state="submitted",
        text="Please help.",
    )
    raw = sign(
        message.as_bytes(policy=policy.SMTP),
        selector="scheduler",
        domain=DOMAIN,
        private_key=local.key,
    )
    if edge == "disabled":
        write_registration(local.registry, replace(local.registration, enabled=False))
    elif edge == "unregistered":
        (local.registry / "agents/scheduler.yaml").unlink()
    elif edge == "tampered":
        raw = raw.replace(b"Please help.", b"Forged body.")
    monkeypatch.setattr(dns.resolver, "Resolver", lambda *a, **kw: pytest.fail("unexpected DNS"))
    milter = cls()
    replies = []
    milter.setreply = lambda *args: replies.append(args)
    milter.addheader = lambda *args: None
    milter.getsymval = lambda name: "amx-sibling" if name == "{daemon_name}" else None
    assert milter.connect("mailhost", 2, ("127.0.0.1", 40000)) == Milter.CONTINUE
    assert milter.envfrom(f"<scheduler@{DOMAIN}>") == Milter.CONTINUE
    assert milter.envrcpt(f"<intake+t_local@{DOMAIN}>") == Milter.CONTINUE
    parsed = BytesParser(policy=policy.SMTP).parsebytes(raw)
    for name, value in parsed.raw_items():
        milter.header(name, value.encode())
    milter.body(raw.partition(b"\r\n\r\n")[2])
    assert milter.eom() == (Milter.ACCEPT if edge == "valid" else Milter.REJECT), replies
    milter.close()


@pytest.mark.parametrize("malformed", [b"v=1; b=invalid", b"d=agents.home.arpa; s=\xff"])
def test_malformed_signature_before_local_signature_preserves_wire_index(
    local, monkeypatch, malformed
):
    monkeypatch.setattr(dns.resolver, "Resolver", lambda *a, **kw: pytest.fail("unexpected DNS"))
    raw = b"DKIM-Signature: " + malformed + b"\r\n" + signed(local)
    result = verify_local(local, raw)
    assert result.verified and result.domain == DOMAIN and result.selector == "scheduler"


def test_local_signature_cannot_be_misattributed_to_foreign_identity(local, monkeypatch):
    foreign = "agents.foreign.test"
    # A real local signature over an unaligned From is not a foreign identity,
    # even with malformed leading and trailing foreign signature headers.
    raw = b"DKIM-Signature: v=1; b=invalid\r\n" + signed(local, sender_domain=foreign)
    raw = raw.replace(
        b"\r\nFrom:",
        f"\r\nDKIM-Signature: v=1; d={foreign}; s=scheduler; b=invalid\r\nFrom:".encode(),
    )

    def resolve(_self, name, kind, **kwargs):
        value = b"v=DMARC1; p=reject" if name.startswith("_dmarc.") else local.record
        return [SimpleNamespace(strings=(value,))]

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", resolve)
    result = verify_local(local, raw)
    assert not result.verified
    assert result.domain == DOMAIN and result.reason == "dmarc fail: unaligned From"
