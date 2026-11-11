from __future__ import annotations

import base64
import re
import subprocess
from datetime import UTC, datetime

import dkim
import dns.resolver
import pytest

from amx.identity import sign, verify
from amx.profile import SCHEMA_BASE, build


@pytest.fixture(scope="module")
def dkim_material(tmp_path_factory):
    root = tmp_path_factory.mktemp("dkim")
    private_key = root / "test.private.pem"
    public_key = root / "test.public.der"
    subprocess.run(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:1024",
            "-out",
            str(private_key),
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "openssl",
            "pkey",
            "-in",
            str(private_key),
            "-pubout",
            "-outform",
            "DER",
            "-out",
            str(public_key),
        ],
        check=True,
        capture_output=True,
    )
    record = b"v=DKIM1; k=rsa; p=" + base64.b64encode(public_key.read_bytes())
    return private_key, record


def _signed_profile(private_key) -> bytes:
    message = build(
        sender="scheduler@agents.northwind.test",
        to="intake+t_signed@agents.contoso.test",
        cc="victor@northwind.test",
        reply_to="scheduler@agents.northwind.test",
        subject="Signed controls",
        intent="request",
        task="t_signed",
        task_state="submitted",
        text="Please process this signed request.",
        payload={"action": "intake"},
        schema=f"{SCHEMA_BASE}request.json",
        in_reply_to="<parent@agents.northwind.test>",
        references=("<root@agents.northwind.test>", "<parent@agents.northwind.test>"),
        card="https://northwind.test/.well-known/agents/scheduler.json",
        reply_by=datetime(2026, 9, 25, 12, tzinfo=UTC),
        idempotency_key="idem-signed",
        message_id="<signed-controls@agents.northwind.test>",
        date=datetime(2026, 9, 24, 12, tzinfo=UTC),
    )
    return sign(
        message.as_bytes(),
        selector="scheduler",
        domain="agents.northwind.test",
        private_key=private_key,
    )


def _verify(raw: bytes, record: bytes) -> bool:
    def dnsfunc(_name: bytes, timeout: int = 5) -> bytes:
        assert timeout > 0
        return record

    return bool(dkim.verify(raw, dnsfunc=dnsfunc))


def _replace_header(raw: bytes, name: str, value: str) -> bytes:
    pattern = re.compile(
        rb"^" + re.escape(name.encode()) + rb":[^\r\n]*(?:\r\n[ \t][^\r\n]*)*",
        re.IGNORECASE | re.MULTILINE,
    )
    replaced, count = pattern.subn(f"{name}: {value}".encode(), raw, count=1)
    assert count == 1
    return replaced


def _strip_header(raw: bytes, name: str) -> bytes:
    pattern = re.compile(
        rb"^" + re.escape(name.encode()) + rb":[^\r\n]*(?:\r\n[ \t][^\r\n]*)*\r\n",
        re.IGNORECASE | re.MULTILINE,
    )
    stripped, count = pattern.subn(b"", raw, count=1)
    assert count == 1
    return stripped


@pytest.mark.parametrize(
    "header",
    [
        "Agent-Protocol",
        "Agent-Intent",
        "Agent-Task",
        "Agent-Task-State",
        "Agent-Schema",
        "Agent-Card",
        "Agent-Reply-By",
        "Agent-Idempotency-Key",
        "Auto-Submitted",
        "In-Reply-To",
        "References",
        "Cc",
        "Reply-To",
        "Content-Type",
    ],
)
def test_mutating_any_consumed_control_or_thread_header_breaks_dkim(
    dkim_material, header: str
) -> None:
    private_key, record = dkim_material
    signed = _signed_profile(private_key)
    assert _verify(signed, record)
    assert not _verify(_replace_header(signed, header, "tampered"), record)


def test_stripping_signed_profile_header_breaks_dkim(dkim_material) -> None:
    private_key, record = dkim_material
    signed = _signed_profile(private_key)
    assert _verify(signed, record)
    assert not _verify(_strip_header(signed, "Agent-Intent"), record)


class _TxtAnswer:
    def __init__(self, value: bytes) -> None:
        self.strings = (value,)


def test_verify_requires_real_dkim_and_aligned_dmarc_policy(dkim_material, monkeypatch) -> None:
    private_key, record = dkim_material
    signed = _signed_profile(private_key)

    def resolve(_self, name: str, kind: str, **_kwargs):
        assert kind == "TXT"
        if name == "scheduler._domainkey.agents.northwind.test":
            return [_TxtAnswer(record)]
        if name == "_dmarc.agents.northwind.test":
            return [_TxtAnswer(b"v=DMARC1; p=reject")]
        raise dns.resolver.NXDOMAIN

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", resolve)
    result = verify(signed, "127.0.0.1")
    assert result.verified
    assert result.aligned
    assert result.domain == "agents.northwind.test"
    assert result.selector == "scheduler"
    assert result.reason == "dkim pass; dmarc aligned"


def test_verify_reports_revoked_selector_as_no_key(dkim_material, monkeypatch) -> None:
    private_key, _record = dkim_material

    def no_records(_self, _name: str, _kind: str, **_kwargs):
        raise dns.resolver.NXDOMAIN

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", no_records)
    result = verify(_signed_profile(private_key), "127.0.0.1")
    assert not result.verified
    assert not result.aligned
    assert result.reason == "dkim fail: no key"


def test_verify_accepts_any_valid_aligned_signature_when_unaligned_signature_is_first(
    dkim_material, monkeypatch
) -> None:
    private_key, record = dkim_material
    aligned = _signed_profile(private_key)
    relay_first = sign(
        aligned,
        selector="relay",
        domain="relay.test",
        private_key=private_key,
    )

    def resolve(_self, name: str, kind: str, **_kwargs):
        assert kind == "TXT"
        if name in {
            "relay._domainkey.relay.test",
            "scheduler._domainkey.agents.northwind.test",
        }:
            return [_TxtAnswer(record)]
        if name == "_dmarc.agents.northwind.test":
            return [_TxtAnswer(b"v=DMARC1; p=reject")]
        raise dns.resolver.NXDOMAIN

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", resolve)

    result = verify(relay_first, "127.0.0.1")

    assert result.verified
    assert result.aligned
    assert result.domain == "agents.northwind.test"
    assert result.selector == "scheduler"
