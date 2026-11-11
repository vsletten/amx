"""Optional DKIM signing and verification helpers for the prototype."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from email import policy
from email.parser import BytesParser
from pathlib import Path

import dkim
import dns.exception
import dns.resolver
import yaml

from amx import domain_dkim
from amx.provision import dkim_public_key, dkim_txt_value
from amx.registry import check_name, check_selector, read_registrations, selector_agent

_DKIM_TAG = re.compile(rb"(?:^|;)\s*([a-z]+)=([^;]+)")

# Every header whose value the profile parser or ingress policy consumes after DKIM
# verification must be covered by the signature. Optional headers are harmless here:
# dkimpy includes them in h= only when they are present in the message.
_SIGNED_HEADERS = [
    b"from",
    b"to",
    b"cc",
    b"reply-to",
    b"subject",
    b"date",
    b"message-id",
    b"in-reply-to",
    b"references",
    b"auto-submitted",
    b"mime-version",
    b"content-type",
    b"content-transfer-encoding",
    b"content-disposition",
    b"agent-protocol",
    b"agent-intent",
    b"agent-task",
    b"agent-task-state",
    b"agent-schema",
    b"agent-card",
    b"agent-reply-by",
    b"agent-idempotency-key",
]


@dataclass(frozen=True, slots=True)
class DkimResult:
    """Verified DKIM identity, when validation succeeds."""

    verified: bool
    domain: str | None = None
    selector: str | None = None
    aligned: bool = False
    reason: str = "dkim fail: no signature"
    # SH-44: who the domain vouches for: the signed From address's local part, without its
    # task sub-address (``codex`` for ``codex+t_x@…``). Set only when verified; this, not the
    # selector, is the agent that grants and the agent lane name.
    agent: str | None = None
    # SH-40: the From address itself once DKIM passes and aligns with it, whatever its local part
    # (people's addresses have dots); accept_from matches it. Set even when ``agent`` is None.
    sender: str | None = None

    @property
    def identity(self) -> str | None:
        """The verified agent's name, else the selector (for the reason's sake)."""
        return self.agent if self.verified else self.selector


# SH-40: a person counts as a listed sender only when no third party could re-send their signed
# message with a header of their own: each of these must be over-signed (listed in h= more times
# than the message has it, the way Gmail signs), so adding one breaks the signature.
_SENDER_SIGNED = ("from", "to", "cc", "subject", "reply-to")


def _sender_safe(raw: bytes, tags: dict[str, str]) -> bool:
    """Whether a verified signature binds what an agent acts on: no ``l=`` (appended body text
    would pass), and every header in :data:`_SENDER_SIGNED` over-signed."""
    if "l" in tags:
        return False
    signed = [name.strip().casefold() for name in re.sub(r"\s+", "", tags.get("h", "")).split(":")]
    try:
        headers = BytesParser(policy=policy.compat32).parsebytes(raw, headersonly=True)
        present = [name.casefold() for name in headers]
    except Exception:  # the stdlib header parser raises on some malformed input
        return False
    return all(signed.count(name) > present.count(name) for name in _SENDER_SIGNED)


def _signatures(verifier: dkim.DKIM) -> list[dict[str, str]]:
    """Each DKIM-Signature's tags exactly as dkimpy parsed them, in the order its ``idx`` counts.

    One parse decides both which signature dkimpy verifies and what its tags say: a scan of our
    own could split header lines differently (a bare LF) and read another signature's d=/h=/l=.
    """
    from dkim.util import parse_tag_value

    signatures = []
    for name, value in verifier.headers:
        if name.lower() != b"dkim-signature":
            continue
        try:
            tags = {
                key.decode("ascii"): re.sub(r"\s+", "", item.decode("ascii"))
                for key, item in parse_tag_value(value).items()
            }
        except Exception:  # an unparseable signature vouches for no one, but keeps its index
            tags = {}
        signatures.append(tags)
    return signatures


def _signature_identities(raw: bytes) -> list[tuple[int, str, str]]:
    headers, _, _body = raw.partition(b"\r\n\r\n")
    unfolded = re.sub(rb"\r\n[ \t]+", b" ", headers)
    identities: list[tuple[int, str, str]] = []
    index = -1
    for line in unfolded.split(b"\r\n"):
        if not line.lower().startswith(b"dkim-signature:"):
            continue
        index += 1
        try:
            tags = {
                key.decode("ascii"): value.strip().decode("ascii")
                for key, value in _DKIM_TAG.findall(line)
            }
        except UnicodeDecodeError:
            continue
        domain = tags.get("d")
        selector = tags.get("s")
        if domain and selector:
            # Keep the wire index even when an earlier signature lacks d=/s= or is
            # malformed. Verification must never attribute another signature's identity.
            identities.append((index, domain, selector))
    return identities


def _local_key(
    selector: str,
    registry_dir: Path | None,
    keys_dir: Path | None,
    configured_selectors: frozenset[str] = frozenset(),
) -> bytes | None:
    """Resolve a published registry selector or an explicitly enabled YAML selector."""
    if keys_dir is None:
        return None
    try:
        domain_state = domain_dkim.read(registry_dir)
        if domain_state is not None:
            published = {item for item, _role in domain_state.selectors(datetime.now(UTC))}
            if selector in published:
                return _key_record(keys_dir, selector)
            if domain_state.active is not None and selector not in configured_selectors:
                # The domain signs its registered agents: only its own published selectors (a
                # migrated lane's agent keys among them, while they retire) and the YAML
                # agents' configured ones are authority now.
                return None
        # Validate before any path construction. Reuse registration's ownership/rotation
        # grammar, with a full character check (its regexes allow a final newline).
        if re.fullmatch(r"[a-z0-9.-]+", selector) is None:
            return None
        name = check_name(selector_agent(selector))
        check_selector(name, selector)
        try:
            registration = read_registrations(registry_dir).get(name) if registry_dir else None
        except TypeError:
            # Mixed-type unknown YAML keys can fail before the registry's parser try.
            return None
        if registration is not None:
            if not registration.enabled or selector not in {
                item for item, _role in registration.selectors(datetime.now(UTC))
            }:
                return None
        elif selector not in configured_selectors:
            return None
        return _key_record(keys_dir, selector)
    except (OSError, ValueError, yaml.YAMLError, subprocess.SubprocessError):
        # Missing, malformed or concurrently removed state is not authority to use DNS.
        return None


def _key_record(keys_dir: Path, selector: str) -> bytes | None:
    """The DKIM TXT value of a local key, for a selector already checked against the state."""
    if re.fullmatch(r"[a-z0-9.-]+", selector) is None:
        return None
    try:
        root = keys_dir.resolve()
        key = (root / f"{selector}.private.pem").resolve()
    except RuntimeError:
        # Older pathlib versions report symlink loops as RuntimeError, not OSError.
        return None
    if not key.is_relative_to(root):
        return None
    return dkim_txt_value(dkim_public_key(key)).encode("ascii")


_AGENT_NAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,62})")


def from_identity(raw: bytes) -> tuple[str | None, str, str] | None:
    """``(agent, domain, address)`` from the one address the From header names, read one way.

    The domain is the one DKIM alignment checks, and the agent comes from the same address, so
    the two can never disagree. None (no domain to align, so no verified identity) unless:

    - there is exactly one From header, holding exactly one address and no group, with no
      parser defects (an unclosed quote or a comment inside the address is one);
    - its address is ASCII and appears verbatim in the header as sent, so neither an RFC 2047
      encoded word, nor a comment, nor folding produced it.

    The agent is the local part without its ``+`` task sub-address, lowered by ASCII rules; it is
    None unless that is an agent name (amx.registry's grammar: no dots or quotes), so a sender's
    chosen local part such as ``boss.k1`` never stands for ``boss``.
    """
    try:
        sent = BytesParser(policy=policy.compat32).parsebytes(raw, headersonly=True)
        parsed = BytesParser(policy=policy.default).parsebytes(raw, headersonly=True)
        sent_from, parsed_from = sent.get_all("From"), parsed.get_all("From")
        if not sent_from or not parsed_from or len(sent_from) != 1 or len(parsed_from) != 1:
            return None
        header = parsed_from[0]
        groups = getattr(header, "groups", ())
        if getattr(header, "defects", None) or len(groups) != 1 or groups[0].display_name:
            return None
        if len(groups[0].addresses) != 1:
            return None
        address = groups[0].addresses[0]
        spec = address.addr_spec
        username, domain = address.username, address.domain
    except Exception:  # the stdlib header parser raises on some malformed input
        # A From the parser cannot read names no one: fail closed, never crash the milter.
        return None
    if not (username and domain and spec.isascii()) or spec not in str(sent_from[0]):
        return None
    name = username.partition("+")[0].lower()
    return (name if _AGENT_NAME.fullmatch(name) else None), domain.lower(), spec.lower()


def from_agent(address: str) -> str | None:
    """The agent a From header's value names (:func:`from_identity`), for tools and checks."""
    identity = from_identity(f"From: {address}\r\n\r\n".encode("utf-8", "surrogateescape"))
    return identity[0] if identity else None


def _own_agent_enabled(
    agent: str | None,
    selector: str,
    registry_dir: Path | None,
    configured_selectors: frozenset[str],
) -> bool:
    """Whether the gateway's own domain vouches for ``agent``: registered and enabled, or a
    YAML agent. An agent's own key (before SH-44) also signs only for that agent."""
    if agent is None:
        return False
    if not domain_dkim.is_domain_selector(selector) and selector_agent(selector) != agent:
        return False
    if agent in {selector_agent(item) for item in configured_selectors}:
        return True
    try:
        registration = read_registrations(registry_dir).get(agent) if registry_dir else None
    except (OSError, TypeError, ValueError, yaml.YAMLError):
        return False
    return registration is not None and registration.enabled


def verify(
    raw: bytes,
    nameserver: str | None = None,
    *,
    agent_domain: str | None = None,
    registry_dir: Path | None = None,
    keys_dir: Path | None = None,
    configured_selectors: frozenset[str] = frozenset(),
) -> DkimResult:
    """Verify DKIM and exact From alignment; own-domain authority is local, never DNS.

    Local selectors follow the registry's DNS publication lifecycle, including pending
    and unexpired retiring keys. Its DMARC policy is implicit. Other domains use DNS
    unchanged. No local configuration/registration/key means no own-domain identity.
    """
    identities = _signature_identities(raw)
    if not identities:
        return DkimResult(False)
    resolver = None
    own_domain = agent_domain.casefold() if agent_domain else None

    def txt(query: str, timeout: int = 5) -> bytes | None:
        nonlocal resolver
        normalized = query.rstrip(".").casefold()
        if own_domain is not None:
            if normalized == f"_dmarc.{own_domain}":
                return b"v=DMARC1; p=reject"
            suffix = f"._domainkey.{own_domain}"
            if normalized.endswith(suffix):
                return _local_key(
                    normalized[: -len(suffix)], registry_dir, keys_dir, configured_selectors
                )
        # Construct lazily: a private gateway need not even have resolver configuration.
        if resolver is None:
            resolver = dns.resolver.Resolver(configure=nameserver is None)
            if nameserver is not None:
                resolver.nameservers = [nameserver]
        try:
            answer = resolver.resolve(query, "TXT", lifetime=timeout)
        except dns.exception.DNSException:
            return None
        return b"".join(answer[0].strings)

    sender = from_identity(raw)
    # No single plain From address: nothing to align, so no verified identity (SH-44).
    from_agent_name, from_domain, from_address = sender if sender is not None else (None, "", "")
    verified_unaligned: tuple[str, str] | None = None
    had_key = False
    try:
        verifier = dkim.DKIM(raw)
    except dkim.DKIMException:
        return DkimResult(False, reason="dkim fail: malformed message")
    signatures = _signatures(verifier)
    identities = [
        (index, tags["d"], tags["s"])
        for index, tags in enumerate(signatures)
        if tags.get("d") and tags.get("s")
    ]
    if not identities:
        return DkimResult(False)
    for index, domain, selector in identities:
        key_name = f"{selector}._domainkey.{domain}"
        key_record = txt(key_name)
        if key_record is None:
            continue
        assert key_record is not None
        had_key = True

        def dnsfunc(
            name: bytes,
            timeout: int = 5,
            key_name: str = key_name,
            key_record: bytes = key_record,
        ) -> bytes:
            query = name.rstrip(b".").decode()
            if query.casefold() == key_name.casefold():
                return key_record
            record = txt(query, timeout)
            if record is None:
                raise dns.resolver.NXDOMAIN
            return record

        try:
            dkim_verified = bool(verifier.verify(idx=index, dnsfunc=dnsfunc))
        except (dkim.DKIMException, dns.exception.DNSException, ValueError):
            dkim_verified = False
        if not dkim_verified:
            continue
        if not from_domain or from_domain != domain.casefold():
            verified_unaligned = verified_unaligned or (domain, selector)
            continue

        dmarc = txt(f"_dmarc.{from_domain}")
        if dmarc is None:
            return DkimResult(False, domain, selector, aligned=True, reason="dmarc fail: no policy")
        tags = {
            key.strip().casefold(): value.strip().casefold()
            for item in dmarc.decode("ascii", errors="ignore").split(";")
            if "=" in item
            for key, value in (item.split("=", 1),)
        }
        if tags.get("v") != "dmarc1" or "p" not in tags:
            return DkimResult(
                False, domain, selector, aligned=True, reason="dmarc fail: invalid policy"
            )
        tags = signatures[index]
        # SH-40: only a signature that binds the headers and the whole body vouches for a person.
        from_address = from_address if _sender_safe(raw, tags) else None
        agent = from_agent_name
        if agent is None:
            return DkimResult(
                False,
                domain,
                selector,
                aligned=True,
                reason="dkim pass, but From is not an agent address",
                sender=from_address,
            )
        own = own_domain is not None and from_domain == own_domain
        if own and not _own_agent_enabled(agent, selector, registry_dir, configured_selectors):
            return DkimResult(
                False,
                domain,
                selector,
                aligned=True,
                reason="dkim fail: From names no enabled agent of this domain",
                sender=from_address,
            )
        return DkimResult(
            True,
            domain,
            selector,
            aligned=True,
            reason="dkim pass; dmarc aligned",
            agent=agent,
            sender=from_address,
        )

    if verified_unaligned is not None:
        domain, selector = verified_unaligned
        return DkimResult(False, domain, selector, reason="dmarc fail: unaligned From")
    _index, domain, selector = identities[0]
    if not had_key:
        return DkimResult(False, domain, selector, reason="dkim fail: no key")
    return DkimResult(False, domain, selector, reason="dkim fail: bad signature")


def sign(
    raw: bytes,
    *,
    selector: str,
    domain: str,
    private_key: str | Path | bytes,
) -> bytes:
    """Return raw bytes prefixed with a relaxed DKIM signature."""
    key = private_key if isinstance(private_key, bytes) else Path(private_key).read_bytes()
    signature = dkim.sign(
        raw,
        selector.encode(),
        domain.encode(),
        key,
        canonicalize=(b"relaxed", b"relaxed"),
        include_headers=_SIGNED_HEADERS,
    )
    return signature + raw
