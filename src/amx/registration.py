"""The operator's registration flow: add, remove, enable, rotate, and check an agent (PLAN §5.2).

The org's administrator vouches for an agent by registering it; agents never register
themselves. Since SH-44 the domain signs every agent's mail with one key (:mod:`amx.domain_dkim`),
so registering changes no DNS. Each operation here changes up to three places, in an order that
keeps them consistent for the gateway and the mailhost, which pick changes up without a restart:

- before SH-44 only: the agent's own DKIM private key, 0600 in the gateway's keys directory
  (``<selector>.private.pem``);
- the mailhost's accounts file (:mod:`amx.accounts`): the IMAP password's hash;
- the registry (:mod:`amx.registry`): the agent, its token's hash, and its selectors.

The plaintext password and token exist only in memory and in one credentials bundle the
operator hands to the agent's host (:func:`amx.credentials.write_bundle`). Nothing here prints
or logs a secret; what it prints is the DNS the operator must publish.
"""

from __future__ import annotations

import contextlib
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import dns.exception
import dns.resolver

from amx.accounts import Account, new_generation, read_accounts, set_account, set_state
from amx.address_lists import parse_outbound_allowlist
from amx.credentials import hash_password, hash_token, new_secret, write_bundle
from amx.mailbox import ImapEndpoint
from amx.provision import dkim_public_key, dkim_txt_value, generate_dkim_key
from amx.registry import (
    DEFAULT_INTENTS,
    Registration,
    RetiredSelector,
    atomic_write,
    check_name,
    delete_registration,
    locked,
    read_registrations,
    write_registration,
)

_DURATION = re.compile(r"^(\d+)([smhd])$")
_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}
_ROTATED = re.compile(r"^[a-z0-9-]+\.k(\d+)$")


class RegistrationError(ValueError):
    """An operation the registry's current state does not allow; nothing was changed."""


def parse_duration(text: str) -> timedelta:
    """``90s``, ``30m``, ``12h``, or ``7d``."""
    match = _DURATION.match(text.strip())
    if match is None:
        raise ValueError(f"duration must look like 90s, 30m, 12h, or 7d: {text!r}")
    return timedelta(**{_UNITS[match.group(2)]: int(match.group(1))})


def _now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


@dataclass(frozen=True, slots=True)
class Site:
    """Where one gateway's registration state lives, as seen from where the command runs."""

    domain: str
    agent_domain: str
    registry_dir: Path
    keys_dir: Path
    accounts_file: Path
    yaml_agents: frozenset[str] = frozenset()
    # Local parts this gateway reserves beyond RESERVED_NAMES: its control address (§5.10) and
    # its role addresses.
    reserved: frozenset[str] = frozenset()
    # Loads the gateway's configuration as it now stands and raises if it does not load. Every
    # command runs it on its result under the lock, and undoes its writes if it fails: a
    # registry the gateway cannot load would block every later reload, a revocation included.
    validate: Callable[[], object] | None = None
    # New DKIM keys' size: 2048, or 1024 where a DNS editor cannot hold the longer record (the
    # live lane's tls.dkim_bits, docs/selfhost-public.md §4).
    dkim_bits: int = 2048
    # The zone the records are published in, for their names relative to it (default: domain).
    zone: str | None = None

    @property
    def dns_zone(self) -> str:
        return self.zone or self.domain

    def address(self, name: str) -> str:
        return f"{name}@{self.agent_domain}"

    def key_path(self, selector: str) -> Path:
        return self.keys_dir / f"{selector}.private.pem"


# DNS ------------------------------------------------------------------------------------------


def generate_key(path: Path, bits: int = 2048) -> None:
    """A new RSA key (2048 bits by default), 0600, never overwriting a file (``amx.provision``)."""
    if bits not in (1024, 2048):
        raise ValueError("a DKIM key is 2048 bits, or 1024 where DNS cannot hold the record")
    generate_dkim_key(path, bits)


def public_key(private_key: Path) -> str:
    """The base64 DER public key that goes in the DKIM record's ``p=`` tag."""
    return dkim_public_key(private_key)


def dkim_value(private_key: Path) -> str:
    """The DKIM TXT value for a key."""
    return dkim_txt_value(public_key(private_key))


def dkim_name(selector: str, agent_domain: str) -> str:
    return f"{selector}._domainkey.{agent_domain}"


def relative_name(fqdn: str, zone: str) -> str:
    """A record's name relative to the zone, as most DNS hosts' Name fields expect."""
    suffix = "." + zone.strip(".").casefold()
    name = fqdn.strip(".").casefold()
    return name[: -len(suffix)] if name.endswith(suffix) else name


def zone_txt(value: str) -> str:
    """A TXT value as zone-file strings, split at 255 characters (RFC 1035 character-strings)."""
    return " ".join(f'"{value[index : index + 255]}"' for index in range(0, len(value), 255))


def record_lines(fqdn: str, value: str, zone: str, *, ttl: int = 3600) -> list[str]:
    """Publish one TXT record as a zone-file line and in a DNS host's zone-relative form."""
    return [
        f"  zone file: {fqdn}. {ttl} IN TXT {zone_txt(value)}",
        f"  DNS host:  Type TXT | Name {relative_name(fqdn, zone)} | Value {value} | TTL 1 hour",
    ]


def card_value(site: Site, name: str) -> str:
    return f"v=amx1; card=https://{site.domain}/.well-known/agents/{name}.json"


def lookup_txt(name: str, nameserver: str | None, timeout: float = 5.0) -> list[str] | None:
    """Every TXT string set at ``name`` (each joined), or None when there is none.

    ``nameserver`` is an address, or ``address:port`` for a resolver on another port (IPv4).
    """
    resolver = dns.resolver.Resolver(configure=nameserver is None)
    if nameserver is not None:
        host, _, port = (
            nameserver.rpartition(":") if nameserver.count(":") == 1 else (nameserver, "", "")
        )
        resolver.nameservers = [host or nameserver]
        if port:
            resolver.port = int(port)
    try:
        answer = resolver.resolve(name, "TXT", lifetime=timeout)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return None
    except dns.exception.DNSException as error:
        raise RuntimeError(f"cannot look up {name}: {error}") from error
    return [b"".join(record.strings).decode("ascii", errors="replace") for record in answer]


def _tags(value: str) -> dict[str, str]:
    tags = {}
    for item in value.split(";"):
        key, equals, tag_value = item.partition("=")
        if equals:
            tags[key.strip().casefold()] = re.sub(r"\s+", "", tag_value)
    return tags


def dkim_matches(published: list[str] | None, private_key: Path) -> str:
    """``ok``, ``missing``, or ``mismatch`` for a published DKIM record against a local key."""
    if not published:
        return "missing"
    expected = public_key(private_key)
    for value in published:
        tags = _tags(value)
        if tags.get("v", "DKIM1").upper() == "DKIM1" and tags.get("p") == expected:
            return "ok"
    return "mismatch"


# Registry operations ---------------------------------------------------------------------------


def _registration(site: Site, name: str) -> Registration:
    registration = read_registrations(site.registry_dir).get(name)
    if registration is None:
        if name in site.yaml_agents:
            raise RegistrationError(f"{name} is configured in the gateway YAML; edit it there")
        raise RegistrationError(f"{name} is not registered in {site.registry_dir}")
    return registration


@contextlib.contextmanager
def _restoring(path: Path) -> Iterator[None]:
    """Put ``path`` back as it was (or absent) if the operation fails partway."""
    before = path.read_bytes() if path.exists() else None
    try:
        yield
    except BaseException:
        if before is None:
            with contextlib.suppress(FileNotFoundError):
                path.unlink()
        else:
            atomic_write(path, before.decode("utf-8"), mode=0o600)
        raise


def _check(site: Site) -> None:
    """Refuse a result the gateway would not load (the caller restores what it wrote)."""
    if site.validate is None:
        return
    try:
        site.validate()
    except Exception as error:
        raise RegistrationError(
            f"the gateway would not load the result, so nothing changed: {error}"
        ) from error


@contextlib.contextmanager
def _guarded(site: Site, name: str) -> Iterator[None]:
    """Run a command's writes, check the gateway still loads, and undo them all if not."""
    registration = site.registry_dir / "agents" / f"{name}.yaml"
    before = registration.read_bytes() if registration.exists() else None
    with _restoring(site.accounts_file):
        try:
            yield
            _check(site)
        except BaseException:
            if before is None:
                registration.unlink(missing_ok=True)
            else:
                atomic_write(registration, before.decode("utf-8"))
            raise


@contextlib.contextmanager
def _created(paths: list[Path]) -> Iterator[list[Path]]:
    """Remove the files an operation created if a later step fails."""
    try:
        yield paths
    except BaseException:
        for path in reversed(paths):
            with contextlib.suppress(FileNotFoundError):
                path.unlink()
        raise


def set_policy(
    site: Site,
    name: str,
    *,
    household: str | None = None,
    accept_from: list[str] | None = None,
    outbound_allowlist: list[str] | None = None,
    default_household: bool = False,
    inherit_accept_from: bool = False,
    inherit_outbound_allowlist: bool = False,
) -> Registration:
    """Change only household/list policy under the ordinary guarded registry transaction.

    None leaves a field unchanged; explicit reset flags unset it. An empty list stays empty.
    Keys, credentials, mailbox accounts and the one-time bundle are never rewritten.
    """
    check_name(name)
    if (
        (household is not None and default_household)
        or (accept_from is not None and inherit_accept_from)
        or (outbound_allowlist is not None and inherit_outbound_allowlist)
    ):
        raise ValueError("cannot set and reset the same policy field")
    changes: dict[str, object] = {}
    if household is not None or default_household:
        changes["household"] = None if default_household else household
    for field_name, value, reset in (
        ("accept_from", accept_from, inherit_accept_from),
        ("outbound_allowlist", outbound_allowlist, inherit_outbound_allowlist),
    ):
        if value is not None or reset:
            changes[field_name] = None if reset else parse_outbound_allowlist(value, field_name)
    if not changes:
        raise ValueError("provide a household or sender/recipient policy change")
    with locked(site.registry_dir):
        registration = replace(_registration(site, name), **changes)
        with _guarded(site, name):
            write_registration(site.registry_dir, registration)
    return registration


def _new_credentials() -> tuple[str, str, str, str]:
    token, password = new_secret(32), new_secret(24)
    return token, hash_token(token), password, hash_password(password)


def _bundle(
    site: Site, name: str, token: str, password: str, imap: str, submission: str
) -> dict[str, object]:
    return {
        "address": site.address(name),
        "imap": imap,  # as amx-runner --imap takes it: host:port, or imaps://host[:port]
        "submission": submission,
        "password": password,
        "token": token,
        "note": "One-time credentials for this agent's host. Install them, then delete this file.",
    }


def check_endpoints(imap: str, submission: str) -> None:
    """The endpoints the bundle names, in the forms amx-runner takes."""
    try:
        ImapEndpoint.parse(imap)
    except ValueError as error:
        raise ValueError(f"--imap must be host:port or imaps://host[:port]: {error}") from error
    # smtp:// only: the SDK and amx-runner speak STARTTLS on the submission port, not SMTPS.
    if not re.match(r"^smtp://[^/:\s]+:\d+$", submission):
        raise ValueError(f"--submission must be smtp://host:port, not {submission!r}")


@dataclass(frozen=True, slots=True)
class AddResult:
    registration: Registration
    bundle: Path
    key: Path | None  # None: the domain key signs for it (SH-44), so there is nothing to publish


def add(
    site: Site,
    name: str,
    *,
    bundle: Path,
    imap: str,
    submission: str,
    mode: str = "remote",
    handler: str = "mailbox-only",
    watermark: int = 2,
    workers: int = 1,
    intents: tuple[str, ...] = DEFAULT_INTENTS,
    schemas: tuple[str, ...] = ("*",),
    can_open_tasks: bool = True,
    household: str | None = None,
    accept_from: list[str] | None = None,
    outbound_allowlist: list[str] | None = None,
) -> AddResult:
    """Register a new agent: a mailbox login, a gateway entry, and one bundle.

    A lane whose domain signs (SH-44) makes no key and needs no DNS. A lane from before it (no
    ``dkim.yaml``, or a migration whose domain key is still pending) gives the agent its own
    key, as before, so it can sign until the domain key is active.
    """
    check_name(name)
    if name in site.reserved:
        raise RegistrationError(f"{name} is reserved on this gateway (a control or role address)")
    check_endpoints(imap, submission)
    address = site.address(name)
    with locked(site.registry_dir):
        if name in site.yaml_agents:
            raise RegistrationError(f"{name} is already configured in the gateway YAML")
        existing = read_registrations(site.registry_dir).get(name)
        if existing is not None:
            hint = " (disabled: `amx agent enable` it)" if not existing.enabled else ""
            raise RegistrationError(f"{name} is already registered{hint}")
        domain_signs = _domain_signs(site)
        key = None if domain_signs else site.key_path(name)
        if key is not None and key.exists():
            raise RegistrationError(f"a key for selector {name} already exists: {key}")
        accounts = read_accounts(site.accounts_file)
        previous = accounts.get(address)
        if previous is not None and previous.state != "purge":
            raise RegistrationError(f"{address} already has a mail account ({previous.state})")
        if bundle.exists():
            raise RegistrationError(f"the bundle path already exists: {bundle}")
        token, token_hash, password, password_hash = _new_credentials()
        registration = Registration(
            name=name,
            submit_token_hash=token_hash,
            mode=mode,
            handler=handler,
            watermark=watermark,
            workers=workers,
            intents=intents,
            schemas=schemas,
            can_open_tasks=can_open_tasks,
            household=household,
            accept_from=(
                parse_outbound_allowlist(accept_from, "accept_from")
                if accept_from is not None
                else None
            ),
            outbound_allowlist=(
                parse_outbound_allowlist(outbound_allowlist)
                if outbound_allowlist is not None
                else None
            ),
            imap_endpoint=imap,
            submission_endpoint=submission,
            created_at=_now(),
        )
        with _created([]) as created:
            # The bundle first: if a later step fails the operator deletes a file, rather than
            # holding an agent whose secrets nobody has.
            write_bundle(bundle, _bundle(site, name, token, password, imap, submission))
            created.append(bundle)
            if key is not None:
                # Recorded first: a key written but not fsynced must still be removed on
                # failure (checked absent under the lock above, so it is this command's).
                created.append(key)
                try:
                    generate_key(key, site.dkim_bits)
                except FileExistsError:  # another writer's, made outside the lock: not ours
                    created.remove(key)
                    raise
            # The mailbox before the gateway: once the gateway names the agent, RCPT accepts
            # its mail. The mailhost picks the line up on its own schedule, so this only makes
            # the mailbox likely to be first (PLAN §8).
            generation = new_generation()
            try:
                set_account(
                    site.accounts_file, Account(address, password_hash, "enabled", generation)
                )
                write_registration(site.registry_dir, registration)
                _check(site)
            except BaseException:
                # The mailhost may already have made the account: a tombstone of this
                # generation has it delete it, where dropping the line would leave it.
                with contextlib.suppress(Exception):
                    delete_registration(site.registry_dir, name)
                with contextlib.suppress(Exception):
                    set_account(site.accounts_file, Account(address, "-", "purge", generation))
                raise
    return AddResult(registration, bundle, key)


def _domain_signs(site: Site) -> bool:
    """Whether the domain's own key signs every agent (SH-44: ``dkim.yaml`` has an active one)."""
    from amx import domain_dkim

    state = domain_dkim.read(site.registry_dir)
    return state is not None and state.active is not None


def _forget_retiring(site: Site, selectors: set[str]) -> None:
    """Drop a purged agent's own keys from the domain's retiring list (SH-44): gone, not due."""
    from amx import domain_dkim

    state = domain_dkim.read(site.registry_dir)
    if state is None or not any(item.selector in selectors for item in state.retiring):
        return
    kept = tuple(item for item in state.retiring if item.selector not in selectors)
    domain_dkim.write(site.registry_dir, site.agent_domain, replace(state, retiring=kept))


def _account(site: Site, name: str) -> Account:
    """The agent's line in the accounts file, checked before anything is written."""
    account = read_accounts(site.accounts_file).get(site.address(name))
    if account is None:
        raise RegistrationError(
            f"{site.address(name)} has no line in {site.accounts_file}: is that the mailhost's "
            "accounts file (--accounts-file)?"
        )
    return account


def disable(site: Site, name: str) -> Registration:
    """``amx agent remove``, step one: RCPT refuses the agent, and no login works."""
    with locked(site.registry_dir):
        registration = _registration(site, name)
        _account(site, name)
        if not registration.enabled:
            raise RegistrationError(f"{name} is already disabled ({registration.disabled_at})")
        updated = replace(registration, enabled=False, disabled_at=_now())
        # The gateway first (RCPT refuses from its next reload), then the mailbox login.
        with _guarded(site, name):
            write_registration(site.registry_dir, updated)
            set_state(site.accounts_file, site.address(name), "disabled")
    return updated


def enable(site: Site, name: str) -> Registration:
    """Undo :func:`disable`: the same credentials and key work again."""
    with locked(site.registry_dir):
        registration = _registration(site, name)
        _account(site, name)
        if registration.enabled:
            raise RegistrationError(f"{name} is already enabled")
        updated = replace(registration, enabled=True, disabled_at=None)
        with _guarded(site, name):
            set_state(site.accounts_file, site.address(name), "enabled")
            write_registration(site.registry_dir, updated)
    return updated


@dataclass(frozen=True, slots=True)
class PurgeResult:
    registration: Registration
    deleted_keys: tuple[Path, ...]
    unpublish: tuple[str, ...]  # the DNS names the operator should now delete


def purge(site: Site, name: str, *, grace: timedelta, force: bool = False) -> PurgeResult:
    """``amx agent remove --purge``: forget the agent, delete its mailbox and its keys.

    Only a disabled agent, and only once it has been disabled for ``grace`` (unless ``force``):
    the pause is when an operator notices the wrong agent went.
    """
    with locked(site.registry_dir):
        registration = _registration(site, name)
        if registration.enabled:
            raise RegistrationError(f"disable {name} first: `amx agent remove {name}`")
        disabled_at = registration.disabled_at or _now()
        remaining = disabled_at + grace - _now()
        if remaining > timedelta(0) and not force:
            raise RegistrationError(
                f"{name} was disabled at {disabled_at.isoformat()}; its grace period ends in "
                f"{remaining} (pass --now to purge anyway)"
            )
        selectors = [
            registration.selector,
            *([registration.pending_selector] if registration.pending_selector else []),
            *(retired.selector for retired in registration.retired_selectors),
        ]
        # A domain-signed agent (SH-44) never had a record of its own; one migrated from its
        # own key had one only while that key existed.
        published = (
            [selector for selector in selectors if site.key_path(selector).exists()]
            if _domain_signs(site)
            else selectors
        )
        # The gateway forgets it (RCPT: unknown agent, the same 5.1.1), then the mailhost
        # deletes the mailbox, then the keys go. A line already missing is written as a
        # tombstone, so the mailhost deletes whatever it has.
        address = site.address(name)
        account = read_accounts(site.accounts_file).get(address)
        generation = account.generation if account is not None else new_generation()
        # The keys go only once the gateway is known to load without the agent (a hold rule
        # that names it, say, would stop it loading).
        with _guarded(site, name):
            delete_registration(site.registry_dir, name)
            # Checked before the tombstone: the mailhost acts on it within a second, and a
            # mailbox it deleted would not come back with a rollback.
            _check(site)
            set_account(site.accounts_file, Account(address, "-", "purge", generation))
        deleted = []
        for selector in selectors:
            key = site.key_path(selector)
            with contextlib.suppress(FileNotFoundError):
                key.unlink()
                deleted.append(key)
        _forget_retiring(site, set(selectors))
    unpublish = (
        *(dkim_name(selector, site.agent_domain) for selector in published),
        f"{name}._agents.{site.agent_domain}",
    )
    return PurgeResult(registration, tuple(deleted), unpublish)


def _next_selector(registration: Registration) -> str:
    used = [registration.selector, registration.pending_selector or ""] + [
        retired.selector for retired in registration.retired_selectors
    ]
    generations = [int(match.group(1)) for match in map(_ROTATED.match, used) if match]
    return f"{registration.name}.k{max(generations, default=1) + 1}"


@dataclass(frozen=True, slots=True)
class RotateResult:
    registration: Registration
    bundle: Path | None
    staged_selector: str | None


def rotate(
    site: Site,
    name: str,
    *,
    credentials: bool = True,
    dkim: bool = True,
    bundle: Path | None = None,
    imap: str | None = None,
    submission: str | None = None,
) -> RotateResult:
    """New token and password (a new bundle), and a new DKIM key staged under a new selector.

    The new key is not used until :func:`activate`: receivers look the new selector up only once
    mail carries it, so the operator publishes it first and checks it (``amx dns check``).
    """
    if not (credentials or dkim):
        raise RegistrationError("nothing to rotate: pass --credentials, --dkim, or both")
    with locked(site.registry_dir):
        if dkim and _domain_signs(site):
            # The domain's key signs for every agent (SH-44): an agent has no key to rotate.
            if not credentials:
                raise RegistrationError(
                    "this domain signs every agent with one key: rotate it with `amx dkim stage`"
                )
            dkim = False
        registration = _registration(site, name)
        updated = registration
        staged = None
        written: Path | None = None
        if dkim and registration.pending_selector:
            raise RegistrationError(
                f"{registration.pending_selector} is already staged: activate it first "
                f"(`amx agent rotate {name} --activate`)"
            )
        if credentials:
            imap = imap or registration.imap_endpoint
            submission = submission or registration.submission_endpoint
            if not (imap and submission):
                raise RegistrationError("pass --imap and --submission for the new bundle")
            check_endpoints(imap, submission)
            if bundle is None or bundle.exists():
                raise RegistrationError("pass --bundle with a path that does not exist yet")
        with _created([]) as created:
            if dkim:
                staged = _next_selector(registration)
                key = site.key_path(staged)
                if key.exists():
                    raise RegistrationError(f"a key for selector {staged} already exists: {key}")
                created.append(key)
                try:
                    generate_key(key, site.dkim_bits)
                except FileExistsError:  # another writer's, made outside the lock
                    created.remove(key)
                    raise
                updated = replace(updated, pending_selector=staged)
            password_hash = None
            if credentials:
                assert bundle is not None and imap and submission
                token, token_hash, password, password_hash = _new_credentials()
                write_bundle(bundle, _bundle(site, name, token, password, imap, submission))
                created.append(bundle)
                written = bundle
                updated = replace(
                    updated,
                    submit_token_hash=token_hash,
                    imap_endpoint=imap,
                    submission_endpoint=submission,
                )
            # Both secrets change together or neither does: a half rotation would leave the
            # agent's host with one old and one new credential and no bundle to fix it.
            with _guarded(site, name):
                if password_hash is not None:
                    current = _account(site, name)
                    set_account(
                        site.accounts_file,
                        Account(
                            site.address(name), password_hash, current.state, current.generation
                        ),
                    )
                write_registration(site.registry_dir, updated)
    return RotateResult(updated, written, staged)


@dataclass(frozen=True, slots=True)
class ActivateResult:
    registration: Registration
    retired: str
    pruned: tuple[Path, ...]


def activate(
    site: Site, name: str, *, overlap: timedelta, expected: str | None = None
) -> ActivateResult:
    """Sign with the staged key from now on; keep the old one published for ``overlap``.

    Mail signed with the old key may still be in queues or in receivers' DNS caches, so its
    record stays until the overlap ends (``amx dns render`` keeps printing it). Retired keys
    whose overlap has ended are deleted here.
    """
    with locked(site.registry_dir):
        if _domain_signs(site):
            raise RegistrationError(
                "this domain signs every agent with one key: activate it with `amx dkim activate`"
            )
        registration = _registration(site, name)
        if not registration.pending_selector:
            raise RegistrationError(f"{name} has no staged key: run `amx agent rotate {name}`")
        if expected is not None and registration.pending_selector != expected:
            raise RegistrationError(
                f"the staged key is now {registration.pending_selector}, not the {expected} "
                "that was checked; check DNS again"
            )
        now = _now()
        retired = (
            *(item for item in registration.retired_selectors if item.until > now),
            RetiredSelector(registration.selector, now + overlap),
        )
        expired = [item for item in registration.retired_selectors if item.until <= now]
        updated = replace(
            registration,
            selector=registration.pending_selector,
            pending_selector=None,
            retired_selectors=retired,
        )
        with _guarded(site, name):
            write_registration(site.registry_dir, updated)
        pruned = []
        for item in expired:
            key = site.key_path(item.selector)
            with contextlib.suppress(FileNotFoundError):
                key.unlink()
                pruned.append(key)
    return ActivateResult(updated, registration.selector, tuple(pruned))
