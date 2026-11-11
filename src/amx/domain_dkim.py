"""One DKIM key for every agent of a domain (SH-44).

The gateway holds every signing key and signs for whichever agent authenticated at submission,
so a key per agent never kept agents apart, and each new agent cost a DNS record. Instead the
domain signs: one selector, ``amx.<yyyy-mm>``, published once at
``<selector>._domainkey.<agent domain>``. The signature covers ``From``, so the agent a receiver
sees is the signed From address's local part (:func:`amx.identity.verify`), the way all mail
works. Adding or removing an agent changes no DNS; ``amx agent remove`` is the revocation.

The state lives in ``<registry_dir>/dkim.yaml`` beside the agents' files, so the gateway's
registry reload picks a change up without a restart:

- ``active``: the selector every agent signs with. None while a running lane migrates from
  per-agent keys: those keep signing until :func:`activate` sees the domain key in DNS.
- ``pending``: a key staged for the next activation (the first one, or a rotation).
- ``retiring``: selectors no longer signed with but still published until ``until`` (mail in
  queues, receivers' DNS caches): the previous domain key, and a migrated lane's agent keys.

No file means the lane predates SH-44 and signs per agent as before.
"""

from __future__ import annotations

import contextlib
import re
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from amx.registry import (
    RetiredSelector,
    _iso,
    _timestamp,
    atomic_write,
    locked,
    read_registrations,
)

FILE = "dkim.yaml"
HEADER = "# Written by `amx dkim` (SH-44): the domain's DKIM selectors. Keys are in keys_dir.\n"
# Dotted and dated, so it never parses as an agent's selector: agent names have no dots, and a
# rotated agent key is "<name>.k<N>" (amx.registry).
_SELECTOR = re.compile(r"^amx\.[0-9]{4}-[0-9]{2}(?:-[0-9]{1,3})?$")


def signature_selector(raw: bytes) -> str | None:
    """The ``s=`` of a message's first DKIM-Signature (for checks and tools, not for trust)."""
    match = re.search(rb"(?im)^dkim-signature:(?:.|\r?\n(?=[ \t]))*?[;\s]s=([a-z0-9.-]+)", raw)
    return match.group(1).decode("ascii") if match else None


def is_domain_selector(selector: str) -> bool:
    """Whether ``selector`` has the domain key's form, ``amx.<yyyy-mm>[-<n>]``."""
    return _SELECTOR.fullmatch(selector) is not None


@dataclass(frozen=True, slots=True)
class DomainDkim:
    """The domain's selectors, as ``dkim.yaml`` records them."""

    active: str | None = None
    pending: str | None = None
    retiring: tuple[RetiredSelector, ...] = ()

    def __post_init__(self) -> None:
        for selector in (self.active, self.pending):
            if selector is not None and not is_domain_selector(selector):
                raise ValueError(f"domain selector {selector!r} is not amx.<yyyy-mm>[-<n>]")
        if self.active is None and self.pending is None:
            raise ValueError("dkim.yaml needs an active or a pending selector")

    def selectors(self, now: datetime) -> list[tuple[str, str]]:
        """Every selector that should be in DNS now, with its role (as Registration's)."""
        published = [(self.active, "active")] if self.active else []
        if self.pending:
            published.append((self.pending, "pending"))
        published += [
            (item.selector, f"retiring until {_iso(item.until)}")
            for item in self.retiring
            if item.until > now
        ]
        return published

    def to_mapping(self, agent_domain: str) -> dict[str, Any]:
        return {
            "agent_domain": agent_domain,
            "active": self.active,
            "pending": self.pending,
            "retiring": [
                {"selector": item.selector, "until": _iso(item.until)} for item in self.retiring
            ],
        }


def path(registry_dir: Path) -> Path:
    return registry_dir / FILE


def read(registry_dir: Path | None) -> DomainDkim | None:
    """The domain's state, or None for a lane that still signs per agent."""
    if registry_dir is None:
        return None
    try:
        raw = yaml.safe_load(path(registry_dir).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    source = str(path(registry_dir))
    if not isinstance(raw, dict) or set(raw) - {"agent_domain", "active", "pending", "retiring"}:
        raise ValueError(f"{source}: holds agent_domain, active, pending, and retiring")
    retiring_raw = raw.get("retiring") or []
    if not isinstance(retiring_raw, list):
        raise ValueError(f"{source}: retiring must be a list")
    retiring = []
    for index, item in enumerate(retiring_raw):
        if not isinstance(item, dict) or set(item) != {"selector", "until"}:
            raise ValueError(f"{source}: retiring[{index}] needs selector and until")
        retiring.append(
            RetiredSelector(
                str(item["selector"]), _timestamp(item["until"], f"{source}: retiring[{index}]")
            )
        )
    try:
        return DomainDkim(
            active=str(raw["active"]) if raw.get("active") else None,
            pending=str(raw["pending"]) if raw.get("pending") else None,
            retiring=tuple(retiring),
        )
    except ValueError as error:
        raise ValueError(f"{source}: {error}") from error


def write(registry_dir: Path, agent_domain: str, state: DomainDkim) -> Path:
    target = path(registry_dir)
    atomic_write(target, HEADER + yaml.safe_dump(state.to_mapping(agent_domain), sort_keys=False))
    return target


def _now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _new_selector(site: Any, state: DomainDkim | None, now: datetime) -> str:
    """``amx.<yyyy-mm>``, or the next ``-<n>`` when that month's name is taken."""
    taken = set()
    if state is not None:
        taken = {state.active, state.pending} | {item.selector for item in state.retiring}
    base = f"amx.{now:%Y-%m}"
    for index in range(1, 1000):
        selector = base if index == 1 else f"{base}-{index}"
        if selector not in taken and not site.key_path(selector).exists():
            return selector
    raise ValueError(f"no free domain selector for {base}")


def _agent_keys(site: Any, now: datetime) -> list[str]:
    """The per-agent selectors a pre-SH-44 lane publishes and still has keys for."""
    selectors = []
    for registration in read_registrations(site.registry_dir).values():
        for selector, _role in registration.selectors(now):
            if site.key_path(selector).exists():
                selectors.append(selector)
    return selectors


@contextlib.contextmanager
def _write_checked(site: Any) -> Any:
    """Write dkim.yaml, check the gateway still loads, and put the old file back if not."""
    from amx.registration import _check, _restoring

    with _restoring(path(site.registry_dir)):
        yield
        _check(site)


def ensure(site: Any, *, migrating: bool | None = None) -> DomainDkim:
    """The domain's state, creating its first key if there is none (idempotent).

    A new lane signs with it at once: nothing was published before it. A lane whose agents sign
    with their own keys (``migrating``, by default whether any such key exists) gets the domain
    key as ``pending``: its agents keep signing as before until :func:`activate`.
    """
    from amx.registration import generate_key

    with locked(site.registry_dir):
        state = read(site.registry_dir)
        if state is not None:
            return state
        now = _now()
        if migrating is None:
            migrating = bool(_agent_keys(site, now))
        selector = _new_selector(site, None, now)
        key = site.key_path(selector)
        generate_key(key, site.dkim_bits)
        state = DomainDkim(pending=selector) if migrating else DomainDkim(active=selector)
        try:
            with _write_checked(site):
                write(site.registry_dir, site.agent_domain, state)
        except BaseException:
            key.unlink(missing_ok=True)
            raise
        return state


def stage(site: Any) -> DomainDkim:
    """A new domain key, staged: publish it, then :func:`activate` it."""
    from amx.registration import RegistrationError, generate_key

    with locked(site.registry_dir):
        state = read(site.registry_dir)
        if state is None:
            raise RegistrationError("this lane has no domain key yet: run `amx dkim init`")
        if state.pending is not None:
            raise RegistrationError(f"{state.pending} is already staged: activate it first")
        selector = _new_selector(site, state, _now())
        key = site.key_path(selector)
        generate_key(key, site.dkim_bits)
        staged = replace(state, pending=selector)
        try:
            with _write_checked(site):
                write(site.registry_dir, site.agent_domain, staged)
        except BaseException:
            key.unlink(missing_ok=True)
            raise
        return staged


def activate(
    site: Any,
    *,
    overlap: timedelta,
    nameserver: str | None = None,
    expected: str | None = None,
    check_dns: bool = True,
) -> DomainDkim:
    """Sign with the staged domain key from now on, once DNS serves it.

    The previous domain key, or on a migrating lane every agent's own keys, stay published for
    ``overlap``: mail they signed may still be queued or cached. The DNS check is what makes
    switching safe; ``check_dns=False`` is for a lane nobody outside has received mail from.
    """
    from amx.registration import RegistrationError, dkim_matches, dkim_name, lookup_txt

    with locked(site.registry_dir):
        state = read(site.registry_dir)
        if state is None or state.pending is None:
            raise RegistrationError("no staged domain key: run `amx dkim stage` first")
        if expected is not None and state.pending != expected:
            raise RegistrationError(
                f"the staged key is now {state.pending}, not the {expected} that was checked"
            )
        if check_dns:
            published = lookup_txt(dkim_name(state.pending, site.agent_domain), nameserver)
            status = dkim_matches(published, site.key_path(state.pending))
            if status != "ok":
                raise RegistrationError(
                    f"{dkim_name(state.pending, site.agent_domain)} is {status} in DNS: publish "
                    "it (`amx dns render`), then activate"
                )
        now = _now()
        previous = [state.active] if state.active else _agent_keys(site, now)
        kept = [item for item in state.retiring if item.until > now]
        listed = {item.selector for item in kept}
        retiring = (
            *kept,
            *(
                RetiredSelector(selector, now + overlap)
                for selector in previous
                if selector not in listed
            ),
        )
        activated = DomainDkim(active=state.pending, pending=None, retiring=retiring)
        with _write_checked(site):
            write(site.registry_dir, site.agent_domain, activated)
        return activated


def retire(site: Any) -> tuple[str, ...]:
    """Forget retiring selectors whose overlap has ended and delete their keys."""
    with locked(site.registry_dir):
        state = read(site.registry_dir)
        if state is None:
            return ()
        now = _now()
        expired = [item.selector for item in state.retiring if item.until <= now]
        if not expired:
            return ()
        kept = tuple(item for item in state.retiring if item.until > now)
        with _write_checked(site):
            write(site.registry_dir, site.agent_domain, replace(state, retiring=kept))
        for selector in expired:
            site.key_path(selector).unlink(missing_ok=True)
        return tuple(expired)
