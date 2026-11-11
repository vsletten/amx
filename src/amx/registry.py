"""Registered agents and trust grants: the files ``amx agent`` and ``amx trust`` write.

The gateway YAML is the operator's file. What the registration commands add lives beside it, in
``registry_dir`` (gateway YAML), one small file per agent or grant, so a command never rewrites
the operator's YAML and two commands never write the same file:

- ``agents/<name>.yaml``: an agent the operator registered (``amx agent add --live``). It holds
  only hashes: ``submit_token_hash`` for the gateway; the IMAP password's hash goes to the
  mailhost's accounts file (:mod:`amx.accounts`), never here.
- ``trust/<d>--<s>.yaml``: a grant for another domain's agent (``amx trust add``).

``load_config`` merges both into the gateway's agents and trust table, and the gateway reloads
them when they change (:mod:`amx.reload`). Every write is atomic (a temporary file in the same
directory, then a rename), so the gateway never reads half a file; names starting with ``.`` are
ignored for that reason. A command holds ``.lock`` for its whole read-modify-write.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import os
import re
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from amx.address_lists import parse_outbound_allowlist

AGENTS_DIR = "agents"
TRUST_DIR = "trust"
HEADER = "# Written by `amx agent` (PLAN §5.2). Hashes only: the plaintext went to one bundle.\n"
TRUST_HEADER = "# Written by `amx trust` (PLAN §5.2): a grant for another domain's agent.\n"
# An agent's name is its address's local part and its first DKIM selector. No dots: a rotated
# key's selector is "<name>.k<N>", and grants on s=<name> cover it (PLAN §5.2).
_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62})$")
# `amx agent rotate` names a new key "<name>.k<N>"; no other label is a rotation.
_ROTATION = re.compile(r"^k[0-9]{1,9}$")
_DOMAIN = re.compile(
    r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$"
)
# Local parts that mean something else to a mail domain (RFC 2142), or to amx: "control" is the
# gateway's own control address (agent-control-mail).
RESERVED_NAMES = frozenset({"postmaster", "abuse", "mailer-daemon", "hostmaster", "control"})
_MODES = ("remote", "sync", "queued")
DEFAULT_INTENTS = ("request", "response", "update", "ack", "error")
_AGENT_KEYS = frozenset(
    {
        "name",
        "mode",
        "handler",
        "watermark",
        "workers",
        "enabled",
        "submit_token_hash",
        "selector",
        "pending_selector",
        "retired_selectors",
        "grant",
        "external_per_day",
        "imap_endpoint",
        "submission_endpoint",
        "created_at",
        "disabled_at",
        "household",
        "accept_from",
        "outbound_allowlist",
    }
)


def check_name(name: str) -> str:
    """An agent name: lower-case letters, digits, and hyphens, and not a reserved local part."""
    if not _NAME.match(name):
        raise ValueError("agent name must be lower-case letters, digits, or hyphens (at most 63)")
    if name in RESERVED_NAMES:
        raise ValueError(f"{name} is a reserved local part")
    return name


def check_household(household: object, accept_from: frozenset[str] | None) -> None:
    """A label uses the agent-name grammar, and never inherits the operator's senders."""
    if household is None:
        return
    if not isinstance(household, str) or not _NAME.fullmatch(household):
        raise ValueError("household must be lower-case letters, digits, or hyphens (at most 63)")
    if not accept_from:
        raise ValueError("a household agent must have its own non-empty accept_from")


def selector_agent(selector: str) -> str:
    """The agent a DKIM selector belongs to: ``intake`` for ``intake`` and ``intake.k2``.

    Only rotation labels (``k`` and digits) count: any other dotted selector stays itself, so a
    grant on ``s=intake`` is not widened to names the domain may have delegated elsewhere.
    """
    head, dot, label = selector.partition(".")
    return head if dot and _ROTATION.match(label) else selector


def check_selector(name: str, selector: str) -> str:
    """A selector of ``name``'s: the name itself, or ``<name>.k<N>`` after a rotation."""
    head, dot, label = selector.partition(".")
    if head != name or (dot and not _ROTATION.match(label)):
        raise ValueError(f"selector {selector!r} is not {name!r} or {name!r}.k<N>")
    return selector


def _timestamp(value: object, field_name: str) -> datetime:
    if isinstance(value, datetime):
        stamp = value
    elif isinstance(value, str):
        try:
            stamp = datetime.fromisoformat(value)
        except ValueError as error:
            raise ValueError(f"{field_name} must be an ISO 8601 time") from error
    else:
        raise ValueError(f"{field_name} must be an ISO 8601 time")
    return stamp if stamp.tzinfo else stamp.replace(tzinfo=UTC)


def _iso(stamp: datetime | None) -> str | None:
    return None if stamp is None else stamp.astimezone(UTC).isoformat(timespec="seconds")


def _strings(value: object, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"{field_name} must be a list of strings")
    return tuple(value)


@dataclass(frozen=True, slots=True)
class RetiredSelector:
    """A key the agent no longer signs with, still published until ``until`` (DNS caches)."""

    selector: str
    until: datetime


@dataclass(frozen=True, slots=True)
class Registration:
    """One registered agent, as ``agents/<name>.yaml`` records it."""

    name: str
    submit_token_hash: str
    mode: str = "remote"
    handler: str = "mailbox-only"
    watermark: int = 2
    workers: int = 1
    enabled: bool = True
    selector: str = ""
    pending_selector: str | None = None
    retired_selectors: tuple[RetiredSelector, ...] = ()
    intents: tuple[str, ...] = DEFAULT_INTENTS
    schemas: tuple[str, ...] = ("*",)
    can_open_tasks: bool = True
    external_per_day: int | None = None
    # Where the agent's host reaches its IMAP and submission (not secret): `amx agent rotate`
    # writes the next bundle with them.
    imap_endpoint: str | None = None
    submission_endpoint: str | None = None
    created_at: datetime | None = None
    disabled_at: datetime | None = None
    household: str | None = None
    accept_from: frozenset[str] | None = None
    outbound_allowlist: frozenset[str] | None = None

    def __post_init__(self) -> None:
        check_name(self.name)
        check_household(self.household, self.accept_from)
        if not self.selector:
            object.__setattr__(self, "selector", self.name)
        check_selector(self.name, self.selector)
        if self.pending_selector is not None:
            check_selector(self.name, self.pending_selector)
        for retired in self.retired_selectors:
            check_selector(self.name, retired.selector)
        if self.mode not in _MODES:
            raise ValueError(f"{self.name}: mode must be one of {', '.join(_MODES)}")
        if self.mode == "remote" and self.handler != "mailbox-only":
            raise ValueError(f"{self.name}: a remote agent's handler runs on its own host")
        if self.watermark < 1 or self.workers < 1:
            raise ValueError(f"{self.name}: watermark and workers must be at least 1")

    def selectors(self, now: datetime) -> list[tuple[str, str]]:
        """Every selector that should be in DNS now, with its role (active, pending, retiring)."""
        published = [(self.selector, "active")]
        if self.pending_selector:
            published.append((self.pending_selector, "pending"))
        published += [
            (retired.selector, f"retiring until {_iso(retired.until)}")
            for retired in self.retired_selectors
            if retired.until > now
        ]
        return published

    def to_mapping(self) -> dict[str, Any]:
        """The file's content (a mapping that :func:`registration_from` reads back)."""
        return {
            "name": self.name,
            "mode": self.mode,
            "handler": self.handler,
            "watermark": self.watermark,
            "workers": self.workers,
            "enabled": self.enabled,
            "submit_token_hash": self.submit_token_hash,
            "selector": self.selector,
            "pending_selector": self.pending_selector,
            "retired_selectors": [
                {"selector": item.selector, "until": _iso(item.until)}
                for item in self.retired_selectors
            ],
            "grant": {
                "intents": list(self.intents),
                "schemas": list(self.schemas),
                "can_open_tasks": self.can_open_tasks,
            },
            "external_per_day": self.external_per_day,
            "imap_endpoint": self.imap_endpoint,
            "submission_endpoint": self.submission_endpoint,
            "created_at": _iso(self.created_at),
            "disabled_at": _iso(self.disabled_at),
            "household": self.household,
            "accept_from": None if self.accept_from is None else sorted(self.accept_from),
            "outbound_allowlist": (
                None if self.outbound_allowlist is None else sorted(self.outbound_allowlist)
            ),
        }


def registration_from(raw: object, source: str) -> Registration:
    """Parse one registration file's mapping; unknown keys and wrong types fail."""
    if not isinstance(raw, dict):
        raise ValueError(f"{source}: a registration must be a mapping")
    unknown = sorted(set(raw) - _AGENT_KEYS)
    if unknown:
        raise ValueError(f"{source}: unknown keys: {', '.join(map(str, unknown))}")
    token_hash = raw.get("submit_token_hash")
    if not isinstance(token_hash, str) or not token_hash:
        raise ValueError(f"{source}: submit_token_hash is required")
    grant = raw.get("grant") or {}
    if not isinstance(grant, dict) or set(grant) - {"intents", "schemas", "can_open_tasks"}:
        raise ValueError(f"{source}: grant accepts intents, schemas, and can_open_tasks")
    retired_raw = raw.get("retired_selectors") or []
    if not isinstance(retired_raw, list):
        raise ValueError(f"{source}: retired_selectors must be a list")
    retired = []
    for index, item in enumerate(retired_raw):
        if not isinstance(item, dict) or set(item) != {"selector", "until"}:
            raise ValueError(f"{source}: retired_selectors[{index}] needs selector and until")
        retired.append(
            RetiredSelector(
                str(item["selector"]),
                _timestamp(item["until"], f"{source}: retired_selectors[{index}].until"),
            )
        )
    for key in ("enabled", "can_open_tasks"):
        value = raw.get(key, True) if key == "enabled" else grant.get(key, True)
        if not isinstance(value, bool):
            raise ValueError(f"{source}: {key} must be true or false")
    per_day = raw.get("external_per_day")
    try:
        return Registration(
            name=str(raw.get("name", "")),
            submit_token_hash=token_hash,
            mode=str(raw.get("mode", "remote")),
            handler=str(raw.get("handler", "mailbox-only")),
            watermark=int(raw.get("watermark", 2)),
            workers=int(raw.get("workers", 1)),
            enabled=bool(raw.get("enabled", True)),
            selector=str(raw.get("selector") or ""),
            pending_selector=str(raw["pending_selector"]) if raw.get("pending_selector") else None,
            retired_selectors=tuple(retired),
            intents=_strings(grant.get("intents", list(DEFAULT_INTENTS)), "grant.intents"),
            schemas=_strings(grant.get("schemas", ["*"]), "grant.schemas"),
            can_open_tasks=bool(grant.get("can_open_tasks", True)),
            external_per_day=None if per_day is None else int(per_day),
            household=raw.get("household"),
            accept_from=(
                parse_outbound_allowlist(raw["accept_from"], "accept_from")
                if raw.get("accept_from") is not None
                else None
            ),
            outbound_allowlist=(
                parse_outbound_allowlist(raw["outbound_allowlist"])
                if raw.get("outbound_allowlist") is not None
                else None
            ),
            imap_endpoint=str(raw["imap_endpoint"]) if raw.get("imap_endpoint") else None,
            submission_endpoint=(
                str(raw["submission_endpoint"]) if raw.get("submission_endpoint") else None
            ),
            created_at=_timestamp(raw["created_at"], "created_at")
            if raw.get("created_at")
            else None,
            disabled_at=(
                _timestamp(raw["disabled_at"], "disabled_at") if raw.get("disabled_at") else None
            ),
        )
    except (TypeError, ValueError) as error:
        raise ValueError(f"{source}: {error}") from error


@dataclass(frozen=True, slots=True)
class Grant:
    """A trust grant for another domain's agent, as ``trust/<d>--<s>.yaml`` records it."""

    d: str
    s: str
    intents: tuple[str, ...] = DEFAULT_INTENTS
    schemas: tuple[str, ...] = ("*",)
    can_open_tasks: bool = False

    def __post_init__(self) -> None:
        if not _DOMAIN.match(self.d):
            raise ValueError(f"grant domain {self.d!r} must be a lower-case domain name")
        # An agent-lane grant names one agent by its name (SH-44: the verified From's local
        # part): no wildcards (PLAN §5.2), and no dotted or rotated selector.
        if not _NAME.match(self.s):
            raise ValueError(f"grant selector {self.s!r} must be an agent name")

    @property
    def filename(self) -> str:
        return f"{self.d}--{self.s}.yaml"

    def to_mapping(self) -> dict[str, Any]:
        return {
            "d": self.d,
            "s": self.s,
            "intents": list(self.intents),
            "schemas": list(self.schemas),
            "can_open_tasks": self.can_open_tasks,
        }


def grant_from(raw: object, source: str) -> Grant:
    """Parse one trust file's mapping."""
    if not isinstance(raw, dict) or set(raw) - {"d", "s", "intents", "schemas", "can_open_tasks"}:
        raise ValueError(f"{source}: a grant has d, s, intents, schemas, and can_open_tasks")
    can_open = raw.get("can_open_tasks", False)
    if not isinstance(can_open, bool):
        raise ValueError(f"{source}: can_open_tasks must be true or false")
    try:
        return Grant(
            d=str(raw.get("d", "")),
            s=str(raw.get("s", "")),
            intents=_strings(raw.get("intents", list(DEFAULT_INTENTS)), "intents"),
            schemas=_strings(raw.get("schemas", ["*"]), "schemas"),
            can_open_tasks=can_open,
        )
    except ValueError as error:
        raise ValueError(f"{source}: {error}") from error


def _files(directory: Path) -> list[Path]:
    if not directory.is_dir():
        return []
    return sorted(
        path
        for path in directory.iterdir()
        if path.suffix == ".yaml" and not path.name.startswith(".") and path.is_file()
    )


def read_registrations(registry_dir: Path) -> dict[str, Registration]:
    """Every registered agent, by name. A file must be named for the agent it holds."""
    registrations: dict[str, Registration] = {}
    for path in _files(registry_dir / AGENTS_DIR):
        registration = registration_from(
            yaml.safe_load(path.read_text(encoding="utf-8")), str(path)
        )
        if path.stem != registration.name:
            raise ValueError(f"{path}: holds agent {registration.name!r}, not {path.stem!r}")
        registrations[registration.name] = registration
    return registrations


def read_grants(registry_dir: Path) -> list[Grant]:
    """Every grant ``amx trust add`` wrote, in file-name order."""
    grants = []
    for path in _files(registry_dir / TRUST_DIR):
        grant = grant_from(yaml.safe_load(path.read_text(encoding="utf-8")), str(path))
        if path.name != grant.filename:
            raise ValueError(f"{path}: holds the grant for {grant.d}/{grant.s}")
        grants.append(grant)
    return grants


def fingerprint(registry_dir: Path) -> str:
    """What the reload watcher compares: a digest of every registry file's name and content.

    Content, not mtimes: a coarse clock (or a copy that keeps mtimes) must not hide a change.
    """
    digest = hashlib.sha256()
    for sub in (AGENTS_DIR, TRUST_DIR):
        for path in _files(registry_dir / sub):
            try:
                content = path.read_bytes()
            except FileNotFoundError:  # removed between the listing and the read
                continue
            digest.update(f"{sub}/{path.name}\0{len(content)}\0".encode())
            digest.update(content)
    try:  # SH-44: the domain's DKIM selectors (amx.domain_dkim) reload like the agents
        content = (registry_dir / "dkim.yaml").read_bytes()
    except FileNotFoundError:
        content = None
    if content is not None:
        digest.update(f"dkim.yaml\0{len(content)}\0".encode())
        digest.update(content)
    return digest.hexdigest()


def atomic_write(path: Path, text: str, mode: int = 0o644) -> None:
    """Write ``text`` to ``path`` through a temporary file and a rename in the same directory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)
        raise


def write_registration(registry_dir: Path, registration: Registration) -> Path:
    """Write (or replace) one agent's file."""
    path = registry_dir / AGENTS_DIR / f"{registration.name}.yaml"
    text = HEADER + yaml.safe_dump(registration.to_mapping(), sort_keys=False)
    atomic_write(path, text)
    return path


def delete_registration(registry_dir: Path, name: str) -> bool:
    """Remove one agent's file; return whether there was one."""
    path = registry_dir / AGENTS_DIR / f"{check_name(name)}.yaml"
    try:
        path.unlink()
    except FileNotFoundError:
        return False
    return True


def write_grant(registry_dir: Path, grant: Grant) -> Path:
    """Write (or replace) one grant's file."""
    path = registry_dir / TRUST_DIR / grant.filename
    atomic_write(path, TRUST_HEADER + yaml.safe_dump(grant.to_mapping(), sort_keys=False))
    return path


def delete_grant(registry_dir: Path, d: str, s: str) -> bool:
    """Remove one grant's file; return whether there was one."""
    path = registry_dir / TRUST_DIR / Grant(d, s).filename
    try:
        path.unlink()
    except FileNotFoundError:
        return False
    return True


@contextlib.contextmanager
def locked(registry_dir: Path) -> Iterator[None]:
    """Hold the registry's lock for one command's read-modify-write."""
    registry_dir.mkdir(parents=True, exist_ok=True)
    with open(registry_dir / ".lock", "a", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)
