"""The mailhost's view of registered agents: one login per line, hashes only.

``amx agent add --live`` and its siblings record each registered agent's mailbox login here,
and the mailhost picks the file up without a restart:

- Dovecot (``deploy/mailhost/sync-accounts.sh``) merges it into its passwd-file, adds the INBOX
  ACL line every agent gets, and pre-creates the hold-queue folders before the login works;
  Dovecot re-reads a passwd-file whose mtime changed at the next authentication.
- Stalwart (``amx.adapters.stalwart sync``) upserts, disables, or destroys the accounts through
  its management API, reusing the provisioning plan's account shape.

Each line is ``address:hash:state:generation``:

- ``enabled``: the agent's own login works;
- ``disabled``: the account and its mail stay, and no login works, not even a master login
  (``amx agent remove``, the first step);
- ``purge``: the account and its mail are deleted (``amx agent remove --purge``); the line stays
  as a tombstone with ``-`` for the hash, so a mailhost that was down catches up.

The generation is random per registration and survives a rotation. A mailhost that finds an
address's mailbox made for another generation deletes it before provisioning, so an agent
registered again under a purged name never inherits the old one's mail, even when the tombstone
was replaced before the mailhost saw it.

The file is MTA-neutral on purpose: the registration commands do not know which mailhost runs.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from pathlib import Path

from amx.credentials import is_password_hash
from amx.registry import atomic_write

STATES = ("enabled", "disabled", "purge")
_GENERATION = re.compile(r"^[0-9a-f]{16}$")
HEADER = (
    "# amx registered mail accounts (PLAN §5.2): address:hash:state:generation,\n"
    "# state is enabled, disabled, or purge. Written by `amx agent`; the mailhost merges it\n"
    "# without a restart. Hashes only.\n"
)


@dataclass(frozen=True, slots=True)
class Account:
    """One registered agent's mailbox login."""

    address: str
    password_hash: str
    state: str
    generation: str

    def __post_init__(self) -> None:
        local, at, domain = self.address.partition("@")
        if not (local and at and domain) or self.address != self.address.casefold():
            raise ValueError(f"account address must be a lower-case address: {self.address!r}")
        if ":" in self.address or any(character.isspace() for character in self.address):
            raise ValueError(f"account address has a separator in it: {self.address!r}")
        if self.state not in STATES:
            raise ValueError(f"account state must be one of {', '.join(STATES)}")
        if self.state == "purge":
            if self.password_hash != "-":
                raise ValueError("a purged account keeps no hash")
        elif not is_password_hash(self.password_hash):
            raise ValueError(f"{self.address}: the password must be a {{SHA512-CRYPT}} hash")
        if not _GENERATION.match(self.generation):
            raise ValueError(f"{self.address}: the generation must be 16 hex digits")

    def line(self) -> str:
        return f"{self.address}:{self.password_hash}:{self.state}:{self.generation}"


def new_generation() -> str:
    """A registration's generation: random, so a name registered again gets a fresh mailbox."""
    return secrets.token_hex(8)


def read_accounts(path: Path) -> dict[str, Account]:
    """Every account in the file, by address (a missing file has none)."""
    if not path.exists():
        return {}
    accounts: dict[str, Account] = {}
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        address, _, rest = line.partition(":")
        fields = rest.rsplit(":", 2)
        if len(fields) != 3:
            raise ValueError(f"{path}:{number}: expected address:hash:state:generation")
        try:
            account = Account(address, *fields)
        except ValueError as error:
            raise ValueError(f"{path}:{number}: {error}") from error
        if address in accounts:
            raise ValueError(f"{path}:{number}: {address} is listed twice")
        accounts[address] = account
    return accounts


def write_accounts(path: Path, accounts: dict[str, Account]) -> None:
    """Replace the file atomically, 0600: only the operator and the mailhost's sync read it."""
    body = "".join(account.line() + "\n" for account in sorted(accounts.values(), key=_key))
    atomic_write(path, HEADER + body, mode=0o600)


def set_account(path: Path, account: Account) -> None:
    """Add or replace one account's line (callers hold the registry lock)."""
    accounts = read_accounts(path)
    accounts[account.address] = account
    write_accounts(path, accounts)


def set_state(path: Path, address: str, state: str) -> Account:
    """Move one account to ``state``; a purge drops the hash. Returns the new line."""
    accounts = read_accounts(path)
    current = accounts.get(address)
    if current is None:
        raise KeyError(f"{address} has no mail account in {path}")
    updated = Account(
        address, "-" if state == "purge" else current.password_hash, state, current.generation
    )
    accounts[address] = updated
    write_accounts(path, accounts)
    return updated


def _key(account: Account) -> str:
    return account.address
