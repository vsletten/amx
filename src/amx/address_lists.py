"""Address/domain lists shared by gateway configuration and the agent registry."""

from __future__ import annotations


def parse_outbound_allowlist(raw: object, name: str = "outbound_allowlist") -> frozenset[str]:
    """Addresses (``user@example.com``) and domains (``example.com``), casefolded."""
    if raw is None:
        return frozenset()
    if not isinstance(raw, list):
        raise ValueError(f"{name} must be a list of addresses or domains")
    entries: set[str] = set()
    for value in raw:
        # ``*@example.com`` is the same as ``example.com``: every address at that domain.
        entry = str(value).strip().casefold().removeprefix("*").removeprefix("@")
        local, at, domain = entry.rpartition("@")
        if (
            not entry
            or any(c.isspace() or c in "<>%!,*:/;[]()\"'" for c in entry)
            or domain.startswith(".")
            or domain.endswith(".")
            or ".." in domain
            or (at and (not local or "@" in local))
            or "." not in domain
        ):
            raise ValueError(f"{name}: not an address or domain: {value!r}")
        entries.add(entry)
    return frozenset(entries)


def address_listed(address: str, entries: frozenset[str]) -> bool:
    """Match exactly one address or its domain, never a subdomain."""
    address = address.strip().strip("<>").casefold()
    return address in entries or address.rpartition("@")[2] in entries
