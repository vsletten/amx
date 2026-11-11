"""Scan tracked text for deployment identities; standard library only.

Optional private deny regexes are read at runtime, never included in diagnostics.
Version quads are exempt only in version contexts (image tags, dependency versions
or explicit version prose), not in URLs or address configuration.
"""

import argparse
import ipaddress
import os
import re
import subprocess
import sys
from pathlib import Path

QUEUE = re.compile(r"\bTASK-\d+\b", re.I)
IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
EMAIL = re.compile(r"[\w][\w.!#$%&'*+/=?^`{|}~-]*@([a-z0-9-]+(?:\.[a-z0-9-]+)+)", re.I)
TAILNET = re.compile(r"\b(?:[a-z0-9-]+\.)+ts\.net\b", re.I)
HOME = re.compile(r"(?<![\w./])/(?:home|Users)/[^/\s\"'`]+(?=/|$|[\s\"'`])")
# home.arpa is reserved for home networks by RFC 8375, not a public mailbox domain.
RESERVED = (
    "example.com",
    "example.org",
    "example.net",
    "example",
    "test",
    "invalid",
    "localhost",
    "home.arpa",
)
NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
    )
)


def reserved_email(domain: str) -> bool:
    domain = domain.lower()
    return domain == "users.noreply.github.com" or any(
        domain == suffix or domain.endswith("." + suffix) for suffix in RESERVED
    )


def version_quad(line: str, match: re.Match) -> bool:
    """Recognize version syntax, but never exempt an IP URL or address assignment."""
    prefix = line[: match.start()]
    suffix = line[match.end() :]
    if re.search(r"[a-z][a-z0-9+.-]*://[^\s]*$", prefix, re.I):
        return False
    # RFC section references are identifiers, not network endpoints.
    if re.search(r"\bRFC\s+\d+\s+§\s*$", prefix):
        return True
    # Container image tags, including FROM/COPY --from and compose image fields.
    if re.search(r"[\w.-]+(?:/[\w.-]+)+:v?$", prefix):
        return True
    if re.search(
        r"(?:^\s*(?:image\s*:|FROM\s+(?:--platform=\S+\s+)?)\s*[\"']?"
        r"|\bCOPY\s+--from=)[\w.-]+:v?$",
        prefix,
        re.I,
    ):
        return True
    if re.search(
        r"\b(?:version|versions|release|tag)\s*(?:[=:]|such as)?\s*[`\"']?v?$", prefix, re.I
    ):
        return True
    return bool(re.search(r"[\w-]+(?:==|>=|<=|~=|>|<)\s*$", prefix)) and not suffix.startswith(":")


def public_ip(line: str, match: re.Match) -> bool:
    try:
        address = ipaddress.IPv4Address(match[0])
    except ipaddress.AddressValueError:
        return False
    value = int(address)
    # A contiguous dotted netmask (including /0 and /32), not an arbitrary quad.
    inverse = value ^ 0xFFFFFFFF
    if inverse & (inverse + 1) == 0:
        return False
    return not any(address in network for network in NETWORKS) and not version_quad(line, match)


def rules(line: str, deny: tuple[re.Pattern, ...] = ()) -> list[str]:
    hits = []
    if QUEUE.search(line):
        hits.append("queue-id")
    if any(public_ip(line, match) for match in IPV4.finditer(line)):
        hits.append("public-ipv4")
    if any(
        not reserved_email(match[1]) and match[0].lower() != "noreply@github.com"
        for match in EMAIL.finditer(line)
    ):
        hits.append("email")
    if any(match[0].lower() != "placeholder.ts.net" for match in TAILNET.finditer(line)):
        hits.append("tailnet")
    if HOME.search(line):
        hits.append("home-path")
    if any(pattern.search(line) for pattern in deny):
        hits.append("private-deny")
    return hits


def scan(root: Path, deny: tuple[re.Pattern, ...] = ()) -> list[str]:
    tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).split(b"\0")
    hits = []
    for raw in tracked:
        if not raw:
            continue
        path = Path(raw.decode("utf-8", errors="surrogateescape"))
        if path.parts[0] == "third_party":
            continue
        entry = root / path
        # A tracked symlink's content is its target name, not the referent.
        # This also handles dangling links and never opens devices or FIFOs.
        data = (
            os.readlink(entry).encode("utf-8", errors="surrogateescape")
            if entry.is_symlink()
            else entry.read_bytes()
        )
        if b"\0" in data:
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        for number, line in enumerate(text.splitlines(), 1):
            hits.extend(f"{path}:{number}: {rule}" for rule in rules(line, deny))
    return hits


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deny-file", type=Path)
    args = parser.parse_args()
    try:
        deny = (
            tuple(
                re.compile(line, re.I)
                for line in args.deny_file.read_text().splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            )
            if args.deny_file
            else ()
        )
        root = Path(
            subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip()
        )
        hits = scan(root, deny)
    except (OSError, re.error, subprocess.SubprocessError):
        print("Hygiene check failed: cannot read tracked files or deny regexes", file=sys.stderr)
        return 2
    for hit in hits:
        print(hit)
    return int(bool(hits))


if __name__ == "__main__":
    sys.exit(main())
