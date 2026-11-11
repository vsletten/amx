"""``amx live preflight``: is the live domain ready? Read-only: no mail, no changes.

Every check only looks. DNS checks query records; reachability checks open a TCP connection
and close it without a word of SMTP (the outbound check never sends EHLO); TLS checks open the
lane's own ports on this host, finish the handshake, and quit. Nothing is written anywhere.
"""

from __future__ import annotations

import ipaddress
import json
import shlex
import smtplib
import socket
import ssl
import subprocess
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

import dns.exception
import dns.resolver
import dns.reversename

from amx import domain_dkim
from amx.live import LiveParams, Selector, apex_sends_nothing, cert_info, dkim_selectors
from amx.provision import dkim_public_key

TIMEOUT = 8.0
WELL_KNOWN_MX_DOMAIN = "gmail.com"


@dataclass(frozen=True, slots=True)
class Result:
    """One check: PASS, WARN, FAIL, SKIP, or INFO, with what was seen."""

    status: str
    check: str
    detail: str


@dataclass(frozen=True, slots=True)
class Options:
    resolver: str | None = None
    probe: str | None = None
    outbound: str | None = None
    skip_outbound: bool = False
    local_host: str = "127.0.0.1"


class Lookup:
    """DNS answers as strings; NXDOMAIN and NODATA are empty, other failures raise."""

    def __init__(self, server: str | None) -> None:
        self.resolver = dns.resolver.Resolver(configure=server is None)
        if server is not None:
            host, _, port = server.rpartition(":") if server.count(":") == 1 else (server, "", "")
            self.resolver.nameservers = [host or server]
            if port:
                self.resolver.port = int(port)
        self.resolver.lifetime = TIMEOUT

    def query(self, name: str, rdtype: str) -> list[str]:
        try:
            answer = self.resolver.resolve(name, rdtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        if rdtype == "TXT":
            return [b"".join(item.strings).decode("utf-8", "replace") for item in answer]
        return [item.to_text() for item in answer]

    def txt(self, name: str, prefix: str) -> list[str]:
        return [value for value in self.query(name, "TXT") if value.lower().startswith(prefix)]


def _tags(record: str) -> dict[str, str]:
    tags = {}
    for part in record.split(";"):
        key, equals, value = part.strip().partition("=")
        if equals:
            tags[key.strip().lower()] = value.strip()
    return tags


def spf_verdict(lookup: Lookup, domain: str, ip: str, depth: int = 0) -> tuple[str, str]:
    """A subset of SPF (ip4, a, mx, include, redirect, all): ``pass``, ``fail``, or why not."""
    if depth > 5:
        return "unknown", "too many includes"
    records = lookup.txt(domain, "v=spf1")
    if len(records) != 1:
        return "unknown", f"{len(records)} SPF records at {domain}"
    address = ipaddress.IPv4Address(ip)
    redirect = None

    def matches(hosts: list[str], prefix: int) -> bool:
        return any(
            address in ipaddress.IPv4Network(f"{host}/{prefix}", strict=False) for host in hosts
        )

    for term in records[0].split()[1:]:
        qualifier = term[0] if term[0] in "+-~?" else "+"
        mechanism = term.lstrip("+-~?")
        result = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}[qualifier]
        name, _, argument = mechanism.partition(":")
        argument, _, prefix_text = argument.partition("/")
        if "/" in name:
            name, _, prefix_text = name.partition("/")
        prefix = int(prefix_text or 32)
        if name == "all":
            return result, records[0]
        if name == "ip4" and address in ipaddress.IPv4Network(mechanism[4:], strict=False):
            return result, records[0]
        if name == "a" and matches(lookup.query(argument or domain, "A"), prefix):
            return result, records[0]
        if name == "mx":
            exchanges = [
                value.split()[-1].rstrip(".") for value in lookup.query(argument or domain, "MX")
            ]
            if any(matches(lookup.query(host, "A"), prefix) for host in exchanges):
                return result, records[0]
        if name == "include":
            verdict, _ = spf_verdict(lookup, argument, ip, depth + 1)
            if verdict == "pass":
                return result, records[0]
        if mechanism.startswith("redirect="):
            redirect = mechanism.partition("=")[2]
    if redirect:
        return spf_verdict(lookup, redirect, ip, depth + 1)
    return "neutral", records[0]


def dns_checks(params: LiveParams, lookup: Lookup) -> list[Result]:
    results = []
    ip = params.public_ip

    def check(name: str, run: Callable[[], Result]) -> None:
        try:
            results.append(run())
        except (dns.exception.DNSException, OSError, ValueError) as error:
            results.append(
                Result("FAIL", name, f"lookup failed: {error.__class__.__name__}: {error}")
            )

    def a_record() -> Result:
        values = lookup.query(params.mx_host, "A")
        if ip not in values:
            return Result("FAIL", "dns:a", f"{params.mx_host} A {values or 'missing'}, want {ip}")
        extra = [value for value in values if value != ip]
        if extra:
            return Result("WARN", "dns:a", f"{params.mx_host} also resolves to {extra}")
        return Result("PASS", "dns:a", f"{params.mx_host} A {ip}")

    def aaaa_record() -> Result:
        values = lookup.query(params.mx_host, "AAAA")
        if values:
            return Result(
                "WARN",
                "dns:aaaa",
                f"{params.mx_host} AAAA {values}: the bundle listens on IPv4 only; senders that "
                "prefer IPv6 fall back to IPv4 only after a failed connect",
            )
        return Result("PASS", "dns:aaaa", "no AAAA (the bundle is IPv4-only)")

    def mx_record() -> Result:
        values = [value.split() for value in lookup.query(params.agent_domain, "MX")]
        hosts = [host.rstrip(".").casefold() for _preference, host in values]
        if params.mx_host not in hosts:
            return Result("FAIL", "dns:mx", f"{params.agent_domain} MX {hosts or 'missing'}")
        others = [host for host in hosts if host != params.mx_host]
        if others:
            return Result("WARN", "dns:mx", f"other MX hosts too: {others}")
        return Result("PASS", "dns:mx", f"{params.agent_domain} MX {params.mx_host}")

    def spf(domain: str, name: str) -> Callable[[], Result]:
        def run() -> Result:
            verdict, record = spf_verdict(lookup, domain, ip)
            if verdict == "pass":
                return Result("PASS", name, f"{domain}: {record}")
            status = "FAIL" if verdict in ("fail", "softfail", "neutral") else "WARN"
            return Result(status, name, f"{domain}: SPF {verdict} for {ip} ({record})")

        return run

    def _activate_hint(item: Selector) -> str:
        if domain_dkim.is_domain_selector(item.selector):
            return "amx live dkim activate"
        return f"amx live agent rotate {item.agent} --activate"

    def dkim(item: Selector) -> Callable[[], Result]:
        """One selector that should be in DNS now (PLAN §5.2's rotation, §11.5).

        The key an agent signs with must be published exactly, or its mail fails DKIM: FAIL. A
        staged key is not used until `amx live agent rotate --activate`, which checks it in DNS
        itself, and a retiring one only covers mail signed before the switch: WARN.
        """
        name = f"dns:dkim:{item.selector}"
        active = item.role == "active"
        soft = "FAIL" if active else "WARN"

        def run() -> Result:
            key = params.keys_dir / item.key
            if not key.is_file():
                return Result(soft, name, f"no key at {key} ({item.role})")
            host = f"{item.selector}._domainkey.{params.agent_domain}"
            records = lookup.txt(host, "v=dkim1")
            if not records:
                if item.role == "pending":
                    return Result(
                        "WARN",
                        name,
                        f"staged key not published at {host}: publish it (amx live dns), then "
                        f"`{_activate_hint(item)}`",
                    )
                return Result(soft, name, f"no DKIM TXT at {host} ({item.role})")
            if len(records) > 1:
                return Result("FAIL", name, f"{len(records)} DKIM records at {host}: keep one")
            published = "".join(_tags(records[0]).get("p", "").split())
            if published != dkim_public_key(key):
                return Result(
                    soft,
                    name,
                    f"{host} publishes a different key ({len(published)} characters of p=): "
                    f"stale, or cut short by the DNS editor ({item.role})",
                )
            if item.role == "pending":
                return Result(
                    "PASS",
                    name,
                    f"{host} matches the staged {key.name}: activate it with "
                    f"`{_activate_hint(item)}`",
                )
            return Result("PASS", name, f"{host} matches {key.name} ({item.role})")

        return run

    def dmarc() -> Result:
        records = lookup.txt(f"_dmarc.{params.agent_domain}", "v=dmarc1")
        if len(records) > 1:
            # RFC 7489 §6.6.3: more than one record means no policy at all.
            return Result("FAIL", "dns:dmarc", f"{len(records)} DMARC records: keep one")
        if records:
            policy = _tags(records[0]).get("p", "?")
            status = "PASS" if policy == params.dmarc_policy else "WARN"
            return Result(status, "dns:dmarc", f"_dmarc.{params.agent_domain}: {records[0]}")
        parent = lookup.txt(f"_dmarc.{params.org_domain}", "v=dmarc1")
        if parent:
            tags = _tags(parent[0])
            governs = tags.get("sp", tags.get("p", "?"))
            return Result(
                "FAIL",
                "dns:dmarc",
                f"no _dmarc.{params.agent_domain}: {params.org_domain}'s record governs it "
                f"with p={governs} ({parent[0]})",
            )
        return Result("FAIL", "dns:dmarc", f"no DMARC record at _dmarc.{params.agent_domain}")

    def apex_spf() -> Result:
        # The zone's own name sends no mail: its record says so (v=spf1 -all).
        records = lookup.txt(params.dns_zone, "v=spf1")
        if len(records) != 1:
            return Result(
                "FAIL", "dns:spf-apex", f"{len(records)} SPF records at {params.dns_zone}"
            )
        status = "PASS" if records[0].split() == ["v=spf1", "-all"] else "WARN"
        return Result(status, "dns:spf-apex", f"{params.dns_zone}: {records[0]}")

    def apex_dmarc() -> Result:
        records = lookup.txt(f"_dmarc.{params.dns_zone}", "v=dmarc1")
        if not records:
            return Result("FAIL", "dns:dmarc-apex", f"no DMARC record at _dmarc.{params.dns_zone}")
        if len(records) > 1:
            return Result("FAIL", "dns:dmarc-apex", f"{len(records)} DMARC records: keep one")
        policy = _tags(records[0]).get("p", "?")
        status = "PASS" if policy == params.dmarc_policy else "WARN"
        return Result(status, "dns:dmarc-apex", f"_dmarc.{params.dns_zone}: {records[0]}")

    def ptr() -> Result:
        names = [
            value.rstrip(".").casefold()
            for value in lookup.query(dns.reversename.from_address(ip).to_text(), "PTR")
        ]
        if params.mx_host not in names:
            return Result(
                "FAIL", "dns:ptr", f"PTR of {ip} is {names or 'missing'}, want {params.mx_host}"
            )
        return Result("PASS", "dns:ptr", f"{ip} -> {params.mx_host} (and back, see dns:a)")

    def tls_rpt() -> Result:
        records = lookup.txt(f"_smtp._tls.{params.agent_domain}", "v=tlsrptv1")
        if records:
            return Result("PASS", "dns:tls-rpt", records[0])
        status = "WARN" if params.tls_rpt else "INFO"
        return Result(
            status, "dns:tls-rpt", f"no TLS-RPT record at _smtp._tls.{params.agent_domain}"
        )

    def caa() -> Result:
        labels = params.mx_host.split(".")
        for index in range(len(labels) - 1):
            name = ".".join(labels[index:])
            values = lookup.query(name, "CAA")
            issuers = [
                value.split(None, 2)[2].strip('"') for value in values if " issue " in f" {value} "
            ]
            if values:
                if params.tls_mode == "acme" and "letsencrypt.org" not in issuers:
                    return Result("FAIL", "dns:caa", f"CAA at {name} allows only {issuers}")
                return Result("PASS", "dns:caa", f"CAA at {name}: {issuers}")
        return Result("INFO", "dns:caa", "no CAA records: any CA may issue")

    check("dns:a", a_record)
    check("dns:aaaa", aaaa_record)
    check("dns:mx", mx_record)
    check("dns:spf", spf(params.agent_domain, "dns:spf"))
    check("dns:spf-helo", spf(params.mx_host, "dns:spf-helo"))
    for item in dkim_selectors(params):
        check(f"dns:dkim:{item.selector}", dkim(item))
    check("dns:dmarc", dmarc)
    if params.manage_apex:
        if apex_sends_nothing(params):
            check("dns:spf-apex", apex_spf)
        check("dns:dmarc-apex", apex_dmarc)
    check("dns:ptr", ptr)
    check("dns:tls-rpt", tls_rpt)
    check("dns:caa", caa)
    return results


PROBE_SCRIPT = """
for port in {ports}; do
  if command -v nc >/dev/null 2>&1; then
    nc -z -w 5 {ip} "$port" >/dev/null 2>&1 && echo "$port open" || echo "$port closed"
  else
    timeout 5 bash -c "</dev/tcp/{ip}/$port" >/dev/null 2>&1 \\
      && echo "$port open" || echo "$port closed"
  fi
done
"""


def probe_checks(params: LiveParams, probe: str) -> list[Result]:
    """TCP connects from another host (over ssh), or from here with ``local``. Nothing is sent."""
    names = (
        ("submission", "imaps") if params.profile == "private" else ("smtp", "submission", "imaps")
    )
    ports = [params.ports[name] for name in names]
    script = PROBE_SCRIPT.format(ports=" ".join(map(str, ports)), ip=shlex.quote(params.public_ip))
    command = ["sh", "-c", script]
    if probe.startswith("-"):
        # ssh would read it as an option (-oProxyCommand=...), not as the host to probe from.
        return [Result("FAIL", "reach:inbound", f"--probe must name a host, not {probe!r}")]
    if probe != "local":
        command = [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            probe,
            "sh",
            "-c",
            shlex.quote(script),
        ]
    try:
        output = subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        return [Result("FAIL", "reach:inbound", f"probe {probe} did not run: {error}")]
    seen = dict(line.split() for line in output.stdout.splitlines() if line.count(" ") == 1)
    if not seen:
        return [Result("FAIL", "reach:inbound", f"probe {probe}: {output.stderr.strip()[:200]}")]
    where = "from this host (not an outside view)" if probe == "local" else f"from {probe}"
    return [
        Result(
            "PASS" if seen.get(str(port)) == "open" else "FAIL",
            f"reach:inbound:{port}",
            f"{params.public_ip}:{port} {seen.get(str(port), 'untested')} {where}",
        )
        for port in ports
    ]


def outbound_check(params: LiveParams, lookup: Lookup, target: str | None) -> Result:
    """Open and close one TCP connection to port 25 of a well-known MX. No SMTP is spoken.

    Over IPv4 only, as Postfix sends (inet_protocols = ipv4): a host whose provider blocks IPv4
    port 25 but not IPv6 must fail here.
    """
    if target is None:
        exchanges = sorted(
            (int(preference), host.rstrip("."))
            for preference, host in (
                value.split() for value in lookup.query(WELL_KNOWN_MX_DOMAIN, "MX")
            )
        )
        if not exchanges:
            return Result("FAIL", "reach:outbound-25", f"no MX for {WELL_KNOWN_MX_DOMAIN}")
        host, port = exchanges[0][1], 25
        addresses = lookup.query(host, "A")
    else:
        host, _, port_text = target.rpartition(":")
        port = int(port_text)
        try:
            addresses = [str(ipaddress.IPv4Address(host))]
        except ValueError:
            addresses = lookup.query(host, "A")
    if not addresses:
        return Result("FAIL", "reach:outbound-25", f"no IPv4 address for {host}")
    try:
        with socket.create_connection((addresses[0], port), timeout=10):
            pass
    except OSError as error:
        return Result(
            "FAIL",
            "reach:outbound-25",
            f"cannot connect to {host} ({addresses[0]}):{port} ({error}); many clouds block "
            "outbound 25 by default",
        )
    return Result(
        "PASS",
        "reach:outbound-25",
        f"TCP connect to {host} ({addresses[0]}):{port} over IPv4 (closed, no SMTP)",
    )


def _leaf_der(path: Path) -> bytes:
    text = path.read_text(encoding="ascii")
    end = "-----END CERTIFICATE-----"
    return ssl.PEM_cert_to_DER_cert(text[: text.index(end) + len(end)])


def _context(params: LiveParams) -> ssl.SSLContext:
    ca = params.tls_dir / "ca.pem"
    return ssl.create_default_context(
        cafile=str(ca) if params.tls_mode == "self-signed" or params.tls_ca_file else None
    )


def tls_checks(params: LiveParams, host: str) -> list[Result]:
    """The certificate on file, and the one each running port serves (verified, same one)."""
    results = []
    server = params.tls_dir / "server.pem"
    if not server.is_file():
        return [Result("FAIL", "tls:file", f"no certificate at {server}")]
    info = cert_info(server)
    days = (info["expires"] - datetime.now(UTC)).days
    status = "PASS"
    notes = [f"{', '.join(info['names'])}; issuer {info['issuer']}; {days} days left"]
    if params.mx_host not in info["names"]:
        status, notes = "FAIL", [*notes, f"does not name {params.mx_host}"]
    if days < 0:
        status = "FAIL"
    elif days < 21 and status == "PASS":
        status = "WARN"
    if params.tls_mode == "acme" and "amx live" in info["issuer"]:
        status, notes = "FAIL", [*notes, "self-signed in acme mode (run amx live certs)"]
    results.append(Result(status, "tls:file", "; ".join(notes)))
    expected = _leaf_der(server)

    def served(name: str, port: int, open_: Callable[[ssl.SSLContext], bytes | None]) -> None:
        try:
            der = open_(_context(params))
        except ConnectionRefusedError:
            results.append(Result("SKIP", name, f"{host}:{port} refused (is the lane up?)"))
            return
        except (OSError, ssl.SSLError, smtplib.SMTPException) as error:
            results.append(Result("FAIL", name, f"{host}:{port}: {error}"))
            return
        if der != expected:
            results.append(Result("FAIL", name, f"{host}:{port} serves another certificate"))
        else:
            results.append(Result("PASS", name, f"{host}:{port} verified as {params.mx_host}"))

    def smtp(port: int, submission: bool) -> Callable[[ssl.SSLContext], bytes | None]:
        def open_(context: ssl.SSLContext) -> bytes | None:
            with smtplib.SMTP(host, port, timeout=TIMEOUT) as client:
                client._host = params.mx_host  # verify the MX host's name, not the address
                client.ehlo("preflight.invalid")
                if not client.has_extn("starttls"):
                    raise smtplib.SMTPException("STARTTLS is not offered")
                if submission and client.has_extn("auth"):
                    raise smtplib.SMTPException("AUTH is offered before TLS")
                client.starttls(context=context)
                client.ehlo("preflight.invalid")
                if submission and not client.has_extn("auth"):
                    raise smtplib.SMTPException("AUTH is not offered after STARTTLS")
                assert isinstance(client.sock, ssl.SSLSocket)
                return client.sock.getpeercert(binary_form=True)

        return open_

    def imaps(context: ssl.SSLContext) -> bytes | None:
        with (
            socket.create_connection((host, params.ports["imaps"]), timeout=TIMEOUT) as raw,
            context.wrap_socket(raw, server_hostname=params.mx_host) as wrapped,
        ):
            return wrapped.getpeercert(binary_form=True)

    if params.profile != "private":
        served("tls:smtp-starttls", params.ports["smtp"], smtp(params.ports["smtp"], False))
    served("tls:submission", params.ports["submission"], smtp(params.ports["submission"], True))
    served("tls:imaps", params.ports["imaps"], imaps)
    return results


def source_address_check(params: LiveParams) -> Result:
    """Which local address the host would send from (no packet leaves: a route lookup)."""
    try:
        output = subprocess.run(
            ["ip", "route", "get", "192.0.2.1"], capture_output=True, text=True, check=True
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return Result("SKIP", "host:source-ip", "no `ip route` here")
    words = output.split()
    source = words[words.index("src") + 1] if "src" in words else "?"
    if source == params.public_ip:
        return Result("PASS", "host:source-ip", f"outbound source address {source}")
    return Result(
        "INFO",
        "host:source-ip",
        f"local source address {source}, not {params.public_ip}: fine behind a provider's 1:1 NAT, "
        "otherwise mail leaves from an address the PTR and SPF do not name",
    )


def allowlist_check(params: LiveParams) -> Result:
    """Whether agents may write only to approved recipients (PLAN §11.2)."""
    if params.profile == "private":
        return Result(
            "PASS",
            "policy:outbound",
            "local-only; outbound_allowlist narrows recipients outside gateway own domains",
        )
    count = len(params.outbound_allowlist)
    if count:
        return Result("PASS", "policy:outbound", f"outbound_allowlist has {count} entries")
    return Result(
        "WARN",
        "policy:outbound",
        "no outbound_allowlist: agents may write to anyone (holds and the daily ceiling only)",
    )


def run_checks(params: LiveParams, options: Options) -> list[Result]:
    private = params.profile == "private"
    lookup = None if private else Lookup(options.resolver)
    results = (
        [Result("INFO", "dns:private", "no public DNS required; own-agent keys resolve locally")]
        if lookup is None
        else dns_checks(params, lookup)
    )
    if options.probe:
        results += probe_checks(params, options.probe)
    else:
        results.append(Result("SKIP", "reach:inbound", "no --probe host given"))
    if private or options.skip_outbound:
        reason = "private profile: no internet probe" if private else "--skip-outbound"
        results.append(Result("SKIP", "reach:outbound-25", reason))
    else:
        try:
            assert lookup is not None
            results.append(outbound_check(params, lookup, options.outbound))
        except (dns.exception.DNSException, ValueError) as error:
            results.append(Result("FAIL", "reach:outbound-25", f"{error}"))
    tls = tls_checks(params, options.local_host)
    if params.mta == "stalwart":
        from amx.live_stalwart import preflight_checks

        results += preflight_checks(params)
        # A fresh bundle must actually serve TLS; a stopped lane is not a pass.
        tls = [Result("FAIL", r.check, r.detail) if r.status == "SKIP" else r for r in tls]
    results += tls
    if not private:
        results.append(source_address_check(params))
    results.append(allowlist_check(params))
    return results


def render(results: list[Result], *, as_json: bool = False) -> str:
    if as_json:
        return json.dumps([asdict(result) for result in results], indent=2) + "\n"
    width = max(len(result.check) for result in results)
    lines = [f"{result.status:<4}  {result.check:<{width}}  {result.detail}" for result in results]
    counts = {status: sum(r.status == status for r in results) for status in ("FAIL", "WARN")}
    lines.append(f"\n{counts['FAIL']} failed, {counts['WARN']} warnings, {len(results)} checks")
    return "\n".join(lines) + "\n"
