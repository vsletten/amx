"""SH-00 native Stalwart probes, inside the suite's network-less probe container.

This is test instrumentation, not SH-13's gateway sibling implementation. The two
milter recorders and LMTP sink replace policy/handlers only to observe Stalwart's
wire behavior. The ordinary suite separately exercises the real amx gateway.
Never run this against an existing datastore or outside make suite.
"""

from __future__ import annotations

import argparse
import contextlib
import copy
import hashlib
import imaplib
import json
import os
import smtplib
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path
from typing import Any

# The local-only init image copies the standard-library adapter beside this tool.
try:
    import stalwart
except ModuleNotFoundError:
    from amx.adapters import stalwart

HOST = "127.0.0.1"
SITE = stalwart.Site(
    domain="contoso.test",
    agent_domain="agents.contoso.test",
    hostname="mail.contoso.test",
    gateway_host=HOST,
    gateway_ip=HOST,
    trusted_network="127.0.0.0/8",
)
USERS = [("ops@contoso.test", "dev-ops"), ("intake@agents.contoso.test", "dev-intake")]
MASTERS = {"gateway": "dev-gateway", "approver": "dev-approver"}
PRIVATE_DOMAINS = ("home.arpa", "amx.internal", "placeholder.ts.net")


def operation(plan: list[dict], name: str) -> dict:
    (found,) = [item for item in plan if item["object"] == name]
    return found


def probe_plan() -> list[dict]:
    """Keep experimental settings out of the shipped dev/live gateway configuration."""
    plan = copy.deepcopy(stalwart.render_plan(SITE, USERS, MASTERS))
    listeners = operation(plan, "NetworkListener")["value"]
    for name, port in (
        ("submissions", 465),
        ("submission", 587),
        ("sibling-in", 10027),
        ("sibling", 10028),
    ):
        listeners[name] = {
            "name": name,
            "protocol": "smtp",
            "bind": {f"127.0.0.1:{port}": True},
            "useTls": port in (465, 587),
            "tlsImplicit": port == 465,
        }
    operation(plan, "MtaStageAuth")["value"]["require"] = stalwart.expression(
        "local_port == 465 || local_port == 587"
    )
    listeners["client-http"] = {
        "name": "client-http",
        "protocol": "http",
        "bind": {"127.0.0.1:80": True},
        "useTls": False,
    }
    # The first milter records ingress/submission; the second identifies the sibling
    # listener by the endpoint it reaches, not the constant daemon_name macro.
    milters = operation(plan, "MtaMilter")
    milters["matchOn"] = ["hostname", "port"]
    ingress = milters["value"]["milter-gateway"]
    ingress["enable"] = stalwart.expression(
        "false", ("local_port == 25 || local_port == 465 || local_port == 587", "true")
    )
    milters["value"]["milter-sibling"] = ingress | {
        "port": 8891,
        "enable": stalwart.expression("false", ("listener == 'sibling'", "true")),
    }
    operation(plan, "MtaRoute")["value"]["route-sibling"] = {
        "@type": "Relay",
        "name": "sibling-loop",
        "address": HOST,
        "port": 10028,
        "protocol": "smtp",
        "implicitTls": False,
    }
    operation(plan, "MtaOutboundStrategy")["value"]["route"] = stalwart.expression(
        "'local'",
        ("received_via_port == 10027", "'sibling-loop'"),
        ("rcpt_domain == 'agents.contoso.test'", "'gateway'"),
    )
    # Explicit file-based development certificate: never trust the server's fallback
    # certificate and never read an operator's credentials/certificates.
    plan.append(
        {
            "@type": "create",
            "object": "Certificate",
            "value": {
                "probe-cert": {
                    "certificate": {"@type": "File", "filePath": "/tls/server.pem"},
                    "privateKey": {"@type": "File", "filePath": "/tls/server-key.pem"},
                }
            },
        }
    )
    operation(plan, "SenderAuth")["value"]["dkimSignDomain"] = stalwart.expression(
        "false",
        (
            "sender_domain == 'contoso.test' && (local_port == 465 || local_port == 587)",
            "sender_domain",
        ),
    )
    plan.append(
        {
            "@type": "create",
            "object": "DkimSignature",
            "value": {
                "probe-dkim": {
                    "@type": "Dkim1RsaSha256",
                    "domainId": "#domain-site",
                    "selector": "sh00",
                    "privateKey": {"@type": "File", "filePath": "/tls/server-key.pem"},
                }
            },
        }
    )
    return plan


def read_exact(stream, count: int) -> bytes:
    data = bytearray()
    while len(data) < count:
        part = stream.read(count - len(data))
        if not part:
            raise EOFError("truncated milter frame")
        data.extend(part)
    return bytes(data)


def frame(payload: bytes) -> bytes:
    return struct.pack("!I", len(payload)) + payload


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, port: int, handler):
        super().__init__((HOST, port), handler)
        self.rows: list[dict[str, Any]] = []
        self.messages: dict[str, bytes] = {}
        self.guard = threading.Lock()

    def record(self, row: dict) -> None:
        with self.guard:
            self.rows.append(row)

    def snapshot(self) -> list[dict]:
        with self.guard:
            return copy.deepcopy(self.rows)


class MilterRecorder(socketserver.StreamRequestHandler):
    """v6 recorder with headers enabled; never logs AUTH credentials or message bodies."""

    def handle(self) -> None:
        self.connection.settimeout(15)
        row: dict[str, Any] = {"commands": [], "macros": {}, "headers": [], "body_bytes": 0}
        try:
            while True:
                size = struct.unpack("!I", read_exact(self.rfile, 4))[0]
                if not 1 <= size <= 16 * 1024 * 1024:
                    raise ValueError("invalid milter frame size")
                packet = read_exact(self.rfile, size)
                command, payload = packet[:1], packet[1:]
                row["commands"].append(command.decode("ascii"))
                if command == b"O":
                    version, _actions, offered = struct.unpack("!III", payload)
                    row["offered_protocol"] = offered
                    # No skip/no-reply flags: receive headers and EOH, avoiding the
                    # NOHDRS-without-NOEOH combination. This isn't amx negotiation.
                    self.wfile.write(frame(b"O" + struct.pack("!III", min(version, 6), 0, 0)))
                elif command == b"D":
                    parts = payload[1:].removesuffix(b"\0").split(b"\0")
                    macros = dict(zip(parts[::2], parts[1::2], strict=True))
                    # Whitelist identity metadata only, never all MTA macros.
                    row["macros"][payload[:1].decode()] = {
                        key.decode(): value.decode(errors="replace")
                        for key, value in macros.items()
                        if key in (b"{auth_authen}", b"{daemon_name}", b"{client_port}")
                    }
                elif command in (b"Q", b"K"):
                    break
                elif command == b"A":
                    continue
                else:
                    if command == b"L":
                        row["headers"].append(payload.split(b"\0", 1)[0].decode())
                    elif command == b"B":
                        row["body_bytes"] += len(payload)
                    self.wfile.write(frame(b"c"))
                self.wfile.flush()
        except (EOFError, OSError, ValueError) as error:
            row["error"] = type(error).__name__
        finally:
            self.server.record(row)


class LmtpSink(socketserver.StreamRequestHandler):
    """Loopback-only LMTP observer; one named recipient deliberately fails for DSNs."""

    def handle(self) -> None:
        self.connection.settimeout(15)
        self.wfile.write(b"220 probe LMTP\r\n")
        recipients: list[str] = []
        while line := self.rfile.readline(65537):
            verb = line.split(b" ", 1)[0].strip().upper()
            if verb == b"LHLO":
                self.wfile.write(b"250-probe\r\n250 8BITMIME\r\n")
            elif verb == b"MAIL":
                recipients = []
                self.wfile.write(b"250 2.1.0 OK\r\n")
            elif verb == b"RCPT":
                recipient = line.decode().strip().split(":", 1)[1].strip("<>")
                if recipient.startswith("fail@"):
                    self.wfile.write(b"550 5.1.1 SH-00 deliberate recipient failure\r\n")
                else:
                    recipients.append(recipient)
                    self.wfile.write(b"250 2.1.5 OK\r\n")
            elif verb == b"DATA":
                self.wfile.write(b"354 send data\r\n")
                chunks = []
                while (part := self.rfile.readline(65537)) not in (b".\r\n", b""):
                    chunks.append(part[1:] if part.startswith(b"..") else part)
                raw = b"".join(chunks)
                message = BytesParser(policy=policy.default).parsebytes(raw)
                with self.server.guard:
                    self.server.messages[str(message.get("Message-ID", ""))] = raw
                self.server.record(
                    {
                        "message_id": str(message.get("Message-ID", "")),
                        "recipients": list(recipients),
                        "received_count": len(message.get_all("Received", [])),
                        "dkim": [str(value) for value in message.get_all("DKIM-Signature", [])],
                    }
                )
                for _recipient in recipients:
                    self.wfile.write(b"250 2.0.0 delivered\r\n")
            elif verb == b"QUIT":
                self.wfile.write(b"221 bye\r\n")
                return
            else:
                self.wfile.write(b"250 OK\r\n")


@contextlib.contextmanager
def serving(port: int, handler) -> Iterator[Server]:
    with Server(port, handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            thread.join(timeout=5)


def message(label: str, recipient: str = "intake@agents.contoso.test") -> bytes:
    mail = EmailMessage(policy=policy.SMTP)
    mail["From"] = "ops@contoso.test"
    mail["To"] = recipient
    mail["Message-ID"] = f"<sh00-{label}@contoso.test>"
    mail["Subject"] = f"SH-00 {label}"
    mail.set_content("Native loopback-only Stalwart probe.")
    return mail.as_bytes()


def send(
    port: int,
    label: str,
    recipient: str = "intake@agents.contoso.test",
    *,
    raw: bytes | None = None,
    sender: str = "ops@contoso.test",
) -> None:
    # The mounted development CA verifies localhost (not a public or operator CA).
    tls = ssl.create_default_context(cafile="/tls/dev-ca.pem")
    client = (
        smtplib.SMTP_SSL(HOST, port, timeout=15, context=tls)
        if port == 465
        else smtplib.SMTP(HOST, port, timeout=15)
    )
    with client:
        client.ehlo("localhost")
        if port == 587:
            client.starttls(context=tls)
            client.ehlo("localhost")
        if port in (465, 587):
            client.login("ops@contoso.test", "dev-ops")
        refused = client.sendmail(
            sender, [recipient], raw if raw is not None else message(label, recipient)
        )
        if refused:
            raise RuntimeError("probe recipient refused")


def apply(plan: list[dict], path: Path) -> None:
    path.write_text(stalwart.plan_text(plan))
    # Never inherit host/provider credentials. These fixed credentials exist only
    # in this network-less disposable server and never enter the result artifact.
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": str(path.parent),
        "STALWART_URL": "http://127.0.0.1:8080",
        "STALWART_USER": "admin",
        "STALWART_PASSWORD": "dev-admin",
    }
    try:
        subprocess.run(
            ["/usr/local/bin/stalwart-cli", "--no-color", "apply", "--file", str(path)],
            env=env,
            check=True,
            timeout=60,
        )
    finally:
        path.unlink(missing_ok=True)


def ready(server: stalwart.PrivateServer) -> None:
    stalwart.wait_for(
        lambda: server.running() and stalwart.http_ok("http://127.0.0.1:8080/healthz/ready"),
        60,
        "private Stalwart management listener",
    )


def imap_connection(configuration: dict | None = None):
    if configuration is None:
        return imaplib.IMAP4(HOST, 143, timeout=10)
    if configuration["imap"]["port"] != 993 or configuration["imap"]["socketType"] != "SSL":
        raise RuntimeError("discovered IMAP configuration unsupported by sealed probe")
    return imaplib.IMAP4_SSL(
        HOST, 993, timeout=10, ssl_context=ssl.create_default_context(cafile="/tls/dev-ca.pem")
    )


def mailbox_headers(
    folder: str = "INBOX", login: str = "ops@contoso.test", configuration: dict | None = None
) -> list[Any]:
    with imap_connection(configuration) as client:
        client.login(login, "dev-ops")
        status, _ = client.select(stalwart._quoted(folder), readonly=True)
        if status != "OK":
            raise RuntimeError("probe mailbox cannot be read")
        status, data = client.uid("SEARCH", None, "ALL")
        if status != "OK":
            raise RuntimeError("probe mailbox search failed")
        messages = []
        for uid in (data[0] or b"").split():
            status, fetched = client.uid("FETCH", uid, "(BODY.PEEK[HEADER])")
            if status != "OK":
                raise RuntimeError("probe mailbox fetch failed")
            raw = next(item[1] for item in fetched if isinstance(item, tuple))
            messages.append(BytesParser(policy=policy.default).parsebytes(raw))
        return messages


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # never follow a discovery response outside the sealed server


def discovery_candidates(hostname: str) -> list[tuple[str, str, str]]:
    """ISP-hosted Thunderbird candidates, HTTPS first; no external ISPDB fetch."""
    domain = hostname.removeprefix("mail.")
    return [
        (scheme, host, path)
        for scheme in ("https", "http")
        for host, path in (
            (f"autoconfig.{domain}", "/mail/config-v1.1.xml"),
            (domain, "/.well-known/autoconfig/mail/config-v1.1.xml"),
        )
    ]


def client_configuration(root: ET.Element) -> dict | None:
    """Parse real native XML; never invent settings when discovery fails."""
    if root.tag != "clientConfig":
        return None
    incoming = root.find(".//incomingServer[@type='imap']")
    outgoing = root.find(".//outgoingServer[@type='smtp']")
    if incoming is None or outgoing is None:
        return None
    result = {}
    for kind, node in (("imap", incoming), ("smtp", outgoing)):
        result[kind] = {
            name: node.findtext(name, "")
            for name in ("hostname", "port", "socketType", "username", "authentication")
        }
        result[kind]["port"] = int(result[kind]["port"])
        if result[kind]["hostname"] != SITE.hostname:
            raise RuntimeError("native XML advertises unexpected host; refuse external connection")
    return result


def autodiscover_configuration(root: ET.Element) -> dict:
    """Describe actual response structure; HTTP 200 alone is not configuration."""

    def local(tag: str) -> str:
        return tag.rpartition("}")[2]

    protocols = []
    schemas = set()
    actions = []
    for node in root.iter():
        if node.tag.startswith("{"):
            schemas.add(node.tag[1:].partition("}")[0])
        if local(node.tag) == "Action":
            actions.append(node.text or "")
        if local(node.tag) == "Protocol":
            protocols.append({local(child.tag): child.text or "" for child in node})
    types = {protocol.get("Type", "").upper() for protocol in protocols}
    return {
        "root": local(root.tag),
        "schemas": sorted(schemas),
        "actions": actions,
        "protocols": protocols,
        "settings_response": local(root.tag) == "Autodiscover"
        and "settings" in actions
        and {"IMAP", "SMTP"} <= types,
    }


def discovery() -> dict:
    tls = ssl.create_default_context(cafile="/tls/dev-ca.pem")
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=tls)
    )
    candidates = [
        *discovery_candidates(SITE.hostname),
        ("https", SITE.hostname, "/mail/config-v1.1.xml"),
        ("https", SITE.hostname, "/autodiscover/autodiscover.xml"),
    ]
    rows = []
    payload = (
        b'<?xml version="1.0"?><Autodiscover xmlns="http://schemas.microsoft.com/exchange/'
        b'autodiscover/outlook/requestschema/2006"><Request><EMailAddress>ops@contoso.test'
        b"</EMailAddress><AcceptableResponseSchema>http://schemas.microsoft.com/exchange/"
        b"autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>"
        b"</Request></Autodiscover>"
    )
    # The seventh request uses the real autodiscover POST shape.
    for index, (scheme, host, path) in enumerate([*candidates, candidates[-1]]):
        data = payload if index == len(candidates) else None
        row = {"scheme": scheme, "host": host, "path": path, "method": "POST" if data else "GET"}
        request = urllib.request.Request(
            f"{scheme}://localhost{path}",
            data=data,
            headers={"Host": host, "Content-Type": "text/xml"},
        )
        try:
            with opener.open(request, timeout=10) as response:
                body = response.read(65536)
                row.update(
                    status=response.status,
                    bytes=len(body),
                    content_type=response.headers.get("Content-Type", ""),
                )
                try:
                    root = ET.fromstring(body)
                    row["configuration"] = client_configuration(root)
                    row["client_config"] = row["configuration"] is not None
                    if data is not None:
                        row["autodiscover"] = autodiscover_configuration(root)
                except ET.ParseError:
                    row["client_config"] = False
        except urllib.error.HTTPError as error:
            row["status"] = error.code
        except (OSError, urllib.error.URLError) as error:
            row["error"] = type(error).__name__
        rows.append(row)
    missing = all(row.get("status") in (404, 405) for row in rows)
    return {
        "status": "native-missing" if missing else "measured-see-responses",
        "http_observations": rows,
        "hostname_only_setup": "refused: no native configuration; SH-11 must serve discovery"
        if missing
        else "not claimed; inspect responses for valid client configuration",
        "transport": "fixture DNS alias to localhost; development CA verifies localhost only; "
        "real discovery hostname DNS/certificates unmeasured",
        "lookup_limit": "ISP-hosted branches; external ISPDB/MX fallback deliberately not fetched",
    }


def client_protocol(configuration: dict | None = None) -> dict:
    """Read, authenticated send, then approve a fixture hold with an ordinary login."""
    port = configuration["smtp"]["port"] if configuration else 587
    if port not in (465, 587):
        raise RuntimeError("discovered submission port unsupported by sealed probe")
    send(port, "client", "ops@contoso.test")
    stalwart.wait_for(
        lambda: any(
            m.get("Message-ID") == "<sh00-client@contoso.test>"
            for m in mailbox_headers(configuration=configuration)
        ),
        15,
        "client submission in INBOX",
    )
    folder = "Holds/intake/Held"
    with imaplib.IMAP4(HOST, 143, timeout=10) as owner:
        owner.login(stalwart.master_login(SITE.hold_mailbox, "gateway", SITE), "dev-gateway")
        if owner.append(stalwart._quoted(folder), None, None, message("hold"))[0] != "OK":
            raise RuntimeError("fixture hold APPEND failed")
    shared = stalwart.shared_name(SITE, folder)
    approved = stalwart.shared_name(SITE, "Holds/intake/Approved")
    with imap_connection(configuration) as client:
        client.login("approver@contoso.test", "dev-approver")
        if client.select(stalwart._quoted(shared))[0] != "OK":
            raise RuntimeError("approver cannot read shared Held")
        status, data = client.uid("SEARCH", None, "ALL")
        if status != "OK" or not data[0]:
            raise RuntimeError("fixture hold not visible")
        if client.uid("MOVE", data[0].split()[-1], stalwart._quoted(approved))[0] != "OK":
            raise RuntimeError("approver MOVE failed")
        if client.select(stalwart._quoted(approved), readonly=True)[0] != "OK":
            raise RuntimeError("approver cannot read Approved")
        status, data = client.uid("SEARCH", None, "ALL")
        if status != "OK" or not data[0]:
            raise RuntimeError("approved fixture missing after MOVE")
    return {
        "status": "pass",
        "read": "IMAP INBOX",
        "send": f"{port} TLS SASL",
        "settings_source": "native autoconfig XML"
        if configuration
        else "explicit development settings",
        "approval": "ordinary approver account UID MOVE, read back in Approved",
        "limit": "fixture hold only; real gateway release is the ordinary suite's S06c",
    }


def client_checks() -> dict:
    observed = discovery()
    configuration = next(
        (r["configuration"] for r in observed["http_observations"] if r.get("client_config")), None
    )
    if configuration:
        protocol = client_protocol(configuration)
        observed["hostname_only_setup"] = (
            "native XML parsed; advertised protocol settings exercised"
        )
        return {"status": "pass", "discovery": observed, "protocol": protocol}
    return {
        "status": "measured-discovery-unavailable",
        "discovery": observed,
        "directly_configured_protocol": client_protocol(),
    }


def native_checks(
    ingress: Server, sibling: Server, sink: Server, progress: dict | None = None
) -> dict:
    progress = {} if progress is None else progress
    results: dict[str, Any] = {}
    for port in (25, 465, 587, 10025, 10027, 10028):
        before = (len(ingress.snapshot()), len(sibling.snapshot()))
        label = f"port-{port}"
        send(port, label)
        stalwart.wait_for(
            lambda label=label: any(
                r["message_id"] == f"<sh00-{label}@contoso.test>" for r in sink.snapshot()
            ),
            20,
            f"LMTP delivery from {port}",
        )
        # Stalwart closes each stage connection before accepting DATA. Wait for
        # recorder threads to observe QUIT, not a guessed wall-clock sleep.
        expected = (
            (3, 0) if port in (25, 465, 587) else ((0, 3) if port in (10027, 10028) else (0, 0))
        )
        stalwart.wait_for(
            lambda before=before, expected=expected: (
                len(ingress.snapshot()) >= before[0] + expected[0]
                and len(sibling.snapshot()) >= before[1] + expected[1]
            ),
            5,
            f"milter records from {port}",
        )
        normal = ingress.snapshot()[before[0] :]
        loop = sibling.snapshot()[before[1] :]
        counts = (len(normal), len(loop))
        rows = normal or loop
        if counts != expected:
            raise RuntimeError(f"port {port}: milter counts {counts}, expected {expected}")
        results[str(port)] = {
            "ingress_connections": counts[0],
            "sibling_connections": counts[1],
            "milter": rows,
            "deliveries": [
                row
                for row in sink.snapshot()
                if row["message_id"] == f"<sh00-{label}@contoso.test>"
            ],
        }
        if any("error" in row for row in rows):
            raise RuntimeError(f"port {port}: milter observer did not finish cleanly")
        if port in (465, 587):
            if not all(
                "ops@contoso.test"
                in [
                    value
                    for macros in row["macros"].values()
                    for key, value in macros.items()
                    if key == "{auth_authen}"
                ]
                for row in rows
            ):
                raise RuntimeError(f"port {port}: SASL identity missing from a stage replay")
            if not any("E" in row["commands"] for row in rows):
                raise RuntimeError(f"port {port}: DATA replay not observed")
    send(10027, "dsn", "fail@agents.contoso.test")
    stalwart.wait_for(
        lambda: any(m.get_content_type() == "multipart/report" for m in mailbox_headers()),
        40,
        "DSN from sibling LMTP failure",
    )
    progress.update(
        {
            "a": {
                "status": "pass",
                "mechanism": "10027 -> loopback SMTP 10028 -> gateway LMTP",
                "dsn": "multipart/report delivered to local sender after deliberate LMTP refusal",
                "limit": "LMTP observer, not SH-13 gateway sibling authorization",
            },
            "b": {"status": "pass", "identity": "ops@contoso.test on all three stage connections"},
            "c": {"status": "pass", "ports": results},
            "f": {
                "status": "unmeasured",
                "reason": "recorder is not amx's native pymilter negotiation; "
                "run the ordinary Stalwart suite for the gateway path",
            },
        }
    )
    progress["e"] = client_checks()
    progress["d"] = signing_split(sink)
    return progress


def body_observation(before: bytes, after: bytes) -> dict:
    """Report bytes honestly; only the measured trailing-empty-line delta is allowed.

    amx.identity.sign uses relaxed/relaxed. RFC 6376 section 3.4.4 and dkimpy's
    Relaxed.canonicalize_body ignore trailing empty lines. This is narrower than
    accepting every canonical-equivalent edit: any other delta still fails.
    """
    from dkim.canonicalization import Relaxed

    equal = before == after
    appended_crlf = before.endswith(b"\r\n") and after == before + b"\r\n"
    if not equal and not appended_crlf:
        raise RuntimeError("reinjection body delta is not identical or exactly one appended CRLF")
    canonical_equal = Relaxed.canonicalize_body(before) == Relaxed.canonicalize_body(after)
    if not canonical_equal:
        raise RuntimeError("reinjection changed the canonical DKIM body")
    return {
        "equal": equal,
        "before_bytes": len(before),
        "after_bytes": len(after),
        "before_sha256": hashlib.sha256(before).hexdigest(),
        "after_sha256": hashlib.sha256(after).hexdigest(),
        "delta": "identical" if equal else "appended CRLF (one trailing empty line)",
        "dkim_relaxed_canonical_equal": canonical_equal,
    }


def signing_split(sink: Server, fixture: Path = Path("/fixture")) -> dict:
    import dkim

    keys = json.loads((fixture / "public.json").read_text())

    def dns(name, **_kwargs):
        return keys.get(name.decode().rstrip("."), "").encode()

    with sink.guard:
        people = sink.messages["<sh00-port-587@contoso.test>"]
    parsed_people = BytesParser(policy=policy.default).parsebytes(people)
    signatures = parsed_people.get_all("DKIM-Signature", [])

    def people_dns(name, **_kwargs):
        expected = "sh00._domainkey.contoso.test"
        return keys[expected].encode() if name.decode().rstrip(".") == expected else b""

    if len(signatures) != 1 or not dkim.verify(people, dnsfunc=people_dns):
        raise RuntimeError("people-domain native signature missing or invalid")
    agent = (fixture / "agent.eml").read_bytes()
    before = BytesParser(policy=policy.default).parsebytes(agent)
    message_id = str(before["Message-ID"])
    if len(before.get_all("DKIM-Signature", [])) != 1 or not dkim.verify(agent, dnsfunc=dns):
        raise RuntimeError("fixture is not a valid actual gateway-signed message")
    send(10025, "gateway-signature", raw=agent, sender="intake@agents.contoso.test")
    stalwart.wait_for(lambda: message_id in sink.messages, 20, "signed agent reinjection")
    with sink.guard:
        after = sink.messages[message_id]
    parsed_after = BytesParser(policy=policy.default).parsebytes(after)
    if parsed_after.get_all("DKIM-Signature", []) != before.get_all("DKIM-Signature", []):
        raise RuntimeError("reinjection added or changed the gateway signature")
    if not dkim.verify(after, dnsfunc=dns):
        raise RuntimeError("reinjected gateway signature no longer verifies")
    before_body = agent.split(b"\r\n\r\n", 1)[1]
    after_body = after.split(b"\r\n\r\n", 1)[1]
    observed_body = body_observation(before_body, after_body)
    return {
        "status": "pass",
        "people_dkim_verified": True,
        "people_signature_count": 1,
        "agent_dkim_verified_before_and_after": True,
        "agent_signature_unchanged": True,
        "agent_signature_count": 1,
        "agent_body": observed_body,
        "agent_message_id": message_id,
        "limit": "original signature unchanged; raw body equality/delta reported, not assumed",
    }


def private_domains(path: Path) -> dict:
    rows = []
    for index, domain in enumerate(PRIVATE_DOMAINS):
        domains = {
            f"probe-{index}-{kind}": {"name": name, "dkimManagement": {"@type": "Manual"}}
            for kind, name in (("people", domain), ("agents", "agents." + domain))
        }
        try:
            apply(
                [{"@type": "upsert", "object": "Domain", "matchOn": ["name"], "value": domains}],
                path,
            )
        except subprocess.CalledProcessError as error:
            # A transport/CLI failure is not evidence that domain validation
            # rejected the candidate. Preserve the distinction for the reviewer.
            rows.append(
                {
                    "people": domain,
                    "agents": "agents." + domain,
                    "accepted": None,
                    "apply_exit": error.returncode,
                    "status": "apply failed; inspect native CLI output",
                }
            )
        else:
            # An apply exit code alone isn't readback of the registered objects.
            env = {
                "PATH": "/usr/local/bin:/usr/bin:/bin",
                "HOME": str(path.parent),
                "STALWART_URL": "http://127.0.0.1:8080",
                "STALWART_USER": "admin",
                "STALWART_PASSWORD": "dev-admin",
            }
            query = subprocess.run(
                ["/usr/local/bin/stalwart-cli", "--no-color", "query", "Domain", "--json"],
                env=env,
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            names = {json.loads(line)["name"] for line in query.stdout.splitlines() if line.strip()}
            rows.append(
                {
                    "people": domain,
                    "agents": "agents." + domain,
                    "accepted": {domain, "agents." + domain} <= names,
                }
            )
    return {
        "status": "measured",
        "candidates": rows,
        "default": "home.arpa"
        if any(r["people"] == "home.arpa" and r["accepted"] is True for r in rows)
        else "undecided",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite-owned", action="store_true", help="internal make suite entry only")
    args = parser.parse_args()
    if not args.suite_owned or os.environ.get("AMX_SH00_PROBE") != "suite-owned":
        parser.error("invoke via make suite MTA_CT=stalwart SH00_PROBE=1, never directly")
    report: dict[str, Any] = {
        "schema": 1,
        "status": "failed",
        "checks": {},
        "scope": "native Stalwart, loopback-only disposable datastore",
    }
    try:
        with tempfile.TemporaryDirectory(prefix="amx-sh00-") as scratch:
            root = Path(scratch)
            config = root / "config.json"
            config.write_text(json.dumps({"@type": "RocksDb", "path": str(root / "data")}))
            plan = probe_plan()
            settings, accounts = stalwart.phases(plan)
            with stalwart.PrivateServer("/usr/local/bin/stalwart", str(config)) as server:
                ready(server)
                apply(settings, root / "plan.ndjson")
            with stalwart.PrivateServer("/usr/local/bin/stalwart", str(config)) as server:
                ready(server)
                apply(accounts, root / "plan.ndjson")
                stalwart.ensure_mailboxes(
                    lambda: imaplib.IMAP4(HOST, 143, timeout=10),
                    SITE,
                    [user for user, _password in USERS],
                    lambda user: stalwart.master_login(user, "gateway", SITE),
                    "dev-gateway",
                )
                report["checks"]["g"] = private_domains(root / "plan.ndjson")
                with (
                    serving(8890, MilterRecorder) as ingress,
                    serving(8891, MilterRecorder) as sibling,
                    serving(2424, LmtpSink) as sink,
                ):
                    try:
                        native_checks(ingress, sibling, sink, report["checks"])
                    finally:
                        report["observations"] = {
                            "ingress": ingress.snapshot(),
                            "sibling": sibling.snapshot(),
                            "lmtp": sink.snapshot(),
                        }
            report["status"] = "partial"  # never a final SH-00 Verdict
        return 0
    except Exception as error:
        report["error"] = type(error).__name__ + ": " + str(error)
        return 1
    finally:
        print("AMX_SH00_RESULT=" + json.dumps(report, sort_keys=True), flush=True)


if __name__ == "__main__":
    sys.exit(main())
