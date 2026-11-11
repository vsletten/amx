"""Native Stalwart discovery and a TLS-only standard mail-client protocol path.

No static settings fallback, global DNS patch, system proxy, or plaintext credential URL.
The live validator injects only a connection factory to its sealed loopback edge.
"""

from __future__ import annotations

import base64
import http.client
import imaplib
import json
import os
import smtplib
import ssl
import time
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from email.message import EmailMessage
from pathlib import Path

from amx.mailbox import quote_mailbox


@dataclass(frozen=True)
class Settings:
    hostname: str
    imap_port: int
    smtp_port: int
    smtp_tls: str
    username: str
    source: str


class NativeHTTPError(OSError):
    def __init__(self, status):
        self.status = status
        super().__init__(f"native HTTPS status={status}")


def https_request(
    host,
    port,
    path,
    context,
    *,
    body=None,
    headers=None,
    connection_factory=http.client.HTTPSConnection,
):
    origin = f"https://{host}:{port}"
    for _attempt in range(4):
        connection = connection_factory(host, port, context=context, timeout=10)
        try:
            connection.request(
                "POST" if body is not None else "GET", path, body=body, headers=headers or {}
            )
            response = connection.getresponse()
            # Pinned Stalwart redirects /.well-known/jmap to /jmap/session (307).
            # Never forward credentials across origins, downgrade, or rewrite a POST.
            if response.status in (301, 302, 303, 307, 308) and body is None:
                target = urllib.parse.urlsplit(
                    urllib.parse.urljoin(origin + path, response.getheader("Location", ""))
                )
                if (
                    target.scheme != "https"
                    or target.hostname != host
                    or (target.port or 443) != port
                    or target.username
                    or target.password
                    or target.fragment
                ):
                    raise ValueError("refuse cross-origin native redirect")
                path = urllib.parse.urlunsplit(("", "", target.path, target.query, ""))
                continue
            if response.status != 200:
                raise NativeHTTPError(response.status)
            content = response.read(65537)
            if len(content) > 65536:
                raise ValueError("native response exceeds limit")
            return content
        finally:
            connection.close()
    raise ValueError("native redirect limit exceeded")


def discover(
    hostname: str, address: str, context: ssl.SSLContext, *, port=443, request=https_request
) -> Settings:
    domain = address.rpartition("@")[2]
    candidates = (
        ("autoconfig." + domain, "/mail/config-v1.1.xml"),
        (domain, "/.well-known/autoconfig/mail/config-v1.1.xml"),
        (hostname, "/mail/config-v1.1.xml"),
    )
    for host, path in candidates:
        try:
            raw = request(
                host, port, path + "?" + urllib.parse.urlencode({"emailaddress": address}), context
            )
            root = ET.fromstring(raw)
            if root.tag != "clientConfig":
                continue
            incoming = root.find(".//incomingServer[@type='imap']")
            outgoing = root.find(".//outgoingServer[@type='smtp']")
            if incoming is None or outgoing is None:
                continue
            for node in (incoming, outgoing):
                if node.findtext("hostname") != hostname:
                    raise ValueError("native discovery points outside the requested mailhost")
                if node.findtext("authentication") != "password-cleartext":
                    raise ValueError("unsupported native authentication")
                if node.findtext("username") not in ("%EMAILADDRESS%", address):
                    raise ValueError("native discovery username mismatch")
            if incoming.findtext("socketType") != "SSL" or outgoing.findtext("socketType") not in (
                "SSL",
                "STARTTLS",
            ):
                raise ValueError("native discovery must require TLS")
            imap_port = int(incoming.findtext("port", "0"))
            smtp_port = int(outgoing.findtext("port", "0"))
            if not all(1 <= value <= 65535 for value in (imap_port, smtp_port)):
                raise ValueError("bad discovered port")
            return Settings(
                hostname,
                imap_port,
                smtp_port,
                outgoing.findtext("socketType"),
                address,
                "https://" + host + path,
            )
        except (OSError, ET.ParseError):
            continue
    raise OSError("native autoconfig unavailable; no invented settings fallback")


def issue_app_password(
    params, address: str, password: str, output: Path, *, request=https_request
) -> None:
    """Ask Stalwart to create a real secondary credential, never synthesize one.

    Stalwart 0.16 refuses AppPassword credentials in management Account/set. Its
    authenticated x:AppPassword/set creates them and returns the secret once.
    """
    context = ssl.create_default_context(
        cafile=(
            str(params.tls_dir / "ca.pem")
            if params.tls_mode == "self-signed"
            or (params.tls_mode == "files" and params.tls_ca_file)
            else None
        )
    )
    host, port = params.mx_host, params.ports["discovery"]
    auth = "Basic " + base64.b64encode(f"{address}:{password}".encode()).decode()
    headers = {"Authorization": auth, "Content-Type": "application/json"}
    deadline = time.monotonic() + 45
    attempts = 0
    while True:
        attempts += 1
        try:
            session = json.loads(request(host, port, "/.well-known/jmap", context, headers=headers))
            break
        except OSError as error:
            status = error.status if isinstance(error, NativeHTTPError) else "transport"
            if status not in ("transport", 401, 503):
                raise OSError(f"native stage=session status={status} attempts={attempts}") from None
            if time.monotonic() >= deadline:
                raise OSError(
                    f"native stage=session status={status} attempts={attempts} deadline exceeded"
                ) from None
            time.sleep(0.5)
    api = urllib.parse.urlsplit(session["apiUrl"])
    if api.scheme != "https" or api.hostname != host or (api.port or 443) != port:
        raise ValueError("refuse cross-origin JMAP API")
    account = session["primaryAccounts"].get("urn:ietf:params:jmap:mail")
    if not account:
        raise ValueError("native session has no mail account")
    body = json.dumps(
        {
            "using": ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"],
            "methodCalls": [
                [
                    "x:AppPassword/set",
                    {"accountId": account, "create": {"mail": {"description": "amx mail client"}}},
                    "app",
                ]
            ],
        }
    ).encode()
    # Reserve the output first, so an existing path cannot lose a newly generated secret.
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        result = json.loads(request(host, port, api.path, context, body=body, headers=headers))
        responses = result["methodResponses"]
        if len(responses) != 1 or responses[0][0] != "x:AppPassword/set":
            raise ValueError("native app password request failed")
        token = responses[0][1].get("created", {}).get("mail", {}).get("secret")
        if not isinstance(token, str) or not token.startswith("app_"):
            raise ValueError("native app password not created")
        with os.fdopen(fd, "w") as stream:
            fd = -1
            stream.write(token + "\n")
    except BaseException:
        if fd != -1:
            os.close(fd)
        output.unlink(missing_ok=True)
        raise


class MailClient:
    def __init__(
        self,
        settings: Settings,
        password: str,
        context: ssl.SSLContext,
        *,
        imap_factory=imaplib.IMAP4_SSL,
        smtp_ssl_factory=smtplib.SMTP_SSL,
    ):
        self.settings, self.password, self.context = settings, password, context
        self.imap_factory, self.smtp_ssl_factory = imap_factory, smtp_ssl_factory

    def imap(self):
        client = self.imap_factory(
            self.settings.hostname, self.settings.imap_port, ssl_context=self.context, timeout=10
        )
        try:
            client.login(self.settings.username, self.password)
        except BaseException:
            client.shutdown()
            raise
        return client

    def send(self, message: EmailMessage):
        settings = self.settings
        if settings.smtp_tls == "SSL":
            smtp = self.smtp_ssl_factory(
                settings.hostname, settings.smtp_port, context=self.context, timeout=10
            )
        else:
            smtp = smtplib.SMTP(settings.hostname, settings.smtp_port, timeout=10)
            smtp.ehlo()
            smtp.starttls(context=self.context)
        with smtp:
            smtp.ehlo()
            smtp.login(settings.username, self.password)
            if smtp.send_message(message):
                raise RuntimeError("person submission refused recipient")

    def approve(self, held: str, approved: str, uid: bytes):
        with self.imap() as client:
            if client.select(quote_mailbox(held))[0] != "OK":
                raise RuntimeError("cannot select hold queue")
            if client.uid("MOVE", uid, quote_mailbox(approved))[0] != "OK":
                raise RuntimeError("owner approval MOVE refused")
