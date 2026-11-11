"""Mailbox access through the mailhost's master-user IMAP login (Dovecot, or Stalwart in M6)."""

from __future__ import annotations

import imaplib
import logging
import re
import select
import ssl
import time
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from email import policy
from email.message import Message
from email.parser import BytesParser

from amx.config import MailboxConfig
from amx.policy import TAINT_HEADER, TASK_TAINT_HEADER
from amx.runtime import Backlog
from amx.tasks import valid_token

LOG = logging.getLogger(__name__)
# What reading the liveness age can raise; bound at import, as imaplib.IMAP4 is a class to patch.
_AGE_ERRORS = (imaplib.IMAP4.error, OSError, ValueError, KeyError, OverflowError, RuntimeError)

# PLAN §5.9: a remote agent's runner sets \Seen when it takes an INBOX message and this keyword
# when its handler is done with it. What lacks the keyword is the agent's backlog.
HANDLED_KEYWORD = "$AmxHandled"
TAKEN_KEYWORD = "$AmxTaken"  # MCP custody, distinct from the legacy runner's Seen
# Set beside HANDLED_KEYWORD on a copy the AX target refused under its external policy (an
# unverified sender to a session that takes only verified mail): kept in the mailbox, not retried.
NOT_DELIVERED_KEYWORD = "$AmxNotDelivered"
_REASON = re.compile(r"[a-z0-9][a-z0-9_-]*")


def taint_reasons(values: Iterable[object]) -> tuple[str, ...]:
    """The reason tokens in taint header values, each once, in order; anything else is dropped.

    Reasons are gateway-written tokens such as ``directs-recipient``. Keeping only tokens means a
    value read back from a mailbox can never carry a line break into a stored taint or a header.
    It fails closed: a value present but with no readable reason still taints (``tainted-input``).
    """
    texts = [str(value) for value in values]
    reasons = (reason.strip().casefold() for text in texts for reason in text.split(","))
    kept = tuple(dict.fromkeys(reason for reason in reasons if _REASON.fullmatch(reason)))
    return kept or (("tainted-input",) if texts else ())


def _task(headers: Message) -> str | None:
    """A filed copy's task: its Agent-Task, else the token in the gateway's Delivered-To."""
    task = str(headers.get("Agent-Task", "") or "").strip()
    if not task:
        delivered = headers.get_all("Delivered-To", [])
        local = str(delivered[0]).partition("@")[0] if delivered else ""
        task = local.partition("+")[2].strip().casefold()
    return task if task and valid_token(task) else None


@dataclass(frozen=True, slots=True)
class ImapEndpoint:
    """Where an agent's own client reaches IMAP: ``host:port`` in plain text, or ``imaps://``.

    Plain ``host:port`` (or ``imap://``) is the dev stack's compose network. ``imaps://host:port``
    is implicit TLS, the live bundle's port 993, verified against the system's trust store or a
    CA file (PLAN §5.9: a runner on a laptop reaches a public host).
    """

    host: str
    port: int
    tls: bool = False

    @classmethod
    def parse(cls, value: str) -> ImapEndpoint:
        """Read ``host:port``, ``imap://host:port``, or ``imaps://host[:port]``."""
        scheme, separator, rest = value.partition("://")
        if not separator:
            scheme, rest = "imap", value
        if scheme not in ("imap", "imaps"):
            raise ValueError(f"IMAP endpoint must be host:port or imap(s)://host:port: {value!r}")
        host, colon, port = rest.rstrip("/").rpartition(":")
        if not colon:
            host, port = rest.rstrip("/"), ""
        if not port:
            if scheme == "imap":
                raise ValueError(f"IMAP endpoint needs a port: {value!r}")
            port = "993"
        if not host or not port.isdigit():
            raise ValueError(f"bad IMAP endpoint: {value!r}")
        return cls(host.strip("[]"), int(port), scheme == "imaps")

    def connect(
        self, *, ca_file: str | None = None, timeout: float = 30, server_hostname: str | None = None
    ) -> imaplib.IMAP4:
        """Open the connection; implicit TLS verifies the certificate and the host name."""
        if not self.tls:
            return imaplib.IMAP4(self.host, self.port, timeout=timeout)
        context = ssl.create_default_context(cafile=ca_file)
        if server_hostname:

            class NamedIMAP(imaplib.IMAP4_SSL):
                def _create_socket(self, timeout):
                    raw = imaplib.IMAP4._create_socket(self, timeout)
                    return self.ssl_context.wrap_socket(raw, server_hostname=server_hostname)

            return NamedIMAP(self.host, self.port, ssl_context=context, timeout=timeout)
        return imaplib.IMAP4_SSL(self.host, self.port, ssl_context=context, timeout=timeout)


_ATOM_SPECIALS = frozenset('(){ %*"\\')


def connect_mailbox(config: MailboxConfig, *, timeout: float = 30) -> imaplib.IMAP4:
    """Open the gateway mailbox path; live Stalwart uses verified implicit TLS."""
    return ImapEndpoint(config.host, config.port, config.tls).connect(
        ca_file=config.tls_ca_file, timeout=timeout, server_hostname=config.tls_server_name
    )


def quote_mailbox(name: str) -> str:
    """A mailbox name as an IMAP astring: unchanged if it is an atom, else a quoted string.

    imaplib sends arguments as they are, and a shared folder's name can have a space in it
    (Stalwart: ``Shared Folders/<owner>/...``).
    """
    if name and all(" " < char < "\x7f" and char not in _ATOM_SPECIALS for char in name):
        return name
    return '"' + name.replace("\\", "\\\\").replace('"', '\\"') + '"'


class MailboxAppender:
    """Append to and inspect arbitrary local mailboxes as the master user."""

    def __init__(self, config: MailboxConfig) -> None:
        self.config = config

    def append(self, address: str, raw: bytes, folder: str = "INBOX") -> None:
        """Append one message and require the IMAP server to acknowledge it."""
        login = self.config.login_for(address)
        with connect_mailbox(self.config, timeout=10) as client:
            client.login(login, self.config.master_password)
            status, detail = client.append(
                quote_mailbox(folder), None, imaplib.Time2Internaldate(time.time()), raw
            )
            if status != "OK":
                raise RuntimeError(f"IMAP APPEND failed for {address}: {detail!r}")

    @contextmanager
    def _inbox(self, address: str) -> Iterator[imaplib.IMAP4]:
        """Open ``address``'s INBOX read-only (EXAMINE: no flag changes, not even \\Recent)."""
        login = self.config.login_for(address)
        with connect_mailbox(self.config, timeout=10) as client:
            client.login(login, self.config.master_password)
            status, detail = client.select("INBOX", readonly=True)
            if status != "OK":
                raise RuntimeError(f"cannot examine INBOX for {address}: {detail!r}")
            yield client

    @staticmethod
    def _search(client: imaplib.IMAP4, *criteria: str) -> list[bytes]:
        status, data = client.uid("SEARCH", None, *criteria)
        if status != "OK":
            raise RuntimeError(f"IMAP SEARCH {' '.join(criteria)} failed: {data!r}")
        return (data[0] or b"").split()

    def backlog(self, address: str) -> int:
        """Count the INBOX messages a remote agent has not finished: its queued plus running."""
        with self._inbox(address) as client:
            return len(self._search(client, "UNDELETED", "UNKEYWORD", HANDLED_KEYWORD))

    def backlog_state(self, address: str, clock: Callable[[], float] = time.time) -> Backlog:
        """The backlog, plus how long the oldest message nobody has taken has waited.

        The age is the remote agent's liveness as the gateway sees it (PLAN §5.9): a runner that
        is up takes each message within seconds of its filing, so an age that keeps growing
        means nothing is reading. The filing time is the message's INTERNALDATE, which the
        gateway's own append sets. One FETCH more than ``backlog``, and only when something
        waits. The count alone decides admission: a FETCH that fails (a message expunged between
        the two commands, a date this cannot read) leaves the age unknown, never the INBOX full.
        """
        with self._inbox(address) as client:
            uids = self._search(client, "UNDELETED", "UNKEYWORD", HANDLED_KEYWORD)
            if not uids:
                return Backlog(0)
            try:
                oldest = self._oldest_untaken(client, uids, clock)
            except _AGE_ERRORS as error:
                LOG.warning("cannot age %s's untaken mail: %s", address, error)
                oldest = None
        return Backlog(len(uids), oldest)

    @staticmethod
    def _oldest_untaken(
        client: imaplib.IMAP4, uids: list[bytes], clock: Callable[[], float]
    ) -> float | None:
        status, data = client.uid("FETCH", b",".join(uids).decode(), "(FLAGS INTERNALDATE)")
        if status != "OK":
            raise RuntimeError(f"IMAP FETCH of FLAGS INTERNALDATE failed: {data!r}")
        filed = [
            time.mktime(stamp)
            for line in (item[0] if isinstance(item, tuple) else item for item in data)
            if isinstance(line, bytes)
            and b"\\Seen" not in imaplib.ParseFlags(line)
            and TAKEN_KEYWORD.lower().encode()
            not in {flag.lower() for flag in imaplib.ParseFlags(line)}
            and (stamp := imaplib.Internaldate2tuple(line)) is not None
        ]
        return max(0.0, clock() - min(filed)) if filed else None

    def tainted_in_progress(
        self, address: str, task_taint: Callable[[str], str | None] | None = None
    ) -> str | None:
        """Taint of unfinished INBOX mail taken by the runner (Seen) or MCP ($AmxTaken).

        That is the remote form of a tainted handler context: whatever the agent sends meanwhile
        may have been steered by those messages, whether the message itself or its task is
        tainted. Unread mail cannot have steered anything. Returns ``None`` when there are none.
        ``task_taint`` looks up each message's task now, since the task may have been tainted
        after the copy was filed. This holds only for a runner that takes a message before acting
        on it (PLAN §8).
        """
        fields = f"{TAINT_HEADER} {TASK_TAINT_HEADER} AGENT-TASK DELIVERED-TO"
        with self._inbox(address) as client:
            uids = self._search(
                client,
                "UNDELETED",
                "OR",
                "SEEN",
                "KEYWORD",
                TAKEN_KEYWORD,
                "UNKEYWORD",
                HANDLED_KEYWORD,
            )
            if not uids:
                return None
            status, data = client.uid(
                "FETCH", b",".join(uids).decode(), f"(BODY.PEEK[HEADER.FIELDS ({fields})])"
            )
            if status != "OK":
                raise RuntimeError(f"IMAP FETCH of {fields} failed: {data!r}")
        reasons: list[str] = []
        for item in data:
            if not isinstance(item, tuple):
                continue
            headers = BytesParser(policy=policy.default).parsebytes(item[1], headersonly=True)
            values = headers.get_all(TAINT_HEADER, []) + headers.get_all(TASK_TAINT_HEADER, [])
            task = _task(headers)
            stored = task_taint(task) if task_taint is not None and task else None
            reasons += taint_reasons(values) + (taint_reasons([stored]) if stored else ())
        return ", ".join(dict.fromkeys(reasons)) or None

    def unfinished(self, address: str, recipient: str, message_id: str) -> bool:
        """Whether the INBOX holds a copy of this delivery the agent has not finished.

        A copy is this delivery when its ``Delivered-To`` stamp is ``recipient`` and its
        Message-ID is ``message_id``; unfinished means no ``$AmxHandled``. A remote agent's
        refusal names such a copy (PLAN §5.11). The unfinished set is small (the watermark
        bounds it), so its headers are compared here, the same way on every IMAP server.
        """
        with self._inbox(address) as client:
            uids = self._search(client, "UNDELETED", "UNKEYWORD", HANDLED_KEYWORD)
            if not uids:
                return False
            status, data = client.uid(
                "FETCH",
                b",".join(uids).decode(),
                "(BODY.PEEK[HEADER.FIELDS (DELIVERED-TO MESSAGE-ID)])",
            )
            if status != "OK":
                raise RuntimeError(f"IMAP FETCH of Delivered-To failed: {data!r}")
        wanted = (recipient.casefold(), message_id.strip())
        for item in data:
            if not isinstance(item, tuple):
                continue
            headers = BytesParser(policy=policy.default).parsebytes(item[1], headersonly=True)
            stamped = [
                str(value).strip().casefold() for value in headers.get_all("Delivered-To", [])
            ]
            if (stamped[:1], str(headers.get("Message-ID", "")).strip()) == (
                [wanted[0]],
                wanted[1],
            ):
                return True
        return False


def idle(client: imaplib.IMAP4, seconds: float) -> bool:
    """Wait in RFC 2177 IDLE until the server reports a change or ``seconds`` pass.

    Python 3.13's imaplib has no IDLE, so this speaks it over the documented ``send`` and
    ``readline`` methods. Returns whether an untagged response arrived.
    """
    tag = b"AMXIDLE"
    client.send(tag + b" IDLE\r\n")
    line = client.readline()
    if not line.startswith(b"+"):
        raise imaplib.IMAP4.error(f"IDLE refused: {line!r}")
    changed = False
    readable, _, _ = select.select([client.socket()], [], [], seconds)
    if readable:
        changed = client.readline().startswith(b"*")
    client.send(b"DONE\r\n")
    while True:
        line = client.readline()
        if not line:
            raise imaplib.IMAP4.abort("connection closed during IDLE")
        if line.startswith(tag + b" "):
            if not line[len(tag) + 1 :].upper().startswith(b"OK"):
                raise imaplib.IMAP4.error(f"IDLE failed: {line!r}")
            return changed
        changed = changed or line.startswith(b"*")
