"""Helpers for black-box AMX compose scenarios."""

from __future__ import annotations

import imaplib
import json
import re
import smtplib
import time
from collections.abc import Callable
from email import policy
from email.message import EmailMessage, Message
from email.parser import BytesParser
from pathlib import Path
from typing import Any

from amx.identity import sign
from amx.mailbox import quote_mailbox


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    """Read complete JSONL records while tolerating one in-flight final append."""
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    rows: list[dict[str, Any]] = []
    for index, line in enumerate(lines):
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            if index == len(lines) - 1 and not text.endswith("\n"):
                continue
            raise
    return rows


def send_raw(
    host: str,
    envelope_from: str,
    recipients: str | list[str],
    raw: bytes,
    *,
    port: int = 25,
) -> dict[str, tuple[int, bytes]]:
    """Send adversarial raw bytes and return per-recipient refusal details."""
    recipient_list = [recipients] if isinstance(recipients, str) else recipients
    with smtplib.SMTP(host, port, timeout=15) as client:
        return client.sendmail(envelope_from, recipient_list, raw)


def smtp_transaction(
    host: str,
    envelope_from: str,
    recipient: str,
    raw: bytes,
    *,
    port: int = 25,
) -> tuple[int, bytes]:
    """Run an SMTP transaction and return the final DATA response."""
    with smtplib.SMTP(host, port, timeout=15) as client:
        code, response = client.mail(envelope_from)
        if code >= 400:
            return code, response
        code, response = client.rcpt(recipient)
        if code >= 400:
            return code, response
        return client.data(raw)


def signed_message(
    message: EmailMessage,
    *,
    selector: str,
    domain: str,
    private_key: str | Path,
) -> bytes:
    """Serialize and DKIM-sign an email message for a scenario."""
    return sign(
        message.as_bytes(policy=policy.SMTP),
        selector=selector,
        domain=domain,
        private_key=private_key,
    )


def _increment_zone_serial(text: str) -> str:
    updated, count = re.subn(
        r"(IN SOA .*?\()(\d+)",
        lambda match: f"{match.group(1)}{int(match.group(2)) + 1}",
        text,
        count=1,
    )
    if count != 1:
        raise ValueError("zone must contain exactly one numeric SOA serial")
    return updated


def drop_zone_record(path: str | Path, owner: str) -> str:
    """Remove one single-line owner record, bump the SOA serial, and return the record."""
    zone_path = Path(path)
    lines = zone_path.read_text(encoding="utf-8").splitlines()
    matches = [line for line in lines if line.split(maxsplit=1)[0] == owner]
    if len(matches) != 1:
        raise ValueError(f"expected exactly one zone record for {owner}, found {len(matches)}")
    updated = "\n".join(line for line in lines if line != matches[0]) + "\n"
    zone_path.write_text(_increment_zone_serial(updated), encoding="utf-8")
    return matches[0]


def set_zone_record(path: str | Path, record: str) -> None:
    """Replace one single-line owner record and bump the zone's SOA serial."""
    if "\n" in record or not record.strip():
        raise ValueError("zone record must be one non-empty line")
    owner = record.split(maxsplit=1)[0]
    zone_path = Path(path)
    lines = zone_path.read_text(encoding="utf-8").splitlines()
    retained = [line for line in lines if not line or line.split(maxsplit=1)[0] != owner]
    updated = "\n".join([*retained, record]) + "\n"
    zone_path.write_text(_increment_zone_serial(updated), encoding="utf-8")


def folder_messages(
    host: str, username: str, password: str, folder: str = "INBOX", *, port: int = 143
) -> list[Message]:
    """Return every message in one IMAP folder, newest first, without setting \\Seen."""
    messages: list[Message] = []
    with imaplib.IMAP4(host, port, timeout=10) as client:
        client.login(username, password)
        status, _ = client.select(quote_mailbox(folder), readonly=True)
        if status != "OK":
            raise RuntimeError(f"cannot select {folder} for {username}")
        status, data = client.uid("SEARCH", None, "ALL")
        if status != "OK":
            raise RuntimeError(f"cannot search {folder} for {username}")
        for uid in reversed((data[0] or b"").split()):
            status, fetched = client.uid("FETCH", uid, "(BODY.PEEK[])")
            if status != "OK":
                continue
            raw = next((item[1] for item in fetched if isinstance(item, tuple)), None)
            if raw is not None:
                messages.append(BytesParser(policy=policy.default).parsebytes(raw))
    return messages


def subscribed_folders(
    host: str, username: str, password: str, *, port: int = 143
) -> frozenset[str]:
    """Return the folders a mail client that shows only subscriptions (Roundcube) would list."""
    with imaplib.IMAP4(host, port, timeout=10) as client:
        client.login(username, password)
        status, data = client.lsub()
        if status != "OK":
            raise RuntimeError(f"cannot list subscriptions for {username}")
    return frozenset(_listed_name(line) for line in data if isinstance(line, bytes))


def _listed_name(line: bytes) -> str:
    """The mailbox name that ends one LIST or LSUB response line, quoted or not."""
    text = line.decode("utf-8", "replace").strip()
    quoted = re.search(r'"((?:[^"\\]|\\.)*)"$', text)
    if quoted:
        return re.sub(r"\\(.)", r"\1", quoted[1])
    return text.rsplit(" ", 1)[-1]


def wait_for_message(
    host: str,
    username: str,
    password: str,
    predicate: Callable[[Message], bool],
    *,
    port: int = 143,
    timeout: float = 30.0,
    folder: str = "INBOX",
) -> Message:
    """Poll an IMAP folder (INBOX by default) until a message matches."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for message in folder_messages(host, username, password, folder, port=port):
            if predicate(message):
                return message
        time.sleep(0.25)
    raise TimeoutError(f"no matching message arrived in {folder} for {username}")


def move_message(
    host: str,
    username: str,
    password: str,
    message_id: str,
    source: str,
    destination: str,
    *,
    port: int = 143,
) -> None:
    """IMAP MOVE one message by Message-ID, as a person dragging it in a mail client would."""
    with imaplib.IMAP4(host, port, timeout=10) as client:
        client.login(username, password)
        status, _ = client.select(quote_mailbox(source))
        if status != "OK":
            raise RuntimeError(f"cannot select {source} for {username}")
        status, data = client.uid("SEARCH", None, "ALL")
        if status != "OK":
            raise RuntimeError(f"cannot search {source} for {username}")
        for uid in (data[0] or b"").split():
            status, fetched = client.uid("FETCH", uid, "(BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])")
            header = next((item[1] for item in fetched if isinstance(item, tuple)), b"")
            parsed = BytesParser(policy=policy.default).parsebytes(header, headersonly=True)
            if str(parsed.get("Message-ID", "")).strip() != message_id:
                continue
            status, detail = client.uid("MOVE", uid, quote_mailbox(destination))
            if status != "OK":
                raise RuntimeError(f"MOVE to {destination} failed: {detail!r}")
            return
    raise LookupError(f"{message_id} is not in {source} for {username}")


def wait_journal(
    path: str | Path,
    predicate: Callable[[dict[str, Any]], bool],
    *,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Poll newline-delimited trace JSON exported by a scenario helper."""
    deadline = time.monotonic() + timeout
    journal_path = Path(path)
    while time.monotonic() < deadline:
        if journal_path.exists():
            for line in journal_path.read_text(encoding="utf-8").splitlines():
                item = json.loads(line)
                if predicate(item):
                    return item
        time.sleep(0.25)
    raise TimeoutError(f"no matching journal event in {journal_path}")
