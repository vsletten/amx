"""The DSN a remote agent's refusal becomes, and who may receive one (PLAN §5.11). Pure; no I/O.

An in-process handler's ``Refuse`` is an LMTP ``550``, and the sending MTA writes the bounce. A
remote agent's mail was already accepted with ``250`` when the gateway filed it, so its runner
sends a ``refuse`` command instead, and the gateway writes that bounce itself: an RFC 3464
``multipart/report`` to the original envelope sender, shaped like the MTAs' own (null envelope
sender, ``MAILER-DAEMON@<domain>``, unsigned). Only the gateway's words and the agent's status and
reason token reach the sender, never the handler's own text.

The DSN goes only where the gateway verified the sender at ingress, so that a refusal cannot be
turned into backscatter at a forged MAIL FROM.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from email.utils import formatdate

from amx.config import TrustGrant
from amx.policy import is_reserved_transport_header
from amx.profile import ProfileError
from amx.registry import selector_agent
from amx.transport import transport_metadata

# What each refusal reason tells the sender, in the gateway's words.
_MEANING = {
    "policy": "the agent does not take this message",
    "content": "the agent cannot use what this message carries",
    "unsupported": "the agent does not handle this kind of message",
    "handler-failed": "the agent failed to process this message",
    "unreadable": "the agent could not read this message",
}


@dataclass(frozen=True, slots=True)
class BounceVerdict:
    """Whether a refusal's DSN may be sent, and the rule that decided (a token, for the journal)."""

    send: bool
    why: str


def bounce_verdict(
    delivered: bytes,
    envelope_from: str | None,
    grant_for: Callable[[str, str], TrustGrant | None],
) -> BounceVerdict:
    """Decide whether the refused message's envelope sender gets a DSN.

    Only a sender the gateway verified at ingress does: agent-lane mail, which the milter accepts
    only with a DKIM signature aligned with ``From`` and a trust grant for that ``(d, s)``, whose
    envelope sender is in the verified domain, and whose grant still stands. ``delivered`` is the
    message as LMTP journaled it, with the milter's verdict headers. Everything else is recorded
    and gets no DSN:

    - ``null-sender``: a bounce, which is never bounced (RFC 5321 §4.5.5);
    - ``sender-unrecorded``: delivered before the gateway kept the envelope sender;
    - ``sender-unverified``: the human lane, or mail the milter never saw. The milter verifies DKIM
      only on the agent lane, and the gateway checks no SPF, so no person's sender is verified;
    - ``sender-unaligned``: a verified signature, but a MAIL FROM outside its domain, which is
      exactly what backscatter at a forged address looks like;
    - ``no-grant``: the sender's grant was revoked after the delivery.
    """
    if envelope_from is None:
        return BounceVerdict(False, "sender-unrecorded")
    if not envelope_from:
        return BounceVerdict(False, "null-sender")
    headers = BytesParser(policy=policy.default).parsebytes(delivered, headersonly=True)
    try:
        metadata = transport_metadata(headers)
    except ProfileError:
        metadata = None
    if (
        metadata is None
        or metadata.lane != "agent"
        or metadata.trust != "verified"
        or not metadata.verified_domain
        or not metadata.verified_selector
    ):
        return BounceVerdict(False, "sender-unverified")
    domain = metadata.verified_domain.casefold().rstrip(".")
    sender_domain = envelope_from.rpartition("@")[2].casefold().rstrip(".")
    if sender_domain != domain and not sender_domain.endswith(f".{domain}"):
        return BounceVerdict(False, "sender-unaligned")
    # SH-44 stores the verified agent's name here. A message stored before it holds the key's
    # selector, which the domain's own DNS chose, so its rotation label is safe to drop; an agent
    # name has no dots, so this changes nothing for it.
    if grant_for(metadata.verified_domain, selector_agent(metadata.verified_selector)) is None:
        return BounceVerdict(False, "no-grant")
    return BounceVerdict(True, "verified")


def dsn_message_id(recipient: str, message_id: str, domain: str) -> str:
    """The DSN's Message-ID, the same every time the same refusal is reported.

    A DSN sent again (a retried command whose first reinjection was not recorded) then reaches the
    sender's gateway with the Message-ID it already delivered, and its LMTP answers the copy as a
    duplicate: the sender's agent sees one failure.
    """
    digest = hashlib.sha256(f"{recipient}\n{message_id}".encode()).hexdigest()[:32]
    return f"<dsn-{digest}@{domain}>"


def _header_block(raw: bytes) -> bytes:
    """The refused message's header block, less the receiving gateway's own verdict headers.

    Those (lane, trust, judgment probabilities, taint) are what this gateway concluded, not what
    the sender sent, so they stay here. The rest is returned as delivered, ``Received`` included,
    as an MTA's bounce returns it.
    """
    block = raw.replace(b"\r\n", b"\n").split(b"\n\n", 1)[0]
    kept: list[bytes] = []
    keep = True
    for line in block.split(b"\n"):
        if line[:1] in (b" ", b"\t"):
            if keep:
                kept.append(line)
            continue
        name = line.partition(b":")[0].decode("ascii", "replace").strip()
        keep = not is_reserved_transport_header(name)
        if keep:
            kept.append(line)
    return b"".join(line + b"\r\n" for line in kept)


def build_dsn(
    *,
    original: bytes,
    envelope_from: str,
    recipient: str,
    status: str,
    reason: str,
    domain: str,
    reporting_mta: str,
    message_id: str,
    arrival: str | None = None,
    date: str | None = None,
) -> bytes:
    """Build the RFC 3464 report: a notice, the ``message/delivery-status``, the headers.

    ``domain`` is the gateway's own (the ``MAILER-DAEMON`` address), ``reporting_mta`` the name
    the agent's mail is addressed to, and ``arrival`` the delivery's journal time (RFC 5322). The
    envelope sender of the result is null, as for every bounce.
    """
    original_id = str(
        BytesParser(policy=policy.default)
        .parsebytes(original, headersonly=True)
        .get("Message-ID", "")
    ).strip()
    boundary = f"=_amx-dsn-{message_id.strip('<>').partition('@')[0]}"
    meaning = _MEANING.get(reason, "the agent refused this message")
    diagnostic = f"smtp; 550 {status} refused by the recipient agent ({reason})"
    notice = (
        f"This is the mail system at {reporting_mta}.\r\n"
        "\r\n"
        f"Your message {original_id} was delivered to the agent at <{recipient}>, and the\r\n"
        f"agent refused it: {meaning} ({status}, {reason}).\r\n"
        "\r\n"
        "The agent's own explanation is not included. Its report and your message's\r\n"
        "headers are attached.\r\n"
    )
    per_message = f"Reporting-MTA: dns; {reporting_mta}\r\n"
    if arrival:
        per_message += f"Arrival-Date: {arrival}\r\n"
    per_recipient = (
        f"Final-Recipient: rfc822; {recipient}\r\n"
        "Action: failed\r\n"
        f"Status: {status}\r\n"
        f"Diagnostic-Code: {diagnostic}\r\n"
    )
    headers = _header_block(original)
    eight_bit = any(byte > 127 for byte in headers)
    top = (
        f"From: Mail Delivery System <MAILER-DAEMON@{domain}>\r\n"
        f"To: {envelope_from}\r\n"
        "Subject: Undelivered Mail Returned to Sender\r\n"
        f"Date: {date or formatdate(localtime=True)}\r\n"
        f"Message-ID: {message_id}\r\n"
        "Auto-Submitted: auto-replied\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/report; report-type=delivery-status;\r\n"
        f' boundary="{boundary}"\r\n'
        f"Content-Transfer-Encoding: {'8bit' if eight_bit else '7bit'}\r\n"
    )
    body = (
        "This is a MIME-encapsulated message.\r\n"
        "\r\n"
        f"--{boundary}\r\n"
        "Content-Description: Notification\r\n"
        "Content-Type: text/plain; charset=us-ascii\r\n"
        "\r\n"
        f"{notice}"
        "\r\n"
        f"--{boundary}\r\n"
        "Content-Description: Delivery report\r\n"
        "Content-Type: message/delivery-status\r\n"
        "\r\n"
        f"{per_message}"
        "\r\n"
        f"{per_recipient}"
        "\r\n"
        f"--{boundary}\r\n"
        "Content-Description: Undelivered Message Headers\r\n"
        "Content-Type: text/rfc822-headers\r\n"
        f"Content-Transfer-Encoding: {'8bit' if eight_bit else '7bit'}\r\n"
        "\r\n"
    )
    return top.encode() + b"\r\n" + body.encode() + headers + f"\r\n--{boundary}--\r\n".encode()
