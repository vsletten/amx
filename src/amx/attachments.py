"""Clean-room MIME attachment types and safe names; no native sniffing dependency."""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from email import policy
from email.message import Message
from io import BytesIO
from pathlib import PurePosixPath
from typing import Any
from zipfile import BadZipFile, ZipFile

DEFAULT_MAX_BYTES = 10 * 1024 * 1024
EXECUTABLE_TYPES = frozenset(
    {
        "application/vnd.microsoft.portable-executable",
        "application/x-executable",
        "application/x-mach-binary",
        "text/x-script",
    }
)
DEFAULT_BLOCKED_TYPES = EXECUTABLE_TYPES | {"application/x-msdownload"}


def safe_filename(name: str) -> str:
    """A portable basename, at most 180 UTF-8 bytes, without controls or dot paths."""
    name = name.replace("\\", "/").rsplit("/", 1)[-1]
    name = "".join(c for c in name if not unicodedata.category(c).startswith("C"))
    name = name.encode("utf-8")[:180].decode("utf-8", "ignore").strip(" .")
    return name or "attachment"


def sniff_type(content: bytes, filename: str = "") -> str:
    """Identify bytes, never trust a declared MIME type (nor an executable's suffix)."""
    for magic, kind in (
        (b"MZ", "application/vnd.microsoft.portable-executable"),
        (b"\x7fELF", "application/x-executable"),
        (b"\xfe\xed\xfa\xce", "application/x-mach-binary"),
        (b"\xce\xfa\xed\xfe", "application/x-mach-binary"),
        (b"\xfe\xed\xfa\xcf", "application/x-mach-binary"),
        (b"\xcf\xfa\xed\xfe", "application/x-mach-binary"),
        (b"\xca\xfe\xba\xbe", "application/x-mach-binary"),
        (b"\xbe\xba\xfe\xca", "application/x-mach-binary"),
        (b"\xca\xfe\xba\xbf", "application/x-mach-binary"),
        (b"\xbf\xba\xfe\xca", "application/x-mach-binary"),
        (b"#!", "text/x-script"),
        (b"%PDF-", "application/pdf"),
        (b"\x89PNG\r\n\x1a\n", "image/png"),
        (b"\xff\xd8\xff", "image/jpeg"),
        (b"GIF87a", "image/gif"),
        (b"GIF89a", "image/gif"),
    ):
        if content.startswith(magic):
            return kind
    if content.startswith(b"RIFF") and content[8:12] == b"WEBP":
        return "image/webp"
    if content.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        try:
            # Inspect names only: never inflate an untrusted archive (including zip bombs).
            with ZipFile(BytesIO(content)) as archive:
                names = set(archive.namelist())
            if "[Content_Types].xml" in names:
                for directory, kind in (
                    ("word/", "wordprocessingml.document"),
                    ("xl/", "spreadsheetml.sheet"),
                    ("ppt/", "presentationml.presentation"),
                ):
                    if any(name.startswith(directory) for name in names):
                        return "application/vnd.openxmlformats-officedocument." + kind
        except (BadZipFile, ValueError):
            pass
        return "application/zip"
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return "application/octet-stream"
    if text and all(c.isprintable() or c in "\n\r\t" for c in text):
        return {
            ".csv": "text/csv",
            ".md": "text/markdown",
            ".markdown": "text/markdown",
            ".json": "application/json",
        }.get(PurePosixPath(filename).suffix.lower(), "text/plain")
    return "application/octet-stream"


@dataclass(frozen=True, slots=True)
class Attachment:
    """An outgoing attachment. ``declared_type`` is optional; bytes decide policy."""

    filename: str
    content: bytes
    declared_type: str | None = None


@dataclass(frozen=True, slots=True)
class ReceivedAttachment:
    """A received part; decoded bytes are available on demand through ``content``."""

    index: int
    filename: str
    declared_type: str
    _part: Message

    @property
    def content(self) -> bytes:
        decoded = self._part.get_payload(decode=True)
        if decoded is not None:
            return decoded
        payload = self._part.get_payload()
        if isinstance(payload, list):
            if (
                self.declared_type == "message/rfc822"
                and len(payload) == 1
                and isinstance(payload[0], Message)
            ):
                return _mime_bytes(payload[0])
            # Unknown message/* types can also carry nested messages. Keep their MIME
            # representation rather than making metadata, listing or scanning raise.
            return _mime_bytes(self._part)
        if payload is None:
            return b""
        if isinstance(payload, str):
            return payload.encode("utf-8", "surrogateescape")
        return bytes(payload) if isinstance(payload, (bytes, bytearray)) else b""

    @property
    def type(self) -> str:
        return sniff_type(self.content, self.filename)

    @property
    def size(self) -> int:
        return len(self.content)

    def metadata(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "filename": self.filename,
            "type": self.type,
            "declared_type": self.declared_type,
            "size": self.size,
        }


def _mime_bytes(part: Message) -> bytes:
    """Serialize even MIME structures unsupported by standard generator handlers."""
    payload = part.get_payload()
    try:
        if (
            isinstance(payload, list)
            and part.get_content_maintype() == "message"
            and part.get_content_type() != "message/delivery-status"
        ):
            # Recurse ourselves: the generic message/* generator serializes only child 0,
            # even in a nested unknown message type beneath this entity.
            raise ValueError("generic structured message")
        return part.as_bytes(policy=policy.SMTP)
    except (AttributeError, TypeError, ValueError, UnicodeError):
        # For example, a structured list under an application/* or text/* handler.
        # Serialize the original headers and every child, not just the first child.
        headers = b"".join(policy.SMTP.fold_binary(name, value) for name, value in part.raw_items())
        children = payload if isinstance(payload, list) else []
        return (
            headers
            + b"\r\n"
            + b"\r\n".join(_mime_bytes(child) for child in children if isinstance(child, Message))
        )


def received_attachments(message: Message) -> tuple[ReceivedAttachment, ...]:
    """Enumerate file/attachment parts, excluding the profile's inline machine payload."""
    result = []
    # Local import avoids the profile -> attachment types dependency cycle.
    from amx.profile import ProfileError, validated_machine_part

    try:
        machine = validated_machine_part(message)
    except ProfileError:
        machine = None
    pending = [message]
    while pending:
        part = pending.pop()
        if part is machine:
            continue
        if part.get_content_disposition() == "attachment" or part.get_filename():
            result.append(
                ReceivedAttachment(
                    len(result),
                    safe_filename(part.get_filename() or ""),
                    part.get_content_type(),
                    part,
                )
            )
        elif part.is_multipart():
            pending.extend(
                child for child in reversed(part.get_payload()) if isinstance(child, Message)
            )
    return tuple(result)


def security_parts(message: Message) -> tuple[ReceivedAttachment, ...]:
    """Scan attachment leaves, regardless of container disposition or claimed purpose.

    Presentation rules (one attached email/container, hiding the profile JSON file) are
    not security rules. No sender-controlled headers exempt a leaf once that leaf or
    one of its ancestors is file-like. Ordinary body leaves are not attachments and
    must not be classified as executables merely because their text starts with ``#!``.
    """
    leaves: list[Message] = []

    def visit(part: Message, inside_attachment: bool = False) -> None:
        file_like = (
            inside_attachment
            or part.get_content_disposition() == "attachment"
            or bool(part.get_filename())
            or part.get_content_maintype() not in {"text", "multipart"}
        )
        if part.is_multipart():
            payload = part.get_payload()
            if isinstance(payload, list):
                for child in payload:
                    if isinstance(child, Message):
                        # Forwarded message bodies remain prose; nested files retain
                        # their own filename/disposition or non-text content type.
                        visit(child, file_like and part.get_content_type() != "message/rfc822")
            return
        if file_like:
            leaves.append(part)

    visit(message)
    return tuple(
        ReceivedAttachment(
            index, safe_filename(part.get_filename() or ""), part.get_content_type(), part
        )
        for index, part in enumerate(leaves)
    )
