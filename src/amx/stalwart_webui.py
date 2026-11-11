"""Pinned genuine WebUI: verify immutable bytes before atomic native publication."""

from __future__ import annotations

import hashlib
import io
import os
import tempfile
import urllib.request
import zipfile
from pathlib import Path

WEBUI_VERSION = "v1.0.11"
WEBUI_URL = f"https://github.com/stalwartlabs/webui/releases/download/{WEBUI_VERSION}/webui.zip"
WEBUI_SHA256 = "d67e68caba02024301c79da9f15fe465de9bf5382cee54bdf9c309a97b4179a5"
WEBUI_RESOURCE = "file:///secrets/webui.zip"
MAX_BYTES = 64 * 1024 * 1024


def validate_webui(data: bytes) -> bytes:
    """Return the same checked bytes; never reopen a mutable source path."""
    if len(data) > MAX_BYTES or hashlib.sha256(data).hexdigest() != WEBUI_SHA256:
        raise ValueError("WebUI bundle does not match pinned SHA256")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            if "index.html" not in archive.namelist() or archive.testzip() is not None:
                raise ValueError("WebUI bundle is not a complete WebUI ZIP")
    except (zipfile.BadZipFile, RuntimeError) as error:
        raise ValueError("WebUI bundle is not a valid ZIP") from error
    return data


def read_webui(path: Path) -> bytes:
    with path.open("rb") as stream:
        return validate_webui(stream.read(MAX_BYTES + 1))


def fetch_webui() -> bytes:
    with urllib.request.urlopen(WEBUI_URL, timeout=60) as response:
        return validate_webui(response.read(MAX_BYTES + 1))


def publish_webui(destination: Path, data: bytes) -> None:
    """0600 temp, complete write/flush, then replace; failures retain old destination."""
    validate_webui(data)
    fd, name = tempfile.mkstemp(prefix=".webui-", dir=destination.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def prepare_webui(destination: Path, *, staged: bool) -> None:
    if destination.is_file():
        read_webui(destination)
    elif staged:
        raise ValueError("staged WebUI is missing; run install again")
    else:
        publish_webui(destination, fetch_webui())
