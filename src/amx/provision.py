"""Agent key and DNS record helpers shared by ``amx agent add``, ``amx dns``, and ``amx live``."""

from __future__ import annotations

import base64
import os
import secrets
import subprocess
from pathlib import Path


def write_private(path: Path, data: bytes | str, mode: int = 0o600) -> None:
    """Write ``data`` so that it is never readable wider than ``mode``, replacing atomically."""
    raw = data.encode("utf-8") if isinstance(data, str) else data
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        # The rename is durable only once the directory is (a crash must not empty a secret).
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def generate_dkim_key(path: Path, bits: int = 2048) -> None:
    """Create an RSA DKIM signing key at ``path`` (0600); refuse to overwrite one."""
    if path.exists():
        raise FileExistsError(f"key already exists: {path}")
    result = subprocess.run(
        ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", f"rsa_keygen_bits:{bits}"],
        check=True,
        capture_output=True,
    )
    write_private(path, result.stdout)


def dkim_public_key(private_key: Path) -> str:
    """The base64 DER public key for a DKIM ``p=`` tag."""
    result = subprocess.run(
        ["openssl", "pkey", "-in", str(private_key), "-pubout", "-outform", "DER"],
        check=True,
        capture_output=True,
    )
    return base64.b64encode(result.stdout).decode()


def dkim_txt_value(public_key: str) -> str:
    """The TXT value that publishes an RSA DKIM key."""
    return f"v=DKIM1; k=rsa; p={public_key}"


def txt_strings(value: str, size: int = 255) -> list[str]:
    """Split a TXT value into DNS character-strings of at most ``size`` bytes (RFC 1035 3.3)."""
    return [value[index : index + size] for index in range(0, len(value), size)] or [""]
