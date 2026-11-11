from __future__ import annotations

import pytest

from scenarios.support import compose_exec


@pytest.mark.integration
def test_s08_journal_chain_detects_raw_tamper_and_recovers() -> None:
    for service in ("gateway-nw", "gateway-ct"):
        verified = compose_exec(
            service,
            "/app/.venv/bin/amx",
            "journal",
            "verify",
            "/etc/amx/gateway.yaml",
        )
        assert "OK" in verified.stdout

    tamper = """
from pathlib import Path
from amx.journal import Journal
from amx.store import Store
root=Path('/data')
store=Store(root/'journal.sqlite')
row=store.rows('SELECT raw_sha256 FROM journal ORDER BY sequence LIMIT 1')[0]
path=Journal(root,store).raw_path(str(row['raw_sha256']))
backup=path.with_suffix('.backup')
backup.write_bytes(path.read_bytes())
data=bytearray(path.read_bytes())
data[-1] ^= 1
path.write_bytes(data)
"""
    compose_exec("gateway-ct", "/app/.venv/bin/python", "-c", tamper)
    failed = compose_exec(
        "gateway-ct",
        "/app/.venv/bin/amx",
        "journal",
        "verify",
        "/etc/amx/gateway.yaml",
        check=False,
    )
    try:
        assert failed.returncode == 1
        assert "raw content hash mismatch" in failed.stderr
    finally:
        restore = """
from pathlib import Path
from amx.journal import Journal
from amx.store import Store
root=Path('/data')
store=Store(root/'journal.sqlite')
row=store.rows('SELECT raw_sha256 FROM journal ORDER BY sequence LIMIT 1')[0]
path=Journal(root,store).raw_path(str(row['raw_sha256']))
backup=path.with_suffix('.backup')
path.write_bytes(backup.read_bytes())
backup.unlink()
"""
        compose_exec("gateway-ct", "/app/.venv/bin/python", "-c", restore)
    recovered = compose_exec(
        "gateway-ct",
        "/app/.venv/bin/amx",
        "journal",
        "verify",
        "/etc/amx/gateway.yaml",
    )
    assert "OK" in recovered.stdout
    print(f"S08 TAMPER DETECTED: {failed.stderr.strip()}")
    print(f"S08 RECOVERED: {recovered.stdout.strip()}")
