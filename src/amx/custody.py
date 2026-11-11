"""Same-user mailbox arbitration shared by the native runner and amx-mcp.

IMAP flags remain authoritative across hosts. This local transaction closes the
read/claim race for cooperating clients on one agent host and fences uncertain AX
sends even when recovery has cleared Seen. Never age out a message claim.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any


class Custody:
    def __init__(
        self,
        address: str,
        *,
        directory: Path | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if directory is not None:
            root = directory
        else:
            state_home = os.environ.get("XDG_STATE_HOME")
            # A numeric container UID need not have a resolvable home. Consult
            # it only when neither explicit state location was supplied.
            base = Path(state_home) if state_home is not None else Path.home() / ".local/state"
            root = base / "amx/custody"
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path = root / (hashlib.sha256(address.casefold().encode()).hexdigest() + ".sqlite")
        self.clock = clock
        # Create with owner-only permissions, including on permissive umasks.
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        with sqlite3.connect(self.path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY, data TEXT)")

    @contextmanager
    def locked(self) -> Iterator[dict[str, Any]]:
        db = sqlite3.connect(self.path, timeout=30)
        try:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT data FROM state WHERE id=1").fetchone()
            state: dict[str, Any] = json.loads(row[0]) if row else {"claims": {}}
            yield state
            db.execute("INSERT OR REPLACE INTO state VALUES (1, ?)", (json.dumps(state),))
            db.commit()
        finally:
            db.close()

    def poll(self) -> None:
        with self.locked() as state:
            state["mcp_poll"] = self.clock()

    def recent(self, grace: float) -> bool:
        with self.locked() as state:
            age = self.clock() - state.get("mcp_poll", float("-inf"))
            return 0 <= age <= grace

    def ax_presence(self, available: bool) -> None:
        with self.locked() as state:
            state["ax_until"] = self.clock() + 5 if available else 0

    def ax_available(self, state: dict[str, Any]) -> bool:
        return self.clock() <= state.get("ax_until", 0)
