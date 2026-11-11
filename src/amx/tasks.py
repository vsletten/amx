"""Task token and lifecycle helpers."""

from __future__ import annotations

import base64
import re
import secrets

from amx.store import TERMINAL_STATES, Store

# The token rides in the recipient sub-address, and the gateways fold recipient addresses to lower
# case (as many MTAs do), so a token must survive that: lower-case letters, digits, "_" and "-".
TOKEN_PATTERN = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")


def mint_token() -> str:
    """Mint an opaque task token that is safe in a case-folded sub-address (80 random bits)."""
    return f"t_{base64.b32encode(secrets.token_bytes(10)).decode('ascii').lower()}"


def valid_token(token: str) -> bool:
    """Return whether a task token survives a case-folded recipient sub-address unchanged."""
    return TOKEN_PATTERN.fullmatch(token) is not None


class Tasks:
    """Task lifecycle facade over :class:`amx.store.Store`."""

    def __init__(self, store: Store) -> None:
        self.store = store

    def open(self, agent: str, token: str | None = None) -> str:
        """Create a submitted task and return its token."""
        task_token = token or mint_token()
        self.store.put_task(task_token, agent, "submitted")
        return task_token

    def set_state(self, token: str, agent: str, state: str) -> None:
        """Set a task state, creating the task if needed."""
        self.store.put_task(token, agent, state)

    def is_closed(self, token: str, agent: str | None = None) -> bool:
        """Return whether the task has reached a terminal state."""
        task = self.store.task(token, agent)
        return task is not None and str(task["state"]) in TERMINAL_STATES
