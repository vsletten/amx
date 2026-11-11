"""Reload the gateway's configuration while it runs: agents, tokens, grants (PLAN §5.2).

``amx agent add --live`` and its siblings write the registry (:mod:`amx.registry`); an operator
may also edit the gateway YAML. :class:`ConfigWatcher` polls both once a second, by content, and
hands a freshly loaded configuration to the gateway (``amx.gateway.LiveGateway.apply``), which
brings the running parts in line and then swaps the configuration they read.

Why a file watch and not SIGHUP: the milter runs inside libmilter, which owns SIGHUP and stops
the milter on it (measured: a pymilter process exits on SIGHUP). A watch also needs no access to
the gateway's process, only to the files the commands already write.

A configuration that does not load is logged and not applied; the gateway keeps running on the
one it has. One that changes what only a restart can change is applied without those fields
where it can be: the listeners, TLS files, mailbox connection, and submission client host stay as
running, and everything else (agents, tokens, grants, rules) takes effect, so an agent's
revocation is never held back by an unrelated edit waiting for a restart. A change to the domain,
the data directory, the registry path, or the control address is not applied at all: the agents
and grants loaded under it would not fit the gateway that runs.
"""

from __future__ import annotations

import dataclasses
import hashlib
import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from amx.config import GatewayConfig, load_config
from amx.registry import fingerprint as registry_fingerprint

LOG = logging.getLogger(__name__)

# GatewayConfig fields a running gateway cannot change: its listeners are bound, its store is
# open, and its watchers are logged in with this mailbox configuration.
RESTART_FIELDS = (
    "domain",
    "agent_domain",
    "data_dir",
    "mailbox",
    "milter_host",
    "milter_port",
    "lmtp_host",
    "sibling_milter_port",
    "people_milter_port",
    "lmtp_port",
    "submission_host",
    "submission_port",
    "submission_tls_cert",
    "submission_tls_key",
    "submission_tls_ca",
    "registry_dir",
    # Built into each in-process agent's submission client, which a reload does not rebuild.
    "submission_client_host",
)
# Of those, the ones whose running value can stand while the rest of a new configuration is
# applied: nothing loaded from the YAML or the registry depends on them. The others (the domains
# the grants are built for, the data directory, the registry path, the control address that agent
# names are checked against) block the whole change until a restart.
KEEPABLE_FIELDS = frozenset(
    {
        "mailbox",
        "milter_host",
        "milter_port",
        "lmtp_host",
        "sibling_milter_port",
        "people_milter_port",
        "lmtp_port",
        "submission_host",
        "submission_port",
        "submission_tls_cert",
        "submission_tls_key",
        "submission_tls_ca",
        "submission_client_host",
    }
)
# An agent whose handler, mode, or worker count changed gets a new runtime registration.
_RUNTIME_FIELDS = ("handler", "mode", "workers")


@dataclass(frozen=True, slots=True)
class AgentChanges:
    """How a reload changes the agents, by name."""

    added: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()
    rebuilt: tuple[str, ...] = ()  # handler, mode, or workers changed
    changed: tuple[str, ...] = ()  # anything else: enabled, watermark, token, selector, ...

    def __bool__(self) -> bool:
        return bool(self.added or self.removed or self.rebuilt or self.changed)

    def summary(self) -> str:
        parts = [
            f"{label} {', '.join(names)}"
            for label, names in (
                ("added", self.added),
                ("removed", self.removed),
                ("rebuilt", self.rebuilt),
                ("changed", self.changed),
            )
            if names
        ]
        return "; ".join(parts) or "no agent changes"


def diff_agents(old: GatewayConfig, new: GatewayConfig) -> AgentChanges:
    """Compare two configurations' agents."""
    added = tuple(sorted(set(new.agents) - set(old.agents)))
    removed = tuple(sorted(set(old.agents) - set(new.agents)))
    rebuilt: list[str] = []
    changed: list[str] = []
    for name in sorted(set(old.agents) & set(new.agents)):
        before, after = old.agents[name], new.agents[name]
        if any(getattr(before, field) != getattr(after, field) for field in _RUNTIME_FIELDS):
            rebuilt.append(name)
        elif before != after:
            changed.append(name)
    return AgentChanges(added, removed, tuple(rebuilt), tuple(changed))


def restart_needed(old: GatewayConfig, new: GatewayConfig) -> list[str]:
    """The fields that differ and that only a restart can apply."""
    fields = [field for field in RESTART_FIELDS if getattr(old, field) != getattr(new, field)]
    # The control address is built into each in-process agent's submission client too; the
    # rest of `control` (max_ttl_seconds) is read at each use and reloads.
    if old.control.address != new.control.address:
        fields.append("control.address")
    return fields


def config_fingerprint(config_path: Path, registry_dir: Path | None) -> str:
    """A digest of the gateway YAML and every registry file (content, not mtimes)."""
    digest = hashlib.sha256()
    try:
        digest.update(config_path.read_bytes())
    except FileNotFoundError:
        digest.update(b"\0missing")
    if registry_dir is not None:
        digest.update(registry_fingerprint(registry_dir).encode())
    return digest.hexdigest()


def keep_running(current: GatewayConfig, new: GatewayConfig) -> GatewayConfig:
    """``new`` with the restart-only fields as ``current`` runs them."""
    return dataclasses.replace(new, **{field: getattr(current, field) for field in KEEPABLE_FIELDS})


class RestartNeeded(RuntimeError):
    """A new configuration changes what only a gateway restart can apply."""


class ConfigWatcher(threading.Thread):
    """Poll the configuration's files and apply each change once it loads cleanly."""

    def __init__(
        self,
        config_path: Path,
        current: Callable[[], GatewayConfig],
        apply: Callable[[GatewayConfig], None],
        *,
        interval: float = 1.0,
        load: Callable[[Path], GatewayConfig] = load_config,
    ) -> None:
        super().__init__(name="amx-config-watch", daemon=True)
        self.config_path = config_path
        self.current = current
        self.apply = apply
        self.interval = interval
        self.load = load
        self._stopped = threading.Event()
        # The files as last applied. None: the first check always loads, so a change made
        # between the gateway's own load and this watcher's start is not missed.
        self._seen: str | None = None
        # The files as last reported failing: a failure is logged once, and retried every poll.
        self._failed: str | None = None

    def stop(self) -> None:
        self._stopped.set()

    def check(self) -> bool:
        """Reload if the files changed since the last applied configuration.

        Return whether a new configuration was applied. A change that fails (a file that does
        not load, a handler that does not import, a store that is busy) is tried again at every
        poll until it applies, because a failed disable or rotation must not stay unapplied;
        it is logged once per distinct content.
        """
        seen = config_fingerprint(self.config_path, self.current().registry_dir)
        if seen == self._seen:
            return False
        report = seen != self._failed
        try:
            new = self.load(self.config_path)
            current = self.current()
            blocked = restart_needed(current, new)
            if blocked and not set(blocked) <= KEEPABLE_FIELDS:
                raise RestartNeeded(f"{', '.join(blocked)} can change only on a restart")
            if blocked:
                new = keep_running(current, new)
            self.apply(new)
            if blocked and report:
                LOG.error(
                    "config reload applied, except %s, which a restart applies",
                    ", ".join(blocked),
                )
        except RestartNeeded as error:
            if report:
                LOG.error("config reload not applied: %s", error)
            self._failed = seen
            return False
        except Exception as error:
            if report:
                LOG.error("config reload failed; keeping the running configuration: %s", error)
            self._failed = seen
            return False
        self._seen, self._failed = seen, None
        return True

    def run(self) -> None:
        while not self._stopped.wait(self.interval):
            try:
                self.check()
            except Exception:  # never let the watcher die; the next change is tried afresh
                LOG.exception("config watcher failed")
