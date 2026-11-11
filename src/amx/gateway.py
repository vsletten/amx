"""AMX gateway process entrypoint."""

from __future__ import annotations

import argparse
import importlib
import logging
import threading
from collections.abc import Callable
from pathlib import Path

from amx.adapters.holdwatch import FolderWatcher, HoldService, watchers_for
from amx.adapters.lmtp import LmtpHandler
from amx.adapters.lmtp import controller as lmtp_controller
from amx.adapters.submission import SubmissionService
from amx.adapters.submission import controller as submission_controller
from amx.config import AgentConfig, GatewayConfig, load_config
from amx.journal import Journal
from amx.mailbox import MailboxAppender
from amx.reload import AgentChanges, ConfigWatcher, diff_agents
from amx.runtime import Handler, HandlerRegistry, load_handler
from amx.sdk import Agent
from amx.store import Store
from amx.tls_reload import ReloadableTLS, ReloadServer

LOG = logging.getLogger(__name__)


def _can_submit(agent: AgentConfig) -> bool:
    return agent.submit_token is not None or agent.submit_token_hash is not None


def outbound_agent(
    config: GatewayConfig,
    name: str,
    agent: AgentConfig,
    internal_token: Callable[[str], str] | None = None,
) -> Agent | None:
    """The submission client an in-process handler sends and declares through (``ctx``).

    A dev agent uses its configured token. A registered agent's config holds only a hash, so it
    uses ``internal_token``, which only this process knows (PLAN §5.2). A remote agent, or one
    that cannot submit, has none.
    """
    if agent.mode == "remote" or not _can_submit(agent):
        return None
    token = agent.submit_token or (internal_token(name) if internal_token else None)
    if token is None:
        return None
    return Agent(
        f"{name}@{config.agent_domain}",
        f"smtp://{config.submission_client_host}:{config.submission_port}",
        token,
        tls_ca_file=str(config.submission_tls_ca) if config.submission_tls_ca else None,
        control_address=config.control_address,
        max_bytes=config.limits.max_bytes,
    )


def outbound_agents(
    config: GatewayConfig, internal_token: Callable[[str], str] | None = None
) -> dict[str, Agent]:
    """Every in-process agent's submission client (see :func:`outbound_agent`)."""
    clients = {
        name: outbound_agent(config, name, agent, internal_token)
        for name, agent in config.agents.items()
    }
    return {name: client for name, client in clients.items() if client is not None}


class LiveGateway:
    """The running parts one configuration drives, and how a reload changes them (PLAN §5.2).

    Every component reads the configuration through this object or holds a reference that
    :meth:`apply` replaces, so a reload takes effect at each component's next read. The order
    keeps every read consistent with what the runtime can do:

    1. Handlers of new or rebuilt agents are imported first; a failure changes nothing.
    2. New runtime registrations go in before the configuration names the agent, so no RCPT is
       accepted for an agent LMTP cannot dispatch.
    3. The configuration is swapped.
    4. Removed agents leave the runtime only after the configuration dropped them, so RCPT
       refuses them (``550 5.1.1``) before LMTP could.
    5. Hold watchers follow: one pair per enabled agent that can submit.
    """

    def __init__(
        self,
        config: GatewayConfig,
        store: Store,
        registry: HandlerRegistry,
        mailbox: MailboxAppender,
        submission: SubmissionService,
        lmtp: LmtpHandler,
        *,
        start_watchers: bool = True,
    ) -> None:
        self._config = config
        self.store = store
        self.registry = registry
        self.mailbox = mailbox
        self.submission = submission
        self.lmtp = lmtp
        self.holds = HoldService(submission, store, lmtp.deliver_local)
        self.watchers: dict[str, list[FolderWatcher]] = {}
        self._start_watchers = start_watchers
        self._lock = threading.Lock()  # one apply at a time

    @property
    def config(self) -> GatewayConfig:
        return self._config

    def current(self) -> GatewayConfig:
        """The configuration now in force (the milter calls this at every stage)."""
        return self._config

    def _address(self, config: GatewayConfig, name: str) -> str:
        return f"{name}@{config.agent_domain}"

    def _register(
        self, config: GatewayConfig, name: str, agent: AgentConfig, handler: Handler | str
    ) -> None:
        address = self._address(config, name)
        self.registry.register(
            name,
            handler,
            mode=agent.mode,
            watermark=agent.watermark,
            workers=agent.workers,
            # A remote agent's queue is its INBOX (PLAN §5.9): what its runner has not finished,
            # and how long the oldest message it has not taken has waited.
            backlog=(lambda address=address: self.mailbox.backlog_state(address))
            if agent.mode == "remote"
            else None,
        )

    def _outbound(self, config: GatewayConfig, name: str, agent: AgentConfig) -> Agent | None:
        """The submission client an in-process handler replies through, if it may submit."""
        return outbound_agent(config, name, agent, self.submission.internal_token)

    def _watchers(self, config: GatewayConfig, name: str) -> None:
        """Start or stop ``name``'s hold watchers to match ``config``."""
        agent = config.agents.get(name)
        wanted = agent is not None and agent.enabled and _can_submit(agent)
        running = self.watchers.get(name)
        if running and not wanted:
            for watcher in self.watchers.pop(name):
                watcher.stop()
        elif wanted and not running and self._start_watchers:
            started = watchers_for(config, [name], self.holds)
            for watcher in started:
                watcher.start()
            self.watchers[name] = started

    def start(self) -> None:
        """Register every configured agent and start its watchers (the initial apply)."""
        config = self._config
        for name, agent in config.agents.items():
            self._register(config, name, agent, agent.handler)
            self.store.add_agent(
                name, self._address(config, name), agent.handler, enabled=agent.enabled
            )
            outbound = self._outbound(config, name, agent)
            if outbound is not None:
                self.lmtp.outbound_agents[name] = outbound
        for name in config.agents:
            self._watchers(config, name)

    def apply(self, new: GatewayConfig) -> None:
        """Bring the running gateway in line with ``new``, then make it current."""
        with self._lock:
            old = self._config
            changes = diff_agents(old, new)
            # 1. Import first: a handler that does not load leaves everything as it was.
            handlers: dict[str, Handler | str] = {}
            for name in (*changes.added, *changes.rebuilt):
                target = new.agents[name].handler
                handlers[name] = target if target == "mailbox-only" else load_handler(target)
            # 2. Runtime registrations for new and rebuilt agents (a rebuilt agent's old
            # workers finish the jobs already queued, then exit).
            for name, handler in handlers.items():
                self._register(new, name, new.agents[name], handler)
            for name in changes.changed:
                self.registry.set_watermark(name, new.agents[name].watermark)
            for name in (*changes.added, *changes.rebuilt, *changes.changed):
                outbound = self._outbound(new, name, new.agents[name])
                if outbound is None:
                    self.lmtp.outbound_agents.pop(name, None)
                else:
                    self.lmtp.outbound_agents[name] = outbound
            # 3. The swap: each reference is replaced whole. Nothing before it writes the store,
            # so a busy store cannot leave a disable or a rotation unapplied.
            self._config = new
            self.lmtp.config = new
            self.submission.config = new
            # 4. Removed agents leave the runtime last.
            for name in changes.removed:
                self.registry.unregister(name)
                self.lmtp.outbound_agents.pop(name, None)
            # 5. Hold watchers, and the store's agents table (a record for trace; best effort).
            for name in {*old.agents, *new.agents}:
                self._watchers(new, name)
            self._record_agents(old, new, changes)
            other = "; trust changed" if old.trust != new.trust else ""
            LOG.info("config reloaded: %s%s", changes.summary(), other)

    def _record_agents(self, old: GatewayConfig, new: GatewayConfig, changes: AgentChanges) -> None:
        try:
            for name in (*changes.added, *changes.rebuilt, *changes.changed):
                agent = new.agents[name]
                self.store.add_agent(
                    name, self._address(new, name), agent.handler, enabled=agent.enabled
                )
            for name in changes.removed:
                self.store.add_agent(
                    name, self._address(old, name), old.agents[name].handler, enabled=False
                )
        except Exception as error:  # the configuration is applied; this is only a record
            LOG.warning("config reloaded, but the agents table was not updated: %s", error)

    def stop(self) -> None:
        for watchers in self.watchers.values():
            for watcher in watchers:
                watcher.stop()


def run(config_path: str, *, reload_interval: float = 1.0) -> None:
    """Run LMTP, submission, and milter listeners for one gateway configuration."""
    from amx.adapters.milter import run_milter

    config = load_config(config_path)
    config.data_dir.mkdir(parents=True, exist_ok=True)
    store = Store(config.data_dir / "journal.sqlite")
    journal = Journal(config.data_dir, store)
    registry = HandlerRegistry()
    mailbox = MailboxAppender(config.mailbox)
    submission_service = SubmissionService(config, journal, mailbox=mailbox)
    handler = LmtpHandler(config, store, journal, registry, mailbox, {})
    gateway = LiveGateway(config, store, registry, mailbox, submission_service, handler)
    gateway.start()
    recovered = handler.recover()
    if recovered:
        LOG.warning("requeued %d interrupted deliveries", recovered)
    controller = lmtp_controller(handler, config)
    if config.submission_tls_cert is None or config.submission_tls_key is None:
        raise ValueError("submission TLS certificate and key are required")
    tls = ReloadableTLS(config.submission_tls_cert, config.submission_tls_key)
    submission = submission_controller(submission_service, tls_context=tls.context)
    controller.start()
    submission.start()
    tls_server = ReloadServer(config.data_dir, tls)
    tls_server.start()
    watcher = ConfigWatcher(
        Path(config_path), gateway.current, gateway.apply, interval=reload_interval
    )
    watcher.start()
    try:
        run_milter(gateway.current, store, registry)
    finally:
        tls_server.stop()
        watcher.stop()
        gateway.stop()
        submission.stop()
        controller.stop()
        registry.stop()


def main() -> None:
    """CLI entrypoint for the long-running gateway."""
    parser = argparse.ArgumentParser(description="run an AMX milter + LMTP gateway")
    parser.add_argument("--config", required=True)
    arguments = parser.parse_args()
    try:
        importlib.import_module("Milter")
    except ImportError:
        parser.exit(
            2,
            "The native AMX gateway is not included in the client wheel. "
            "Use the gateway container image, or a source checkout with libmilter headers "
            "and `uv sync --locked --group gateway` (patched vendored pymilter).\n",
        )
    logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(threadName)s %(message)s")
    logging.getLogger("amx").setLevel(logging.INFO)
    threading.current_thread().name = "amx-milter-main"
    run(arguments.config)


if __name__ == "__main__":
    main()
