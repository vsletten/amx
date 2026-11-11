"""AMX handler registry, sync and queued dispatch, and per-agent backpressure accounting."""

from __future__ import annotations

import importlib
import itertools
import logging
import queue
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal, TypeAlias, cast

from amx.profile import Inbound

LOG = logging.getLogger(__name__)

# An RCPT admission that never reaches LMTP (for example a lost connection after end-of-data)
# stops counting toward depth after this many seconds.
RESERVATION_TTL = 60.0


class TryLater(RuntimeError):
    """Ask the delivering MTA to retry later."""


class Refuse(RuntimeError):
    """Permanently refuse LMTP delivery with an enhanced status code.

    ``reason`` is an optional token from ``amx.control.REFUSAL_REASONS``. In-process, ``code`` and
    ``text`` become the LMTP reply and the MTA's bounce. A remote agent's runner cannot answer
    SMTP, so it sends the gateway a ``refuse`` command with a status and a reason token instead,
    and the gateway writes the DSN; the free ``text`` stays on the agent's host (PLAN §5.11).
    """

    def __init__(self, code: str, text: str, *, reason: str | None = None) -> None:
        super().__init__(text)
        self.code = code
        self.text = text
        self.reason = reason


@dataclass(slots=True)
class Context:
    """Per-delivery context whose outbound methods use authenticated submission."""

    agent: str
    metadata: dict[str, Any]
    send_message: Callable[..., Any] | None = None
    reply_message: Callable[..., Any] | None = None
    declare_state: Callable[..., Any] | None = None

    def declare(self, command: str, **fields: Any) -> Any:
        """Declare this agent's own state to its gateway (PLAN §5.10): ``pause`` (``until``,
        ``reason``), ``resume``, or ``capacity`` (``max``, ``ttl_seconds``)."""
        if self.declare_state is None:
            raise RuntimeError("declare is unavailable outside a bound delivery context")
        return self.declare_state(command, **fields)

    def reply(self, **message: Any) -> Any:
        """Reply through the bound authenticated submission client."""
        if self.reply_message is None:
            raise RuntimeError("reply is unavailable outside a bound delivery context")
        return self.reply_message(**message)

    def send(self, **message: Any) -> Any:
        """Send through the bound authenticated submission client."""
        if self.send_message is None:
            raise RuntimeError("send is unavailable outside a bound delivery context")
        return self.send_message(**message)


Handler: TypeAlias = Callable[[Inbound, Context], None]  # noqa: UP040
Job: TypeAlias = Callable[[], None]  # noqa: UP040


def load_handler(target: str) -> Handler:
    """Import a ``module:function`` handler (in the gateway, or in a remote agent's runner)."""
    module_name, separator, attribute = target.partition(":")
    if not separator:
        raise ValueError(f"handler target must be module:function: {target}")
    candidate = getattr(importlib.import_module(module_name), attribute)
    if not callable(candidate):
        raise TypeError(f"handler is not callable: {target}")
    return cast(Handler, candidate)


@dataclass(frozen=True, slots=True)
class Backlog:
    """A remote agent's mailbox as the RCPT watermark reads it (PLAN §5.9).

    ``count`` is what its runner has not finished. ``oldest_untaken`` is how many seconds the
    oldest message it has not even taken (no ``\\Seen``) has waited: a runner that is alive keeps
    it near zero, so it is the gateway's view of the agent's liveness. None when nothing waits.
    """

    count: int
    oldest_untaken: float | None = None


@dataclass(slots=True)
class _Reservation:
    agent: str
    expires: float
    key: str | None = None
    bound: bool = False


@dataclass(slots=True)
class Admission:
    """One LMTP recipient delivery's claim on the RCPT admission the milter counted for it."""

    agent: str
    key: str | None
    settled: bool = False


@dataclass(slots=True)
class _Pool:
    mode: Literal["sync", "queued", "remote"]
    watermark: int
    workers: int
    jobs: queue.Queue[Job | None]
    threads: list[threading.Thread]
    queued: int = 0
    running: int = 0


class HandlerRegistry:
    """Load named handlers, run them sync or through bounded worker pools, and report depth.

    Depth is what the RCPT watermark reads: jobs queued, handlers running, and messages admitted
    at RCPT that have not reached LMTP yet. Counting the admissions is what makes a burst of
    parallel SMTP sessions see a full agent at RCPT instead of all passing at depth zero. A remote
    agent's queued and running work is in its mailbox instead, and the milter adds its
    :meth:`backlog` at RCPT (PLAN §5.9).
    """

    def __init__(self, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._handlers: dict[str, Handler | None] = {}
        self._pools: dict[str, _Pool] = {}
        self._backlogs: dict[str, Callable[[], int | Backlog]] = {}
        self._reservations: dict[int, _Reservation] = {}
        self._ids = itertools.count(1)
        self._lock = threading.Lock()
        self._clock = clock
        # Held by the milter around read-depth / decide / reserve so concurrent RCPTs serialize.
        self.admission = threading.Lock()

    def register(
        self,
        agent: str,
        target: str | Handler,
        *,
        mode: Literal["sync", "queued", "remote"] = "sync",
        watermark: int = 2,
        workers: int = 1,
        backlog: Callable[[], int | Backlog] | None = None,
    ) -> None:
        """Register a callable or ``module:function`` target; queued mode starts its workers.

        A remote agent has no handler here (``mailbox-only``); ``backlog`` counts the work waiting
        for it in its mailbox.
        """
        handler: Handler | None
        if target == "mailbox-only":
            handler = None
        elif isinstance(target, str):
            handler = load_handler(target)
        else:
            handler = target
        if mode not in {"sync", "queued", "remote"}:
            raise ValueError(f"unsupported handler mode: {mode}")
        if mode == "remote" and handler is not None:
            raise ValueError(f"a remote agent's handler runs on its own host: {agent}")
        pool = _Pool(mode, max(1, watermark), max(1, workers), queue.Queue(), [])
        with self._lock:
            previous = self._pools.get(agent)
            self._handlers[agent] = handler
            if backlog is not None:
                self._backlogs[agent] = backlog
            else:
                self._backlogs.pop(agent, None)
            self._pools[agent] = pool
        if previous is not None:  # a reload rebuilt the agent: its old workers finish and exit
            for _thread in previous.threads:
                previous.jobs.put(None)
        if mode == "queued":
            for index in range(pool.workers):
                thread = threading.Thread(
                    target=self._work,
                    args=(agent, pool),
                    name=f"amx-{agent}-{index}",
                    daemon=True,
                )
                pool.threads.append(thread)
                thread.start()

    def registered(self, agent: str) -> bool:
        """Whether ``agent`` has a handler registration (a config reload adds and removes them)."""
        return agent in self._pools

    def set_watermark(self, agent: str, watermark: int) -> None:
        """Change a registered agent's depth bound in place (a config reload)."""
        with self._lock:
            pool = self._pools.get(agent)
            if pool is not None:
                pool.watermark = max(1, watermark)

    def unregister(self, agent: str) -> None:
        """Forget an agent a config reload removed.

        LMTP now refuses its mail (``5.1.1``), and a queued agent's workers exit once the jobs
        already queued have run: each job owns its delivery's retries and records.
        """
        with self._lock:
            pool = self._pools.pop(agent, None)
            self._handlers.pop(agent, None)
            self._backlogs.pop(agent, None)
        if pool is not None:
            for _thread in pool.threads:
                pool.jobs.put(None)

    def mode(self, agent: str) -> Literal["sync", "queued", "remote"]:
        """Return the dispatch mode for an agent (unknown agents are sync)."""
        pool = self._pools.get(agent)
        return pool.mode if pool is not None else "sync"

    def _live_reservations(self, agent: str, now: float) -> int:
        expired = [key for key, value in self._reservations.items() if value.expires <= now]
        for key in expired:
            del self._reservations[key]
        return sum(1 for value in self._reservations.values() if value.agent == agent)

    def depth(self, agent: str) -> int:
        """Return queued + running + admitted-but-undelivered work for an agent."""
        with self._lock:
            pool = self._pools.get(agent)
            active = pool.queued + pool.running if pool is not None else 0
            return active + self._live_reservations(agent, self._clock())

    def backlog(self, agent: str) -> int:
        """Return a remote agent's unfinished mailbox messages; 0 for an agent hosted here."""
        return self.backlog_state(agent).count

    def backlog_state(self, agent: str) -> Backlog:
        """Read a remote agent's mailbox backlog; nothing waits for an agent hosted here.

        This reads the mailhost, so only the RCPT watermark check calls it. A backlog that cannot
        be read counts as full: RCPT answers 450 and the sender retries, as for a gateway that is
        down.
        """
        count = self._backlogs.get(agent)
        if count is None:
            return Backlog(0)
        try:
            value = count()
        except Exception as error:
            LOG.warning("cannot read %s's mailbox backlog; counting it full: %s", agent, error)
            pool = self._pools.get(agent)
            return Backlog(pool.watermark if pool is not None else 1)
        return value if isinstance(value, Backlog) else Backlog(int(value))

    def reserve(self, agent: str) -> int:
        """Count one RCPT admission toward depth until LMTP settles it, it is released, or TTL."""
        with self._lock:
            reservation_id = next(self._ids)
            self._reservations[reservation_id] = _Reservation(
                agent, self._clock() + RESERVATION_TTL
            )
            return reservation_id

    def bind(self, reservation_id: int, message_id: str | None) -> None:
        """Attach the accepted message's Message-ID so its LMTP delivery can settle it."""
        with self._lock:
            reservation = self._reservations.get(reservation_id)
            if reservation is not None:
                reservation.key = message_id.strip() if message_id else None
                reservation.bound = True
                reservation.expires = self._clock() + RESERVATION_TTL

    def release(self, reservation_id: int) -> None:
        """Drop an admission whose SMTP transaction was rejected or aborted."""
        with self._lock:
            self._reservations.pop(reservation_id, None)

    def _settle_locked(self, admission: Admission | None) -> None:
        if admission is None or admission.settled:
            return
        admission.settled = True
        matches = [
            reservation_id
            for reservation_id, value in self._reservations.items()
            if value.agent == admission.agent and value.bound and value.key == admission.key
        ]
        if matches:
            del self._reservations[min(matches)]

    def settle(self, admission: Admission) -> None:
        """Drop a delivery's RCPT admission if it was not already moved into queued or running."""
        with self._lock:
            self._settle_locked(admission)

    def full(self, agent: str) -> bool:
        """Return whether a queued agent's bounded work queue has no free slot."""
        with self._lock:
            pool = self._pools.get(agent)
            return pool is not None and pool.queued + pool.running >= pool.watermark

    def submit(
        self, agent: str, job: Job, *, force: bool = False, admission: Admission | None = None
    ) -> bool:
        """Enqueue a job for a queued agent; return false when the bounded queue is full.

        The job's RCPT admission, if any, turns into the queued slot in the same critical
        section, so the work is never uncounted between LMTP arrival and the queue. ``force``
        bypasses the bound for work the gateway already accepted (restart recovery, local task
        events); depth then exceeds the watermark until the backlog drains.
        """
        with self._lock:
            pool = self._pools.get(agent)
            if pool is None or pool.mode != "queued":
                raise ValueError(f"agent is not in queued mode: {agent}")
            if not force and pool.queued + pool.running >= pool.watermark:
                return False
            self._settle_locked(admission)
            pool.queued += 1
            pool.jobs.put(job)
            return True

    def _work(self, agent: str, pool: _Pool) -> None:
        while True:
            job = pool.jobs.get()
            if job is None:
                return
            with self._lock:
                pool.queued -= 1
                pool.running += 1
            try:
                job()
            except Exception:  # A job owns its own retries; never let one kill the worker.
                LOG.exception("queued job for %s failed", agent)
            finally:
                with self._lock:
                    pool.running -= 1

    def join(self, agent: str, timeout: float = 5.0) -> None:
        """Wait until an agent's queue is empty and nothing is running (tests and shutdown)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                pool = self._pools.get(agent)
                if pool is None or pool.queued + pool.running == 0:
                    return
            time.sleep(0.01)
        raise TimeoutError(f"queued work for {agent} did not drain")

    def stop(self) -> None:
        """Stop every worker after the jobs already queued."""
        for pool in self._pools.values():
            for _thread in pool.threads:
                pool.jobs.put(None)
        for pool in self._pools.values():
            for thread in pool.threads:
                thread.join(timeout=5)

    def dispatch(
        self,
        agent: str,
        message: Inbound,
        context: Context,
        *,
        admission: Admission | None = None,
    ) -> None:
        """Invoke an agent's handler on the calling thread, propagating typed failures.

        In sync mode the delivery's RCPT admission becomes the running slot atomically.
        """
        with self._lock:  # a config reload may unregister the agent at any moment
            known = agent in self._handlers
            handler = self._handlers.get(agent)
            pool = self._pools.get(agent)
        if not known or pool is None:
            raise Refuse("5.1.1", "unknown agent")
        if handler is None:
            return
        sync = pool.mode == "sync"
        if sync:
            with self._lock:
                self._settle_locked(admission)
                pool.running += 1
        try:
            handler(message, context)
        finally:
            if sync:
                with self._lock:
                    pool.running -= 1
