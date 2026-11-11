"""PyMilter adapter for the pure AMX ingress policy."""

from __future__ import annotations

import contextlib
import logging
import tempfile
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from email import policy as email_policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any

import Milter  # type: ignore[import-untyped]

from amx.attachments import security_parts
from amx.config import GatewayConfig
from amx.control import iso
from amx.identity import verify as verify_dkim
from amx.judge import (
    Judge,
    JudgeBackendConfig,
    JudgeInput,
    JudgeUnavailable,
    Judgment,
    machine_part_text,
    make_judge,
)
from amx.policy import (
    AgentState,
    Stage,
    State,
    TxnContext,
    Verdict,
    apply_judgment,
    evaluate,
    is_reserved_transport_header,
    judgment_header,
)
from amx.profile import parse
from amx.runtime import RESERVATION_TTL, Backlog, HandlerRegistry
from amx.store import Store

LOG = logging.getLogger(__name__)
_CURRENT_TASK = object()
# The gateway's configuration, or a function returning the current one: the gateway reloads it
# while the milter runs (amx.reload), and each callback reads the latest.
ConfigSource = GatewayConfig | Callable[[], GatewayConfig]


Controls = Mapping[str, Any]  # agent → its declaration in force (Store.controls rows)


def _agent_states(
    config: GatewayConfig,
    registry: HandlerRegistry,
    controls: Controls,
    *,
    backlog_for: str | None = None,
) -> dict[str, AgentState]:
    """Each agent's state. ``backlog_for`` also counts that remote agent's mailbox (RCPT only).

    Called under the admission lock, which LMTP also holds while it files a remote agent's
    message and settles its admission, so each message is counted exactly once: as an admission
    or as an INBOX message, never both and never neither. ``controls`` are the agents' own
    declarations in force (PLAN §5.10).
    """
    states = {}
    for name, agent in config.agents.items():
        backlog = registry.backlog_state(name) if name == backlog_for else Backlog(0)
        control = controls.get(name)
        command = control["command"] if control is not None else None
        states[name] = AgentState(
            enabled=agent.enabled,
            depth=registry.depth(name) + backlog.count,
            watermark=agent.watermark,
            paused_until=float(control["ends_at"]) if command == "pause" else None,
            declared_max=int(control["max"]) if command == "capacity" else None,
            oldest_untaken=backlog.oldest_untaken,
        )
    return states


def _policy_state(
    config: GatewayConfig,
    store: Store,
    registry: HandlerRegistry,
    controls: Controls | None = None,
) -> State:
    """The policy's view of the gateway. Only RCPT reads the agents' declarations, so it
    passes ``controls``; no other stage looks at an agent's admission."""
    return State(
        agent_domain=config.agent_domain,
        agents=_agent_states(config, registry, controls or {}),
        known_tasks=store.task_keys(),
        closed_tasks=store.task_keys(closed=True),
        blocklist=config.blocklist,
        grants=config.trust,
        limits=config.limits,
        greylisting=config.greylisting,
        known_domains=config.known_domains,
        control_agent=config.control.address,
        people_domain=config.people_domain,
        accept_from={
            name: entries for name in config.agents if (entries := config.accept_from_for(name))
        },
        households={name: agent.household for name, agent in config.agents.items()},
    )


# RCPT refusals decided before the agent's admission is looked at: a declaration beside one of
# these would suggest it was the reason.
_BEFORE_ADMISSION = frozenset(
    {"control-address", "agent-unknown", "invalid-task-token", "closed-task"}
)


def rcpt_detail(agent: AgentState | None, *, rule: str, backlog_read: bool) -> str | None:
    """What trace shows beside an RCPT admission decision about an agent with a declaration in
    force, or one whose mailbox backlog was read: the depth against the effective watermark
    (whenever it was read), the declaration, and the oldest untaken message's age (PLAN §5.9,
    §5.10). None otherwise, so other rows read as before. A pause is decided before any backlog
    is read, so its row shows no depth."""
    if agent is None or rule in _BEFORE_ADMISSION:
        return None
    if not (backlog_read or agent.paused_until or agent.declared_max):
        return None
    parts = []
    if backlog_read or agent.declared_max is not None:
        parts.append(f"depth {agent.depth}/{agent.limit}")
    if agent.declared_max is not None:
        parts.append(f"declared capacity {agent.declared_max} (configured {agent.watermark})")
    if agent.paused_until is not None:
        parts.append(f"declared pause until {iso(agent.paused_until)}")
    if backlog_read and agent.oldest_untaken is not None:
        parts.append(f"oldest untaken {agent.oldest_untaken:.0f}s")
    return ", ".join(parts)


def _address(value: str | bytes) -> str:
    text = value.decode(errors="surrogateescape") if isinstance(value, bytes) else value
    return text.strip().strip("<>")


def _macro(milter: Any, name: str) -> str:
    try:
        return str(milter.getsymval(name) or "")
    except Exception:  # No milter context (unit tests) or no such macro.
        return ""


def _daemon_name(milter: Any) -> str:
    """The MTA's ``{daemon_name}`` macro: "Stalwart v0.16.23" from Stalwart; Postfix sends
    ``milter_macro_daemon_name`` ($myhostname by default)."""
    return _macro(milter, "{daemon_name}")


def session_key(
    milter: Any, daemon: str, hostaddr: Any, *, sibling: bool
) -> tuple[str, str, str, str, str] | None:
    """Name the SMTP session a replaying MTA's milter connection belongs to.

    The MTA (its ``{daemon_name}`` and ``j`` macros), the SMTP client's address and port, and
    the resolved listener class. Equal source tuples on normal and sibling endpoints must not
    share decisions or admissions. Use the class, not the one-use listener handle, so stage
    connections on the same endpoint still correlate. None without a port.
    """
    if not isinstance(hostaddr, tuple) or len(hostaddr) < 2 or not hostaddr[1]:
        return None
    return (
        daemon,
        _macro(milter, "j"),
        str(hostaddr[0]),
        str(hostaddr[1]),
        "sibling" if sibling else "normal",
    )


@dataclass(slots=True)
class ReplayedRecipient:
    """An RCPT the milter accepted in a replayed transaction, and the admission it holds."""

    recipient: str
    agent: str | None
    token: str | None
    reservation: int | None


@dataclass(slots=True)
class ReplayedTransaction:
    """One SMTP transaction's accepted MAIL and RCPTs, for the stage connections that replay it."""

    mail_from: str
    mail: Verdict
    recipients: list[ReplayedRecipient] = field(default_factory=list)


@dataclass(slots=True)
class _Session:
    seen: float
    holder: StageReplay
    transaction: ReplayedTransaction | None = None


class StageReplays:
    """Tie a replaying MTA's per-stage milter connections to the SMTP session they replay.

    Stalwart opens a new milter connection at every stage, and one per RCPT command. Each one
    replays CONNECT, MAIL, and every RCPT accepted so far (PLAN §5.8). The MTA runs one of a
    session's connections at a time, and sends the next only after the last one's replies, so
    the latest to connect holds the session. It walks the session's accepted decisions in order
    and reuses each one its replay matches, so a replay is neither decided nor recorded twice,
    and an RCPT admission counts once, from the RCPT stage to the end of DATA. Nothing here
    decides: what does not match is decided afresh, as before correlation, and so is what comes
    after a connection loses its session. The session's admissions are released when a replay
    shows the MTA dropped them, when the transaction ends or restarts, and when the session has
    been idle for ``ttl`` seconds (the MTA never says a session ended).
    """

    def __init__(
        self,
        release: Callable[[int], None],
        *,
        clock: Callable[[], float] = time.monotonic,
        ttl: float = RESERVATION_TTL,
    ) -> None:
        self._release = release
        self._clock = clock
        self._ttl = ttl
        self._sessions: dict[tuple[str, ...], _Session] = {}
        self._lock = threading.Lock()

    def connect(self, key: tuple[str, ...]) -> StageReplay:
        """A new connection of ``key``'s session, which it now holds if the session is open."""
        with self._lock:
            now = self._clock()
            for stale in [k for k, s in self._sessions.items() if s.seen + self._ttl <= now]:
                self._end(self._sessions.pop(stale))
            replay = StageReplay(self, key)
            session = self._sessions.get(key)
            if session is not None:
                # The previous holder has had all its replies, so if it was a MAIL stage the
                # transaction restarts now, whenever its close() comes.
                replay.restart = self._restart(session, session.holder)
                session.holder, session.seen, replay.replayed = replay, now, True
            return replay

    def _restart(self, session: _Session | None, replay: StageReplay) -> Verdict | None:
        """If ``replay`` replayed MAIL and no RCPT, it was the MAIL stage of a new transaction
        from the same sender (after RSET, say), because every later stage replays an RCPT. Drop
        its predecessor's RCPTs, once, and return the MAIL decision to record."""
        transaction = replay._transaction
        if transaction is None or not replay._mail_replayed or replay._rcpt_seen:
            return None
        if replay._restarted:
            return None
        replay._restarted = True
        if session is not None and session.transaction is transaction:
            self._drop(transaction, 0)
        return transaction.mail

    def _held(
        self, replay: StageReplay, transaction: ReplayedTransaction | None = None
    ) -> _Session | None:
        session = self._sessions.get(replay.key)
        if session is None or session.holder is not replay:
            return None
        if transaction is not None and session.transaction is not transaction:
            return None
        session.seen = self._clock()
        return session

    def _drop(self, transaction: ReplayedTransaction, index: int) -> None:
        for dropped in transaction.recipients[index:]:
            if dropped.reservation is not None:
                self._release(dropped.reservation)
        del transaction.recipients[index:]

    def _end(self, session: _Session) -> None:
        if session.transaction is not None:
            self._drop(session.transaction, 0)
            session.transaction = None


class StageReplay:
    """One stage connection's walk through its session's accepted decisions (StageReplays).

    A true answer means the MTA replayed a decision already made, recorded, and admitted; a
    false one leaves the decision to the caller, made afresh.
    """

    def __init__(self, replays: StageReplays, key: tuple[str, ...]) -> None:
        self.key = key
        self.replayed = False  # the session was open: its CONNECT was decided and recorded
        self.restart: Verdict | None = None  # the MAIL stage this connection took over from
        self._replays = replays
        self._transaction: ReplayedTransaction | None = None
        self._mail_replayed = False
        self._rcpt_seen = False
        self._restarted = False

    def open(self) -> None:
        """The session's CONNECT was just accepted: open it, held by this connection."""
        replays = self._replays
        with replays._lock:
            session = replays._sessions.setdefault(self.key, _Session(replays._clock(), self))
            session.holder = self

    def mail(self, mail_from: str) -> bool:
        """Whether this MAIL replays the open transaction's. If its sender differs, that
        transaction is over (the MTA takes no second MAIL in one) and its admissions go."""
        replays = self._replays
        with replays._lock:
            self._transaction, self._mail_replayed = None, False
            self._rcpt_seen = self._restarted = False
            session = replays._held(self)
            if session is None:
                return False
            if session.transaction is not None and session.transaction.mail_from == mail_from:
                self._transaction, self._mail_replayed = session.transaction, True
                return True
            replays._end(session)
            return False

    def start(self, mail_from: str, mail: Verdict) -> None:
        """This connection's MAIL was just accepted: open its transaction."""
        replays = self._replays
        with replays._lock:
            session = replays._held(self)
            if session is not None:
                replays._end(session)
                session.transaction = self._transaction = ReplayedTransaction(mail_from, mail)

    def recipient(self, index: int, recipient: str) -> bool:
        """Whether this RCPT replays the transaction's ``index``th accepted one. If not, the RCPTs
        from ``index`` on are dropped with their admissions: the MTA replays all it holds, in
        order, so it no longer holds them."""
        replays = self._replays
        with replays._lock:
            self._rcpt_seen = True
            transaction = self._transaction
            if transaction is None or replays._held(self, transaction) is None:
                return False
            recipients = transaction.recipients
            if index < len(recipients) and recipients[index].recipient == recipient:
                return True
            replays._drop(transaction, index)
            return False

    def admit(self, index: int, admitted: ReplayedRecipient) -> bool:
        """Carry an RCPT just accepted in the transaction, for the later stages to replay. False
        if this connection no longer holds it; the caller then keeps the admission itself."""
        replays = self._replays
        with replays._lock:
            transaction = self._transaction
            if transaction is None or replays._held(self, transaction) is None:
                return False
            if len(transaction.recipients) != index:
                return False
            transaction.recipients.append(admitted)
            return True

    def finish(self, replayed: int) -> list[int]:
        """End of DATA ends the transaction. Returns the admissions of the ``replayed`` RCPTs
        that reached it, for the caller to bind or release, and releases any others."""
        replays = self._replays
        with replays._lock:
            transaction, self._transaction = self._transaction, None
            if transaction is None:
                return []
            session = replays._held(self, transaction)
            if session is None:
                return []
            replays._drop(transaction, replayed)
            session.transaction = None
            return [r.reservation for r in transaction.recipients if r.reservation is not None]

    def close(self) -> Verdict | None:
        """The connection closed: the MAIL decision to record if it was a restarting MAIL stage
        that no later connection took over from (see ``StageReplays._restart``)."""
        replays = self._replays
        with replays._lock:
            return replays._restart(replays._held(self), self)


def _header_block_end(data: bytes, names: list[str]) -> int | None:
    """Where the header block at the start of ``data`` ends, if it holds exactly ``names``.

    Lines may end in CRLF or a bare LF. A header block with no blank line after it (a message
    with no body) ends at the end of ``data``. Returns None unless the block's field names are
    exactly the MTA's header callbacks, in order.
    """
    seen: list[str] = []
    position = 0
    while position < len(data):
        newline = data.find(b"\n", position)
        end = len(data) if newline == -1 else newline + 1
        line = data[position:end].rstrip(b"\r\n")
        if not line:
            break
        if line[:1] in (b" ", b"\t"):
            if not seen:
                return None  # a continuation before any field
        else:
            seen.append(line.split(b":", 1)[0].decode("ascii", "replace").strip().casefold())
        position = end
    else:
        end = len(data)
    if seen != [name.strip().casefold() for name in names]:
        return None
    return end


def message_body(chunks: list[bytes], header_names: list[str], body_has_headers: bool) -> bytes:
    """The message body from the milter's BODY chunks.

    Stalwart's milter client sends the whole message, header block included, as the body (by
    design: stalwartlabs/stalwart discussion #2369), after sending the same headers one by one.
    The repeated block is dropped only when it holds exactly the headers the MTA sent, in order.
    Raises ValueError when it cannot be found: judging a body cut in the wrong place could hide
    content from the judge, so the caller fails closed.
    """
    body = b"".join(chunks)
    if not body_has_headers:
        return body
    end = _header_block_end(body, header_names)
    if end is None:
        raise ValueError("the body does not start with the header block the MTA sent")
    return body[end:]


def _reply(milter: Any, verdict: Verdict) -> int:
    if verdict.code:
        smtp_code, enhanced = verdict.code.split(" ", 1)
        milter.setreply(smtp_code, enhanced, verdict.text)
    return Milter.TEMPFAIL if verdict.action == "tempfail" else Milter.REJECT


def judge_input(raw: bytes, subject: str) -> JudgeInput:
    """Build the judge's view of a message: its parts as data, never gateway-added headers."""
    inbound = parse(raw)
    return JudgeInput(
        text_part=inbound.text,
        machine_part=None if inbound.payload is None else machine_part_text(inbound.payload),
        header_intent=inbound.intent if inbound.protocol is not None else None,
        subject=subject,
        in_thread=inbound.thread.in_reply_to is not None,
    )


def run_judge(
    judge: Judge, raw: bytes, subject: str, checks: frozenset[str]
) -> tuple[Judgment | None, str | None]:
    """Ask the judge; any failure becomes an error the lane's ladder decides about (fail closed)."""
    try:
        return judge.judge(judge_input(raw, subject), checks), None
    except JudgeUnavailable as error:
        return None, str(error)
    except Exception as error:  # A broken judge must not accept mail unjudged.
        LOG.exception("content judge failed")
        return None, f"judge error: {error}"


def judging_on(config: GatewayConfig) -> bool:
    """Whether any agent or lane can have its mail judged under ``config``."""
    return (
        config.content_judge.mode != "off"
        or any(agent.content_judge_mode not in {None, "off"} for agent in config.agents.values())
        or any(mode != "off" for mode in config.content_judge.lane_modes.values())
    )


def judge_cache() -> Callable[[GatewayConfig], Judge | None]:
    """The judge for a configuration: built once per backend, and only once judging is on.

    A backend that cannot be built is logged and answers None, which the verdict ladder treats
    as a judge error (fail closed), rather than failing the milter callback.
    """
    built: dict[JudgeBackendConfig, Judge] = {}
    lock = threading.Lock()

    def judge_for(config: GatewayConfig) -> Judge | None:
        if not judging_on(config):
            return None
        backend = config.content_judge.backend
        with lock:
            judge = built.get(backend)
            if judge is None:
                try:
                    judge = built[backend] = make_judge(backend)
                except Exception:
                    LOG.exception("cannot build the %s content judge", backend.backend)
                    return None
            return judge

    return judge_for


def build_milter(
    config: ConfigSource,
    store: Store,
    registry: HandlerRegistry,
    judge: Judge | None = None,
    replays: StageReplays | None = None,
    *,
    judge_for: Callable[[GatewayConfig], Judge | None] | None = None,
    listener_sibling: Callable[[str], bool] | None = None,
) -> type[Milter.Base]:
    """Build a per-connection PyMilter class bound to gateway dependencies.

    ``config`` may be a function that returns the current configuration; ``judge_for`` then
    picks the judge for it (see :func:`judge_cache`). Without one, ``judge`` is used as given.
    """
    replays = StageReplays(registry.release) if replays is None else replays
    current: Callable[[], GatewayConfig] = (
        config if callable(config) else (lambda fixed=config: fixed)  # type: ignore[misc]
    )
    pick_judge: Callable[[GatewayConfig], Judge | None] = judge_for or (lambda _config: judge)

    class AmxMilter(Milter.Base):
        def __init__(self) -> None:
            self.client_ip: str | None = None
            self.mail_from: str | None = None
            self.sender_domain: str | None = None
            self.recipient: str | None = None
            self.recipient_agent: str | None = None
            self.task_token: str | None = None
            self.recipients: list[tuple[str, str | None, str | None]] = []
            self.headers: list[tuple[bytes, bytes]] = []
            self.reserved_headers: list[str] = []
            self.body_chunks: list[bytes] = []
            self.header_names: list[str] = []
            self.body_has_headers = False
            self.sibling = False
            self.submission = False
            self.auth_authen: str | None = None
            self.reservations: list[int] = []
            # Set when the MTA replays the session on a new connection at every stage (Stalwart).
            self.replay: StageReplay | None = None

        def _release_reservations(self) -> None:
            for reservation in self.reservations:
                registry.release(reservation)
            self.reservations = []

        def _record(
            self,
            stage: Stage,
            verdict: Verdict,
            task: str | object | None = _CURRENT_TASK,
            detail: str | None = None,
            agent: str | None = None,
        ) -> None:
            recorded_task = self.task_token if task is _CURRENT_TASK else task
            assert recorded_task is None or isinstance(recorded_task, str)
            store.record_policy(
                stage.value,
                verdict.rule,
                verdict.action,
                verdict.code,
                recorded_task,
                verdict.text if detail is None else f"{verdict.text} [{detail}]".lstrip(),
                agent=agent,
            )

        def _accept_recipient(self, recipient: str, agent: str | None, token: str | None) -> int:
            self.recipient = recipient
            self.recipient_agent = agent
            self.task_token = token
            self.recipients.append((recipient, agent, token))
            return Milter.CONTINUE

        def _settle(self, message_id: str | None, *, accepted: bool) -> None:
            """End of DATA: bind this message's admissions for LMTP to settle, or release them."""
            reservations = self.reservations
            if self.replay is not None:
                reservations += self.replay.finish(len(self.recipients))
            self.reservations = []
            for reservation in reservations:
                if accepted:
                    registry.bind(reservation, message_id)
                else:
                    registry.release(reservation)

        def connect(self, _hostname: str, _family: int, hostaddr: Any) -> int:
            self.client_ip = str(hostaddr[0]) if isinstance(hostaddr, tuple) else str(hostaddr)
            daemon = _daemon_name(self)
            self.submission = daemon in {"amx-submission", "Stalwart amx-submission"}
            if listener_sibling is None:
                self.sibling = daemon == "amx-sibling"  # Postfix's MTA-owned listener macro
            else:
                try:
                    self.sibling = listener_sibling(_hostname)
                except KeyError:
                    return Milter.TEMPFAIL  # not an admitted frontend connection

            # Stalwart sends the header block again as body, and opens a new connection at every
            # stage that replays the session so far (PLAN §5.8).
            self.body_has_headers = daemon.startswith("Stalwart")
            key = (
                session_key(self, daemon, hostaddr, sibling=self.sibling)
                if self.body_has_headers
                else None
            )
            self.replay = None if key is None else replays.connect(key)
            if self.replay is not None and self.replay.replayed:
                if self.replay.restart is not None:  # the connection before was a MAIL stage
                    self._record(Stage.MAIL, self.replay.restart)
                return Milter.CONTINUE  # the session's first connection decided and recorded it
            verdict = evaluate(
                Stage.CONNECT,
                TxnContext(client_ip=self.client_ip),
                _policy_state(current(), store, registry),
            )
            self._record(Stage.CONNECT, verdict)
            if not verdict.accepted:
                self.replay = None
                return _reply(self, verdict)
            if self.replay is not None:
                self.replay.open()
            return Milter.CONTINUE

        def envfrom(self, sender: str, *_args: str) -> int:
            self._release_reservations()
            self.mail_from = _address(sender)
            # Re-read on every MAIL replay, including Stalwart's DATA connection.
            self.auth_authen = _macro(self, "{auth_authen}") or None
            self.sender_domain = self.mail_from.rpartition("@")[2].casefold() or None
            self.recipient = None
            self.recipient_agent = None
            self.task_token = None
            self.recipients = []
            self.headers = []
            self.header_names = []
            self.reserved_headers = []
            self.body_chunks = []
            if self.replay is not None and self.replay.mail(self.mail_from):
                # Decided and recorded at the MAIL stage. If this connection turns out to be a
                # new transaction's MAIL stage, the next one (or its close()) records it.
                return Milter.CONTINUE
            verdict = evaluate(
                Stage.MAIL,
                TxnContext(mail_from=self.mail_from, sender_domain=self.sender_domain),
                _policy_state(current(), store, registry),
            )
            self._record(Stage.MAIL, verdict)
            if not verdict.accepted:
                return _reply(self, verdict)
            if self.replay is not None:
                self.replay.start(self.mail_from, verdict)
            return Milter.CONTINUE

        def envrcpt(self, recipient: str, *_args: str) -> int:
            config = current()  # one configuration for the whole decision
            normalized_recipient = _address(recipient).casefold()
            local_part, separator, domain = normalized_recipient.rpartition("@")
            agent_name: str | None = None
            token: str | None = None
            # The spellings the MTA delivers to the same mailbox: a quoted local part, and a
            # domain ending in a dot, name the agent too (and the control address, §5.10).
            # postmaster and abuse (role_addresses) are nobody's agent: the MTA delivers them.
            if (
                separator
                and domain.rstrip(".") == config.agent_domain
                and local_part.strip('"').partition("+")[0] not in config.role_addresses
            ):
                agent_name, plus, token_value = local_part.strip('"').partition("+")
                token = token_value if plus and token_value else None
            if any(
                existing == normalized_recipient for existing, _agent, _token in self.recipients
            ):
                # A repeated RCPT in one transaction is one delivery (cleanup dedupes it): no
                # second admission.
                return Milter.CONTINUE
            index = len(self.recipients)
            if self.replay is not None and self.replay.recipient(index, normalized_recipient):
                # Replayed at a later stage: decided, recorded, and admitted at its RCPT stage.
                return self._accept_recipient(normalized_recipient, agent_name, token)
            # The agents' own declarations (PLAN §5.10), read once for this RCPT; a lapsed one
            # is already gone, so the configured watermark and the backlog govern again.
            controls = store.controls(time.time(), config.control.max_ttl_seconds)
            state = _policy_state(config, store, registry, controls)
            context = TxnContext(
                mail_from=self.mail_from,
                sender_domain=self.sender_domain,
                recipient=normalized_recipient,
                recipient_agent=agent_name,
                task_token=token,
                # Read only for a closed task: whether this could be a retry of accepted mail.
                recipient_accepted_mail=token is not None
                and (agent_name, token) in state.closed_tasks
                and store.accepted_delivery(normalized_recipient),
            )
            # Parallel SMTP sessions must not all read the same depth: reading depth, deciding,
            # and counting the admission happen under one lock. The admission keeps counting
            # until LMTP turns it into a queued or running slot (see HandlerRegistry.submit).
            reservation: int | None = None
            backlog_read = False
            with registry.admission:
                state = replace(state, agents=_agent_states(config, registry, controls))
                verdict = evaluate(Stage.RCPT, context, state)
                if verdict.accepted and agent_name and registry.mode(agent_name) == "remote":
                    # Read the remote agent's mailbox (PLAN §5.9) only when nothing else refused
                    # the RCPT; its backlog only adds depth, so it can only turn accept into 450.
                    # A paused agent was refused above, without this round trip (§5.10).
                    state = replace(
                        state,
                        agents=_agent_states(config, registry, controls, backlog_for=agent_name),
                    )
                    backlog_read = True
                    verdict = evaluate(Stage.RCPT, context, state)
                if verdict.accepted and agent_name is not None:
                    reservation = registry.reserve(agent_name)
                    self.reservations.append(reservation)
            detail = rcpt_detail(
                state.agents.get(agent_name) if agent_name else None,
                rule=verdict.rule,
                backlog_read=backlog_read,
            )
            self._record(Stage.RCPT, verdict, token, detail, agent_name)
            if not verdict.accepted:
                return _reply(self, verdict)
            admitted = ReplayedRecipient(normalized_recipient, agent_name, token, reservation)
            # This connection holds the admission until end of DATA or abort, unless the MTA
            # replays stages: then the transaction carries it to the DATA stage's connection.
            carried = self.replay is not None and self.replay.admit(index, admitted)
            if carried and reservation is not None:
                self.reservations.remove(reservation)
            return self._accept_recipient(normalized_recipient, agent_name, token)

        @Milter.decode("bytes")
        def header(self, name: str, value: bytes) -> int:
            self.header_names.append(name)
            if is_reserved_transport_header(name):
                self.reserved_headers.append(name)
                return Milter.CONTINUE
            self.headers.append((name.encode(), value))
            return Milter.CONTINUE

        def body(self, chunk: bytes) -> int:
            self.body_chunks.append(chunk)
            return Milter.CONTINUE

        def _abandon_data_stage(self) -> None:
            if self.replay is not None and (self.header_names or self.body_chunks):
                # A DATA stage that ended before end of DATA (libmilter calls abort() when the
                # MTA drops the connection mid-message): the MTA ends the transaction, so its
                # admissions go, as this connection's own do.
                self.reservations += self.replay.finish(len(self.recipients))

        def abort(self) -> int:
            self._abandon_data_stage()
            self._release_reservations()
            self.recipients = []
            self.headers = []
            self.header_names = []
            self.reserved_headers = []
            self.body_chunks = []
            return Milter.CONTINUE

        def eom(self) -> int:
            config = current()  # one configuration for the whole decision
            try:
                body = message_body(self.body_chunks, self.header_names, self.body_has_headers)
            except ValueError as error:
                # 451, not 5xx: a mismatch means the gateway and the MTA disagree about where the
                # headers end, which is a fault on this side, not in the sender's message. The
                # message waits in the sender's queue while someone reads this row, instead of
                # bouncing a message that may be fine.
                verdict = Verdict("tempfail", "message-unreadable", "451 4.3.0", str(error))
                self._record(Stage.EOD, verdict)
                self._settle(None, accepted=False)
                return _reply(self, verdict)
            raw = b"\r\n".join(name + b": " + value for name, value in self.headers)
            raw += b"\r\n\r\n" + body
            message = BytesParser(policy=email_policy.default).parsebytes(raw)
            from_value = str(message.get("From", ""))
            from_domain = from_value.rpartition("@")[2].rstrip("> ").casefold() or None
            attachment_types = frozenset(part.type for part in security_parts(message))
            # SH-40: people's mail is verified too, for its sender alone (accept_from); only
            # the agent lane takes an identity from it, so people's trust is unchanged.
            checked = verify_dkim(
                raw,
                config.dns_server,
                agent_domain=config.agent_domain,
                registry_dir=config.registry_dir,
                keys_dir=config.keys_dir,
                configured_selectors=frozenset(
                    config.selector_for(name)
                    for name, agent in config.agents.items()
                    if agent.enabled and not agent.registered
                ),
            )
            identity = checked if message.get("Agent-Protocol") else None
            state = _policy_state(config, store, registry)
            message_id = str(message.get("Message-ID", "")).strip() or None
            agent_recipients = [
                (recipient, agent, token)
                for recipient, agent, token in self.recipients
                if agent is not None
            ]
            verdict = evaluate(
                Stage.EOD,
                TxnContext(
                    client_ip=self.client_ip,
                    mail_from=self.mail_from,
                    sender_domain=self.sender_domain,
                    recipient=self.recipient,
                    recipient_agent=self.recipient_agent,
                    task_token=self.task_token,
                    # Only agent recipients carry a task sub-address; a person CC'd in this
                    # domain (victor@northwind.test on an agent thread) has none to compare.
                    recipient_task_tokens=tuple(
                        token for _recipient, _agent, token in agent_recipients
                    ),
                    recipient_agents=tuple(agent for _recipient, agent, _token in agent_recipients),
                    sibling=self.sibling,
                    submission=self.submission,
                    auth_authen=self.auth_authen,
                    # Read only for a closed task: whether LMTP already accepted this message.
                    message_accepted=tuple(
                        message_id is not None
                        and (agent, token or str(message.get("Agent-Task", "")))
                        in state.closed_tasks
                        and store.accepted_delivery(recipient, message_id)
                        for recipient, agent, token in agent_recipients
                    ),
                    raw=raw,
                    dkim_verified=identity.verified if identity else False,
                    dkim_domain=identity.domain if identity else None,
                    # SH-44: the verified agent (the signed From's local part), not the
                    # key's selector, is the identity grants and the agent lane name.
                    dkim_selector=identity.identity if identity else None,
                    identity_error=identity.reason if identity and not identity.verified else None,
                    sender_verified=checked.sender,
                    own_agent_verified=(
                        checked.agent
                        if checked.verified
                        and (checked.domain or "").casefold() == config.agent_domain.casefold()
                        else None
                    ),
                    from_domain=from_domain,
                    size=len(raw),
                    attachment_types=attachment_types,
                ),
                state,
            )
            detail = None
            lane = "agent" if message.get("Agent-Protocol") else "human"
            agent_modes = [
                config.agents[agent].content_judge_mode
                for _recipient, agent, _token in self.recipients
                if agent is not None and agent in config.agents
            ]
            mode = config.content_judge.mode_for(lane, agent_modes)
            judge = pick_judge(config) if verdict.accepted and mode != "off" else None
            if verdict.accepted and mode != "off":
                if judge is None:  # judging is on but no backend was built: fail closed
                    judgment, error = None, "no content judge configured"
                else:
                    judgment, error = run_judge(
                        judge, raw, str(message.get("Subject", "")), config.content_judge.checks
                    )
                verdict = apply_judgment(
                    verdict,
                    judgment,
                    error,
                    mode=mode,
                    lane=lane,
                    grant=state.grant_for(
                        identity.domain if identity else None,
                        identity.identity if identity else None,
                        lane,
                    ),
                    config=config.content_judge,
                )
                detail = judgment_header(mode, judgment, error)
            if verdict.accepted and ("Agent-Grant-Role", "owner") in verdict.headers:
                detail = "; ".join(
                    filter(None, [detail, "grant=owner trust=high can_open_tasks=true"])
                )
            self._record(Stage.EOD, verdict, detail=detail)
            if not verdict.accepted:
                self._settle(None, accepted=False)
                return _reply(self, verdict)
            self._settle(message_id, accepted=True)
            for name in self.reserved_headers:
                self.chgheader(name, 1, None)
            for name, value in verdict.headers:
                self.addheader(name, value)
            if verdict.quarantine:
                self.quarantine(f"amx content judgment: {verdict.quarantine}")
            return Milter.ACCEPT

        def close(self) -> int:
            if self.replay is not None:
                mail_stage = self.replay.close()
                if mail_stage is not None:
                    self._record(Stage.MAIL, mail_stage)
            self._abandon_data_stage()  # also after an exception in eom(), which aborts nothing
            self._release_reservations()
            return Milter.CONTINUE

    return AmxMilter


def run_milter(config: ConfigSource, store: Store, registry: HandlerRegistry) -> None:
    """Run the blocking PyMilter server until terminated."""
    current: Callable[[], GatewayConfig] = (
        config if callable(config) else (lambda fixed=config: fixed)  # type: ignore[misc]
    )
    judge_for = judge_cache()
    judge_for(current())  # build it now if judging is on, as before reloads existed
    Milter.set_flags(Milter.ADDHDRS | Milter.CHGHDRS | Milter.QUARANTINE)
    started = current()
    socket_name = f"inet:{started.milter_port}@{started.milter_host}"
    from amx.adapters.people_milter import people_listener

    listener = (
        people_listener(
            started.milter_host,
            started.people_milter_port,
            (
                started.milter_host if started.milter_host != "0.0.0.0" else "127.0.0.1",
                started.milter_port,
            ),
        )
        if started.people_milter_port
        else contextlib.nullcontext()
    )
    with listener:
        if started.sibling_milter_port:
            from amx.adapters.milter_listener import MilterListeners

            # People forward through the normal frontend, not around its
            # one-use provenance check. Keep the sibling/normal replay partition.
            with tempfile.TemporaryDirectory(prefix="amx-milter-") as directory:
                backend = str(Path(directory) / "native.sock")
                with MilterListeners(
                    started.milter_host, started.milter_port, started.sibling_milter_port, backend
                ) as listeners:
                    Milter.factory = build_milter(
                        current,
                        store,
                        registry,
                        judge_for=judge_for,
                        listener_sibling=listeners.resolve,
                    )
                    Milter.runmilter("amx", f"local:{backend}", 120)
            return
        Milter.factory = build_milter(current, store, registry, judge_for=judge_for)
        Milter.runmilter("amx", socket_name, 120)
