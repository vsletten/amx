"""Timeline lines for ``amx trace`` and the narrated scenario runner (PLAN §5.6).

``amx scenario run S04 --narrate`` runs a scenario's pytest file and, while it runs, prints what
the dev stack does: each gateway's policy decisions and journal entries, the LLM agents'
decisions, and the MTAs' delivery lines (Postfix, or Stalwart for contoso in M6), merged in time
order.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from amx.store import Store

_SCENARIO_ID = re.compile(r"^s?(\d{1,2})[a-z]?$", re.IGNORECASE)
_COMPOSE_LINE = re.compile(
    r"^(?P<service>[\w-]+?)(?:-\d+)?\s*\|\s*(?P<at>\d{4}-\d{2}-\d{2}T[\d:.]+Z)\s+(?P<rest>.*)$"
)
_POSTFIX = re.compile(r"postfix/(?P<process>[\w/-]+)\[\d+\]:\s+(?:[0-9A-F]+:\s+)?(?P<detail>.*)")
_DELIVERY = re.compile(r"to=<(?P<to>[^>]*)>.*?status=(?P<status>\w+) \((?P<said>.*)\)$")
_REFUSAL = re.compile(r"(?:milter-reject|NOQUEUE: milter-reject): (?P<detail>.*?);")
# Stalwart (M6) logs one event per line: "<time>Z LEVEL Text (event.id) key = value, ...".
_STALWART = re.compile(
    r"^\d{4}-\d{2}-\d{2}T[\d:]+Z\s+[A-Z]+\s+.*?\((?P<event>[a-z0-9-]+\.[a-z0-9.-]+)\)(?P<fields>.*)$"
)
_STALWART_FIELD = re.compile(
    r'\b(?P<key>to|hostname|code|details|reason) = (?P<value>"[^"]*"|\[[^]]*\]|\d+)'
)
# The events that say where a message went: accepted and queued, handed on (dsn-success is the
# next hop's 250), deferred, bounced. Milter errors (not its per-stage action-* events, which
# repeat the gateway's own decisions) carry no recipient but explain a 451.
_STALWART_EVENTS = frozenset(
    {
        "smtp.rcpt-to",
        "queue.message-queued",
        "delivery.dsn-success",
        "delivery.dsn-temp-fail",
        "delivery.dsn-perm-fail",
        "delivery.failed",
        "queue.dsn-queued",
    }
)
# Accepted connection-level events are mostly the mailhost healthchecks (every 2 s): not narrated.
_QUIET_STAGES = frozenset({"connect", "helo", "mail"})


def journal_source(row: Any) -> str:
    if row["direction"] == "inbound":
        return "lmtp"
    if row["event"] in {"released", "hold-rejected"}:
        return "holdwatch"
    return "submission"  # outbound mail, and agents' declarations (direction "control")


# Policy rows written outside the milter: holdwatch's, and submission's refused declarations.
_POLICY_SOURCES = {"hold": "holdwatch", "control": "submission"}


def policy_line(row: Any, domain: str) -> str:
    source = _POLICY_SOURCES.get(str(row["stage"]), "milter")
    return (
        f"{row['created_at']} {domain} {source} {str(row['stage']).upper()} "
        f"{row['rule']} -> {row['action']} {row['code'] or ''} {row['detail']}"
    ).rstrip()


def journal_line(row: Any, domain: str) -> str:
    return (
        f"{row['created_at']} {domain} {journal_source(row)} {row['event']} "
        f"journal #{row['sequence']} sha256 {str(row['raw_sha256'])[:12]} {row['detail']}"
    )


def llm_line(row: dict[str, Any], domain: str) -> str:
    at = datetime.fromtimestamp(float(row["at"]), UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
    slots = ",".join(row.get("slots") or [])
    parts = [
        f"{at}Z {domain} llm {row['agent']} ({row.get('lane')}) -> {row.get('tool')}",
        str(row.get("decision") or ""),
        slots,
        f"held={row['held']}" if row.get("held") else "",
        f"{row['latency_ms']} ms" if row.get("latency_ms") is not None else "",
        str(row.get("reason") or ""),
    ]
    return " ".join(part for part in parts if part)


def postfix_line(line: str) -> tuple[str, str] | None:
    """Condense one ``docker compose logs --timestamps`` Postfix line, or None if it is noise."""
    matched = _COMPOSE_LINE.match(line.strip())
    if matched is None:
        return None
    postfix = _POSTFIX.search(matched["rest"])
    if postfix is None:
        return None
    detail = postfix["detail"]
    delivery = _DELIVERY.search(detail)
    refusal = _REFUSAL.search(detail)
    if delivery is not None:
        summary = f"to=<{delivery['to']}> {delivery['status']} ({delivery['said']})"
    elif refusal is not None:
        summary = f"refused: {refusal['detail']}"
    else:
        return None
    service = matched["service"].removesuffix("-1")
    return matched["at"], f"{matched['at']} {service} postfix/{postfix['process']} {summary}"


def stalwart_line(line: str) -> tuple[str, str] | None:
    """Condense one ``docker compose logs --timestamps`` Stalwart line, or None if it is noise."""
    matched = _COMPOSE_LINE.match(line.strip())
    if matched is None:
        return None
    event = _STALWART.match(matched["rest"])
    name = event["event"] if event is not None else ""
    milter_error = name.startswith("milter.") and not name.startswith("milter.action-")
    if event is None or (name not in _STALWART_EVENTS and not milter_error):
        return None
    fields: dict[str, str] = {}
    for field in _STALWART_FIELD.finditer(event["fields"]):
        # A queue event names the whole envelope first and the recipient it is about last.
        fields[field["key"]] = field["value"].strip('"')
    summary = " ".join(f"{key}={value}" for key, value in fields.items())
    service = matched["service"].removesuffix("-1")
    rendered = f"{matched['at']} {service} stalwart {name} {summary}".rstrip()
    return matched["at"], rendered


def mta_line(line: str) -> tuple[str, str] | None:
    """Condense one MTA log line from either mailhost kind (Postfix or Stalwart)."""
    return postfix_line(line) or stalwart_line(line)


def scenario_files(root: Path, ids: Sequence[str], every: bool) -> list[Path]:
    """Map ``S04``, ``s4``, ``4``, or ``S11a`` to scenarios/test_sNN_*.py (``--all``: all)."""
    directory = root / "scenarios"
    if every:
        return sorted(directory.glob("test_s[0-9][0-9]_*.py"))
    files: list[Path] = []
    for scenario in ids:
        matched = _SCENARIO_ID.match(scenario.strip())
        if matched is None:
            raise ValueError(f"not a scenario id: {scenario!r} (try S04 or 4)")
        found = sorted(directory.glob(f"test_s{int(matched[1]):02d}_*.py"))
        if not found:
            raise ValueError(f"no scenario file for {scenario} in {directory}")
        files.extend(path for path in found if path not in files)
    return files


def _quiet(row: Any) -> bool:
    return str(row["stage"]).casefold() in _QUIET_STAGES and row["action"] == "accept"


@dataclass(frozen=True, slots=True)
class Gateway:
    """One gateway's host-side state in the dev stack."""

    label: str  # the agent domain, as trace prints it
    state_dir: Path


class Narrator:
    """Collect new timeline events from the gateways' stores and handler logs since a start."""

    def __init__(self, gateways: Iterable[Gateway], *, since: float | None = None) -> None:
        self.gateways = tuple(gateways)
        self.since = time.time() if since is None else since
        self._seen: dict[tuple[str, str], int] = {}
        self._log_offsets: dict[str, int] = {}
        for gateway in self.gateways:
            store = self._store(gateway)
            for table in ("policy_events", "journal"):
                self._seen[(gateway.label, table)] = self._last(store, table)
            log = gateway.state_dir / "handler.jsonl"
            self._log_offsets[gateway.label] = log.stat().st_size if log.exists() else 0

    @staticmethod
    def _store(gateway: Gateway) -> Store | None:
        path = gateway.state_dir / "journal.sqlite"
        return Store(path) if path.exists() else None

    @staticmethod
    def _last(store: Store | None, table: str) -> int:
        if store is None:
            return 0
        rows = store.rows(f"SELECT COALESCE(MAX(sequence), 0) AS last FROM {table}")
        return int(rows[0]["last"])

    def poll(self) -> list[tuple[str, str]]:
        events: list[tuple[str, str]] = []
        for gateway in self.gateways:
            store = self._store(gateway)
            if store is not None:
                for table, render in (("policy_events", policy_line), ("journal", journal_line)):
                    key = (gateway.label, table)
                    rows = store.rows(
                        f"SELECT * FROM {table} WHERE sequence > ? ORDER BY sequence",
                        (self._seen[key],),
                    )
                    for row in rows:
                        self._seen[key] = int(row["sequence"])
                        if table == "policy_events" and _quiet(row):
                            continue
                        events.append((str(row["created_at"]), render(row, gateway.label)))
            events.extend(self._llm_events(gateway))
        return sorted(events)

    def _llm_events(self, gateway: Gateway) -> list[tuple[str, str]]:
        log = gateway.state_dir / "handler.jsonl"
        if not log.exists():
            return []
        with log.open("rb") as stream:
            stream.seek(self._log_offsets[gateway.label])
            chunk = stream.read()
        complete = chunk[: chunk.rfind(b"\n") + 1]  # leave a half-written line for next time
        self._log_offsets[gateway.label] += len(complete)
        events = []
        for line in complete.decode("utf-8", "replace").splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("kind") == "llm" and float(row.get("at", 0)) >= self.since:
                rendered = llm_line(row, gateway.label)
                events.append((rendered.split(" ", 1)[0], rendered))
        return events


def follow_postfix(compose: Sequence[str], since: float, emit: Callable[[str], None]) -> Any:
    """Stream condensed MTA lines from ``docker compose logs -f`` until the process stops."""
    start = datetime.fromtimestamp(since, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    process = subprocess.Popen(
        [
            *compose,
            *("logs", "-f", "--no-color", "--timestamps", "--since", start),
            *("mailhost-nw", "mailhost-ct", "mailhost-pm"),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )

    def pump() -> None:
        assert process.stdout is not None
        for line in process.stdout:
            condensed = mta_line(line)
            if condensed is not None:
                emit(condensed[1])

    threading.Thread(target=pump, daemon=True).start()
    return process


def run_scenarios(
    root: Path,
    files: Sequence[Path],
    *,
    narrate: bool,
    gateways: Sequence[Gateway],
    compose: Sequence[str],
    pytest_args: Sequence[str] = (),
) -> int:
    """Run the scenario files with pytest; with ``narrate``, print the stack's timeline too."""
    command = [sys.executable, "-m", "pytest", *map(str, files)]
    command += ["-m", "integration", "-q", "-s", "-p", "no:cacheprovider", *pytest_args]
    if not narrate:
        return subprocess.run(command, cwd=root, check=False).returncode
    lock = threading.Lock()

    def emit(line: str) -> None:
        with lock:
            print(f"  | {line}", flush=True)

    narrator = Narrator(gateways)
    postfix = follow_postfix(compose, narrator.since, emit)
    tests = subprocess.Popen(command, cwd=root)
    try:
        while tests.poll() is None:
            for _at, line in narrator.poll():
                emit(line)
            time.sleep(0.3)
        time.sleep(1.0)
        for _at, line in narrator.poll():
            emit(line)
    finally:
        postfix.terminate()
    return int(tests.returncode)
