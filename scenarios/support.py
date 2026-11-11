from __future__ import annotations

import functools
import os
import re
import shutil
import subprocess
import tempfile
import time
from email import policy
from email.message import EmailMessage
from pathlib import Path
from typing import Any

from amx.narrate import mta_line
from amx.profile import SCHEMA_BASE, build
from amx.testkit import read_jsonl, signed_message

os.environ.setdefault("AMX_UID", str(os.getuid()))
os.environ.setdefault("AMX_GID", str(os.getgid()))

ROOT = Path(__file__).resolve().parents[1]
GENERATED = ROOT / "deploy" / "generated"
CT_DB = GENERATED / "state" / "ct" / "journal.sqlite"
NW_DB = GENERATED / "state" / "nw" / "journal.sqlite"
HANDLER_LOG = GENERATED / "state" / "ct" / "handler.jsonl"
NW_HANDLER_LOG = GENERATED / "state" / "nw" / "handler.jsonl"
SCHEDULER_KEY = GENERATED / "keys" / "scheduler.private.pem"
INTAKE_KEY = GENERATED / "keys" / "intake.private.pem"
RESTRICTED_KEY = GENERATED / "keys" / "restricted.private.pem"
CT_JUDGE_DOWN = GENERATED / "state" / "ct" / "judge-down"
DEV_TLS_CA = GENERATED / "tls" / "dev-ca.pem"
COMPOSE = ["docker", "compose", "-p", "amx", "-f", str(ROOT / "deploy" / "compose.yaml")]
if suite_override := os.environ.get("AMX_SUITE_OVERRIDE"):
    # conftest recreates runner-ct: keep the suite's variant and ownership labels,
    # or Compose would replace it with an unowned/base-only container mid-suite.
    if os.environ["AMX_SUITE_MTA"] == "stalwart":
        COMPOSE.extend(["-f", str(ROOT / "deploy" / "compose.stalwart.yaml")])
    COMPOSE.extend(["-f", suite_override])


def signed_request(
    task: str,
    message_id: str,
    *,
    payload: dict[str, Any] | None = None,
    recipient: str | None = None,
    subject: str | None = None,
) -> bytes:
    message = build(
        sender=f"scheduler+{task}@agents.northwind.test",
        to=recipient or f"intake+{task}@agents.contoso.test",
        subject=subject or f"AMX scenario {task}",
        intent="request",
        task=task,
        task_state="submitted",
        text=f"Please process scenario {task}.",
        payload=payload or {"action": "intake", "arguments": {"task": task}},
        schema=f"{SCHEMA_BASE}request.json",
        message_id=message_id,
    )
    return signed_message(
        message,
        selector="scheduler",
        domain="agents.northwind.test",
        private_key=SCHEDULER_KEY,
    )


def signed_agent_message(
    *,
    selector: str,
    task: str,
    recipient: str,
    subject: str,
    text: str,
    intent: str = "request",
    payload: dict[str, Any] | None = None,
    in_reply_to: str | None = None,
    message_id: str | None = None,
) -> bytes:
    """Build and DKIM-sign an agent-lane message from a northwind agent (M4b scenarios)."""
    domain = "agents.northwind.test"
    message = build(
        sender=f"{selector}+{task}@{domain}",
        to=recipient,
        subject=subject,
        intent=intent,  # type: ignore[arg-type]
        task=task,
        task_state="working" if intent == "response" else "submitted",
        text=text,
        payload=payload,
        schema=f"{SCHEMA_BASE}request.json" if payload is not None else None,
        in_reply_to=in_reply_to,
        references=(in_reply_to,) if in_reply_to else (),
        message_id=message_id,
    )
    key = SCHEDULER_KEY if selector == "scheduler" else RESTRICTED_KEY
    return signed_message(message, selector=selector, domain=domain, private_key=key)


def signed_invalid_schema(task: str, message_id: str) -> bytes:
    raw = (ROOT / "spec" / "corpus" / "15-invalid-schema.eml").read_bytes()
    raw = raw.replace(
        b"<temporary-invalid-source@agents.northwind.test>", message_id.encode()
    ).replace(b"t_temporary_invalid_source", task.encode())
    from amx.identity import sign

    return sign(
        raw,
        selector="scheduler",
        domain="agents.northwind.test",
        private_key=SCHEDULER_KEY,
    )


def ordinary_message(
    message_id: str, task: str, *, transport_headers: dict[str, str] | None = None
) -> bytes:
    message = EmailMessage(policy=policy.SMTP)
    message["From"] = "pat@plainmail.test"
    message["To"] = f"intake+{task}@agents.contoso.test"
    message["Subject"] = f"Human scenario {task}"
    message["Message-ID"] = message_id
    for name, value in (transport_headers or {}).items():
        message[name] = value
    message.set_content("Could you help with this ordinary human request?")
    return message.as_bytes()


def refresh_runner_file(
    path: Path, container: str = "amx-runner-ct-1", directory: str = "/state"
) -> bool:
    """Snapshot test evidence from the runner's Linux volume, including a stopped container."""
    path.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        ["docker", "cp", f"{container}:{directory}/{path.name}", str(path)],
        capture_output=True,
        timeout=10,
    )
    return result.returncode == 0


def read_runner_log(path: Path) -> list[dict[str, Any]]:
    if not refresh_runner_file(path):
        return []
    return read_jsonl(path)


def wait_for_handler(
    message_id: str, timeout: float = 30.0, *, path: Path = HANDLER_LOG
) -> list[dict[str, Any]]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rows: list[dict[str, Any]] = []
        if path.parent.name == "runner-ct":
            refresh_runner_file(path)
        if path.exists():
            rows = read_jsonl(path)
            matches = [row for row in rows if row["message_id"] == message_id]
            if matches:
                return matches
        time.sleep(0.25)
    raise TimeoutError(f"handler was not invoked for {message_id}")


def wait_for_task(
    task: str,
    *,
    path: Path,
    intent: str | None = None,
    timeout: float = 60.0,
) -> list[dict[str, Any]]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.parent.name == "runner-ct":
            refresh_runner_file(path)
        if path.exists():
            rows = read_jsonl(path)
            matches = [
                row
                for row in rows
                if row.get("task") == task and (intent is None or row.get("intent") == intent)
            ]
            if matches:
                return matches
        time.sleep(0.25)
    raise TimeoutError(f"handler was not invoked for task {task}")


def _compose_env() -> dict[str, str]:
    """Read fixture environment changes without enabling inherited Compose profiles."""
    return {key: value for key, value in os.environ.items() if key != "COMPOSE_PROFILES"}


def compose_exec(
    service: str, *command: str, check: bool = True
) -> subprocess.CompletedProcess[str]:
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
    # The argv list, shell=False, and every component are repository/test controlled.
    return subprocess.run(  # nosec B603
        [*COMPOSE, "exec", "-T", service, *command],
        check=check,
        capture_output=True,
        text=True,
        cwd=ROOT,
        shell=False,
        env=_compose_env(),
    )


def compose(*arguments: str, timeout: float | None = None) -> subprocess.CompletedProcess[str]:
    """Run one ``docker compose`` subcommand against the scenario stack."""
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
    # The argv list, shell=False, and every component are repository/test controlled.
    return subprocess.run(  # nosec B603
        [*COMPOSE, *arguments],
        timeout=timeout,
        check=True,
        capture_output=True,
        text=True,
        cwd=ROOT,
        shell=False,
        env=_compose_env(),
    )


LMTP_CLIENT = """\
import smtplib, sys
host, port, path, sender, recipient = sys.argv[1:]
with open(path, "rb") as stream:
    raw = stream.read()
with smtplib.LMTP(host, int(port), timeout=15) as lmtp:
    lmtp.ehlo()  # LHLO: mail() does not greet by itself, and an LMTP server requires it
    code, text = lmtp.mail(sender)
    if code == 250:
        code, text = lmtp.rcpt(recipient)
    if code == 250:
        code, text = lmtp.data(raw)
print(code, text.decode())
"""


def lmtp_redeliver(raw_sha256: str, sender: str, recipient: str) -> str:
    """Hand contoso's gateway a journaled message again over LMTP, as an MTA's retry would.

    The gateway's LMTP listener is not published to the host, so the client runs inside
    gateway-ct and reads the exact bytes LMTP journaled. No milter or RCPT policy runs, so the
    outcome is the LMTP dedupe's alone. Returns the recipient's reply line.
    """
    path = f"/data/raw/{raw_sha256[:2]}/{raw_sha256}.eml"
    result = compose_exec(
        "gateway-ct",
        "/app/.venv/bin/python",
        "-c",
        LMTP_CLIENT,
        "127.0.0.1",
        "2424",
        path,
        sender,
        recipient,
    )
    return result.stdout.strip()


def postfix_log(service: str) -> str:
    """Return one mailhost's Postfix log as captured by Compose."""
    return compose("logs", "--no-color", "--timestamps", service).stdout


def wait_for_lmtp_duplicate(recipient: str, timeout: float = 30.0) -> str:
    """Wait for the MX's successful duplicate receipt, not just SMTP queue acceptance.

    The unique S10 recipient correlates the receipt on either MTA. Use the existing
    trace parsers so Postfix and Stalwart field normalization has one implementation.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for raw_line in postfix_log("mailhost-ct").splitlines():
            parsed = mta_line(raw_line)
            if parsed is None:
                continue
            line = parsed[1]
            postfix = f"postfix/lmtp to=<{recipient}> sent (250 2.0.0 duplicate already "
            stalwart = "stalwart delivery.dsn-success "
            if postfix in line or (
                stalwart in line
                and f"to={recipient} " in line
                # Stalwart parses the enhanced status out of the logged reply text.
                and "code=250 details=duplicate already " in line
            ):
                return line
        time.sleep(0.25)
    raise TimeoutError(f"MX did not report an LMTP duplicate for {recipient}")


MTAS = ("postfix", "stalwart")


@functools.cache
def mta_ct() -> str:
    """contoso's MTA: ``postfix``, or ``stalwart`` under ``make up MTA_CT=stalwart`` (M6).

    Read from the mailhost container's image, stopped or running; AMX_MTA_CT overrides it.
    Anything else is an error rather than a default, so no MTA-specific check passes by guess.
    """
    forced = os.environ.get("AMX_MTA_CT")
    if forced:
        if forced not in MTAS:
            raise ValueError(f"AMX_MTA_CT must be one of {MTAS}, not {forced!r}")
        return forced
    image = compose("ps", "-a", "--format", "{{.Image}}", "mailhost-ct").stdout.strip()
    if image.startswith("sha256:"):
        # Recent Docker Compose displays an image ID rather than its configured name.
        container = compose("ps", "-a", "-q", "mailhost-ct").stdout.strip()
        image = subprocess.run(
            ["docker", "inspect", "--format", "{{.Config.Image}}", container],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    if "stalwart" in image:
        return "stalwart"
    if "mailhost" in image:
        return "postfix"
    raise RuntimeError(f"cannot tell contoso's MTA from its mailhost image {image!r}")


def mta_line_for_ct(trace: str) -> str | None:
    """Which MTA wrote the contoso mailhost lines in an ``amx trace`` output, if any."""
    matched = re.search(r"^\S+ mailhost-ct(?:-1)? (postfix|stalwart) ", trace, re.MULTILINE)
    return matched[1] if matched else None


# What a sender's MTA hears when contoso's gateway is down: Postfix answers for an unreachable
# milter with milter_default_action = tempfail, Stalwart with its milter tempFailOnError.
MILTER_DOWN_REPLY = {"postfix": "451 4.7.1", "stalwart": "451 4.3.5"}

# Where contoso's hold queues live (PLAN §5.8): in each agent's own Outbox on Dovecot, where an ACL
# denies the agent every write. On Stalwart an owner can do anything in its own folders, so the
# queues are folder trees of this account, shared read-only to each agent and read-write to the
# approver.
CT_HOLD_OWNER = "holds@contoso.test"


def ct_hold_folder(agent: str, name: str) -> str:
    """One of a contoso agent's hold folders (Held, Approved, Rejected), as its login sees it.

    The approver sees the same name.
    """
    if mta_ct() == "stalwart":
        return f"Shared Folders/{CT_HOLD_OWNER}/Holds/{agent}/{name}"
    return f"Outbox/{name}"


def ct_approver_login(agent: str) -> str:
    """How the person approving a contoso agent's holds logs in (password dev-approver).

    Dovecot: a master login the agent never holds, ACL-limited to moves in Outbox/*. Stalwart:
    an ordinary account, because a Stalwart master login acts with the owner's full rights.
    """
    if mta_ct() == "stalwart":
        return "approver@contoso.test"
    return f"{agent}@agents.contoso.test*approver"


def ct_lmtp_deferrals(needle: str, code: str) -> list[str]:
    """contoso's MTA log lines where the gateway's LMTP deferred a message matching ``needle``."""
    lines = compose("logs", "--no-color", "--timestamps", "mailhost-ct").stdout.splitlines()
    marker = "(delivery.dsn-temp-fail)" if mta_ct() == "stalwart" else "status=deferred"
    return [line for line in lines if needle in line and marker in line and code in line]


def queued_at(service: str, needle: str) -> bool:
    """Return whether ``postqueue -p`` on a mailhost lists a recipient containing ``needle``."""
    return needle in compose_exec(service, "postqueue", "-p").stdout


def trace_task(task: str) -> str:
    """Run the installed trace CLI over both host stores and current Compose logs."""
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
    # The argv list, shell=False, and every component are repository/test controlled.
    logs = subprocess.run(  # nosec B603
        [*COMPOSE, "logs", "--no-color", "--timestamps", "mailhost-nw", "mailhost-ct"],
        check=True,
        capture_output=True,
        text=True,
        cwd=ROOT,
        shell=False,
        env=_compose_env(),
    )
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".postfix.log") as stream:
        stream.write(logs.stdout)
        stream.flush()
        executable = shutil.which("amx") or str(ROOT / ".venv" / "bin" / "amx")
        command = [
            executable,
            "trace",
            task,
            "--config",
            str(ROOT / "deploy" / "gateway" / "northwind.yaml"),
            "--config",
            str(ROOT / "deploy" / "gateway" / "contoso.yaml"),
            "--data-dir",
            str(GENERATED / "state" / "nw"),
            "--data-dir",
            str(GENERATED / "state" / "ct"),
            "--postfix-log",
            stream.name,
        ]
        # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
        # The argv list, shell=False, and every component are repository/test controlled.
        result = subprocess.run(  # nosec B603
            command, check=True, capture_output=True, text=True, cwd=ROOT, shell=False
        )
    print(result.stdout, end="")
    return result.stdout


LLM_HOST_URL = "http://127.0.0.1:11434/v1"  # the host's view of the Ollama the gateways call


def llm_ready() -> str | None:
    """Return why the S11 LLM agents cannot run here, or None when a one-token call works."""
    import json
    import os
    import urllib.request

    base = os.environ.get("AMX_LLM_HOST_URL", LLM_HOST_URL).rstrip("/")
    model = os.environ.get("AMX_LLM_MODEL", "deepseek-v4.1-flash:cloud")
    body = {"model": model, "messages": [{"role": "user", "content": "ok"}], "max_tokens": 1}
    request = urllib.request.Request(
        f"{base}/chat/completions",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # nosec B310
            json.load(response)
    except (OSError, ValueError) as error:
        return f"S11 needs {model} at {base} (the host's Ollama): {error}"
    return None


def llm_decisions(task: str) -> list[dict[str, Any]]:
    """Every LLM agent decision recorded for a task, on either gateway, oldest first."""
    rows = [
        row
        for path in (NW_HANDLER_LOG, HANDLER_LOG)
        if path.exists()
        for row in read_jsonl(path)
        if row.get("kind") == "llm" and row.get("task") == task
    ]
    return sorted(rows, key=lambda row: row["at"])


def wait_for_decision(
    task: str, predicate, *, timeout: float = 180.0, settle: float = 0.0
) -> dict[str, Any]:
    """Wait for an LLM decision matching ``predicate``; optionally until the task goes quiet."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        matches = [row for row in llm_decisions(task) if predicate(row)]
        if matches:
            if settle:
                quiet_since = time.monotonic()
                count = len(llm_decisions(task))
                while time.monotonic() - quiet_since < settle and time.monotonic() < deadline:
                    time.sleep(0.5)
                    if len(llm_decisions(task)) != count:
                        count, quiet_since = len(llm_decisions(task)), time.monotonic()
                matches = [row for row in llm_decisions(task) if predicate(row)]
            return matches[-1]
        time.sleep(0.5)
    raise TimeoutError(f"no matching LLM decision for {task}: {llm_decisions(task)}")


def print_decisions(task: str) -> None:
    for row in llm_decisions(task):
        slots = ",".join(row.get("slots") or [])
        print(
            f"S11 {row['agent']:<11} {row['lane']:<5} {row['tool']:<8} "
            f"{row.get('decision') or '':<7} {slots:<26} held={row.get('held')} "
            f"{row.get('latency_ms', '-')} ms {row.get('reason') or ''}".rstrip()
        )
