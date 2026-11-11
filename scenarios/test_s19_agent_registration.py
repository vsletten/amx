"""S19: an operator registers an agent on the running stack, rotates it, and removes it (§5.2).

Nothing restarts. The org's administrator vouches for a new agent at contoso:
1. ``amx agent add --live`` writes its DKIM key, a mailbox login (hash only), a registry entry
   (token hash only), and one credentials bundle. The DKIM TXT is published in CoreDNS and
   ``amx dns check`` confirms it. northwind grants the new identity (``amx trust add``).
2. gateway-ct picks the agent up from its registry, and the mailhost from its accounts file
   (Dovecot's amx-sync-accounts, or stalwart-sync-ct). An amx-runner on the host, holding only
   the bundle, answers a signed request from scheduler.
3. ``amx agent rotate`` replaces the token and password (the old ones stop working at once) and
   stages a new key under a new selector; once it is in DNS, ``--activate`` signs with it, and
   northwind's grant on s=<name> covers s=<name>.k2.
4. ``amx agent remove`` disables it (RCPT: 550 5.1.1, and no login), and ``--purge`` deletes its
   mailbox and keys.
"""

from __future__ import annotations

import contextlib
import imaplib
import json
import os
import smtplib
import ssl
import subprocess
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from amx import registration as reg
from amx.store import Store
from amx.testkit import drop_zone_record, set_zone_record, smtp_transaction
from scenarios.support import (
    CT_DB,
    DEV_TLS_CA,
    GENERATED,
    NW_HANDLER_LOG,
    ROOT,
    compose,
    compose_exec,
    mta_ct,
    signed_request,
    wait_for_handler,
    wait_for_task,
)

pytestmark = pytest.mark.integration

CONTOSO = ROOT / "deploy" / "gateway" / "contoso.yaml"
NORTHWIND = ROOT / "deploy" / "gateway" / "northwind.yaml"
CT_REGISTRY = GENERATED / "state" / "ct" / "registry"
NW_REGISTRY = GENERATED / "state" / "nw" / "registry"
KEYS = GENERATED / "keys"
ZONE = GENERATED / "zones" / "agents.contoso.test.zone"
# The host's view of contoso: its MX, IMAP (143 in the container), and gateway submission.
MX, IMAP, SUBMISSION = ("127.0.0.1", 2526), ("127.0.0.1", 1432), ("127.0.0.1", 2588)
MASTER = {"postfix": "{user}*gateway", "stalwart": "{user}%gateway@contoso.test"}


def _amx(*arguments: str) -> subprocess.CompletedProcess[str]:
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
    return subprocess.run(  # nosec B603 (the argv is this test's own)
        [sys.executable, "-m", "amx.cli", *arguments],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )


def _ct(*arguments: str) -> subprocess.CompletedProcess[str]:
    """``amx`` against contoso's gateway, with the host's paths for its container paths."""
    return _amx(
        *arguments,
        "--config",
        str(CONTOSO),
        "--registry-dir",
        str(CT_REGISTRY),
        "--keys-dir",
        str(KEYS),
    )


def _wait(predicate, timeout: float, what: str):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.5)
    raise TimeoutError(what)


def _rcpt(address: str) -> tuple[int, str]:
    """contoso's MX's answer to RCPT TO: address (no DATA)."""
    with smtplib.SMTP(*MX, timeout=15) as client:
        client.ehlo("s19.northwind.test")
        client.mail("scheduler@agents.northwind.test")
        code, reply = client.rcpt(address)
        client.rset()
    return code, reply.decode(errors="replace")


def _imap_login(user: str, password: str) -> bool:
    try:
        with imaplib.IMAP4(*IMAP, timeout=10) as client:
            client.login(user, password)
            client.logout()
    except (imaplib.IMAP4.error, OSError):
        return False
    return True


def _submission_login(name: str, token: str) -> bool:
    context = ssl.create_default_context(cafile=str(DEV_TLS_CA))
    try:
        with smtplib.SMTP(*SUBMISSION, timeout=10) as client:
            client.starttls(context=context)
            client.login(name, token)
    except smtplib.SMTPAuthenticationError:
        return False
    return True


def _publish(selector: str) -> None:
    value = reg.dkim_value(KEYS / f"{selector}.private.pem")
    set_zone_record(ZONE, f'{selector}._domainkey IN TXT "{value}"')


def _unpublish(selector: str) -> None:
    with contextlib.suppress(ValueError):
        drop_zone_record(ZONE, f"{selector}._domainkey")


def _runner(bundle: Path, state: Path) -> subprocess.Popen[bytes]:
    """amx-runner on the host, with nothing but the operator's bundle (and the dev CA)."""
    state.mkdir(parents=True, exist_ok=True)
    log = (state / "runner.log").open("ab")
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
    return subprocess.Popen(  # nosec B603 (the argv is this test's own)
        [
            sys.executable,
            "-m",
            "amx.runner",
            "--credentials",
            str(bundle),
            "--ca",
            str(DEV_TLS_CA),
            "--handler",
            "amx.examples.intake:handle",
            "--state",
            str(state),
            "--idle-seconds",
            "5",
        ],
        env=os.environ | {"AMX_HANDLER_LOG": str(state / "handler.jsonl")},
        stdout=log,
        stderr=subprocess.STDOUT,
    )


def _stop(process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(15)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(5)


def _ask(name: str, state: Path) -> str:
    """scheduler asks the new agent for something; return the task once northwind has the answer."""
    suffix = uuid.uuid4().hex[:10]
    task = f"t_s19_{suffix}"
    message_id = f"<s19-{suffix}@agents.northwind.test>"
    recipient = f"{name}+{task}@agents.contoso.test"
    raw = signed_request(task, message_id, recipient=recipient)
    code, response = smtp_transaction(
        "127.0.0.1", f"scheduler+{task}@agents.northwind.test", recipient, raw, port=MX[1]
    )
    assert code == 250, (code, response)
    [handled] = wait_for_handler(message_id, timeout=45, path=state / "handler.jsonl")
    assert (handled["agent"], handled["task"]) == (name, task)
    answer = wait_for_task(task, path=NW_HANDLER_LOG, intent="response", timeout=45)[-1]
    assert (answer["lane"], answer["text"]) == ("agent", "Intake completed the request.")
    return task


def _signed_with(task: str) -> str:
    [sent] = Store(CT_DB).rows(
        "SELECT detail FROM journal WHERE task = ? AND event = 'submission'", (task,)
    )
    return str(sent["detail"])


def _started_at() -> dict[str, str]:
    """When each long-running container last started: a restart would change it."""
    started = {}
    for service in ("gateway-ct", "gateway-nw", "mailhost-ct"):
        container = compose("ps", "-q", service).stdout.strip()
        # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
        inspected = subprocess.run(  # nosec B603 B607
            ["docker", "inspect", "--format", "{{.State.StartedAt}}", container],
            check=True,
            capture_output=True,
            text=True,
        )
        started[service] = inspected.stdout.strip()
    return started


def _session_alive(client: imaplib.IMAP4) -> bool:
    try:
        return client.noop()[0] == "OK"
    except (imaplib.IMAP4.error, OSError):
        return False


def _purged(mta: str, name: str) -> bool:
    """Whether contoso's mailhost deleted the agent's mailbox (its sync logs the purge)."""
    if mta == "postfix":
        home = f"/var/mail/vhosts/agents.contoso.test/{name}"
        gone = compose_exec("mailhost-ct", "sh", "-c", f"test -e {home} || echo gone")
        return gone.stdout.strip() == "gone"
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
    logs = subprocess.run(  # nosec B603 B607 (stalwart-sync-ct is only in compose.stalwart.yaml)
        ["docker", "logs", "amx-stalwart-sync-ct-1"], capture_output=True, text=True
    )
    return f"amx: purged {name}@agents.contoso.test" in logs.stdout + logs.stderr


def _reloaded(service: str, since: str) -> bool:
    logs = compose("logs", "--no-log-prefix", "--since", since, service).stdout
    return "config reloaded" in logs


def test_s19_register_answer_rotate_and_remove_without_a_restart(tmp_path) -> None:
    mta = mta_ct()
    name = f"reg-{uuid.uuid4().hex[:6]}"
    address = f"{name}@agents.contoso.test"
    started = _started_at()
    runner: subprocess.Popen[bytes] | None = None
    try:
        # 1. northwind grants the identity it will hear from, then contoso registers the agent.
        since = datetime.now(UTC).isoformat(timespec="seconds")
        granted = _amx(
            "trust",
            "add",
            "agents.contoso.test",
            name,
            "--intent",
            "response",
            "--can-open-tasks",
            "--config",
            str(NORTHWIND),
            "--registry-dir",
            str(NW_REGISTRY),
        )
        assert granted.returncode == 0, granted.stderr
        bundle = tmp_path / f"{name}.json"
        added = _ct(
            "agent",
            "add",
            name,
            "--live",
            "--watermark",
            "4",
            "--bundle",
            str(bundle),
            "--imap",
            f"{IMAP[0]}:{IMAP[1]}",
            "--submission",
            f"smtp://{SUBMISSION[0]}:{SUBMISSION[1]}",
        )
        assert added.returncode == 0, added.stderr
        secrets = json.loads(bundle.read_text(encoding="utf-8"))
        assert secrets["token"] not in added.stdout + added.stderr
        assert secrets["password"] not in added.stdout + added.stderr
        assert f"DNS host:  Type TXT | Name {name}._domainkey.agents | Value" in added.stdout
        assert _ct("dns", "check", name).returncode == 1  # not published yet
        _publish(name)
        _wait(lambda: _ct("dns", "check", name).returncode == 0, 20, "DKIM never in DNS")
        _wait(lambda: _reloaded("gateway-nw", since), 20, "gateway-nw never reloaded")

        # 2. Both sides pick it up with no restart; the runner holds only the bundle.
        _wait(lambda: _rcpt(address)[0] == 250, 30, "gateway-ct never accepted the agent")
        _wait(
            lambda: _imap_login(address, secrets["password"]),
            60,
            f"{mta}'s mailhost never let the agent log in",
        )
        assert _submission_login(name, secrets["token"])
        runner = _runner(bundle, tmp_path / "runner")
        first = _ask(name, tmp_path / "runner")
        assert f"s={name}" in _signed_with(first)

        # 3. Rotate: new secrets at once, and a staged key that signs only once activated.
        session = imaplib.IMAP4(*IMAP, timeout=10)
        session.login(address, secrets["password"])
        rotated_bundle = tmp_path / f"{name}-2.json"
        rotated = _ct("agent", "rotate", name, "--bundle", str(rotated_bundle))
        assert rotated.returncode == 0, rotated.stderr
        fresh = json.loads(rotated_bundle.read_text(encoding="utf-8"))
        _wait(lambda: not _submission_login(name, secrets["token"]), 15, "old token still works")
        assert _submission_login(name, fresh["token"])
        _wait(lambda: not _imap_login(address, secrets["password"]), 60, "old password works")
        _wait(lambda: _imap_login(address, fresh["password"]), 60, "new password never works")
        # A session opened with the old password does not outlive the rotation on Dovecot
        # (amx-sync-accounts kicks it). Stalwart keeps it: PLAN §8.
        if mta == "postfix":
            _wait(lambda: not _session_alive(session), 15, "the old IMAP session survived")
        else:
            print(f"S19 {mta}: old IMAP session alive after rotation: {_session_alive(session)}")
        with contextlib.suppress(imaplib.IMAP4.error, OSError):
            session.logout()
        _stop(runner)
        runner = _runner(rotated_bundle, tmp_path / "runner")
        second = _ask(name, tmp_path / "runner")
        assert f"s={name} " in _signed_with(second) + " "  # still the old key: not activated
        refused = _ct("agent", "rotate", name, "--activate")
        assert refused.returncode == 1 and "missing in DNS" in refused.stderr
        _publish(f"{name}.k2")
        _wait(lambda: _ct("dns", "check", name).returncode == 0, 20, "staged key never in DNS")
        activated = _ct("agent", "rotate", name, "--activate", "--overlap", "1h")
        assert activated.returncode == 0, activated.stderr
        time.sleep(3)  # the gateway polls its registry once a second
        third = _ask(name, tmp_path / "runner")
        assert f"s={name}.k2" in _signed_with(third), "northwind's grant covers the new selector"
        render = _ct("dns", "render")
        assert f"{name}._domainkey IN TXT" in render.stdout, "the old key stays for the overlap"
        assert f"{name}.k2._domainkey IN TXT" in render.stdout

        # 4. Remove: disabled first (RCPT refuses, no login), then purged.
        removed = _ct("agent", "remove", name)
        assert removed.returncode == 0, removed.stderr
        _code, reply = _wait(
            lambda: (result := _rcpt(address))[0] == 550 and result,
            30,
            "RCPT never refused the disabled agent",
        )
        assert "5.1.1" in reply
        _wait(lambda: not _imap_login(address, fresh["password"]), 60, "login still works")
        assert not _submission_login(name, fresh["token"])
        _stop(runner)
        runner = None
        purged = _ct("agent", "remove", name, "--purge", "--now")
        assert purged.returncode == 0, purged.stderr
        assert not (KEYS / f"{name}.private.pem").exists()
        assert not (KEYS / f"{name}.k2.private.pem").exists()
        master = MASTER[mta].format(user=address)
        assert not _imap_login(master, "dev-gateway")  # nobody logs in: disabled, then purged
        _wait(lambda: _purged(mta, name), 60, "the mailbox outlived the purge")
        assert _rcpt(address)[0] == 550
        # The same name registered again, at once, gets a new mailbox: nothing of the purged
        # agent's mail, even if the mailhost never saw the purge (the generation differs).
        again = tmp_path / f"{name}-again.json"
        readded = _ct(
            "agent",
            "add",
            name,
            "--live",
            "--bundle",
            str(again),
            "--imap",
            f"{IMAP[0]}:{IMAP[1]}",
            "--submission",
            f"smtp://{SUBMISSION[0]}:{SUBMISSION[1]}",
        )
        assert readded.returncode == 0, readded.stderr
        password = json.loads(again.read_text(encoding="utf-8"))["password"]
        _wait(lambda: _imap_login(address, password), 60, "the new agent never logged in")
        with imaplib.IMAP4(*IMAP, timeout=10) as client:
            client.login(address, password)
            for folder in ("INBOX", "Sent"):
                status, data = client.select(folder, readonly=True)
                assert status == "OK" and data[0] == b"0", f"{folder} kept the old agent's mail"
        assert _ct("agent", "remove", name).returncode == 0
        assert _ct("agent", "remove", name, "--purge", "--now").returncode == 0
        assert _started_at() == started, "nothing restarted"
        print(
            f"S19 REGISTRATION ({mta}): {address} added, answered s={name}, rotated to "
            f"s={name}.k2, disabled (550 5.1.1), purged; no restart"
        )
    finally:
        _stop(runner)
        if (CT_REGISTRY / "agents" / f"{name}.yaml").exists():
            _ct("agent", "remove", name)
            _ct("agent", "remove", name, "--purge", "--now")
        for selector in (name, f"{name}.k2"):
            _unpublish(selector)
            (KEYS / f"{selector}.private.pem").unlink(missing_ok=True)
        _amx(
            "trust",
            "remove",
            "agents.contoso.test",
            name,
            "--config",
            str(NORTHWIND),
            "--registry-dir",
            str(NW_REGISTRY),
        )
