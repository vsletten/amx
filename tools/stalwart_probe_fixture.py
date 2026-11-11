"""Obtain an actual gateway-signed SH-00 sample under make suite custody.

Only generated development keys/accounts and the suite's loopback services are
used. No operator credentials or external recipients are accepted.
"""

from __future__ import annotations

import base64
import hashlib
import imaplib
import json
import os
import sqlite3
import stat
import subprocess
import time
from email import policy
from email.parser import BytesParser
from pathlib import Path

import dkim

from amx.sdk import Agent

ROOT = Path(__file__).resolve().parents[1]


def command_output(command: list[str]) -> str:
    # Audited callers use only code-owned, read-only Git/Docker argv; inspect IDs
    # come from the admitted local engine. No shell or external command-input route;
    # local PATH, engine and source are trusted (see require_suite_custody).
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
    return subprocess.run(
        command, cwd=ROOT, capture_output=True, text=True, check=True, timeout=10
    ).stdout.strip()


def process_identity(pid: int) -> tuple[int, int, int]:
    fields = (Path("/proc") / str(pid) / "stat").read_text().rpartition(")")[2].split()
    if fields[0] in ("Z", "X"):
        raise RuntimeError("quiescent suite process")
    return int(fields[1]), int(fields[2]), int(fields[3])  # parent, group, session


def suite_process(lock: Path, pgid: int, *, mode: str = "suite") -> int:
    """Prove native Lease.run custody, even when Make/uv closed the inherited FD.

    Do NOT flock an inherited descriptor: LOCK_UN would release the owner's lock,
    and LOCK_EX on an unrelated descriptor would acquire an unheld lease. Linux
    fdinfo exposes the actual FLOCK attached to the supervisor's open description.
    Require that supervisor to parent the active session leader and our ancestry.
    """
    if pgid <= 1 or os.getpgrp() != pgid or os.getsid(0) != pgid:
        raise RuntimeError("caller is outside the active suite session")
    pid = os.getpid()
    while pid != pgid:
        parent, group, session = process_identity(pid)
        if parent <= 1 or group != pgid or session != pgid:
            raise RuntimeError("caller is not a descendant of the active suite command")
        pid = parent
    supervisor, group, session = process_identity(pgid)
    if (group, session) != (pgid, pgid):
        raise RuntimeError("active command is not a session leader")
    proc = Path("/proc") / str(supervisor)
    if (proc / "cwd").resolve() != ROOT:
        raise RuntimeError("suite supervisor has a foreign root")
    argv = (proc / "cmdline").read_bytes().rstrip(b"\0").decode().split("\0")
    valid_mode = (
        len(argv) == 5 and argv[2:] == ["suite", "--mta", "stalwart"]
        if mode == "suite"
        else mode == "lock" and len(argv) >= 5 and argv[2:4] == ["lock", "--"]
    )
    if (
        len(argv) < 2
        or Path(argv[1]).resolve() != ROOT / "tools/stack_suite.py"
        or not valid_mode
        or not (proc / "exe").resolve().name.startswith("python")
    ):
        raise RuntimeError("active command is not owned by the native suite supervisor")
    process_identity(supervisor)
    identity = lock.stat()
    if not stat.S_ISREG(identity.st_mode) or lock.is_symlink():
        raise RuntimeError("lease is not a named regular file")
    for descriptor in (proc / "fd").iterdir():
        try:
            held = descriptor.stat()
            if (held.st_dev, held.st_ino) != (identity.st_dev, identity.st_ino):
                continue
            lines = (proc / "fdinfo" / descriptor.name).read_text().splitlines()
        except FileNotFoundError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) != 9 or fields[:1] != ["lock:"]:
                continue
            if fields[2:6] != ["FLOCK", "ADVISORY", "WRITE", str(supervisor)]:
                continue
            major, minor, inode = fields[6].split(":")
            if (int(major, 16), int(minor, 16), int(inode)) == (
                os.major(identity.st_dev),
                os.minor(identity.st_dev),
                identity.st_ino,
            ) and fields[7:] == ["0", "EOF"]:
                return supervisor
    raise RuntimeError("native supervisor does not hold the named exclusive kernel lease")


def require_lock_custody() -> None:
    """Read-only generic X0 admission; no dev-stack journal/resources required.

    The environment selects a named lease, never grants admission. Bind the
    active marker to our ancestry/session and its native supervisor's kernel
    FLOCK. Never open, acquire, release or replace the lease inode.
    """
    try:
        lock = Path(os.environ.get("AMX_SUITE_LOCK", "/tmp/amx-validation.lock"))
        if not lock.is_absolute() or lock.resolve() != lock:
            raise RuntimeError("lease path must be canonical and absolute")
        if lock.with_name(lock.name + ".unsafe").exists():
            raise RuntimeError("suite is quarantined")
        active = lock.with_name(lock.name + ".active")
        marker = active.read_bytes()
        pgid = json.loads(marker)["pgid"]
        if type(pgid) is not int:
            raise RuntimeError("suite active identity is not published")
        supervisor = suite_process(lock, pgid, mode="lock")
        if active.read_bytes() != marker or suite_process(lock, pgid, mode="lock") != supervisor:
            raise RuntimeError("suite custody changed during admission")
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
        raise RuntimeError(
            f"Stalwart validation requires native X0 lock custody: {error}"
        ) from error


def require_suite_custody() -> None:
    """Read-only admission BEFORE SDK, mailbox, journal or fixture access.

    Environment and journal values are hints, never authority. Bind them to the
    current native suite process, its actual kernel lease, Git worktree identity,
    engine and token-labelled running containers publishing the fixture endpoints.
    This is a local accident/stale-state guard, not isolation from a hostile UID
    that can modify this source, the supervisor, Docker or /proc itself.
    """
    try:
        lock = Path(os.environ.get("AMX_SUITE_LOCK", "/tmp/amx-validation.lock"))
        if not lock.is_absolute() or lock.resolve() != lock:
            raise RuntimeError("lease path must be canonical and absolute")
        if lock.with_name(lock.name + ".unsafe").exists():
            raise RuntimeError("suite is quarantined")
        active = lock.with_name(lock.name + ".active")
        journal = lock.with_name(lock.name + ".json")
        marker = active.read_bytes()
        pgid = json.loads(marker)["pgid"]
        if type(pgid) is not int:
            raise RuntimeError("suite active identity is not published")
        supervisor = suite_process(lock, pgid)
        contents = journal.read_bytes()
        record = json.loads(contents)
        overlay = str(lock.with_name(lock.name + ".compose.json"))
        root_stat = ROOT.stat()
        if (
            os.environ.get("AMX_SUITE_MTA") != "stalwart"
            or os.environ.get("AMX_SUITE_OVERRIDE") != overlay
            or record["mta"] != "stalwart"
            or record["root"] != str(ROOT)
            or record["overlay"] != overlay
            or record["repository"]
            != command_output(["git", "rev-parse", "--path-format=absolute", "--git-common-dir"])
            or record["worktree"]
            != {
                "git_dir": command_output(["git", "rev-parse", "--absolute-git-dir"]),
                "device": root_stat.st_dev,
                "inode": root_stat.st_ino,
            }
        ):
            raise RuntimeError("suite journal/worktree provenance differs")
        owner = record["owner"]
        if len(owner) != 32 or any(c not in "0123456789abcdef" for c in owner):
            raise RuntimeError("invalid suite ownership token")
        override = json.loads(Path(overlay).read_text())
        for section in ("services", "volumes", "networks"):
            if not override[section] or any(
                value["labels"]["ai.amx.suite-owner"] != owner
                for value in override[section].values()
            ):
                raise RuntimeError("suite overlay token differs")
        if record["engine"] != command_output(["docker", "info", "--format", "{{.ID}}"]):
            raise RuntimeError("suite Docker engine differs")
        names = command_output(
            ["docker", "ps", "-q", "--no-trunc", "--filter", "label=com.docker.compose.project=amx"]
        ).split()
        if not names:
            raise RuntimeError("suite containers are absent")
        containers = json.loads(command_output(["docker", "container", "inspect", *names]))
        endpoints = set()
        for container in containers:
            labels = container["Config"]["Labels"]
            if (
                labels["ai.amx.suite-owner"] != owner
                or labels["com.docker.compose.project"] != "amx"
                or labels["com.docker.compose.project.working_dir"] != str(ROOT / "deploy")
                or not container["State"]["Running"]
            ):
                raise RuntimeError("foreign or stopped suite container")
            for port, bindings in container["NetworkSettings"]["Ports"].items():
                for binding in bindings or []:
                    endpoints.add(
                        (
                            labels["com.docker.compose.service"],
                            port,
                            binding["HostIp"],
                            binding["HostPort"],
                        )
                    )
        if not {
            ("gateway-ct", "2587/tcp", "127.0.0.1", "2588"),
            ("mailhost-ct", "143/tcp", "127.0.0.1", "1432"),
        }.issubset(endpoints):
            raise RuntimeError("fixture endpoints are not published by the owning suite")
        # Recheck local custody after the read-only Docker/Git queries. No owner
        # lock acquisition/release, journal rewrite or recovery/adoption occurs.
        if (
            active.read_bytes() != marker
            or journal.read_bytes() != contents
            or suite_process(lock, pgid) != supervisor
        ):
            raise RuntimeError("suite custody changed during admission")
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        RuntimeError,
        subprocess.SubprocessError,
    ) as error:
        raise RuntimeError(
            f"SH-00 fixture requires make suite Stalwart custody: {error}"
        ) from error


def public_record(path: Path) -> str:
    result = subprocess.run(
        ["openssl", "pkey", "-in", str(path), "-pubout", "-outform", "DER"],
        capture_output=True,
        check=True,
        timeout=10,
    )
    return "v=DKIM1; k=rsa; p=" + base64.b64encode(result.stdout).decode()


def signed_copy(message_id: str) -> bytes:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        with imaplib.IMAP4("127.0.0.1", 1432, timeout=5) as client:
            client.login("intake@agents.contoso.test", "dev-intake")
            if client.select("Sent", readonly=True)[0] != "OK":
                raise RuntimeError("gateway Sent folder unavailable")
            status, data = client.uid("SEARCH", None, "ALL")
            if status != "OK":
                raise RuntimeError("Sent SEARCH failed")
            for uid in (data[0] or b"").split():
                status, fetched = client.uid("FETCH", uid, "(BODY.PEEK[])")
                if status != "OK":
                    raise RuntimeError("Sent FETCH failed")
                raw = next(item[1] for item in fetched if isinstance(item, tuple))
                parsed = BytesParser(policy=policy.default).parsebytes(raw)
                if parsed.get("Message-ID") == message_id:
                    return raw
        time.sleep(0.2)
    raise TimeoutError("actual gateway signed copy not filed in Sent")


def journal_copy(root: Path, message_id: str) -> bytes:
    """The exact bytes _sign handed to _reinject, not IMAP's stored representation."""
    with sqlite3.connect((root / "journal.sqlite").as_uri() + "?mode=ro", uri=True) as connection:
        rows = connection.execute(
            "SELECT raw_sha256 FROM journal WHERE message_id = ? AND direction = 'outbound' "
            "AND event = 'submission'",
            (message_id,),
        ).fetchall()
    if len(rows) != 1:
        raise RuntimeError("expected one actual gateway submission journal row")
    digest = rows[0][0]
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise RuntimeError("invalid generated journal content address")
    raw = (root / "raw" / digest[:2] / f"{digest}.eml").read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise RuntimeError("gateway journal content address mismatch")
    return raw


def main() -> None:
    require_suite_custody()
    generated = ROOT / "deploy/generated"
    sent = Agent(
        "intake@agents.contoso.test",
        "smtp://127.0.0.1:2588",
        "dev-intake-token",
        tls_ca_file=str(generated / "tls/dev-ca.pem"),
    ).send(
        to="ops@contoso.test",
        subject="SH-00 actual gateway signing fixture",
        intent="request",
        text="Loopback-only signing probe; no external recipient.",
    )
    if sent.held:
        raise RuntimeError("signing fixture was held, not signed/sent")
    stored = signed_copy(sent.message_id)  # separately prove the actual Sent filing
    raw = journal_copy(generated / "state/ct", sent.message_id)
    keys = {
        "intake._domainkey.agents.contoso.test": public_record(
            generated / "keys/intake.private.pem"
        ),
        "sh00._domainkey.contoso.test": public_record(generated / "tls/server-key.pem"),
    }

    def dns(name, **_kwargs):
        return keys.get(name.decode().rstrip("."), "").encode()

    if not dkim.verify(raw, dnsfunc=dns):
        raise RuntimeError("actual gateway sample fails DKIM verification")
    directory = generated / "state/sh00"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "agent.eml").write_bytes(raw)
    (directory / "public.json").write_text(json.dumps(keys))
    print(
        "AMX_SH00_FIXTURE="
        + json.dumps(
            {
                "message_id": sent.message_id,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "gateway_signed": True,
                "dkim_verified": True,
                "source": "gateway outbound submission journal exact reinjection bytes",
                "sent_copy_identical": stored == raw,
            }
        )
    )


if __name__ == "__main__":
    main()
