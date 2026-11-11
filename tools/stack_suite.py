"""Serialize fixed-port validation stacks across worktrees (Linux flock).

Only `suite` owns/reclaims the dev stack. `lock -- COMMAND ...` shares the same
lease for live-validate and the future SH-26 selfhost validator.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK = Path(os.environ.get("AMX_SUITE_LOCK", "/tmp/amx-validation.lock"))
OWNER_LABEL = "ai.amx.suite-owner"
SIGNALS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)


class Interrupted(Exception):
    def __init__(self, signum: int):
        self.signum = signum


def interrupt(signum: int, _frame: object) -> None:
    raise Interrupted(signum)


def group_active(pgid: int) -> bool:
    """Linux group/session membership; zombies are quiescent, not active work."""
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            fields = (entry / "stat").read_text().rpartition(")")[2].split()
        except ProcessLookupError:
            continue
        except FileNotFoundError:
            continue
        if int(fields[2]) == pgid and int(fields[3]) == pgid and fields[0] not in ("Z", "X"):
            return True
    return False


def settles(pgid: int, grace: float = 5) -> bool:
    """An exiting holder drops its flock before /proc shows it as a zombie, so a
    waiter can wake inside that window. Allow a bounded settle, then fail closed."""
    deadline = time.monotonic() + grace
    while group_active(pgid):
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.02)
    return True


def sync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def publish(path: Path, value: dict, *, exclusive: bool = False) -> None:
    """Durable publication: failure before spawn must refuse the command."""
    temporary = path if exclusive else path.with_name(path.name + ".new")
    with temporary.open("x" if exclusive else "w") as stream:
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())
    if not exclusive:
        temporary.replace(path)
    sync_directory(path.parent)


class Lease:
    def __init__(self, fd: int):
        self.fd = fd
        self.quiescent = True

    def stop(self, process: subprocess.Popen, term_grace: float = 10) -> None:
        # The unreaped session leader pins the group ID: never signal a recycled
        # PID/group, and never infer membership from command strings or lock FDs.
        handlers = {sig: signal.signal(sig, signal.SIG_IGN) for sig in SIGNALS}
        self.quiescent = False
        try:
            for sig, grace in ((signal.SIGTERM, term_grace), (signal.SIGKILL, 5)):
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, sig)
                deadline = time.monotonic() + grace
                while group_active(process.pid) and time.monotonic() < deadline:
                    time.sleep(0.02)
                if not group_active(process.pid):
                    self.quiescent = True
                    return
            # The active marker predates spawn. No fallible late diagnostic write
            # or indefinite waiter/orphan is needed to preserve admission.
            raise RuntimeError("process group still active after KILL; admission quarantined")
        finally:
            for sig, handler in handlers.items():
                signal.signal(sig, handler)

    def run(
        self, command: list[str], *, cwd: Path = ROOT, env=None, capture=False, term_grace=10
    ) -> str:
        # Immediate children retain the lease on supervisor SIGKILL. On handled
        # interruption we also stop descendants that legitimately closed that FD.
        env = dict(os.environ if env is None else env)
        env.pop("COMPOSE_PROFILES", None)
        with tempfile.TemporaryFile(mode="w+") as output:
            marker = LOCK.with_name(LOCK.name + ".active")
            process = None
            published = False
            try:
                # Defer handled signals until child identity and exception custody
                # are installed. SIGKILL before identity publication still leaves
                # the pre-spawn marker: ambiguous liveness always fails closed.
                blocked = signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
                try:
                    publish(marker, {"pgid": None}, exclusive=True)
                    published = True
                    # All callers are fixed local Docker/Git/Make argv below, or
                    # the intentionally trusted local `lock -- COMMAND` CLI.
                    # No remote content is interpreted; never shell-escape argv.
                    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
                    process = subprocess.Popen(
                        command,
                        cwd=cwd,
                        env=env,
                        pass_fds=(self.fd,),
                        start_new_session=True,
                        stdout=output if capture else None,
                        text=True,
                        shell=False,
                        # This CLI is single-threaded. Do not let our temporary
                        # custody mask make the child's TERM handler unreachable.
                        preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_SETMASK, blocked),
                    )
                    publish(marker, {"pgid": process.pid})
                finally:
                    signal.pthread_sigmask(signal.SIG_SETMASK, blocked)
                os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOWAIT)
                if group_active(process.pid):
                    self.stop(process, term_grace)
            except BaseException:
                if process is not None and self.quiescent:
                    self.stop(process, term_grace)
                raise
            finally:
                handlers = {sig: signal.signal(sig, signal.SIG_IGN) for sig in SIGNALS}
                try:
                    if self.quiescent and published:
                        if process is not None:
                            process.wait()
                        marker.unlink(missing_ok=True)
                        sync_directory(marker.parent)
                finally:
                    for sig, handler in handlers.items():
                        signal.signal(sig, handler)
            assert process is not None
            if process.returncode:
                raise subprocess.CalledProcessError(process.returncode, command)
            output.seek(0)
            return output.read() if capture else ""


@contextlib.contextmanager
def locked():
    # Never unlink this inode: a waiter may already have it open. Do not use
    # TMPDIR/HOME or a checkout-relative default: those differ between workers.
    if not LOCK.is_absolute():
        raise RuntimeError("AMX_SUITE_LOCK must be absolute and shared across worktrees")
    with LOCK.open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print(f"amx: waiting for host validation lock {LOCK}", flush=True)
            fcntl.flock(lock, fcntl.LOCK_EX)
        unsafe = LOCK.with_name(LOCK.name + ".unsafe")
        if unsafe.exists():
            raise RuntimeError(
                f"refusing validation: unsafe marker requires investigation: {unsafe}"
            )
        marker = LOCK.with_name(LOCK.name + ".active")
        if marker.exists():
            pgid = json.loads(marker.read_text())["pgid"]
            if not isinstance(pgid, int) or pgid <= 1 or not settles(pgid):
                raise RuntimeError(
                    f"refusing validation: active group marker requires investigation: {marker}"
                )
            marker.unlink()  # proven quiescent after a killed supervisor
            sync_directory(marker.parent)
        print(f"amx: acquired host validation lock {LOCK}", flush=True)
        yield Lease(lock.fileno())


def resources(lease: Lease) -> dict[str, list[str]]:
    return {
        kind: lease.run(
            ["docker", *args, "--filter", "label=com.docker.compose.project=amx"], capture=True
        ).split()
        for kind, args in (
            ("container", ["ps", "-aq", "--no-trunc"]),
            ("volume", ["volume", "ls", "-q"]),
            ("network", ["network", "ls", "-q", "--no-trunc"]),
        )
    }


def repository(lease: Lease, root: Path) -> str:
    return lease.run(
        ["git", "rev-parse", "--path-format=absolute", "--git-common-dir"], cwd=root, capture=True
    ).strip()


def worktree_identity(lease: Lease, root: Path) -> dict:
    stat = root.stat()
    return {
        "git_dir": lease.run(
            ["git", "rev-parse", "--absolute-git-dir"], cwd=root, capture=True
        ).strip(),
        "device": stat.st_dev,
        "inode": stat.st_ino,
    }


def compose(record: dict) -> list[str]:
    files = [str(Path(record["root"]) / "deploy" / "compose.yaml")]
    if record["mta"] == "stalwart":
        files.append(str(Path(record["root"]) / "deploy" / "compose.stalwart.yaml"))
    return [
        "docker",
        "compose",
        "-p",
        "amx",
        *[a for f in files for a in ("-f", f)],
        "-f",
        record["overlay"],
    ]


def cleanup(lease: Lease, journal: Path, record: dict) -> None:
    root = Path(record["root"])
    if (
        record["repository"] != repository(lease, ROOT)
        or repository(lease, root) != record["repository"]
        or worktree_identity(lease, root) != record["worktree"]
    ):
        raise RuntimeError("refusing cleanup: recorded worktree repository provenance differs")
    engine = lease.run(["docker", "info", "--format", "{{.ID}}"], capture=True).strip()
    if engine != record["engine"]:
        raise RuntimeError("refusing cleanup: recorded Docker engine differs")
    found = resources(lease)
    for kind, names in found.items():
        for name in names:
            # Inspect labels only, never container content. Even with a journal,
            # a foreign/manual stack must not be removed by project name alone.
            template = "{{json .Config.Labels}}" if kind == "container" else "{{json .Labels}}"
            labels = (
                json.loads(
                    lease.run(["docker", kind, "inspect", "--format", template, name], capture=True)
                )
                or {}
            )
            if labels.get(OWNER_LABEL) != record["owner"]:
                raise RuntimeError(f"refusing cleanup: unrelated amx {kind} {name}")
            if kind == "container" and labels.get("com.docker.compose.project.working_dir") != str(
                root / "deploy"
            ):
                raise RuntimeError(f"refusing cleanup: compose working-dir differs for {name}")
    # Never project-wide down: direct Docker actors need not share our flock.
    # Full container/network IDs cannot select resources created after the scan.
    # Docker volumes have names, not IDs; do not force removal of attached ones.
    for kind, names in found.items():
        for name in names:
            lease.run(
                ["docker", kind, "rm", *(["-f"] if kind == "container" else []), name], cwd=root
            )
    if any(resources(lease).values()):
        raise RuntimeError("cleanup incomplete: amx resources remain; retaining recovery journal")
    state = root / "deploy" / "generated" / "state"
    if state.is_symlink():
        raise RuntimeError("refusing cleanup: generated/state is a symlink")
    if state.exists():
        shutil.rmtree(state)
    (root / "deploy" / "generated" / "mta_ct").unlink(missing_ok=True)
    journal.unlink()
    sync_directory(journal.parent)
    Path(record["overlay"]).unlink(missing_ok=True)


def suite(lease: Lease, mta: str) -> None:
    journal = LOCK.with_name(LOCK.name + ".json")
    if journal.exists():
        print("amx: recovering previous suite before startup", flush=True)
        cleanup(lease, journal, json.loads(journal.read_text()))
    elif any(resources(lease).values()):
        raise RuntimeError("refusing startup: amx resources have no suite ownership journal")
    record = {
        "root": str(ROOT),
        "repository": repository(lease, ROOT),
        "worktree": worktree_identity(lease, ROOT),
        "mta": mta,
        "owner": uuid.uuid4().hex,
        "overlay": str(LOCK.with_name(LOCK.name + ".compose.json")),
        "engine": lease.run(["docker", "info", "--format", "{{.ID}}"], capture=True).strip(),
    }
    # Render names, not secrets, into a tiny ownership-only override. This covers
    # containers AND named volumes/networks, including the previous MTA variant.
    config = json.loads(
        lease.run(
            [*compose(record)[:-2], "--profile", "*", "config", "--format", "json"], capture=True
        )
    )
    overlay = {
        section: {
            name: {"labels": {OWNER_LABEL: record["owner"]}} for name in config.get(section, {})
        }
        for section in ("services", "volumes", "networks")
    }
    Path(record["overlay"]).write_text(json.dumps(overlay))
    publish(journal, record)  # durable before prepare/up can leave remnants
    env = {**os.environ, "AMX_SUITE_OVERRIDE": record["overlay"], "AMX_SUITE_MTA": mta}
    env.pop("COMPOSE_PROFILES", None)
    try:
        for target in ("up", "smoke", "scenarios"):
            lease.run(["make", target, f"MTA_CT={mta}"], env=env)
    except BaseException:
        # Capture failure logs BEFORE down, still under the lease. A logging error
        # must not mask the original error or prevent teardown.
        if lease.quiescent:
            with contextlib.suppress(Exception):
                lease.run([*compose(record), "logs", "--no-color", "--timestamps"])
        raise
    finally:
        # Repeated Ctrl-C/TERM must not interrupt teardown and release the lease.
        for sig in SIGNALS:
            signal.signal(sig, signal.SIG_IGN)
        if lease.quiescent:
            cleanup(lease, journal, record)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    run = sub.add_parser("suite")
    run.add_argument("--mta", choices=("postfix", "stalwart"), default="postfix")
    other = sub.add_parser("lock")
    other.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    for sig in SIGNALS:
        signal.signal(sig, interrupt)
    try:
        with locked() as lease:
            if args.mode == "suite":
                suite(lease, args.mta)
            else:
                command = args.command[1:] if args.command[:1] == ["--"] else args.command
                if not command:
                    parser.error("lock requires a command")
                # Validator cleanup: 30s runner shutdown + 5s KILL + 60s down,
                # then a margin. Never an unbounded supervisor grace.
                lease.run(command, term_grace=120)
    except Interrupted as error:
        return 128 + error.signum
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"amx: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
