"""Opt-in SH-23 native acceptance: real installed runner, private loopback fixture only.

uv run python tools/native_host_acceptance.py --run-native --output /private/new/path \
    --source-sha $(git rev-parse HEAD)

This is intentionally not a pytest test: it changes this login user's service manager.
Only the random fixture address's installation is removed, including on failure.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import signal
import socketserver
import subprocess
import sys
import threading
import time
from pathlib import Path

from amx.credentials import write_bundle
from amx.host import service_id, service_path


class Fixture(socketserver.ThreadingTCPServer):
    """Tiny loopback-only IMAP peer. Not an MTA/integration-suite substitute."""

    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, address: str, password: str):
        self.address, self.password = address, password
        self.messages: list[bytes] = []
        self.handled: set[int] = set()
        self.lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), Peer)

    def add(self, marker: str):
        raw = (
            f"From: fixture@example.invalid\r\nTo: {self.address}\r\n"
            f"Delivered-To: {self.address}\r\nMessage-ID: <{marker}@example.invalid>\r\n"
            "Subject: SH-23 private fixture\r\nAgent-Lane: human\r\nAgent-Trust: low\r\n"
            f"Content-Type: text/plain; charset=utf-8\r\n\r\n{marker}\r\n"
        ).encode()
        with self.lock:
            self.messages.append(raw)


class Peer(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(90)
        self.send(b"* OK private SH-23 IMAP fixture")
        authenticated = False
        while line := self.rfile.readline(65536):
            words = line.strip().split()
            if len(words) < 2:
                return
            tag, command = words[0], words[1].upper()
            fixture = self.server
            assert isinstance(fixture, Fixture)
            if command == b"CAPABILITY":
                self.send(b"* CAPABILITY IMAP4rev1 IDLE")
            elif command == b"LOGIN":
                expected = [fixture.address.encode(), fixture.password.encode()]
                if [word.strip(b'"') for word in words[2:]] != expected:
                    self.send(tag + b" NO fixture login refused")
                    continue
                authenticated = True
            elif command == b"LOGOUT":
                self.send(b"* BYE fixture closing")
                self.send(tag + b" OK LOGOUT")
                return
            elif not authenticated:
                self.send(tag + b" NO authenticate first")
                continue
            elif command == b"SELECT":
                self.send(b"* FLAGS (\\Seen $AmxHandled)")
                self.send(b"* OK [PERMANENTFLAGS (\\Seen \\*)] flags")
                self.send(b"* OK [UIDVALIDITY 1] fixture")
                self.send(f"* {len(fixture.messages)} EXISTS".encode())
            elif command == b"UID":
                action = words[2].upper()
                with fixture.lock:
                    if action == b"SEARCH":
                        ids = [
                            str(i + 1)
                            for i in range(len(fixture.messages))
                            if i + 1 not in fixture.handled
                        ]
                        self.send(("* SEARCH " + " ".join(ids)).encode())
                    elif action == b"FETCH":
                        uid = int(words[3])
                        raw = fixture.messages[uid - 1]
                        self.wfile.write(
                            f"* {uid} FETCH (UID {uid} BODY[] {{{len(raw)}}}\r\n".encode()
                        )
                        self.wfile.write(raw + b")\r\n")
                        self.wfile.flush()
                    elif action == b"STORE":
                        if b"$AmxHandled" in line:
                            fixture.handled.add(int(words[3]))
                    else:
                        raise AssertionError(f"unsupported fixture UID command: {action!r}")
            elif command == b"NOOP":
                self.send(f"* {len(fixture.messages)} EXISTS".encode())
            elif command == b"IDLE":
                self.send(b"+ fixture idling")
                if self.rfile.readline().strip().upper() != b"DONE":
                    return
            else:
                self.send(tag + b" BAD unsupported fixture command")
                continue
            self.send(tag + b" OK " + command)

    def send(self, data):
        self.wfile.write(data + b"\r\n")
        self.wfile.flush()


HANDLER = '''"""Private receive-only handler: no send or reply path."""
import json
import os
from pathlib import Path

def handle(message, context):
    assert message.lane == "human"
    assert message.thread.message_id.endswith("@example.invalid>")
    with Path("received.jsonl").open("a") as stream:
        stream.write(json.dumps({"message_id": message.thread.message_id,
                                 "text": message.text.strip(), "pid": os.getpid(),
                                 "uid": os.getuid()}) + "\\n")
'''


def wait_for(check, description, timeout=65):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(0.25)
    raise RuntimeError(f"timeout: {description}")


def validate_command(argv: list[str]) -> None:
    """Only the fixture's CLI, inspection commands and positive PID lookup are supported."""
    if not argv or any(
        not isinstance(arg, str) or any(ord(c) < 32 or ord(c) == 127 for c in arg) for arg in argv
    ):
        raise ValueError("invalid native fixture argv")
    unit = r"ai\.amx\.runner\.[0-9a-f]{24}\.service"
    target = re.escape(f"gui/{os.getuid()}/") + r"ai\.amx\.runner\.[0-9a-f]{24}"
    valid = False
    if argv[:2] == ["systemctl", "--user"] and len(argv) >= 4:
        valid = re.fullmatch(unit, argv[3]) is not None and (
            (argv[2] == "is-enabled" and len(argv) == 4)
            or (
                argv[2] == "show"
                and argv[4:]
                in [
                    ["-p", "MainPID", "--value"],
                    [
                        "-p",
                        "MainPID",
                        "-p",
                        "ActiveState",
                        "-p",
                        "UnitFileState",
                        "-p",
                        "ExecStart",
                        "-p",
                        "User",
                        "-p",
                        "UMask",
                    ],
                ]
            )
        )
    elif argv[:1] == ["launchctl"] and len(argv) == 3:
        valid = (argv[1] == "print" and re.fullmatch(target, argv[2]) is not None) or (
            argv[1:] == ["print-disabled", f"gui/{os.getuid()}"]
        )
    elif argv[:4] == ["ps", "-o", "uid=", "-p"] and len(argv) == 5:
        valid = re.fullmatch(r"[1-9][0-9]*", argv[4]) is not None
    elif argv[:4] == [sys.executable, "-m", "amx.cli", "host"]:
        if len(argv) == 10 and argv[4] == "install":
            bundle = Path(argv[5])
            valid = (
                bundle.is_absolute()
                and bundle.name == "fixture-bundle.json"
                and argv[6:]
                == [
                    "--state-home",
                    str(bundle.parent / "state"),
                    "--handler",
                    "fixture_handler:handle",
                ]
            )
        elif len(argv) == 9 and argv[4] == "uninstall":
            valid = (
                re.fullmatch(r"sh23-[0-9a-f]{16}@agents\.example\.invalid", argv[5]) is not None
                and argv[6] == "--state-home"
                and Path(argv[7]).is_absolute()
                and argv[8] == "--purge-state"
            )
    if not valid:
        raise ValueError("unsupported native fixture command/arguments")


def command(argv: list[str], *, check=True):
    validate_command(argv)
    # Audited fixture-only command grammar above; tokenized argv and no shell evaluation.
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
    result = subprocess.run(argv, shell=False, capture_output=True, text=True, timeout=50)
    if check and result.returncode:
        raise RuntimeError(f"command failed: {argv!r}: {result.stdout} {result.stderr}")
    return result


def launch_enabled(line: str) -> bool:
    # Older launchctl prints boolean disabled state; current macOS spells it out.
    return bool(re.search(r"=>\s*(?:false|enabled)\s*$", line))


def snapshot(identity: str, output: Path, label: str):
    if sys.platform == "linux":
        result = command(
            [
                "systemctl",
                "--user",
                "show",
                f"{identity}.service",
                "-p",
                "MainPID",
                "-p",
                "ActiveState",
                "-p",
                "UnitFileState",
                "-p",
                "ExecStart",
                "-p",
                "User",
                "-p",
                "UMask",
            ]
        )
        text = result.stdout
        pid = int(re.search(r"^MainPID=(\d+)$", text, re.M)[1])
    else:
        text = command(["launchctl", "print", f"gui/{os.getuid()}/{identity}"]).stdout
        found = re.search(r"\bpid = (\d+)", text)
        pid = int(found[1]) if found else 0
    # Do not persist inherited manager environment (which could contain auth state).
    text = re.sub(
        r"(?m)^\s*(?:inherited |default )?environment = \{\n.*?^\s*\}",
        "\n\tenvironment = [redacted]",
        text,
        flags=re.S,
    )
    (output / f"manager-{label}.txt").write_text(text)
    return pid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-native", action="store_true", help="explicitly allow native install")
    parser.add_argument("--output", type=Path, required=True, help="new private directory")
    parser.add_argument(
        "--source-sha", required=True, help="full source commit used for installation"
    )
    args = parser.parse_args()

    def terminate(_signum, _frame):
        raise SystemExit("native acceptance terminated; cleaning owned installation")

    signal.signal(signal.SIGTERM, terminate)
    if not args.run_native:
        parser.error("native service mutation requires --run-native")
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_sha):
        parser.error("--source-sha must be a full Git SHA")
    if sys.platform not in {"linux", "darwin"}:
        parser.error("Linux or macOS required")
    os.umask(0o077)
    output = args.output.expanduser().absolute()
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    nonce = secrets.token_hex(8)
    address = f"sh23-{nonce}@agents.example.invalid"
    identity = service_id(address)
    path = service_path(identity)
    if path.exists() or path.is_symlink():
        raise RuntimeError("refusing existing fixture service")
    state_home = output / "state"
    directory = state_home / identity
    directory.mkdir(parents=True, mode=0o700)
    (directory / "fixture_handler.py").write_text(HANDLER)
    bundle = output / "fixture-bundle.json"
    password = secrets.token_hex(24)
    fixture = Fixture(address, password)
    thread = threading.Thread(target=fixture.serve_forever, daemon=True)
    thread.start()
    write_bundle(
        bundle,
        {
            "address": address,
            "password": password,
            "token": secrets.token_hex(24),
            "imap": f"127.0.0.1:{fixture.server_address[1]}",
            "submission": "smtp://127.0.0.1:1",
        },
    )
    cli = [sys.executable, "-m", "amx.cli", "host"]
    receipt = {
        "source_sha": args.source_sha,
        "platform": sys.platform,
        "uid": os.getuid(),
        "address": address,
        "service": str(path),
        "python": sys.executable,
    }
    try:
        result = command(
            [
                *cli,
                "install",
                str(bundle),
                "--state-home",
                str(state_home),
                "--handler",
                "fixture_handler:handle",
            ]
        )
        (output / "install.txt").write_text(result.stdout)
        old_pid = wait_for(lambda: snapshot(identity, output, "before"), "runner start")
        uid = int(command(["ps", "-o", "uid=", "-p", str(old_pid)]).stdout.strip())
        assert uid == os.getuid(), "runner changed OS user"
        if sys.platform == "linux":
            enabled = command(["systemctl", "--user", "is-enabled", path.name]).stdout.strip()
            assert enabled == "enabled"
        else:
            import plistlib

            plist = plistlib.loads(path.read_bytes())
            assert plist["RunAtLoad"] and plist["KeepAlive"] and plist["Umask"] == 0o077
            disabled = command(["launchctl", "print-disabled", f"gui/{os.getuid()}"]).stdout
            line = next(line for line in disabled.splitlines() if f'"{identity}"' in line)
            assert launch_enabled(line), f"fixture job not enabled: {line.strip()}"
            enabled = line.strip()
        receipt["enabled_at_login"] = enabled
        received = directory / "received.jsonl"

        def deliveries():
            return (
                [json.loads(line) for line in received.read_text().splitlines()]
                if received.exists()
                else []
            )

        fixture.add(f"before-{nonce}")
        wait_for(lambda: len(deliveries()) == 1 and 1 in fixture.handled, "first fixture handled")
        os.kill(old_pid, signal.SIGKILL)

        def restarted():
            pid = snapshot(identity, output, "after")
            return pid if pid and pid != old_pid else None

        new_pid = wait_for(restarted, "runner restart after SIGKILL")
        fixture.add(f"after-{nonce}")
        wait_for(lambda: len(deliveries()) == 2 and 2 in fixture.handled, "post-restart mail")
        rows = deliveries()
        assert [row["pid"] for row in rows] == [old_pid, new_pid]
        assert all(row["uid"] == os.getuid() for row in rows)
        assert [row["text"] for row in rows] == [f"before-{nonce}", f"after-{nonce}"]
        receipt.update(
            pid_before=old_pid,
            pid_after=new_pid,
            received=rows,
            managed_credentials_mode=oct((directory / "credentials.json").stat().st_mode & 0o777),
            result="passed",
        )
        assert receipt["managed_credentials_mode"] == "0o600"
    except BaseException as error:
        receipt.update(result="failed", error=str(error))
        raise
    finally:
        try:
            if (directory / "install.json").exists():
                result = command(
                    [*cli, "uninstall", address, "--state-home", str(state_home), "--purge-state"]
                )
                (output / "uninstall.txt").write_text(result.stdout)
            assert not path.exists(), "fixture service file survived cleanup"
            if sys.platform == "linux":
                result = command(["systemctl", "--user", "is-enabled", path.name], check=False)
                assert result.returncode != 0
                pid = command(
                    ["systemctl", "--user", "show", path.name, "-p", "MainPID", "--value"],
                    check=False,
                )
                assert pid.stdout.strip() in {"", "0"}
                receipt["cleanup_manager"] = result.stderr.strip() or result.stdout.strip()
            else:
                result = command(
                    ["launchctl", "print", f"gui/{os.getuid()}/{identity}"], check=False
                )
                assert result.returncode != 0
                receipt["cleanup_manager"] = "launchctl print: job absent"
            receipt["cleanup"] = "service file absent; job stopped; owned state purged"
        finally:
            bundle.unlink(missing_ok=True)
            fixture.shutdown()
            fixture.server_close()
            thread.join(timeout=5)
            (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
            print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
