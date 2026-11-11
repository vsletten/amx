"""Native, same-user runner supervision. No Docker, root, or gateway changes (SH-23)."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import plistlib
import re
import shutil
import stat
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Annotated

import typer

from amx.adapters.ax import OfflinePolicy
from amx.credentials import BUNDLE_VERSION, read_bundle
from amx.mailbox import ImapEndpoint
from amx.sdk import Agent

app = typer.Typer(no_args_is_help=True, pretty_exceptions_show_locals=False)


def default_state_home() -> Path:
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "amx/host"


def service_id(address: str) -> str:
    """Full address, not local part: two servers may have the same agent name."""
    if not re.fullmatch(r"[a-z0-9][a-z0-9._+-]*@[a-z0-9][a-z0-9.-]*", address):
        raise ValueError("expected a lowercase agent email address")
    return "ai.amx.runner." + hashlib.sha256(address.encode()).hexdigest()[:24]


def service_path(identity: str) -> Path:
    if sys.platform == "linux":
        root = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
        return root / "systemd/user" / f"{identity}.service"
    if sys.platform == "darwin":
        return Path.home() / "Library/LaunchAgents" / f"{identity}.plist"
    raise ValueError("host services support Linux (systemd user) and macOS (launchd) only")


def manager_command(args: tuple[str, ...]) -> list[str]:
    """Closed grammar: only this user's AMX labels, never arbitrary manager options."""
    if any(
        not isinstance(arg, str) or any(ord(c) < 32 or ord(c) == 127 for c in arg) for arg in args
    ):
        raise ValueError("invalid service manager argv")
    label = r"ai\.amx\.runner\.[0-9a-f]{24}"
    unit = label + r"\.service"
    domain = f"gui/{os.getuid()}"
    valid = False
    if sys.platform == "linux":
        valid = (
            args == ("daemon-reload",)
            or (
                len(args) == 3
                and args[:2] in {("enable", "--now"), ("disable", "--now")}
                and re.fullmatch(unit, args[2]) is not None
            )
            or (
                len(args) == 4
                and args[0] == "show"
                and re.fullmatch(unit, args[1]) is not None
                and args[2]
                in {
                    "--property=LoadState",
                    "--property=ActiveState",
                    "--property=MainPID",
                    "--property=FragmentPath",
                    "--property=DropInPaths",
                }
                and args[3] == "--value"
            )
        )
        command = ["systemctl", "--user"]
    elif sys.platform == "darwin":
        valid = (
            len(args) == 2
            and args[0] in {"print", "enable", "disable", "bootout"}
            and re.fullmatch(re.escape(domain) + "/" + label, args[1]) is not None
        ) or (
            len(args) == 3
            and args[:2] == ("bootstrap", domain)
            and re.fullmatch(label, Path(args[2]).stem) is not None
            and args[2] == str(service_path(Path(args[2]).stem))
        )
        command = ["launchctl"]
    else:
        raise ValueError("unsupported service manager platform")
    if not valid:
        raise ValueError("unsupported service manager operation/arguments")
    return [*command, *args]


class Manager:
    """Only subprocess boundary; unit tests replace run before any command can execute."""

    def run(self, *args: str) -> subprocess.CompletedProcess[str]:
        command = manager_command(args)
        try:
            # Audited closed manager grammar above; tokenized argv, no shell or secret input.
            # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
            return subprocess.run(command, shell=False, capture_output=True, text=True, timeout=45)
        except subprocess.TimeoutExpired:
            raise RuntimeError(
                "service manager timed out; activation/stop may be incomplete"
            ) from None

    def checked(self, *args: str) -> str:
        result = self.run(*args)
        if result.returncode:
            raise RuntimeError(f"service manager {' '.join(args)}: {result.stderr.strip()}")
        return result.stdout

    def loaded(self, identity: str) -> bool:
        if sys.platform == "linux":
            state = self.property(identity, "LoadState")
            if not state:
                raise RuntimeError("service manager returned no LoadState")
            return state != "not-found"
        result = self.run("print", f"gui/{os.getuid()}/{identity}")
        if result.returncode == 0:
            return True
        absent = f'Could not find service "{identity}" in domain for user gui: {os.getuid()}'
        if (
            result.stderr.strip() in {absent, "Bad request.\n" + absent}
            and not result.stdout.strip()
        ):
            return False
        raise RuntimeError(f"service manager print: {result.stderr.strip()}")

    def property(self, identity: str, name: str) -> str:
        return self.checked("show", f"{identity}.service", f"--property={name}", "--value").strip()

    def assert_owned(self, identity: str, path: Path) -> None:
        if not self.loaded(identity):
            return
        if sys.platform == "linux":
            if self.property(identity, "FragmentPath") != str(path) or self.property(
                identity, "DropInPaths"
            ):
                raise ValueError("loaded service configuration differs from owned installation")
        else:
            text = self.checked("print", f"gui/{os.getuid()}/{identity}")
            if not any(line.strip() == f"path = {path}" for line in text.splitlines()):
                raise ValueError("loaded job path differs from owned installation")

    def confirm_inactive(self, identity: str) -> None:
        if sys.platform == "linux":
            if (
                self.property(identity, "ActiveState") not in {"inactive", "failed"}
                or self.property(identity, "MainPID") != "0"
            ):
                raise RuntimeError("service not confirmed inactive; keeping installation")
        elif self.loaded(identity):
            raise RuntimeError("job still loaded; keeping installation")

    def start(self, identity: str, path: Path) -> None:
        if sys.platform == "linux":
            self.checked("daemon-reload")
            self.checked("enable", "--now", path.name)
        else:
            self.checked("enable", f"gui/{os.getuid()}/{identity}")
            self.checked("bootstrap", f"gui/{os.getuid()}", str(path))

    def stop(self, identity: str, path: Path) -> None:
        if sys.platform == "linux":
            self.checked("disable", "--now", path.name)
        else:
            loaded = self.loaded(identity)
            self.checked("disable", f"gui/{os.getuid()}/{identity}")
            if loaded:
                self.checked("bootout", f"gui/{os.getuid()}/{identity}")
        self.confirm_inactive(identity)


def _path(path: Path) -> Path:
    value = path.expanduser().absolute()
    if any(ord(char) < 32 or ord(char) == 127 for char in str(value)):
        raise ValueError("paths must not contain control characters")
    return value


def _quote(value: str, *, exec_arg: bool = False) -> str:
    # systemd performs specifier expansion everywhere and dollar expansion in ExecStart.
    value = value.replace("%", "%%")
    if exec_arg:
        value = value.replace("$", "$$")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render(identity: str, directory: Path, argv: list[str]) -> bytes:
    """No secret in argv/unit/env. No User= or UserName: use the login user's AX socket."""
    if any(ord(char) < 32 or ord(char) == 127 for arg in argv for char in arg):
        raise ValueError("runner arguments must not contain control characters")
    if sys.platform == "darwin":
        return plistlib.dumps(
            {
                "Label": identity,
                "ProgramArguments": argv,
                "WorkingDirectory": str(directory),
                "RunAtLoad": True,
                "KeepAlive": True,
                "ThrottleInterval": 5,
                "Umask": 0o077,
                "Nice": 10,
                "StandardOutPath": str(directory / "runner.log"),
                "StandardErrorPath": str(directory / "runner.err.log"),
            }
        )
    command = " ".join(_quote(arg, exec_arg=True) for arg in argv)
    return (
        f"[Unit]\nDescription=AMX native runner {identity}\n\n[Service]\n"
        # WorkingDirectory uses unit_path_printf, NOT word parsing/C-unescaping:
        # quotes and backslashes are literal. Only % needs escaping. A final /.
        # protects trailing whitespace/backslash from INI trimming/line continuation.
        f"ExecStart={command}\nWorkingDirectory={str(directory).replace('%', '%%')}/.\n"
        "Restart=always\nRestartSec=5\nUMask=0077\nNice=10\n"
        "Environment=OMP_NUM_THREADS=16 OPENBLAS_NUM_THREADS=16 MKL_NUM_THREADS=16\n"
        "\n[Install]\nWantedBy=default.target\n"
    ).encode()


def _unlink_owned(path: Path, owned: os.stat_result) -> None:
    try:
        current = path.lstat()
    except FileNotFoundError:
        return
    if (current.st_dev, current.st_ino) != (owned.st_dev, owned.st_ino):
        raise ValueError(f"file replaced; refusing cleanup: {path}")
    path.unlink()


def _exclusive(path: Path, data: bytes) -> os.stat_result:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    owned = os.fstat(fd)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
    except BaseException:
        _unlink_owned(path, owned)
        raise
    return owned


@contextmanager
def _lock(root: Path):
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(root / ".host.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield


def _install(bundles, state_home, handler, ax, ax_home, ax_binary, ca, offline):
    if not (handler or ax):
        raise ValueError("pass --handler module:function and/or --ax TARGET")
    # Validate every bundle before touching state or the manager. Never print bundle content.
    prepared = []
    identities = set()
    for source in bundles:
        bundle = read_bundle(source)
        if not all(
            isinstance(bundle[key], str) and bundle[key]
            for key in ("address", "imap", "submission", "password", "token")
        ):
            raise ValueError("bundle fields must be non-empty strings")
        identity = service_id(bundle["address"])
        ImapEndpoint.parse(bundle["imap"])
        # Use the runner's own SDK parser, without connecting or importing handlers.
        Agent(bundle["address"], bundle["submission"], bundle["token"])
        if identity in identities:
            raise ValueError("duplicate agent bundle")
        identities.add(identity)
        prepared.append((identity, bundle))
    binary = None
    if ax:
        binary = shutil.which(ax_binary)
        if binary is None:
            raise ValueError("AX executable not found; install AX or set --ax-binary")
    ca = _path(ca) if ca else None
    if ca and not ca.is_file():
        raise ValueError("CA file does not exist")
    root = _path(state_home or default_state_home())
    rendered = []
    # Render the ENTIRE batch before creating even the first credentials file.
    for identity, bundle in prepared:
        directory = root / identity
        credentials = directory / "credentials.json"
        argv = [
            sys.executable,
            "-m",
            "amx.runner",
            "--credentials",
            str(credentials),
            "--state",
            str(directory),
            "--offline",
            offline.value,
        ]
        if handler:
            argv += ["--handler", handler]
        if ca:
            argv += ["--ca", str(ca)]
        if ax:
            argv += [
                "--ax",
                ax,
                # Reuse the full-address digest: local parts can repeat in ~/.ax.
                "--ax-name",
                "amx-" + identity.rsplit(".", 1)[1],
                "--ax-home",
                str(_path(ax_home or Path.home() / ".ax")),
                "--ax-binary",
                binary,
            ]
        path = _path(service_path(identity))
        data = render(identity, directory, argv)
        record = {
            "address": bundle["address"],
            "service": str(path),
            "sha256": hashlib.sha256(data).hexdigest(),
            "platform": sys.platform,
        }
        rendered.append((identity, bundle, path, directory, data, record))
    manager = Manager()
    # One per-user lock also serializes installs using different --state-home values.
    with _lock(service_path(prepared[0][0]).parent):
        for identity, _, path, directory, _, _ in rendered:
            if path.exists() or path.is_symlink() or directory.is_symlink():
                raise ValueError(f"refusing existing service or symlink: {path}")
            for name in ("install.json", "credentials.json"):
                candidate = directory / name
                if candidate.exists() or candidate.is_symlink():
                    raise ValueError(f"runner already installed: {identity}; uninstall it first")
            if manager.loaded(identity):
                raise ValueError(f"runner already installed: {identity}; uninstall it first")
        completed = []
        for identity, bundle, path, directory, data, record in rendered:
            created = []
            activation_attempted = False
            try:
                directory.mkdir(parents=True, exist_ok=True, mode=0o700)
                if directory.stat().st_uid != os.getuid():
                    raise ValueError("runner state must belong to this user")
                directory.chmod(0o700)
                payloads = [
                    (
                        directory / "credentials.json",
                        json.dumps({"amx_credentials": BUNDLE_VERSION, **bundle}).encode(),
                    ),
                    (directory / "install.json", (json.dumps(record) + "\n").encode()),
                    (path, data),
                ]
                for target, payload in payloads:
                    created.append((target, _exclusive(target, payload)))
                # After this boundary a timeout may mean the runner IS active.
                activation_attempted = True
                manager.start(identity, path)
            except (OSError, ValueError, RuntimeError):
                if not activation_attempted:
                    for target, owned in reversed(created):
                        _unlink_owned(target, owned)
                typer.echo(
                    f"install failed for {bundle['address']} ({identity}); "
                    f"completed: {', '.join(completed) or 'none'}; "
                    "uninstall recorded installations before retry",
                    err=True,
                )
                raise
            completed.append(bundle["address"])
            typer.echo(f"installed {bundle['address']}: {path}")


@app.command("install")
def install(
    bundles: Annotated[list[Path], typer.Argument(exists=True, dir_okay=False)],
    handler: Annotated[str | None, typer.Option("--handler")] = None,
    ax: Annotated[str | None, typer.Option("--ax")] = None,
    ax_home: Annotated[Path | None, typer.Option("--ax-home")] = None,
    ax_binary: Annotated[str, typer.Option("--ax-binary")] = "ax",
    ca: Annotated[Path | None, typer.Option("--ca")] = None,
    state_home: Annotated[Path | None, typer.Option("--state-home")] = None,
    offline: Annotated[OfflinePolicy, typer.Option("--offline")] = OfflinePolicy.HOLD,
) -> None:
    """Install bundles from `amx agent add`: one native runner per address at login.

    Run as the agent's OS user, without sudo. Source bundles are not deleted.
    """
    try:
        _install(bundles, state_home, handler, ax, ax_home, ax_binary, ca, offline)
    except (OSError, ValueError, RuntimeError) as error:
        typer.echo(f"error: {error}", err=True)
        raise typer.Exit(1) from None


@app.command("uninstall")
def uninstall(
    address: Annotated[str, typer.Argument(help="Full agent address")],
    state_home: Annotated[Path | None, typer.Option("--state-home")] = None,
    purge_state: Annotated[bool, typer.Option("--purge-state")] = False,
) -> None:
    """Stop and remove only a recorded installation; preserve handling state by default."""
    try:
        identity = service_id(address)
        root = _path(state_home or default_state_home())
        directory = root / identity
        path = service_path(identity)
        with _lock(path.parent):
            if directory.is_symlink() or path.is_symlink():
                raise ValueError("refusing symlink installation")
            receipt = directory / "install.json"
            receipt_stat = receipt.lstat()
            if (
                not stat.S_ISREG(receipt_stat.st_mode)
                or receipt_stat.st_uid != os.getuid()
                or receipt_stat.st_mode & 0o077
            ):
                raise ValueError("installation receipt must be private and owned")
            record = json.loads(receipt.read_text())
            if not isinstance(record, dict) or not isinstance(record.get("sha256"), str):
                raise ValueError("invalid installation receipt")
            if (
                record.get("address") != address
                or record.get("service") != str(path)
                or record.get("platform") != sys.platform
                or not re.fullmatch(r"[0-9a-f]{64}", record.get("sha256", ""))
            ):
                raise ValueError("installation receipt does not match this host/address")
            manager = Manager()
            if path.exists():
                owned = path.lstat()
                if (
                    not stat.S_ISREG(owned.st_mode)
                    or owned.st_uid != os.getuid()
                    or hashlib.sha256(path.read_bytes()).hexdigest() != record["sha256"]
                ):
                    raise ValueError("service file changed; refusing to stop or delete it")
                manager.assert_owned(identity, path)
                manager.stop(identity, path)
                if hashlib.sha256(path.read_bytes()).hexdigest() != record["sha256"]:
                    raise ValueError("service file changed while stopping; refusing cleanup")
                _unlink_owned(path, owned)
            else:
                # Interrupted cleanup is recoverable, but never stop/adopt an unknown job.
                manager.assert_owned(identity, path)
                manager.confirm_inactive(identity)
                if sys.platform == "darwin":
                    manager.checked("disable", f"gui/{os.getuid()}/{identity}")
            if sys.platform == "linux":
                manager.checked("daemon-reload")
            # Recheck after reload; retain receipt/credentials on any ambiguous result.
            manager.confirm_inactive(identity)
            (directory / "credentials.json").unlink(missing_ok=True)
            _unlink_owned(receipt, receipt_stat)
            if purge_state:
                shutil.rmtree(directory)
            typer.echo(f"uninstalled {address}; source bundle unchanged")
    except (OSError, ValueError, KeyError, RuntimeError) as error:
        typer.echo(f"error: {error}", err=True)
        raise typer.Exit(1) from None
