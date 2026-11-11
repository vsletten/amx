"""People accounts: hash-only desired state consumed by Stalwart's management sync."""

from __future__ import annotations

import getpass
import json
import os
import re
import stat
import subprocess
import uuid
from pathlib import Path
from typing import Annotated

import typer

from amx.credentials import hash_password
from amx.live import RESERVED_NAMES, LiveParams, load_params, new_secret
from amx.provision import write_private
from amx.registry import locked

app = typer.Typer(no_args_is_help=True, pretty_exceptions_show_locals=False)
Params = Annotated[Path, typer.Option("--params", exists=True, dir_okay=False)]
SecretFile = Annotated[Path | None, typer.Option("--password-file")]
SecretOut = Annotated[
    Path | None,
    typer.Option("--password-out", help="Generate an account password into a new 0600 file"),
]

RESERVED = {
    "admin",
    "postmaster",
    "abuse",
    "hostmaster",
    "webmaster",
    "security",
    "gateway",
    "approver",
    "holds",
    "amx",
    "mailer-daemon",
    "root",
}


def identity(value: str, domain: str) -> str:
    address = value if "@" in value else f"{value}@{domain}"
    local, _, actual = address.partition("@")
    if (
        actual != domain
        or not re.fullmatch(r"[a-z0-9]+(?:[._-][a-z0-9]+)*", local)
        or len(local) > 64
    ):
        raise ValueError("use a lowercase person name or address in the people domain")
    if local in RESERVED or local in RESERVED_NAMES:
        raise ValueError("reserved system identity")
    return address


def state_path(params: LiveParams) -> Path:
    if params.mta != "stalwart":
        raise ValueError("amx user requires mta: stalwart")
    path = params.secrets_dir / "stalwart" / "people.json"
    if not path.parent.is_dir():
        raise ValueError("run amx live install first")
    return path


def read_people(path: Path) -> dict:
    return json.loads(path.read_text())


def password(secret_file: Path | None, output: Path | None, owned: list) -> str:
    if secret_file and output:
        raise ValueError("choose --password-file or --password-out")
    if output:
        token = new_secret()
        # Exclusive output: never overwrite credentials, follow a symlink or print a secret.
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            owned.append(os.fstat(stream.fileno()))
            stream.write(token + "\n")
    elif secret_file:
        if secret_file.is_symlink() or stat.S_IMODE(secret_file.stat().st_mode) & 0o077:
            raise ValueError("password file must be private (0600) and not a symlink")
        token = secret_file.read_text().strip()
    else:
        token = getpass.getpass("Account password: ")
    if len(token) < 16 or any(ord(char) < 32 for char in token):
        raise ValueError("password must have at least 16 characters and no control characters")
    return token


def change(
    params_path: Path,
    name: str,
    action: str,
    *,
    owner: bool | None = None,
    secret_file: Path | None = None,
    output: Path | None = None,
    app_output: Path | None = None,
) -> None:
    params = load_params(params_path)
    address = identity(name, params.org_domain)
    path = state_path(params)
    with locked(path.parent):
        people = read_people(path)
        current = people.get(address)
        if action == "add" and current:
            raise ValueError("person already exists (removed identities are retained)")
        if action != "add" and (not current or not current["enabled"]):
            raise ValueError("no active managed person by that name")
        before = path.read_bytes()
        owned = []
        try:
            if action == "remove":
                assert current is not None
                current.update(enabled=False, owner=False)
            else:
                secret = password(secret_file, output, owned)
                generation = uuid.uuid4().hex
                people[address] = {
                    "secret": hash_password(secret).removeprefix("{SHA512-CRYPT}"),
                    "owner": bool(current and current["owner"]) if owner is None else owner,
                    "enabled": True,
                    "generation": generation,
                    "ownership": current["ownership"] if current else uuid.uuid4().hex,
                    "generations": [*(current["generations"] if current else []), generation],
                }
            write_private(path, json.dumps(people, indent=2) + "\n")
        except BaseException:
            # write_private can raise AFTER rename (directory fsync). Keep a possibly
            # committed credential. Only unchanged state proves publication failed.
            try:
                if output and owned and path.read_bytes() == before:
                    actual = output.lstat()
                    if (actual.st_dev, actual.st_ino) == (owned[0].st_dev, owned[0].st_ino):
                        output.unlink()
            except OSError:
                pass  # Ambiguous publication/ownership: never remove another file.
            raise
    typer.echo(f"{address}: {action} queued for Stalwart sync")
    if action != "remove" and app_output:
        from amx.mail_client import issue_app_password

        issue_app_password(params, address, secret, app_output)
        typer.echo("native app password written to private output file")


def guarded(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError):
        # Never echo exception payloads from a credential-handling path.
        typer.echo(
            "user operation refused: check identity, state and private password files", err=True
        )
        raise typer.Exit(1) from None


@app.command("add")
def add(
    name: str,
    params: Params,
    owner: bool = False,
    password_file: SecretFile = None,
    password_out: SecretOut = None,
    app_password_out: Annotated[Path | None, typer.Option("--app-password-out")] = None,
):
    guarded(
        change,
        params,
        name,
        "add",
        owner=owner,
        secret_file=password_file,
        output=password_out,
        app_output=app_password_out,
    )


@app.command("passwd")
def passwd(
    name: str,
    params: Params,
    owner: Annotated[bool | None, typer.Option("--owner/--no-owner")] = None,
    password_file: SecretFile = None,
    password_out: SecretOut = None,
    app_password_out: Annotated[Path | None, typer.Option("--app-password-out")] = None,
):
    guarded(
        change,
        params,
        name,
        "passwd",
        owner=owner,
        secret_file=password_file,
        output=password_out,
        app_output=app_password_out,
    )


@app.command("remove")
def remove(name: str, params: Params):
    guarded(change, params, name, "remove")


@app.command("list")
def list_users(params: Params):
    def show():
        for address, person in sorted(read_people(state_path(load_params(params))).items()):
            if person["enabled"]:
                typer.echo(address + (" owner" if person["owner"] else ""))

    guarded(show)


@app.command("profile")
def profile(name: str, params: Params, output: Annotated[Path, typer.Option("--output")]):
    """Write an actual Apple Mail payload; the device prompts for its app password."""
    import plistlib

    def write():
        site = load_params(params)
        address = identity(name, site.org_domain)
        person = read_people(state_path(site)).get(address)
        if not person or not person["enabled"]:
            raise ValueError("unknown person")
        identifier = "ai.amx.mail." + uuid.uuid4().hex
        mail = {
            "PayloadType": "com.apple.mail.managed",
            "PayloadVersion": 1,
            "PayloadIdentifier": identifier + ".account",
            "PayloadUUID": str(uuid.uuid4()),
            "PayloadDisplayName": address,
            "EmailAccountDescription": "amx",
            "EmailAccountType": "EmailTypeIMAP",
            "EmailAddress": address,
            "IncomingMailServerHostName": site.mx_host,
            "IncomingMailServerPortNumber": site.ports["imaps"],
            "IncomingMailServerUseSSL": True,
            "IncomingMailServerUsername": address,
            "IncomingMailServerAuthentication": "EmailAuthPassword",
            "OutgoingMailServerHostName": site.mx_host,
            "OutgoingMailServerPortNumber": site.ports["people_submission"],
            "OutgoingMailServerUseSSL": True,
            "OutgoingMailServerUsername": address,
            "OutgoingMailServerAuthentication": "EmailAuthPassword",
            "OutgoingPasswordSameAsIncomingPassword": True,
        }
        payload = {
            "PayloadType": "Configuration",
            "PayloadVersion": 1,
            "PayloadIdentifier": identifier,
            "PayloadUUID": str(uuid.uuid4()),
            "PayloadDisplayName": "amx " + address,
            "PayloadContent": [mail],
        }
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            plistlib.dump(payload, stream)
        typer.echo(str(output))

    guarded(write)
