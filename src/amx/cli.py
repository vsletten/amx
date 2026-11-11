"""Command-line surfaces: provisioning, DNS, journal verification, tracing, and scenarios."""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated

import typer
import yaml

from amx import domain_dkim
from amx import live as live_lane
from amx import registration as reg
from amx.config import GatewayConfig, load_config
from amx.host import app as host_app
from amx.journal import Journal
from amx.live import app as live_app
from amx.narrate import (
    Gateway,
    journal_line,
    policy_line,
    run_scenarios,
    scenario_files,
    stalwart_line,
)
from amx.provision import dkim_public_key, dkim_txt_value, generate_dkim_key
from amx.registry import Grant, delete_grant, locked, read_grants, read_registrations, write_grant
from amx.store import Store
from amx.users import app as user_app

# `agent add` and `agent rotate` hold an agent's secrets in local variables: never show locals.
app = typer.Typer(no_args_is_help=True, pretty_exceptions_show_locals=False)
agent_app = typer.Typer(no_args_is_help=True)
dns_app = typer.Typer(no_args_is_help=True)
journal_app = typer.Typer(no_args_is_help=True)
scenario_app = typer.Typer(no_args_is_help=True)
trust_app = typer.Typer(no_args_is_help=True)
app.add_typer(agent_app, name="agent")
app.add_typer(dns_app, name="dns")
app.add_typer(trust_app, name="trust")
app.add_typer(journal_app, name="journal")
app.add_typer(scenario_app, name="scenario")
app.add_typer(live_app, name="live")
app.add_typer(host_app, name="host")
app.add_typer(user_app, name="user")

# A source checkout (src/amx/cli.py -> repository root); else the working directory.
_CHECKOUT = Path(__file__).resolve().parents[2]

_COMPOSE_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z")


ConfigOption = Annotated[Path, typer.Option("--config", exists=True, dir_okay=False)]
RegistryOption = Annotated[
    Path | None,
    typer.Option("--registry-dir", help="Override the YAML's registry_dir (a host path)"),
]
KeysOption = Annotated[
    Path | None, typer.Option("--keys-dir", help="Override the YAML's keys_dir (a host path)")
]
AccountsOption = Annotated[
    Path | None,
    typer.Option("--accounts-file", help="Override the YAML's accounts_file (a host path)"),
]
DkimBitsOption = Annotated[
    int | None,
    typer.Option(
        "--dkim-bits",
        help="A new key's size: 2048, or 1024 where DNS cannot hold it (default: the YAML's)",
    ),
]


HouseholdOption = Annotated[
    str | None, typer.Option("--household", help="Agent household label (SH-47)")
]
AcceptFromOption = Annotated[
    list[str] | None,
    typer.Option("--accept-from", help="Allowed person's address or domain; repeatable"),
]
OutboundAllowlistOption = Annotated[
    list[str] | None,
    typer.Option("--outbound-allowlist", help="Outbound address or domain; repeatable"),
]


def _yaml_agents(config_path: Path) -> frozenset[str]:
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    agents = raw.get("agents") if isinstance(raw, dict) else None
    return frozenset(str(name) for name in agents) if isinstance(agents, dict) else frozenset()


def _site(
    config_path: Path,
    registry_dir: Path | None,
    keys_dir: Path | None,
    accounts_file: Path | None,
    *,
    dkim_bits: int | None = None,
) -> tuple[GatewayConfig, reg.Site]:
    """The gateway's registration state, with host-side paths where the YAML's are a container's."""
    config = load_config(config_path)
    registry = registry_dir or config.registry_dir
    accounts = accounts_file or config.accounts_file
    if registry is None:
        raise typer.BadParameter("set registry_dir in the gateway YAML, or pass --registry-dir")
    if accounts is None:
        raise typer.BadParameter("set accounts_file in the gateway YAML, or pass --accounts-file")
    site = reg.Site(
        domain=config.domain,
        agent_domain=config.agent_domain,
        registry_dir=registry,
        keys_dir=keys_dir or config.keys_dir,
        accounts_file=accounts,
        yaml_agents=_yaml_agents(config_path),
        reserved=frozenset({config.control.address}) | config.role_addresses,
        # The gateway's own load, run on each command's result before it is kept.
        validate=lambda: load_config(config_path, registry_dir=registry),
        dkim_bits=dkim_bits or config.dkim_bits,
        zone=config.zone,
    )
    return config, site


def _echo_dkim(site: reg.Site, selector: str, role: str) -> None:
    fqdn = reg.dkim_name(selector, site.agent_domain)
    typer.echo(f"DKIM for selector {selector} ({role}): publish in the {site.dns_zone} zone")
    for line in reg.record_lines(fqdn, reg.dkim_value(site.key_path(selector)), site.dns_zone):
        typer.echo(line)


def _echo_card(site: reg.Site, name: str) -> None:
    fqdn = f"{name}._agents.{site.agent_domain}"
    typer.echo("Discovery (optional): the agent card pointer")
    for line in reg.record_lines(fqdn, reg.card_value(site, name), site.dns_zone):
        typer.echo(line)


def _fail(error: Exception) -> typer.Exit:
    typer.echo(f"error: {error}", err=True)
    return typer.Exit(1)


@agent_app.command("add")
def agent_add(
    name: Annotated[str, typer.Argument(help="Agent local-part and DKIM selector")],
    config_path: ConfigOption,
    handler: Annotated[str | None, typer.Option("--handler")] = None,
    keys_dir: KeysOption = None,
    dev_users: Annotated[Path | None, typer.Option("--dev-users")] = None,
    live: Annotated[
        bool,
        typer.Option(
            "--live",
            help="Operator registration: random credentials, hashes only, one bundle (§5.2)",
        ),
    ] = False,
    mode: Annotated[
        str | None, typer.Option("--mode", help="remote (live default), sync, queued")
    ] = None,
    watermark: Annotated[int, typer.Option("--watermark")] = 2,
    workers: Annotated[int, typer.Option("--workers")] = 1,
    intents: Annotated[list[str] | None, typer.Option("--intent", help="Repeatable")] = None,
    schemas: Annotated[list[str] | None, typer.Option("--schema", help="Repeatable")] = None,
    can_open_tasks: Annotated[bool, typer.Option("--can-open-tasks/--no-open-tasks")] = True,
    bundle: Annotated[
        Path | None, typer.Option("--bundle", help="Where to write the one-time credentials")
    ] = None,
    imap: Annotated[
        str | None,
        typer.Option(
            "--imap",
            help="Where the agent's host reaches IMAP: host:port (plain text), or imaps://host[:port]",
        ),
    ] = None,
    submission: Annotated[
        str | None, typer.Option("--submission", help="smtp://host:port of the gateway")
    ] = None,
    registry_dir: RegistryOption = None,
    accounts_file: AccountsOption = None,
    dkim_bits: DkimBitsOption = None,
    household: HouseholdOption = None,
    accept_from: AcceptFromOption = None,
    outbound_allowlist: OutboundAllowlistOption = None,
) -> None:
    """Register an agent: the dev stack's way by default, or an operator's with --live."""
    if live:
        _agent_add_live(
            name,
            config_path,
            mode=mode or "remote",
            handler=handler or "mailbox-only",
            watermark=watermark,
            workers=workers,
            intents=tuple(intents or reg.DEFAULT_INTENTS),
            schemas=tuple(schemas or ("*",)),
            can_open_tasks=can_open_tasks,
            bundle=bundle,
            imap=imap,
            submission=submission,
            registry_dir=registry_dir,
            keys_dir=keys_dir,
            accounts_file=accounts_file,
            dkim_bits=dkim_bits,
            household=household,
            accept_from=accept_from,
            outbound_allowlist=outbound_allowlist,
        )
        return
    if household is not None or accept_from is not None or outbound_allowlist is not None:
        raise typer.BadParameter(
            "household and address-list options require --live; otherwise edit the gateway YAML"
        )
    handler = handler or "mailbox-only"
    if not name.replace("-", "").isalnum() or name.casefold() != name:
        raise typer.BadParameter("name must contain lowercase letters, digits, or hyphens")
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise typer.BadParameter("config root must be a mapping")
    registered = registry_dir or (
        (config_path.parent / str(raw["registry_dir"])).resolve()
        if raw.get("registry_dir")
        else None
    )
    if registry_dir is None and registered is not None and not registered.is_dir():
        # The YAML names the gateway container's path (the dev stack's /data/registry): a name
        # can be checked against registered agents only with the host's path.
        raise typer.BadParameter(
            f"the YAML's registry_dir {registered} is not on this host: pass --registry-dir "
            "(on the dev stack, deploy/generated/state/<ct|nw>/registry)"
        )
    if registered is not None and name in read_registrations(registered):
        # The YAML would then name a registered agent, and the gateway would not load it.
        raise typer.BadParameter(f"{name} is a registered agent (amx agent add --live)")
    agent_domain = str(raw.get("agent_domain", f"agents.{raw['domain']}"))
    destination = keys_dir or config_path.parent / "keys"
    destination.mkdir(parents=True, exist_ok=True)
    private_key = destination / f"{name}.private.pem"
    try:
        generate_dkim_key(private_key)
    except FileExistsError as error:
        raise typer.BadParameter(str(error)) from error
    agents = raw.setdefault("agents", {})
    if not isinstance(agents, dict):
        raise typer.BadParameter("agents must be a mapping")
    agents[name] = {
        "handler": handler,
        "mode": "sync",
        "watermark": 2,
        "workers": 1,
        "enabled": True,
        "submit_token": f"dev-{name}-token",
    }
    config_path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    if dev_users is not None:
        existing = dev_users.read_text(encoding="utf-8") if dev_users.exists() else ""
        address = f"{name}@{agent_domain}"
        if not any(line.startswith(f"{address}|") for line in existing.splitlines()):
            with dev_users.open("a", encoding="utf-8") as stream:
                stream.write(f"{address}|dev-{name}\n")
    value = dkim_txt_value(dkim_public_key(private_key))
    typer.echo(f'{name}._domainkey.{agent_domain}. 30 IN TXT "{value}"')


def _agent_add_live(
    name: str,
    config_path: Path,
    *,
    mode: str,
    handler: str,
    watermark: int,
    workers: int,
    intents: tuple[str, ...],
    schemas: tuple[str, ...],
    can_open_tasks: bool,
    bundle: Path | None,
    imap: str | None,
    submission: str | None,
    registry_dir: Path | None,
    keys_dir: Path | None,
    accounts_file: Path | None,
    dkim_bits: int | None = None,
    check_hint: str | None = None,
    card: bool = True,
    household: str | None = None,
    accept_from: list[str] | None = None,
    outbound_allowlist: list[str] | None = None,
) -> None:
    if bundle is None or imap is None or submission is None:
        raise typer.BadParameter("--live needs --bundle, --imap, and --submission")
    if mode in {"sync", "queued"} and handler == "mailbox-only":
        raise typer.BadParameter(f"a {mode} agent needs --handler module:function")
    _config, site = _site(config_path, registry_dir, keys_dir, accounts_file, dkim_bits=dkim_bits)
    try:
        result = reg.add(
            site,
            name,
            bundle=bundle,
            imap=imap,
            submission=submission,
            mode=mode,
            handler=handler,
            watermark=watermark,
            workers=workers,
            intents=intents,
            schemas=schemas,
            can_open_tasks=can_open_tasks,
            household=household,
            accept_from=accept_from,
            outbound_allowlist=outbound_allowlist,
        )
    except (reg.RegistrationError, ValueError) as error:
        raise _fail(error) from error
    typer.echo(f"registered {site.address(name)} ({mode}); the gateway and mailhost pick it up")
    if result.key is not None:
        typer.echo(f"  DKIM key: {result.key} (0600)")
    typer.echo(f"  credentials bundle: {result.bundle} (0600, one copy: hand it over, then delete)")
    if result.key is None:
        typer.echo("  DKIM: signed with the domain's key (SH-44); no DNS change for this agent")
    else:
        _echo_dkim(site, name, "active")
    if card:
        _echo_card(site, name)
    if result.key is not None:
        typer.echo(f"then check it: {check_hint or f'amx dns check {name} --config {config_path}'}")


def _set_agent_policy(
    site: reg.Site,
    name: str,
    *,
    household: str | None,
    accept_from: list[str] | None,
    outbound_allowlist: list[str] | None,
    default_household: bool,
    accept_any: bool,
    outbound_any: bool,
    inherit_accept_from: bool,
    inherit_outbound_allowlist: bool,
) -> None:
    try:
        if (accept_any and accept_from is not None) or (
            outbound_any and outbound_allowlist is not None
        ):
            raise ValueError("cannot combine a list with its --any flag")
        reg.set_policy(
            site,
            name,
            household=household,
            accept_from=[] if accept_any else accept_from,
            outbound_allowlist=[] if outbound_any else outbound_allowlist,
            default_household=default_household,
            inherit_accept_from=inherit_accept_from,
            inherit_outbound_allowlist=inherit_outbound_allowlist,
        )
    except (reg.RegistrationError, ValueError) as error:
        raise _fail(error) from error
    typer.echo(
        f"updated {site.address(name)} policy; registry reload applies it, credentials unchanged"
    )


@agent_app.command("set")
def agent_set(
    name: str,
    config_path: ConfigOption,
    household: HouseholdOption = None,
    accept_from: AcceptFromOption = None,
    outbound_allowlist: OutboundAllowlistOption = None,
    default_household: Annotated[bool, typer.Option("--default-household")] = False,
    accept_any: Annotated[bool, typer.Option("--accept-any")] = False,
    outbound_any: Annotated[bool, typer.Option("--outbound-any")] = False,
    inherit_accept_from: Annotated[bool, typer.Option("--inherit-accept-from")] = False,
    inherit_outbound_allowlist: Annotated[
        bool, typer.Option("--inherit-outbound-allowlist")
    ] = False,
    registry_dir: RegistryOption = None,
    keys_dir: KeysOption = None,
    accounts_file: AccountsOption = None,
) -> None:
    """Replace policy fields on a registered agent, without rotating its credentials or keys."""
    _, site = _site(config_path, registry_dir, keys_dir, accounts_file)
    _set_agent_policy(
        site,
        name,
        household=household,
        accept_from=accept_from,
        outbound_allowlist=outbound_allowlist,
        default_household=default_household,
        accept_any=accept_any,
        outbound_any=outbound_any,
        inherit_accept_from=inherit_accept_from,
        inherit_outbound_allowlist=inherit_outbound_allowlist,
    )


@agent_app.command("remove")
def agent_remove(
    name: str,
    config_path: ConfigOption,
    purge: Annotated[
        bool, typer.Option("--purge", help="Delete the mailbox and keys of a disabled agent")
    ] = False,
    grace: Annotated[str, typer.Option("--grace", help="How long disabled before a purge")] = "7d",
    now: Annotated[bool, typer.Option("--now", help="Purge before the grace period ends")] = False,
    registry_dir: RegistryOption = None,
    keys_dir: KeysOption = None,
    accounts_file: AccountsOption = None,
) -> None:
    """Disable an agent (RCPT refuses it, no login works); --purge deletes it after a grace."""
    _config, site = _site(config_path, registry_dir, keys_dir, accounts_file)
    _remove(site, name, purge=purge, grace=grace, now=now, again=_again(config_path))


def _again(config_path: Path) -> Callable[[str], str]:
    """How a follow-up `amx agent` command is spelled for this gateway YAML."""
    return lambda rest: f"amx agent {rest} --config {config_path}"


def _remove(
    site: reg.Site, name: str, *, purge: bool, grace: str, now: bool, again: Callable[[str], str]
) -> None:
    try:
        if not purge:
            disabled = reg.disable(site, name)
            typer.echo(f"disabled {site.address(name)} at {disabled.disabled_at}")
            typer.echo("  RCPT now refuses it (550 5.1.1), and its logins fail.")
            typer.echo(f"  purge after {grace}: {again(f'remove {name} --purge')}")
            return
        purged = reg.purge(site, name, grace=reg.parse_duration(grace), force=now)
    except (reg.RegistrationError, ValueError, KeyError) as error:
        raise _fail(error) from error
    typer.echo(f"purged {site.address(name)}: the mailhost deletes its mailbox")
    for key in purged.deleted_keys:
        typer.echo(f"  deleted {key}")
    typer.echo("  delete these DNS records:")
    for fqdn in purged.unpublish:
        typer.echo(
            f"    {fqdn} (name in zone {site.dns_zone}: {reg.relative_name(fqdn, site.dns_zone)})"
        )


@agent_app.command("enable")
def agent_enable(
    name: str,
    config_path: ConfigOption,
    registry_dir: RegistryOption = None,
    keys_dir: KeysOption = None,
    accounts_file: AccountsOption = None,
) -> None:
    """Re-enable a disabled agent with the credentials and key it had."""
    _config, site = _site(config_path, registry_dir, keys_dir, accounts_file)
    _enable(site, name)


def _enable(site: reg.Site, name: str) -> None:
    try:
        reg.enable(site, name)
    except (reg.RegistrationError, KeyError) as error:
        raise _fail(error) from error
    typer.echo(f"enabled {site.address(name)}")


CredentialsFlag = Annotated[
    bool, typer.Option("--credentials/--no-credentials", help="New token and password")
]
DkimFlag = Annotated[
    bool, typer.Option("--dkim/--no-dkim", help="Stage a new key under a new selector")
]
ActivateFlag = Annotated[
    bool, typer.Option("--activate", help="Sign with the staged key (after it is in DNS)")
]
OverlapOption = Annotated[
    str, typer.Option("--overlap", help="How long the old key stays published")
]
DnsCheckFlag = Annotated[bool, typer.Option("--dns-check/--no-dns-check", help="With --activate")]
DnsServerOption = Annotated[
    str | None, typer.Option("--dns-server", help="Resolver for --activate's check: ip or ip:port")
]


@agent_app.command("rotate")
def agent_rotate(
    name: str,
    config_path: ConfigOption,
    credentials: CredentialsFlag = True,
    dkim: DkimFlag = True,
    activate: ActivateFlag = False,
    overlap: OverlapOption = "7d",
    dns_check: DnsCheckFlag = True,
    dns_server: DnsServerOption = None,
    bundle: Annotated[Path | None, typer.Option("--bundle")] = None,
    imap: Annotated[
        str | None,
        typer.Option(
            "--imap",
            help="For the new bundle (default: as before): host:port, or imaps://host[:port]",
        ),
    ] = None,
    submission: Annotated[
        str | None,
        typer.Option(
            "--submission", help="For the new bundle (default: as before): smtp://host:port"
        ),
    ] = None,
    registry_dir: RegistryOption = None,
    keys_dir: KeysOption = None,
    accounts_file: AccountsOption = None,
    dkim_bits: DkimBitsOption = None,
) -> None:
    """New credentials (a new bundle) and a new staged DKIM key; --activate switches signing."""
    config, site = _site(config_path, registry_dir, keys_dir, accounts_file, dkim_bits=dkim_bits)
    _rotate(
        config,
        site,
        name,
        credentials=credentials,
        dkim=dkim,
        activate=activate,
        overlap=overlap,
        dns_check=dns_check,
        dns_server=dns_server,
        bundle=bundle,
        imap=imap,
        submission=submission,
        again=_again(config_path),
        check=f"amx dns check {name} --config {config_path}",
    )


def _rotate(
    config: GatewayConfig,
    site: reg.Site,
    name: str,
    *,
    credentials: bool,
    dkim: bool,
    activate: bool,
    overlap: str,
    dns_check: bool,
    dns_server: str | None,
    bundle: Path | None,
    imap: str | None,
    submission: str | None,
    again: Callable[[str], str],
    check: str,
) -> None:
    try:
        if activate:
            registration = read_registrations(site.registry_dir).get(name)
            pending = registration.pending_selector if registration else None
            if pending is None:
                raise reg.RegistrationError(
                    f"{name} has no staged key: run `{again(f'rotate {name}')}` first"
                )
            if dns_check:
                status = reg.dkim_matches(
                    reg.lookup_txt(
                        reg.dkim_name(pending, site.agent_domain), dns_server or config.dns_server
                    ),
                    site.key_path(pending),
                )
                if status != "ok":
                    raise reg.RegistrationError(
                        f"the staged key {pending} is {status} in DNS; publish it, or pass "
                        "--no-dns-check"
                    )
            activated = reg.activate(
                site, name, overlap=reg.parse_duration(overlap), expected=pending
            )
            typer.echo(
                f"{site.address(name)} now signs with s={activated.registration.selector}; "
                f"keep {activated.retired} published for {overlap}"
            )
            for key in activated.pruned:
                typer.echo(f"  deleted a retired key past its overlap: {key}")
            return
        rotated = reg.rotate(
            site,
            name,
            credentials=credentials,
            dkim=dkim,
            bundle=bundle,
            imap=imap,
            submission=submission,
        )
    except (reg.RegistrationError, ValueError, RuntimeError) as error:
        raise _fail(error) from error
    if rotated.bundle is not None:
        typer.echo(f"new credentials for {site.address(name)}: the old token and password stop")
        typer.echo(f"  working now. Bundle: {rotated.bundle} (0600, one copy)")
    if rotated.staged_selector is not None:
        _echo_dkim(site, rotated.staged_selector, "staged, not signing yet")
        typer.echo(f"then: {check}")
        typer.echo(f"and:  {again(f'rotate {name} --activate')}")


@agent_app.command("list")
def agent_list(
    config_path: ConfigOption,
    registry_dir: RegistryOption = None,
) -> None:
    """Every agent: the YAML's and the registered ones, with their selectors."""
    config = load_config(config_path, registry_dir=registry_dir)
    registry = registry_dir or config.registry_dir
    registrations = read_registrations(registry) if registry else {}
    now = datetime.now(UTC)
    domain_state = domain_dkim.read(registry)
    if domain_state is not None:
        published = ", ".join(f"{sel} ({role})" for sel, role in domain_state.selectors(now))
        typer.echo(f"domain key (SH-44, every registered agent): {published}")
    for name in sorted(set(config.agents) | set(registrations)):
        registration = registrations.get(name)
        if registration is not None and config.domain_selector is not None:
            state = "enabled" if registration.enabled else f"disabled {registration.disabled_at}"
            typer.echo(
                f"{name}: registered, {registration.mode}, {state}; "
                f"signs with the domain key {config.domain_selector}"
            )
        elif registration is not None:
            selectors = ", ".join(f"{sel} ({role})" for sel, role in registration.selectors(now))
            state = "enabled" if registration.enabled else f"disabled {registration.disabled_at}"
            typer.echo(f"{name}: registered, {registration.mode}, {state}; {selectors}")
        else:
            agent = config.agents[name]
            state = "enabled" if agent.enabled else "disabled"
            typer.echo(f"{name}: gateway YAML, {agent.mode}, {state}; {config.selector_for(name)}")
        configured = config.agents[name]
        accepted = ", ".join(sorted(config.accept_from_for(name))) or "anyone"
        typer.echo(f"  household={configured.household or '(default)'}; accept_from={accepted}")


@dns_app.command("render")
def dns_render(
    config_path: ConfigOption,
    keys_dir: KeysOption = None,
    output: Annotated[Path | None, typer.Option("--output")] = None,
    registry_dir: RegistryOption = None,
) -> None:
    """Render a CoreDNS/BIND zone with agent identity records.

    A registered agent gets a record for each selector that should be published now: the one it
    signs with, a staged one, and retired ones inside their overlap (PLAN §5.2).
    """
    config = load_config(config_path)
    source = keys_dir or config.keys_dir
    if keys_dir is None and not source.is_dir():
        source = config_path.parent / "keys"
    registry = registry_dir or config.registry_dir
    registrations = read_registrations(registry) if registry else {}
    now = datetime.now(UTC)
    lines = [
        f"$ORIGIN {config.agent_domain}.",
        "$TTL 30",
        f"@ IN SOA mail.{config.domain}. hostmaster.{config.domain}. (2026092401 30 30 300 30)",
        f"@ IN NS mail.{config.domain}.",
        f"@ IN MX 10 mail.{config.domain}.",
        '@ IN TXT "v=spf1 mx -all"',
        '_dmarc IN TXT "v=DMARC1; p=reject"',
    ]
    domain_state = domain_dkim.read(registry)
    if domain_state is not None:
        # SH-44: one key for every registered agent (and, while they retire, a migrated
        # lane's agent keys), so the agents below add none of their own.
        for selector, _role in domain_state.selectors(now):
            private_key = source / f"{selector}.private.pem"
            if not private_key.is_file():
                raise typer.BadParameter(f"missing key for {selector}: {private_key}")
            value = dkim_txt_value(dkim_public_key(private_key))
            lines.append(f'{selector}._domainkey IN TXT "{value}"')
    for name in sorted(set(config.agents) | set(registrations)):
        registration = registrations.get(name)
        if registration is not None and config.domain_selector is not None:
            selectors = []
        elif registration is not None:
            selectors = [selector for selector, _role in registration.selectors(now)]
        else:
            selectors = [config.selector_for(name)]
        agent = config.agents.get(name)
        signs = registration is not None or (
            agent is not None and (agent.submit_token or agent.submit_token_hash)
        )
        for selector in selectors:
            private_key = source / f"{selector}.private.pem"
            if not private_key.is_file() and not signs:
                lines.append(f"; {name} receives only: it has no DKIM key to publish")
                continue
            if not private_key.is_file():
                raise typer.BadParameter(f"missing key for {selector}: {private_key}")
            value = dkim_txt_value(dkim_public_key(private_key))
            lines.append(f'{selector}._domainkey IN TXT "{value}"')
        lines.append(
            f'{name}._agents IN TXT "v=amx1; card=https://{config.domain}/.well-known/agents/{name}.json"'
        )
    rendered = "\n".join(lines) + "\n"
    if output is None:
        typer.echo(rendered, nl=False)
    else:
        output.write_text(rendered, encoding="utf-8")
        typer.echo(str(output))


@dns_app.command("check")
def dns_check(
    name: str,
    config_path: ConfigOption,
    dns_server: Annotated[
        str | None,
        typer.Option("--dns-server", help="Ask this resolver (default: the YAML's dns_server)"),
    ] = None,
    registry_dir: RegistryOption = None,
    keys_dir: KeysOption = None,
) -> None:
    """Check that DNS publishes the agent's DKIM keys as they are on disk (after a DNS change).

    Fails (exit 1) when the signing key or a staged one is missing or different; a retiring key
    that is gone early is only a warning.
    """
    config = load_config(config_path)
    keys = keys_dir or config.keys_dir
    registry = registry_dir or config.registry_dir
    nameserver = dns_server or config.dns_server
    registration = read_registrations(registry).get(name) if registry else None
    domain_state = domain_dkim.read(registry) if config.domain_selector else None
    if registration is not None and domain_state is not None:
        # SH-44: the domain's key signs for this agent; check what the domain publishes.
        typer.echo(f"{name} signs with the domain key {config.domain_selector}")
        selectors = domain_state.selectors(datetime.now(UTC))
    elif registration is not None:
        selectors = registration.selectors(datetime.now(UTC))
    elif name in config.agents:
        selectors = [(config.selector_for(name), "active")]
    else:
        raise _fail(ValueError(f"{name} is not an agent of {config.agent_domain}"))
    failed = False
    for selector, role in selectors:
        fqdn = reg.dkim_name(selector, config.agent_domain)
        key = keys / f"{selector}.private.pem"
        if not key.is_file():
            typer.echo(f"MISSING-KEY {fqdn} ({role}): no local key {key}")
            failed = failed or not role.startswith("retiring")
            continue
        try:
            status = reg.dkim_matches(reg.lookup_txt(fqdn, nameserver), key)
        except RuntimeError as error:
            raise _fail(error) from error
        required = not role.startswith("retiring")
        label = status.upper() if status != "ok" else "ok"
        typer.echo(f"{label} {fqdn} ({role})")
        if status != "ok":
            failed = failed or required
            for line in reg.record_lines(fqdn, reg.dkim_value(key), config.zone):
                typer.echo(line)
    try:
        card = reg.lookup_txt(f"{name}._agents.{config.agent_domain}", nameserver)
    except RuntimeError:
        card = None
    typer.echo(f"{'ok' if card else 'absent (optional)'} {name}._agents.{config.agent_domain}")
    if failed:
        raise typer.Exit(1)


@journal_app.command("verify")
def journal_verify(
    config_paths: Annotated[list[Path], typer.Argument(exists=True, dir_okay=False)],
) -> None:
    """Verify one or more gateway hash chains and raw stores."""
    failed = False
    for config_path in config_paths:
        config = load_config(config_path)
        store = Store(config.data_dir / "journal.sqlite")
        verification = Journal(config.data_dir, store).verify()
        if verification.valid:
            typer.echo(f"{config.agent_domain}: OK {verification.entries} entries")
        else:
            failed = True
            typer.echo(f"{config.agent_domain}: FAIL {verification.error}", err=True)
    if failed:
        raise typer.Exit(1)


def declarations(
    store: Store,
    config: GatewayConfig,
    policy_rows: Sequence[sqlite3.Row],
    journal_rows: Sequence[sqlite3.Row],
) -> list[sqlite3.Row]:
    """The agents' own declarations (PLAN §5.10) that could have shaped a task's timeline.

    Those of each local agent the task's RCPT decisions or outbound mail name, made between
    ``control.max_ttl_seconds`` before the task's first row (no declaration lasts longer) and
    its last. Each line states its own expiry, so one that lapsed first reads as such.
    """
    identities = {
        f"{config.agent_domain}/{row['agent']}"
        for row in policy_rows
        if row["agent"] and row["agent"] in config.agents
    }
    identities |= {
        str(row["identity"])
        for row in journal_rows
        if row["direction"] == "outbound" and row["identity"]
    }
    stamps = [str(row["created_at"]) for row in (*policy_rows, *journal_rows)]
    if not identities or not stamps:
        return []
    earliest = datetime.fromisoformat(min(stamps)) - timedelta(
        seconds=config.control.max_ttl_seconds
    )
    since = earliest.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    shown = {int(row["sequence"]) for row in journal_rows}
    rows = store.rows(
        # A refusal (§5.11) is about one message and is journaled under that message's task.
        "SELECT * FROM journal WHERE direction = 'control' AND event != 'control-refuse' "
        "AND created_at BETWEEN ? AND ? "
        f"AND identity IN ({', '.join('?' for _ in identities)}) ORDER BY sequence",
        (since, max(stamps), *sorted(identities)),
    )
    return [row for row in rows if int(row["sequence"]) not in shown]


@app.command("trace")
def trace(
    task: Annotated[str, typer.Argument(help="Task token")],
    config_paths: Annotated[list[Path], typer.Option("--config", exists=True, dir_okay=False)],
    data_dirs: Annotated[
        list[Path] | None,
        typer.Option(
            "--data-dir",
            exists=True,
            file_okay=False,
            help="Host data directory corresponding to each --config",
        ),
    ] = None,
    postfix_logs: Annotated[
        list[Path] | None,
        typer.Option(
            "--postfix-log",
            "--mta-log",
            exists=True,
            dir_okay=False,
            help="Repeatable Postfix, Stalwart, or `docker compose logs --timestamps` input",
        ),
    ] = None,
) -> None:
    """Merge both gateways' policy, journal, and relevant MTA (Postfix or Stalwart) rows."""
    resolved_data_dirs = data_dirs or []
    if resolved_data_dirs and len(resolved_data_dirs) != len(config_paths):
        raise typer.BadParameter("--data-dir must be omitted or supplied once per --config")
    events: list[tuple[str, str]] = []
    for index, config_path in enumerate(config_paths):
        config = load_config(config_path)
        data_dir = resolved_data_dirs[index] if resolved_data_dirs else config.data_dir
        store = Store(data_dir / "journal.sqlite")
        policy_rows = store.rows(
            "SELECT * FROM policy_events WHERE task = ? ORDER BY sequence", (task,)
        )
        journal_rows = store.rows("SELECT * FROM journal WHERE task = ? ORDER BY sequence", (task,))
        for row in policy_rows:
            events.append((str(row["created_at"]), policy_line(row, config.agent_domain)))
        for row in journal_rows:
            events.append((str(row["created_at"]), journal_line(row, config.agent_domain)))
        for row in declarations(store, config, policy_rows, journal_rows):
            events.append((str(row["created_at"]), journal_line(row, config.agent_domain)))
    for log_path in postfix_logs or []:
        for line_number, line in enumerate(
            log_path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1
        ):
            if task not in line:
                continue
            stalwart = stalwart_line(line)
            if stalwart is not None:
                events.append(stalwart)
                continue
            if "postfix/" not in line:
                continue
            timestamp_match = _COMPOSE_TIMESTAMP.search(line)
            if timestamp_match is None:
                timestamp = f"9999-{line_number:09d}"
                displayed_timestamp = "unknown-time"
                source = log_path.stem
                detail = line.strip()
            else:
                timestamp = timestamp_match.group()
                displayed_timestamp = timestamp
                source = line[: timestamp_match.start()].strip(" |") or log_path.stem
                detail = line[timestamp_match.end() :].strip(" |")
            events.append(
                (
                    timestamp,
                    f"{displayed_timestamp} {source} postfix {detail}",
                )
            )
    for _timestamp, rendered in sorted(events):
        typer.echo(rendered)


@scenario_app.command("run")
def scenario_run(
    scenarios: Annotated[
        list[str] | None, typer.Argument(help="Scenario ids such as S04 or 11")
    ] = None,
    every: Annotated[bool, typer.Option("--all", help="Run every scenario")] = False,
    narrate: Annotated[
        bool, typer.Option("--narrate", help="Print the stack's timeline while it runs")
    ] = False,
    root: Annotated[
        Path | None, typer.Option(help="Repository checkout with scenarios/ and deploy/")
    ] = None,
) -> None:
    """Run scenarios against the running dev stack (make up), optionally narrated."""
    if root is None:
        root = _CHECKOUT if (_CHECKOUT / "scenarios").is_dir() else Path.cwd()
    if not every and not scenarios:
        raise typer.BadParameter("name at least one scenario, or pass --all")
    try:
        files = scenario_files(root, scenarios or [], every)
    except ValueError as error:
        raise typer.BadParameter(str(error)) from error
    state = root / "deploy" / "generated" / "state"
    gateways = (
        Gateway("agents.northwind.test", state / "nw"),
        Gateway("agents.contoso.test", state / "ct"),
    )
    compose = ["docker", "compose", "-f", str(root / "deploy" / "compose.yaml")]
    code = run_scenarios(root, files, narrate=narrate, gateways=gateways, compose=compose)
    raise typer.Exit(code)


@trust_app.command("add")
def trust_add(
    d: Annotated[str, typer.Argument(help="The agent's signing domain, e.g. agents.example.com")],
    s: Annotated[str, typer.Argument(help="The agent's name (its first selector)")],
    config_path: ConfigOption,
    intents: Annotated[list[str] | None, typer.Option("--intent", help="Repeatable")] = None,
    schemas: Annotated[list[str] | None, typer.Option("--schema", help="Repeatable")] = None,
    can_open_tasks: Annotated[bool, typer.Option("--can-open-tasks/--no-open-tasks")] = False,
    registry_dir: RegistryOption = None,
) -> None:
    """Grant another domain's agent intents here (receivers grant on d= and s=; PLAN §5.2)."""
    config = load_config(config_path)
    directory = registry_dir or config.registry_dir
    if directory is None:
        raise typer.BadParameter("set registry_dir in the gateway YAML, or pass --registry-dir")
    try:
        grant = Grant(
            d.casefold(),
            s.casefold(),
            intents=tuple(intents or reg.DEFAULT_INTENTS),
            schemas=tuple(schemas or ("*",)),
            can_open_tasks=can_open_tasks,
        )
    except ValueError as error:
        raise _fail(error) from error
    shadowed = [
        grant_
        for grant_ in config.trust
        if grant_.lane == "agent" and (grant_.d, grant_.s) == (grant.d, grant.s)
    ]
    with locked(directory):
        path = write_grant(directory, grant)
    typer.echo(f"granted {grant.d}/{grant.s}: {', '.join(grant.intents)} ({path})")
    if shadowed:
        typer.echo("  note: the gateway YAML already grants this identity, and its grant wins")


@trust_app.command("remove")
def trust_remove(
    d: str,
    s: str,
    config_path: ConfigOption,
    registry_dir: RegistryOption = None,
) -> None:
    """Remove a grant ``amx trust add`` wrote."""
    config = load_config(config_path)
    directory = registry_dir or config.registry_dir
    if directory is None:
        raise typer.BadParameter("set registry_dir in the gateway YAML, or pass --registry-dir")
    with locked(directory):
        removed = delete_grant(directory, d.casefold(), s.casefold())
    if not removed:
        raise _fail(ValueError(f"no grant for {d}/{s} in {directory}"))
    typer.echo(f"removed the grant for {d}/{s}")


@trust_app.command("list")
def trust_list(config_path: ConfigOption, registry_dir: RegistryOption = None) -> None:
    """The grants ``amx trust add`` wrote."""
    config = load_config(config_path)
    directory = registry_dir or config.registry_dir
    for grant in read_grants(directory) if directory else []:
        opens = "can open tasks" if grant.can_open_tasks else "replies only"
        typer.echo(f"{grant.d}/{grant.s}: {', '.join(grant.intents)}; {opens}")


# `amx live agent`: the same commands with the live host's paths and endpoints (PLAN §11.5). ----

live_agent_app = typer.Typer(
    no_args_is_help=True,
    help="This host's agents: `amx agent … --live` with the live state's paths (PLAN §11.5).",
)
live_app.add_typer(live_agent_app, name="agent")


def _live_site(
    params_path: Path, *, changes: str = "grant"
) -> tuple[live_lane.LiveParams, GatewayConfig, reg.Site, Callable[[str], str]]:
    """The live host's registration state: its gateway YAML, registry, keys, and accounts.

    While a restart install left owed has not happened (a migration, say), the running lane
    cannot apply every change (PLAN §11.5). A command that grants (``changes="grant"``: add,
    enable, rotate) refuses then, since it would report an agent live that is not. A revocation
    (``"revoke"``: remove) goes ahead, because its mailhost half applies at once, and says what
    still waits. ``"read"`` checks nothing.
    """
    params = live_lane._params(params_path)
    if not params.gateway_config.is_file():
        raise typer.BadParameter(f"run `amx live install` first; missing {params.gateway_config}")
    if changes != "read":
        try:
            owed = live_lane.pending_restarts(params)
            # Only install's: a restart certs or rotate owes changes no agent's state.
            pending = {name: r.why for name, r in owed.items() if r.origin == "install"}
        except live_lane.DockerUnavailable as error:
            if changes == "grant":
                raise typer.BadParameter(
                    f"{error}: cannot tell whether the lane has restarted since install"
                ) from error
            pending = {"lane": str(error)}
        if pending:
            why = "; ".join(f"the {name}: {reason}" for name, reason in sorted(pending.items()))
            services = " ".join(name for name in sorted(pending) if name != "lane")
            fix = (
                f"`amx live up`, then `amx live compose restart {services}`"
                if services
                else "Docker can be asked"
            )
            message = f"the running lane cannot apply every agent change until {fix} ({why})"
            if changes == "grant":
                raise typer.BadParameter(f"{message}; then run this again")
            typer.echo(
                f"warning: {message}. The mailbox side applies now; the gateway's follows.",
                err=True,
            )
    config, site = _site(
        params.gateway_config,
        params.registry_dir,
        params.keys_dir,
        params.accounts_file,
        dkim_bits=params.dkim_bits,
    )
    suffix = "" if params_path == live_lane.DEFAULT_PARAMS else f" --params {params_path}"
    return params, config, site, lambda rest: f"amx live agent {rest}{suffix}"


def _new_bundle(params: live_lane.LiveParams, name: str) -> Path:
    """A path for one agent's one bundle, under secrets/agents, that does not exist yet."""
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    path = params.bundles_dir / f"{name}-{stamp}.json"
    count = 1
    while path.exists():  # two in one second: the bundle is created with O_EXCL either way
        count += 1
        path = params.bundles_dir / f"{name}-{stamp}-{count}.json"
    return path


@live_agent_app.command("add")
def live_agent_add(
    name: Annotated[str, typer.Argument(help="Agent local-part and first DKIM selector")],
    params_path: live_lane.ParamsOption = live_lane.DEFAULT_PARAMS,
    mode: Annotated[str, typer.Option("--mode", help="remote, queued, or sync")] = "remote",
    handler: Annotated[
        str | None, typer.Option("--handler", help="module:function (queued and sync)")
    ] = None,
    watermark: Annotated[int, typer.Option("--watermark")] = 2,
    workers: Annotated[int, typer.Option("--workers")] = 1,
    intents: Annotated[list[str] | None, typer.Option("--intent", help="Repeatable")] = None,
    schemas: Annotated[list[str] | None, typer.Option("--schema", help="Repeatable")] = None,
    can_open_tasks: Annotated[bool, typer.Option("--can-open-tasks/--no-open-tasks")] = True,
    bundle: Annotated[
        Path | None, typer.Option("--bundle", help="Default: secrets/agents/<name>-<time>.json")
    ] = None,
    imap: Annotated[
        str | None, typer.Option("--imap", help="Default: imaps://<mx_host>[:port]")
    ] = None,
    submission: Annotated[
        str | None, typer.Option("--submission", help="Default: smtp://<mx_host>:<587>")
    ] = None,
    household: HouseholdOption = None,
    accept_from: AcceptFromOption = None,
    outbound_allowlist: OutboundAllowlistOption = None,
) -> None:
    """Register an agent on this host: no restart, hashes only, one credentials bundle."""
    params, _, _, _ = _live_site(params_path)
    written = bundle or _new_bundle(params, name)
    _agent_add_live(
        name,
        params.gateway_config,
        mode=mode,
        handler=handler or "mailbox-only",
        watermark=watermark,
        workers=workers,
        intents=tuple(intents or reg.DEFAULT_INTENTS),
        schemas=tuple(schemas or ("*",)),
        can_open_tasks=can_open_tasks,
        bundle=written,
        imap=imap or live_lane.imap_url(params),
        submission=submission or live_lane.submit_url(params),
        registry_dir=params.registry_dir,
        keys_dir=params.keys_dir,
        accounts_file=params.accounts_file,
        dkim_bits=params.dkim_bits,
        check_hint=f"amx live preflight (dns:dkim:{name})",
        card=False,  # the live host serves no agent card (docs/selfhost-public.md §4)
        household=household,
        accept_from=accept_from,
        outbound_allowlist=outbound_allowlist,
    )
    if mode == "remote":
        ca = (
            " --ca ca.pem"
            if params.tls_mode == "self-signed"
            or (params.tls_mode == "files" and params.tls_ca_file)
            else ""
        )
        typer.echo(
            f"on the agent's host: amx-runner --credentials {written.name}{ca} "
            "--handler module:function"
        )


@live_agent_app.command("set")
def live_agent_set(
    name: str,
    params_path: live_lane.ParamsOption = live_lane.DEFAULT_PARAMS,
    household: HouseholdOption = None,
    accept_from: AcceptFromOption = None,
    outbound_allowlist: OutboundAllowlistOption = None,
    default_household: Annotated[bool, typer.Option("--default-household")] = False,
    accept_any: Annotated[bool, typer.Option("--accept-any")] = False,
    outbound_any: Annotated[bool, typer.Option("--outbound-any")] = False,
    inherit_accept_from: Annotated[bool, typer.Option("--inherit-accept-from")] = False,
    inherit_outbound_allowlist: Annotated[
        bool, typer.Option("--inherit-outbound-allowlist")
    ] = False,
) -> None:
    """Change this host's registered agent policy without reissuing keys or credentials."""
    _, _, site, _ = _live_site(params_path)
    _set_agent_policy(
        site,
        name,
        household=household,
        accept_from=accept_from,
        outbound_allowlist=outbound_allowlist,
        default_household=default_household,
        accept_any=accept_any,
        outbound_any=outbound_any,
        inherit_accept_from=inherit_accept_from,
        inherit_outbound_allowlist=inherit_outbound_allowlist,
    )


@live_agent_app.command("remove")
def live_agent_remove(
    name: str,
    params_path: live_lane.ParamsOption = live_lane.DEFAULT_PARAMS,
    purge: Annotated[
        bool, typer.Option("--purge", help="Delete the mailbox and keys of a disabled agent")
    ] = False,
    grace: Annotated[str, typer.Option("--grace", help="How long disabled before a purge")] = "7d",
    now: Annotated[bool, typer.Option("--now", help="Purge before the grace period ends")] = False,
) -> None:
    """Disable an agent (RCPT refuses it, no login works); --purge deletes it after a grace."""
    _, _, site, again = _live_site(params_path, changes="revoke")
    _remove(site, name, purge=purge, grace=grace, now=now, again=again)


@live_agent_app.command("enable")
def live_agent_enable(
    name: str, params_path: live_lane.ParamsOption = live_lane.DEFAULT_PARAMS
) -> None:
    """Re-enable a disabled agent with the credentials and key it had."""
    _, _, site, _ = _live_site(params_path)
    _enable(site, name)


@live_agent_app.command("rotate")
def live_agent_rotate(
    name: str,
    params_path: live_lane.ParamsOption = live_lane.DEFAULT_PARAMS,
    credentials: CredentialsFlag = True,
    dkim: DkimFlag = True,
    activate: ActivateFlag = False,
    overlap: OverlapOption = "7d",
    dns_check: DnsCheckFlag = True,
    dns_server: DnsServerOption = None,
    bundle: Annotated[
        Path | None, typer.Option("--bundle", help="Default: secrets/agents/<name>-<time>.json")
    ] = None,
) -> None:
    """New credentials (a new bundle) and a new DKIM key under a new selector, staged; then
    --activate, once `amx live preflight` shows the staged key served, switches signing."""
    params, config, site, again = _live_site(params_path)
    _rotate(
        config,
        site,
        name,
        credentials=credentials,
        dkim=dkim,
        activate=activate,
        overlap=overlap,
        dns_check=dns_check,
        dns_server=dns_server,
        bundle=bundle or (_new_bundle(params, name) if credentials and not activate else None),
        imap=None,  # the endpoints the agent was registered with
        submission=None,
        again=again,
        check="amx live dns, publish the staged record, then amx live preflight",
    )


@live_agent_app.command("list")
def live_agent_list(params_path: live_lane.ParamsOption = live_lane.DEFAULT_PARAMS) -> None:
    """This host's agents, with their state and the selectors that should be in DNS."""
    params, _, _, _ = _live_site(params_path, changes="read")
    agent_list(params.gateway_config, registry_dir=params.registry_dir)


# SH-44: one DKIM key for the domain ------------------------------------------------------------

dkim_app = typer.Typer(
    no_args_is_help=True,
    help="The domain's one DKIM key (SH-44): every registered agent signs with it.",
)
app.add_typer(dkim_app, name="dkim")
live_dkim_app = typer.Typer(
    no_args_is_help=True, help="This host's domain DKIM key: `amx dkim` with the live paths."
)
live_app.add_typer(live_dkim_app, name="dkim")

OverlapOption = Annotated[
    str, typer.Option("--overlap", help="How long the replaced keys stay published")
]
DnsCheckOption = Annotated[
    bool,
    typer.Option(
        "--dns-check/--no-dns-check",
        help="Activate only once DNS serves the staged key (skip only if nobody has mail yet)",
    ),
]


def _dkim_status(site: reg.Site) -> None:
    state = domain_dkim.read(site.registry_dir)
    if state is None:
        typer.echo("no domain key: each agent signs with its own (before SH-44)")
        return
    for selector, role in state.selectors(datetime.now(UTC)):
        typer.echo(f"{selector}: {role}")


def _dkim_stage(site: reg.Site, check: str, activate: str, *, init: bool = False) -> None:
    try:
        state = domain_dkim.ensure(site) if init else domain_dkim.stage(site)
    except (reg.RegistrationError, ValueError) as error:
        raise _fail(error) from error
    if state.pending is None:
        assert state.active is not None
        typer.echo(f"every registered agent signs with {state.active}")
        _echo_dkim(site, state.active, "active")
        return
    _echo_dkim(site, state.pending, "staged, not signing yet")
    typer.echo(f"then: {check}")
    typer.echo(f"and:  {activate}")


def _dkim_activate(
    site: reg.Site, *, overlap: str, dns_check: bool, dns_server: str | None
) -> None:
    try:
        state = domain_dkim.activate(
            site,
            overlap=reg.parse_duration(overlap),
            nameserver=dns_server,
            check_dns=dns_check,
        )
    except (reg.RegistrationError, ValueError, RuntimeError) as error:
        raise _fail(error) from error
    typer.echo(f"every registered agent now signs with {state.active}")
    for item in state.retiring:
        typer.echo(f"  keep {item.selector} published until {item.until.isoformat()}")
    typer.echo("  then delete those records, and run `retire` to delete their keys")


def _dkim_retire(site: reg.Site) -> None:
    try:
        retired = domain_dkim.retire(site)
    except (reg.RegistrationError, ValueError) as error:
        raise _fail(error) from error
    if not retired:
        typer.echo("nothing past its overlap")
    for selector in retired:
        fqdn = reg.dkim_name(selector, site.agent_domain)
        typer.echo(
            f"retired {selector}: delete {fqdn} (name in zone {site.dns_zone}: "
            f"{reg.relative_name(fqdn, site.dns_zone)})"
        )


@dkim_app.command("status")
def dkim_status(config_path: ConfigOption, registry_dir: RegistryOption = None) -> None:
    """The domain's selectors and their roles (active, staged, retiring)."""
    _config, site = _site(config_path, registry_dir, None, None)
    _dkim_status(site)


@dkim_app.command("init")
def dkim_init(
    config_path: ConfigOption,
    registry_dir: RegistryOption = None,
    keys_dir: KeysOption = None,
    accounts_file: AccountsOption = None,
) -> None:
    """Create the domain key: active at once on a new gateway, staged if agents have keys."""
    _config, site = _site(config_path, registry_dir, keys_dir, accounts_file)
    suffix = f" --config {config_path}"
    _dkim_stage(site, "publish the record above", f"amx dkim activate{suffix}", init=True)


@dkim_app.command("stage")
def dkim_stage(
    config_path: ConfigOption,
    registry_dir: RegistryOption = None,
    keys_dir: KeysOption = None,
    accounts_file: AccountsOption = None,
) -> None:
    """A new domain key, staged: publish it, then `amx dkim activate`."""
    _config, site = _site(config_path, registry_dir, keys_dir, accounts_file)
    suffix = f" --config {config_path}"
    _dkim_stage(site, "publish the record above", f"amx dkim activate{suffix}")


@dkim_app.command("activate")
def dkim_activate(
    config_path: ConfigOption,
    registry_dir: RegistryOption = None,
    keys_dir: KeysOption = None,
    accounts_file: AccountsOption = None,
    overlap: OverlapOption = "7d",
    dns_check: DnsCheckOption = True,
    dns_server: Annotated[str | None, typer.Option("--dns-server")] = None,
) -> None:
    """Sign with the staged domain key from now on, once DNS serves it."""
    config, site = _site(config_path, registry_dir, keys_dir, accounts_file)
    _dkim_activate(
        site, overlap=overlap, dns_check=dns_check, dns_server=dns_server or config.dns_server
    )


@dkim_app.command("retire")
def dkim_retire(
    config_path: ConfigOption,
    registry_dir: RegistryOption = None,
    keys_dir: KeysOption = None,
    accounts_file: AccountsOption = None,
) -> None:
    """Delete the keys whose overlap has ended, and say which records to delete."""
    _config, site = _site(config_path, registry_dir, keys_dir, accounts_file)
    _dkim_retire(site)


def _live_dkim_site(params_path: Path, changes: str) -> tuple[reg.Site, str]:
    _params, _config, site, _again = _live_site(params_path, changes=changes)
    suffix = "" if params_path == live_lane.DEFAULT_PARAMS else f" --params {params_path}"
    return site, suffix


@live_dkim_app.command("status")
def live_dkim_status(params_path: live_lane.ParamsOption = live_lane.DEFAULT_PARAMS) -> None:
    """This host's domain selectors and their roles."""
    site, _suffix = _live_dkim_site(params_path, "read")
    _dkim_status(site)


@live_dkim_app.command("stage")
def live_dkim_stage(params_path: live_lane.ParamsOption = live_lane.DEFAULT_PARAMS) -> None:
    """A new domain key, staged: publish it, then `amx live dkim activate`."""
    site, suffix = _live_dkim_site(params_path, "grant")
    _dkim_stage(site, f"amx live preflight{suffix}", f"amx live dkim activate{suffix}")


@live_dkim_app.command("activate")
def live_dkim_activate(
    params_path: live_lane.ParamsOption = live_lane.DEFAULT_PARAMS,
    overlap: OverlapOption = "7d",
    dns_check: DnsCheckOption = True,
    dns_server: Annotated[str | None, typer.Option("--dns-server")] = None,
) -> None:
    """Sign with the staged domain key from now on, once DNS serves it."""
    _params, config, site, _again = _live_site(params_path, changes="grant")
    _dkim_activate(
        site, overlap=overlap, dns_check=dns_check, dns_server=dns_server or config.dns_server
    )


@live_dkim_app.command("retire")
def live_dkim_retire(params_path: live_lane.ParamsOption = live_lane.DEFAULT_PARAMS) -> None:
    """Delete the keys whose overlap has ended, and say which records to delete."""
    site, _suffix = _live_dkim_site(params_path, "revoke")
    _dkim_retire(site)


def main() -> None:
    """Run the AMX command group."""
    app()


if __name__ == "__main__":
    main()
