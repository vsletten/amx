"""The live bundle: one agent domain on one internet-facing host (``deploy/live``, PLAN §11).

Everything site-specific is one YAML file of parameters (``deploy/live/live.example.yaml``).
``amx live install`` turns it into a state directory outside the repository:

    <state_dir>/
      compose.env            compose variables (no secrets)
      data/                  the gateway's data directory: journal, raw store, task state
      secrets/        0700   credentials.yaml, gateway/, mailhost/, agents/, tls/, acme/
      dns-records.txt        the records to request, rendered from the keys
      backups/

Secrets are generated here, never typed and never in git: every password and token is random,
every file that holds one is 0600, and the DKIM keys are made by the same helper as
``amx agent add``. API keys (``TYPESAFE_API_KEY``, ``AMX_LLM_API_KEY``) are never written by
this module: they reach the gateway only from the environment of ``amx live up``.

Agents are not configured here. They are registered (``amx live agent add``, which is
``amx agent add --live`` with this site's paths; PLAN §5.2, §11.5): the gateway reads the
registry in ``secrets/gateway/registry`` and the mailhost the accounts file in
``secrets/mailhost/accounts``, both without a restart. ``agents:`` in the parameters file is read
only to migrate an install made before that (:func:`migrate_legacy_agents`).
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any

import typer
import yaml

from amx import domain_dkim
from amx.accounts import Account, new_generation, read_accounts, set_account
from amx.config import ControlConfig, load_config, parse_outbound_allowlist
from amx.credentials import hash_password, hash_token
from amx.journal import Journal
from amx.provision import (
    dkim_public_key,
    dkim_txt_value,
    txt_strings,
    write_private,
)
from amx.registry import (
    Registration,
    locked,
    read_registrations,
    selector_agent,
    write_registration,
)
from amx.reload import KEEPABLE_FIELDS, restart_needed
from amx.store import Store

if TYPE_CHECKING:
    from amx.registration import Site

# A source checkout (src/amx/live.py -> repository root): the bundle's compose file lives there.
CHECKOUT = Path(__file__).resolve().parents[2]
BUNDLE = CHECKOUT / "deploy" / "live"
DEFAULT_PARAMS = BUNDLE / "live.yaml"

LETSENCRYPT = "https://acme-v02.api.letsencrypt.org/directory"
LETSENCRYPT_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"
CERTBOT_IMAGE = "certbot/certbot:v5.8.0"
CERT_NAME = "amx-live"
# The MTA delivers these to the postmaster mailbox; the milter treats them as people's addresses.
ROLE_ADDRESSES = ("postmaster", "abuse")
# No agent may take a role address or the gateway's control address (PLAN §5.10).
RESERVED_NAMES = (*ROLE_ADDRESSES, ControlConfig().address)
POSTMASTER = "postmaster"
SECRET_ENV = ("TYPESAFE_API_KEY", "AMX_LLM_API_KEY")
DEFAULT_HOLD_RULES: tuple[dict[str, Any], ...] = (
    {"name": "first-contact-domain", "when": {"recipient_domain_seen": False}},
    {"name": "commits-money", "when": {"schema_regex": "(order|payment|invoice)"}},
)
_NAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_ADDRESS = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")

app = typer.Typer(
    no_args_is_help=True, help="The live bundle (deploy/live, docs/selfhost-public.md)."
)

ParamsOption = Annotated[
    Path,
    typer.Option(
        "--params",
        envvar="AMX_LIVE_PARAMS",
        help="The site's parameters (default deploy/live/live.yaml)",
    ),
]


class ParamsError(ValueError):
    """The parameters file is invalid."""


def _hostname(value: object, field_name: str) -> str:
    text = str(value or "").strip().rstrip(".").casefold()
    labels = text.split(".")
    if (
        len(labels) < 2
        or all(label.isdigit() for label in labels)
        or not all(_NAME.fullmatch(label) for label in labels)
    ):
        raise ParamsError(f"{field_name} must be a DNS name such as mail.example.com: {value!r}")
    return text


def _mapping(value: object, field_name: str, known: set[str]) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ParamsError(f"{field_name} must be a mapping")
    unknown = sorted(set(map(str, value)) - known)
    if unknown:
        raise ParamsError(f"{field_name} has unknown keys: {', '.join(unknown)}")
    return {str(key): item for key, item in value.items()}


def _secret_key(value: object) -> str | None:
    """The first key anywhere in ``value`` that names a secret, if any."""
    if isinstance(value, dict):
        for key, item in value.items():
            name = str(key)
            lowered = name.casefold()
            if name in SECRET_ENV or lowered.endswith(("api_key", "password", "token", "secret")):
                return name
            found = _secret_key(item)
            if found is not None:
                return found
    elif isinstance(value, list):
        for item in value:
            found = _secret_key(item)
            if found is not None:
                return found
    return None


@dataclass(frozen=True, slots=True)
class LiveAgent:
    """An agent an earlier install configured from the parameters file (``agents:``).

    Read only to migrate it into the registry (:func:`migrate_legacy_agents`).
    """

    name: str
    mode: str = "queued"
    handler: str = "mailbox-only"
    watermark: int = 4
    workers: int = 1
    external_per_day: int | None = None
    content_judge: str | None = None


@dataclass(frozen=True, slots=True)
class LiveParams:
    """The validated parameters of one live deployment."""

    path: Path
    agent_domain: str
    mx_host: str
    public_ip: str
    admin_contact: str
    # `agents:` in the parameters file: an earlier install's agents, to migrate (PLAN §11.5).
    legacy_agents: tuple[LiveAgent, ...]
    org_domain: str
    dns_zone: str
    compose_project: str
    state_dir: Path
    bind_address: str
    ports: Mapping[str, int]
    subnet: ipaddress.IPv4Network
    tls_mode: str
    acme_server: str
    acme_challenge: str
    certbot_image: str
    tls_extra_names: tuple[str, ...]
    dkim_bits: int
    dns_ttl: int
    dmarc_policy: str
    dmarc_rua: str
    manage_apex: bool
    tls_rpt: bool
    caa: str | None
    forward_role_mail: bool
    judge_mode: str
    limits: Mapping[str, Any]
    hold_rules: tuple[Any, ...]
    trust: tuple[Any, ...]
    known_domains: tuple[str, ...]
    llm: Mapping[str, str]
    outbound_allowlist: tuple[str, ...] = ()
    # SH-40: people's mail to the agents only from these verified senders (addresses, domains).
    accept_from: tuple[str, ...] = ()
    compose_overrides: tuple[Path, ...] = field(default=())
    mta: str = "postfix"
    profile: str = "public"
    webmail: bool = False
    admin_bind_address: str = "127.0.0.1"
    webui_bundle: Path | None = None
    tls_certificate: Path | None = None
    tls_private_key: Path | None = None
    tls_ca_file: Path | None = None

    @property
    def mailhost_ip(self) -> str:
        return str(self.subnet.network_address + 10)

    @property
    def gateway_ip(self) -> str:
        return str(self.subnet.network_address + 20)

    @property
    def secrets_dir(self) -> Path:
        return self.state_dir / "secrets"

    @property
    def data_dir(self) -> Path:
        return self.state_dir / "data"

    @property
    def tls_dir(self) -> Path:
        return self.secrets_dir / "tls"

    @property
    def keys_dir(self) -> Path:
        return self.secrets_dir / "gateway" / "keys"

    @property
    def gateway_config(self) -> Path:
        return self.secrets_dir / "gateway" / "gateway.yaml"

    @property
    def registry_dir(self) -> Path:
        """The gateway's registry (PLAN §5.2), beside its YAML, mounted read-only."""
        return self.secrets_dir / "gateway" / "registry"

    @property
    def accounts_file(self) -> Path:
        """The mailhost's registered logins (hashes only), which amx-sync-accounts merges."""
        return self.secrets_dir / "mailhost" / "accounts" / "agents.passwd"

    @property
    def adopt_file(self) -> Path:
        """The migrated agents whose existing mailboxes the mailhost adopts (address:generation)."""
        return self.accounts_file.with_name("adopt")

    @property
    def bundles_dir(self) -> Path:
        """Where `amx live agent add` and `rotate` write an agent's one credentials bundle."""
        return self.secrets_dir / "agents"

    @property
    def compose_env(self) -> Path:
        return self.state_dir / "compose.env"

    @property
    def credentials_path(self) -> Path:
        return self.secrets_dir / "credentials.yaml"

    def address(self, name: str) -> str:
        return f"{name}@{self.agent_domain}"


def load_params(path: Path) -> LiveParams:
    """Read and validate the parameters file; unknown keys fail, as in gateway YAML."""
    if not path.is_file():
        raise ParamsError(f"no parameters file at {path} (copy deploy/live/live.example.yaml)")
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    secret = _secret_key(loaded)
    if secret is not None:
        raise ParamsError(
            f"{secret}: secrets never go in the parameters file (install generates passwords "
            "and tokens; API keys come from the environment of `amx live up`)"
        )
    raw = _mapping(
        loaded,
        "parameters",
        {
            "agent_domain",
            "mx_host",
            "public_ip",
            "admin_contact",
            "agents",
            "org_domain",
            "dns_zone",
            "compose_project",
            "state_dir",
            "network",
            "tls",
            "dns",
            "role_mail",
            "content_judge",
            "limits",
            "hold_rules",
            "trust",
            "known_domains",
            "outbound_allowlist",
            "accept_from",
            "llm",
            "compose_overrides",
            "mta",
            "profile",
            "webmail",
            "stalwart",
        },
    )
    mta = str(raw.get("mta", "postfix"))
    profile = str(raw.get("profile", "public"))
    if mta not in ("postfix", "stalwart"):
        raise ParamsError("mta must be postfix or stalwart")
    if profile not in ("private", "public"):
        raise ParamsError("profile must be private or public")
    if not isinstance(raw.get("webmail", False), bool):
        raise ParamsError("webmail must be true or false")
    if raw.get("webmail") and mta != "stalwart":
        raise ParamsError("webmail is supported by the Stalwart bundle only")
    if profile == "private":
        domain = _hostname(raw.get("org_domain", "home.arpa"), "org_domain")
        raw.setdefault("org_domain", domain)
        raw.setdefault("agent_domain", f"agents.{domain}")
        raw.setdefault("mx_host", f"mail.{domain}")
        raw.setdefault("public_ip", "127.0.0.1")
        raw.setdefault("admin_contact", f"postmaster@{domain}")
    for required in ("agent_domain", "mx_host", "public_ip", "admin_contact"):
        if not raw.get(required):
            raise ParamsError(f"{required} is required")
    agent_domain = _hostname(raw["agent_domain"], "agent_domain")
    mx_host = _hostname(raw["mx_host"], "mx_host")
    try:
        public_ip = ipaddress.IPv4Address(str(raw["public_ip"]))
    except ValueError as error:
        raise ParamsError(f"public_ip must be an IPv4 address: {raw['public_ip']!r}") from error
    admin_contact = str(raw["admin_contact"]).strip()
    if not _ADDRESS.fullmatch(admin_contact):
        raise ParamsError(f"admin_contact must be an email address: {admin_contact!r}")
    org_domain = _hostname(raw.get("org_domain") or agent_domain.partition(".")[2], "org_domain")
    dns_zone = _hostname(raw.get("dns_zone") or org_domain, "dns_zone")
    for name, value in (("agent_domain", agent_domain), ("mx_host", mx_host)):
        if value != dns_zone and not value.endswith(f".{dns_zone}"):
            raise ParamsError(f"{name} {value} is not inside dns_zone {dns_zone}")

    agents_raw = raw.get("agents") or []
    if not isinstance(agents_raw, list):
        raise ParamsError("agents must be a list (read only to migrate an earlier install)")
    agents: list[LiveAgent] = []
    for index, item in enumerate(agents_raw):
        entry = _mapping(
            item,
            f"agents[{index}]",
            {
                "name",
                "mode",
                "handler",
                "watermark",
                "workers",
                "external_per_day",
                "content_judge",
            },
        )
        name = str(entry.get("name", ""))
        if not _NAME.fullmatch(name) or name in RESERVED_NAMES:
            raise ParamsError(
                f"agents[{index}].name must be lowercase letters, digits, or hyphens, and not "
                f"{', '.join(RESERVED_NAMES)}: {name!r}"
            )
        mode = str(entry.get("mode", "queued"))
        if mode not in ("sync", "queued", "remote"):
            raise ParamsError(f"agents[{index}].mode must be sync, queued, or remote")
        handler = str(entry.get("handler") or "mailbox-only")
        if mode == "remote" and handler != "mailbox-only":
            raise ParamsError(f"agents[{index}]: a remote agent's handler runs on its own host")
        judge = entry.get("content_judge")
        agents.append(
            LiveAgent(
                name=name,
                mode=mode,
                handler=handler,
                watermark=int(entry.get("watermark", 4)),
                workers=int(entry.get("workers", 1)),
                external_per_day=(
                    None
                    if entry.get("external_per_day") is None
                    else int(entry["external_per_day"])
                ),
                content_judge=None if judge is None else str(judge),
            )
        )
    if len({agent.name for agent in agents}) != len(agents):
        raise ParamsError("agent names must be unique")

    project = str(raw.get("compose_project") or "amx-live")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", project):
        raise ParamsError("compose_project must be lowercase letters, digits, '-' or '_'")
    base = path.resolve().parent

    def local_path(value: object) -> Path:
        return (base / Path(str(value)).expanduser()).resolve()

    state_dir = local_path(raw.get("state_dir") or f"~/amx-live/{project}")
    stalwart = _mapping(raw.get("stalwart"), "stalwart", {"admin_bind_address", "webui_bundle"})
    admin_bind = str(stalwart.get("admin_bind_address", "127.0.0.1"))
    try:
        address = ipaddress.IPv4Address(admin_bind)
        if not (address.is_loopback or address in ipaddress.IPv4Network("100.64.0.0/10")):
            raise ValueError("not loopback or tailnet")
    except ValueError as error:
        raise ParamsError(
            "stalwart.admin_bind_address must be localhost or a tailnet IPv4"
        ) from error

    network = _mapping(raw.get("network"), "network", {"bind_address", "subnet", "ports"})
    ports_raw = _mapping(
        network.get("ports"),
        "network.ports",
        {"smtp", "submission", "imaps", "acme_http", "webmail", "people_submission", "discovery"},
    )
    ports = {"smtp": 25, "submission": 587, "imaps": 993, "acme_http": 80}
    ports.update({key: int(value) for key, value in ports_raw.items()})
    if mta == "stalwart":
        ports.setdefault("webmail", 8088)
        ports.setdefault("people_submission", 465)
        ports.setdefault("discovery", 443)
    try:
        subnet = ipaddress.IPv4Network(str(network.get("subnet", "172.31.250.0/24")))
        default_bind = "127.0.0.1" if profile == "private" else "0.0.0.0"
        bind_address = str(ipaddress.IPv4Address(str(network.get("bind_address", default_bind))))
    except ValueError as error:
        raise ParamsError(f"network: {error}") from error
    if subnet.num_addresses < 32:
        raise ParamsError("network.subnet must be at least a /27")

    tls = _mapping(
        raw.get("tls"),
        "tls",
        {
            "mode",
            "acme_server",
            "challenge",
            "certbot_image",
            "extra_names",
            "dkim_bits",
            "certificate",
            "private_key",
            "ca_file",
        },
    )
    tls_mode = str(tls.get("mode", "self-signed" if profile == "private" else "acme"))
    if tls_mode not in ("acme", "self-signed", "files"):
        raise ParamsError("tls.mode must be acme, self-signed or files")
    if tls_mode == "files":
        if mta != "stalwart":
            raise ParamsError("tls.mode files requires mta: stalwart")
        if not all(
            isinstance(tls.get(k), str) and tls[k].strip() for k in ("certificate", "private_key")
        ):
            raise ParamsError("tls.mode files requires certificate and private_key paths")
    elif any(k in tls for k in ("certificate", "private_key", "ca_file")):
        raise ParamsError("TLS file paths require tls.mode files")
    if "ca_file" in tls and (not isinstance(tls["ca_file"], str) or not tls["ca_file"].strip()):
        raise ParamsError("tls.ca_file must be a path")
    acme_server = str(tls.get("acme_server", "letsencrypt"))
    acme_server = {"letsencrypt": LETSENCRYPT, "staging": LETSENCRYPT_STAGING}.get(
        acme_server, acme_server
    )
    challenge = str(tls.get("challenge", "http-01"))
    if challenge not in ("http-01", "dns-01-manual"):
        raise ParamsError("tls.challenge must be http-01 or dns-01-manual")
    extra_names = tuple(str(name) for name in tls.get("extra_names") or ())
    if extra_names and tls_mode != "self-signed":
        raise ParamsError("tls.extra_names applies only to self-signed mode")
    dkim_bits = int(tls.get("dkim_bits", 2048))
    if dkim_bits not in (1024, 2048):
        raise ParamsError("tls.dkim_bits must be 2048 (or 1024 where DNS cannot hold the key)")

    dns = _mapping(
        raw.get("dns"),
        "dns",
        {"ttl", "dmarc_policy", "dmarc_rua", "manage_apex", "tls_rpt", "caa"},
    )
    dmarc_policy = str(dns.get("dmarc_policy", "none"))
    if dmarc_policy not in ("none", "quarantine", "reject"):
        raise ParamsError("dns.dmarc_policy must be none, quarantine, or reject")
    dmarc_rua = str(dns.get("dmarc_rua") or f"{POSTMASTER}@{agent_domain}")
    if not _ADDRESS.fullmatch(dmarc_rua):
        raise ParamsError(f"dns.dmarc_rua must be an address: {dmarc_rua!r}")
    rua_domain = dmarc_rua.rpartition("@")[2].casefold()
    if rua_domain != dns_zone and not rua_domain.endswith(f".{dns_zone}"):
        # RFC 7489 §7.1: reporters send to another domain only if it publishes an authorization
        # record (<zone>._report._dmarc.<rua domain>), which a mailbox provider never does.
        raise ParamsError(
            f"dns.dmarc_rua must be inside {dns_zone}: reports to another domain need that "
            "domain's authorization record, so they would never arrive"
        )
    caa = dns.get("caa", "letsencrypt.org")

    role_mail = _mapping(raw.get("role_mail"), "role_mail", {"forward_to_admin"})
    judge = _mapping(raw.get("content_judge"), "content_judge", {"mode"})
    judge_mode = str(judge.get("mode", "enforce"))
    if judge_mode not in ("off", "observe", "enforce"):
        raise ParamsError('content_judge.mode must be "off", observe, or enforce (quote "off")')
    limits = _mapping(
        raw.get("limits"),
        "limits",
        {
            "external_per_day",
            "references_depth",
            "received_depth",
            "max_bytes",
            "blocked_attachment_types",
        },
    )
    llm = _mapping(raw.get("llm"), "llm", {"base_url", "model", "timeout", "briefs"})
    llm_values = {
        "base_url": str(llm.get("base_url", "http://host.docker.internal:11434/v1")),
        "model": str(llm.get("model", "deepseek-v4.1-flash:cloud")),
        "timeout": str(llm.get("timeout", "")),
        "briefs": str(
            local_path(llm["briefs"])
            if llm.get("briefs")
            else CHECKOUT / "deploy" / "gateway" / "llm-briefs.yaml"
        ),
    }
    hold_rules = raw.get("hold_rules", list(DEFAULT_HOLD_RULES))
    trust = raw.get("trust") or []
    if not isinstance(hold_rules, list) or not isinstance(trust, list):
        raise ParamsError("hold_rules and trust must be lists (the gateway YAML's shapes)")
    known_domains = tuple(str(value).casefold() for value in raw.get("known_domains") or ())
    try:
        outbound_allowlist = tuple(sorted(parse_outbound_allowlist(raw.get("outbound_allowlist"))))
        accept_from = tuple(sorted(parse_outbound_allowlist(raw.get("accept_from"), "accept_from")))
    except ValueError as error:
        raise ParamsError(str(error)) from error
    if (
        outbound_allowlist
        and role_mail.get("forward_to_admin")
        and admin_contact.casefold() not in outbound_allowlist
        and admin_contact.casefold().rpartition("@")[2] not in outbound_allowlist
    ):
        # Forwarding relays whatever reaches postmaster@ or abuse@, an agent's mail included.
        raise ParamsError(
            "role_mail.forward_to_admin forwards to admin_contact, which is not on "
            "outbound_allowlist"
        )
    overrides = tuple(local_path(item) for item in raw.get("compose_overrides") or ())
    return LiveParams(
        path=path.resolve(),
        agent_domain=agent_domain,
        mx_host=mx_host,
        public_ip=str(public_ip),
        admin_contact=admin_contact,
        legacy_agents=tuple(agents),
        org_domain=org_domain,
        dns_zone=dns_zone,
        compose_project=project,
        state_dir=state_dir,
        bind_address=bind_address,
        ports=ports,
        subnet=subnet,
        tls_mode=tls_mode,
        acme_server=acme_server,
        acme_challenge=challenge,
        certbot_image=str(tls.get("certbot_image", CERTBOT_IMAGE)),
        tls_extra_names=extra_names,
        dkim_bits=dkim_bits,
        dns_ttl=int(dns.get("ttl", 600)),
        dmarc_policy=dmarc_policy,
        dmarc_rua=dmarc_rua,
        manage_apex=bool(dns.get("manage_apex", False)),
        tls_rpt=bool(dns.get("tls_rpt", True)),
        caa=str(caa) if caa else None,
        forward_role_mail=bool(role_mail.get("forward_to_admin", False)),
        judge_mode=judge_mode,
        limits=limits,
        hold_rules=tuple(hold_rules),
        trust=tuple(trust),
        known_domains=known_domains,
        llm=llm_values,
        outbound_allowlist=outbound_allowlist,
        accept_from=accept_from,
        compose_overrides=overrides,
        mta=mta,
        profile=profile,
        webmail=raw.get("webmail", False),
        admin_bind_address=admin_bind,
        webui_bundle=local_path(stalwart["webui_bundle"]) if stalwart.get("webui_bundle") else None,
        tls_certificate=local_path(tls["certificate"]) if tls.get("certificate") else None,
        tls_private_key=local_path(tls["private_key"]) if tls.get("private_key") else None,
        tls_ca_file=local_path(tls["ca_file"]) if tls.get("ca_file") else None,
    )


# --- credentials ---------------------------------------------------------------------------


def new_secret() -> str:
    """A random password or token: 32 URL-safe characters (192 bits)."""
    return secrets.token_urlsafe(24)


@dataclass(slots=True)
class Credentials:
    """The host's own passwords (``secrets/credentials.yaml``, 0600).

    An agent's secrets are not here: registration hands them to one bundle and keeps hashes
    (PLAN §5.2). ``agents`` holds only what an earlier install generated, until
    :func:`migrate_legacy_agents` has registered those agents.
    """

    gateway_master: str
    approver: str
    postmaster: str
    agents: dict[str, dict[str, str]] = field(default_factory=dict)


def load_credentials(params: LiveParams) -> Credentials:
    """Read the stored credentials, generating whatever is missing (never replacing any)."""
    stored: dict[str, Any] = {}
    if params.credentials_path.exists():
        stored = yaml.safe_load(params.credentials_path.read_text(encoding="utf-8"))
        required = {"gateway_master", "approver", "postmaster"}
        if not isinstance(stored, dict) or not required <= set(stored):
            # Never regenerate silently: that would change every password and token at once.
            raise ParamsError(
                f"{params.credentials_path} is damaged: restore it from a backup, or move it "
                "aside to generate every credential anew"
            )
    agents: dict[str, dict[str, str]] = {}
    for name, values in (stored.get("agents") or {}).items():
        agents[str(name)] = {str(key): str(value) for key, value in (values or {}).items()}
    return Credentials(
        gateway_master=str(stored.get("gateway_master") or new_secret()),
        approver=str(stored.get("approver") or new_secret()),
        postmaster=str(stored.get("postmaster") or new_secret()),
        agents=agents,
    )


def save_credentials(params: LiveParams, credentials: Credentials) -> None:
    body: dict[str, Any] = {
        "gateway_master": credentials.gateway_master,
        "approver": credentials.approver,
        "postmaster": credentials.postmaster,
    }
    if credentials.agents:  # an earlier install's, until they are migrated
        body["agents"] = credentials.agents
    header = "# Generated by `amx live install`. Secret: 0600, never in git.\n"
    write_private(params.credentials_path, header + yaml.safe_dump(body, sort_keys=True))


# --- rendering -----------------------------------------------------------------------------


def gateway_config(params: LiveParams, credentials: Credentials) -> dict[str, Any]:
    """The gateway YAML (PLAN §5.3) for the live domain; the master password is inline, so the
    file is 0600.

    It configures no agent: every agent is in the registry, with its own grant (PLAN §5.2). The
    registry and accounts paths are relative to the YAML, so they name the same files from the
    host, where `amx agent` runs, and from the gateway container, which mounts
    ``secrets/gateway`` read-only at ``/secrets`` (the gateway never reads the accounts file).
    """
    human = {
        "d": "*",
        "s": "*",
        "lane": "human",
        "intents": ["request", "response"],
        "schemas": ["*"],
        "can_open_tasks": False,
        "trust": "low",
    }
    limits = {
        "external_per_day": 10,
        "references_depth": 25,
        "received_depth": 25,
        **params.limits,
        "max_bytes": max_bytes(params),
    }
    config: dict[str, Any] = {
        # People remain external for quotas, but the signed-in local domain is known.
        "domain": params.agent_domain,
        "agent_domain": params.agent_domain,
        "people_domain": params.org_domain if params.mta == "stalwart" else None,
        "dns_zone": params.dns_zone,  # `amx agent` names its records relative to this zone
        "dkim_bits": params.dkim_bits,  # the size of the keys `amx agent` makes
        "data_dir": "/data",
        # The milter and LMTP trust whoever reaches them (PLAN §8), so they listen only on the
        # gateway's address on the bundle's private network; submission is the public port.
        "listeners": {
            "milter_host": params.gateway_ip,
            "milter_port": 8890,
            "people_milter_port": 8892 if params.mta == "stalwart" else 0,
            "sibling_milter_port": 8891 if params.mta == "stalwart" else 0,
            "lmtp_host": params.gateway_ip,
            "lmtp_port": 2424,
            "submission_host": "0.0.0.0",
            "submission_port": 2587,
            "submission_client_host": params.mx_host,
        },
        "postfix_host": params.mailhost_ip,
        "postfix_port": 10025,
        "sibling_port": 10027,
        "keys_dir": "keys",
        "registry_dir": "registry",
        "accounts_file": "../mailhost/accounts/agents.passwd",
        "submission_tls_cert": "/tls/server.pem",
        "submission_tls_key": "/tls/server-key.pem",
        "mailbox": {
            "host": params.mailhost_ip,
            "port": 143,
            "master_user": "gateway",
            "master_password": credentials.gateway_master,
        },
        "role_addresses": list(ROLE_ADDRESSES),
        "agents": {},
        "trust": [*params.trust, human],
        "hold_rules": list(params.hold_rules),
        "known_domains": [
            params.agent_domain,
            *([params.org_domain] if params.mta == "stalwart" else []),
            *params.known_domains,
        ],
        "outbound_allowlist": list(params.outbound_allowlist),
        "accept_from": list(params.accept_from),
        "limits": limits,
        "greylisting": False,
        "content_judge": {
            "backend": "stub",  # `amx live up` switches to jev when TYPESAFE_API_KEY is set
            "mode": params.judge_mode,
            "on_judge_error": {"agent": "tempfail", "human": "taint"},
        },
    }
    if params.tls_mode == "self-signed" or params.tls_ca_file:
        config["submission_tls_ca"] = "/tls/ca.pem"
    if params.mta == "stalwart":
        config["mailbox"].update(
            port=993,
            tls=True,
            tls_ca_file="/tls/ca.pem"
            if params.tls_mode == "self-signed" or params.tls_ca_file
            else None,
            tls_server_name=params.mx_host,
            master_login="{user}%{master}@" + params.org_domain,
            hold_owner=f"holds@{params.org_domain}",
            hold_prefix="Holds/{agent}/",
        )
    if params.profile == "private":
        config["outbound"] = "local-only"
        config["local_domains"] = [params.org_domain, params.agent_domain]
    return config


def password_hash(password: str) -> str:
    """A Dovecot SHA512-CRYPT hash, made here (the password goes to openssl on stdin, never on a
    command line) so that the mailhost never handles a plain password."""
    result = subprocess.run(
        ["openssl", "passwd", "-6", "-stdin"],
        input=password,
        check=True,
        capture_output=True,
        text=True,
    )
    return "{SHA512-CRYPT}" + result.stdout.strip()


def mail_users(params: LiveParams, credentials: Credentials) -> str:
    """The mailhost's own users (``address|hash``), read by its entrypoint at start.

    The postmaster mailbox and the two master logins; agents' logins are registered and reach
    the mailhost through the accounts file (PLAN §5.2).
    """
    users = [
        (params.address(POSTMASTER), credentials.postmaster),
        ("gateway", credentials.gateway_master),
        ("approver", credentials.approver),
    ]
    lines = ["# Generated by `amx live install`: password hashes. 0600, never in git."]
    lines += [f"{user}|{password_hash(password)}" for user, password in users]
    return "\n".join(lines) + "\n"


def imap_url(params: LiveParams) -> str:
    port = params.ports["imaps"]
    return f"imaps://{params.mx_host}" + ("" if port == 993 else f":{port}")


def submit_url(params: LiveParams) -> str:
    return f"smtp://{params.mx_host}:{params.ports['submission']}"


def logins(params: LiveParams, credentials: Credentials) -> str:
    """The two logins a person uses from a mail client (IMAPS, SSL/TLS on connect)."""
    port = params.ports["imaps"]
    if params.mta == "stalwart":
        return (
            f"# Secret: 0600. IMAPS {params.mx_host}:{port}, SSL/TLS.\n"
            f"# Approver: Shared Folders/holds@{params.org_domain}/Holds/<agent>/\n"
            f"user approver@{params.org_domain}\npassword {credentials.approver}\n"
            f"# Postmaster\nuser {POSTMASTER}@{params.org_domain}\n"
            f"password {credentials.postmaster}\n"
        )
    return (
        "# Secret: 0600. The people's logins, for a desktop mail client over IMAPS.\n"
        f"# Server {params.mx_host}, port {port}, SSL/TLS, password authentication.\n\n"
        "Approver (move held mail from Outbox/Held to Outbox/Approved or Outbox/Rejected).\n"
        "One account per agent: the user name is the agent's address, then '*approver'.\n"
        f"  user     <agent>@{params.agent_domain}*approver\n"
        f"  password {credentials.approver}\n\n"
        "Postmaster (postmaster@ and abuse@ mail, DMARC aggregate and TLS reports).\n"
        f"  user     {params.address(POSTMASTER)}\n"
        f"  password {credentials.postmaster}\n"
    )


def max_bytes(params: LiveParams) -> int:
    """The message size limit: the gateway's max_bytes, and port 25's and submission's too."""
    return int(params.limits.get("max_bytes", 10485760))


def compose_variables(params: LiveParams) -> dict[str, str]:
    """The compose file's variables. None is a secret; API keys never pass through here."""
    role_forward = params.admin_contact if params.forward_role_mail else ""
    variables = {
        "MX_HOST": params.mx_host,
        "AGENT_DOMAIN": params.agent_domain,
        "MAILHOST_IP": params.mailhost_ip,
        "GATEWAY_IP": params.gateway_ip,
        "SUBNET": str(params.subnet),
        "BIND_ADDRESS": params.bind_address,
        "SMTP_PORT": str(params.ports["smtp"]),
        "SUBMISSION_PORT": str(params.ports["submission"]),
        "IMAPS_PORT": str(params.ports["imaps"]),
        "SECRETS_DIR": str(params.secrets_dir),
        "DATA_DIR": str(params.data_dir),
        "AMX_UID": str(os.getuid()),
        "AMX_GID": str(os.getgid()),
        "ROLE_ADDRESSES": " ".join(ROLE_ADDRESSES),
        "ROLE_FORWARD": role_forward,
        # Port 25 takes max_bytes; cleanup's global limit leaves room for what signing adds.
        "MAX_BYTES": str(max_bytes(params)),
        "GLOBAL_MAX_BYTES": str(3 * max_bytes(params)),
        "AMX_LLM_BASE_URL": params.llm["base_url"],
        "AMX_LLM_MODEL": params.llm["model"],
        "AMX_LLM_TIMEOUT": params.llm["timeout"],
        "LLM_BRIEFS": params.llm["briefs"],
    }
    if params.mta == "stalwart":
        variables.update(
            STALWART_DIR=str(params.state_dir / "stalwart"),
            WEBMAIL_PORT=str(params.ports["webmail"]),
            PEOPLE_SUBMISSION_PORT=str(params.ports["people_submission"]),
            DISCOVERY_PORT=str(params.ports["discovery"]),
            ADMIN_BIND_ADDRESS=params.admin_bind_address,
        )
    return variables


# --- DNS -----------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Record:
    """One DNS record to request, named absolutely."""

    name: str
    type: str
    data: str
    note: str = ""
    priority: int | None = None

    def relative(self, zone: str) -> str:
        """The name as a DNS manager's Name column shows it: ``@`` for the zone itself."""
        if self.name == zone:
            return "@"
        return self.name.removesuffix(f".{zone}")


# The "agent" a domain key's Selector names: it signs for every registered agent (SH-44).
DOMAIN_AGENTS = "every agent"


@dataclass(frozen=True, slots=True)
class Selector:
    """A DKIM selector that should be in DNS now, and why (PLAN §5.2's rotation)."""

    agent: str
    selector: str
    role: str  # active, pending (staged, not signing yet), or "retiring until <time>"

    @property
    def key(self) -> str:
        return f"{self.selector}.private.pem"


def registrations(params: LiveParams) -> dict[str, Registration]:
    """The registered agents (none before the first install)."""
    return read_registrations(params.registry_dir) if params.registry_dir.is_dir() else {}


def registration_site(params: LiveParams) -> Site:
    """This lane's registration state: its registry, keys, accounts, and the gateway's check."""
    from amx.registration import Site

    return Site(
        domain=params.agent_domain,
        agent_domain=params.agent_domain,
        registry_dir=params.registry_dir,
        keys_dir=params.keys_dir,
        accounts_file=params.accounts_file,
        validate=lambda: load_config(params.gateway_config),
        dkim_bits=params.dkim_bits,
        zone=params.dns_zone,
    )


def dkim_selectors(params: LiveParams) -> list[Selector]:
    """Every selector to publish: the domain's key (SH-44), or each agent's own keys before it.

    Once the domain key is active it is the only one, with any keys it replaced while they
    retire. While a lane migrates (the domain key staged, not yet signing), its agents' own keys
    are listed beside it. Before the install that migrates them, an earlier install's agents
    still sign under their name, so they are listed too: `amx live dns` renders the same records
    across an upgrade.
    """
    now = datetime.now(UTC)
    registered = registrations(params)
    domain_state = domain_dkim.read(params.registry_dir) if params.registry_dir.is_dir() else None
    selectors = (
        [
            Selector(
                DOMAIN_AGENTS if domain_dkim.is_domain_selector(sel) else selector_agent(sel),
                sel,
                role,
            )
            for sel, role in domain_state.selectors(now)
        ]
        if domain_state is not None
        else []
    )
    if domain_state is not None and domain_state.active is not None:
        return selectors
    selectors += [
        Selector(name, selector, role)
        for name, registration in sorted(registered.items())
        for selector, role in registration.selectors(now)
    ]
    selectors += [
        Selector(agent.name, agent.name, "active")
        for agent in params.legacy_agents
        if agent.name not in registered
        and (params.keys_dir / f"{agent.name}.private.pem").is_file()
    ]
    return selectors


def dns_records(params: LiveParams) -> list[Record]:
    """Every record the live domain needs, rendered from the parameters and the DKIM keys."""
    ip = params.public_ip
    spf = f"v=spf1 ip4:{ip} -all"
    # adkim=s: the agents' mail is signed d=<agent domain>. aspf=r: the gateway's own DSNs
    # (PLAN §5.11, MAILER-DAEMON@<agent domain>) are unsigned and pass SPF only through the HELO
    # name, the MX host, which shares the organizational domain.
    dmarc = f"v=DMARC1; p={params.dmarc_policy}; rua=mailto:{params.dmarc_rua}; adkim=s; aspf=r"
    records = [
        Record(params.mx_host, "A", ip, "the MX host; the PTR of the IP must name it back"),
        Record(
            params.agent_domain,
            "MX",
            params.mx_host,
            "agent mail goes to the MX host",
            priority=10,
        ),
        Record(params.agent_domain, "TXT", spf, "SPF for the agents' envelope senders"),
        Record(
            params.mx_host,
            "TXT",
            spf,
            "SPF for the HELO name: covers DSNs, sent from MAILER-DAEMON@ the MX host",
        ),
        Record(f"_dmarc.{params.agent_domain}", "TXT", dmarc, "DMARC for the agents"),
    ]
    for item in dkim_selectors(params):
        key = params.keys_dir / item.key
        value = dkim_txt_value(dkim_public_key(key)) if key.is_file() else f"<no key at {key}>"
        records.append(
            Record(
                f"{item.selector}._domainkey.{params.agent_domain}",
                "TXT",
                value,
                f"DKIM for {item.agent} (selector {item.selector}, {item.role})",
            )
        )
    if params.tls_rpt:
        records.append(
            Record(
                f"_smtp._tls.{params.agent_domain}",
                "TXT",
                f"v=TLSRPTv1; rua=mailto:{params.dmarc_rua}",
                "TLS-RPT: senders report TLS failures to the postmaster mailbox",
            )
        )
    if params.caa:
        records.append(
            Record(
                params.dns_zone if params.manage_apex else params.mx_host,
                "CAA",
                f'0 issue "{params.caa}"',
                "only this CA may issue certificates here",
            )
        )
    if params.manage_apex:
        if apex_sends_nothing(params):
            records.append(
                Record(params.dns_zone, "TXT", "v=spf1 -all", "the zone's own name sends no mail")
            )
        records.extend(
            (
                Record(
                    f"_dmarc.{params.dns_zone}",
                    "TXT",
                    dmarc,
                    "DMARC for the zone and every name without its own record",
                ),
            )
        )
    return records


def apex_sends_nothing(params: LiveParams) -> bool:
    """Whether the zone's own name is neither the agent domain nor the MX host (whose SPF records
    authorize the IP): only then does it get `v=spf1 -all`. Two SPF records at one name are a
    permanent error."""
    return params.dns_zone not in (params.agent_domain, params.mx_host)


def render_dns(params: LiveParams) -> str:
    """The DNS request: records in a DNS manager's terms, the PTR, and what to check."""
    if params.profile == "private":
        return (
            f"# Private profile: no public DNS records required for {params.agent_domain}.\n"
            f"# Resolve {params.mx_host} to this server on your LAN/tailnet.\n"
            "# Own-agent DKIM keys are resolved locally by the gateway (SH-21).\n"
        )
    zone = params.dns_zone
    records = dns_records(params)
    lines = [
        f"# DNS for {params.agent_domain}, in the zone {zone}. TTL {params.dns_ttl} s.",
        "# Type  Name (relative to the zone)  Data",
        "",
    ]
    for record in records:
        priority = f"priority {record.priority}  " if record.priority is not None else ""
        lines.append(f"{record.type:<5} {record.relative(zone)}")
        lines.append(f"      {priority}{record.data}")
        lines.append(f"      ({record.note})")
        if record.type == "TXT" and len(record.data) > 255:
            quoted = " ".join(f'"{part}"' for part in txt_strings(record.data))
            lines.append(
                f"      {len(record.data)} characters: if the editor refuses or cuts it, enter it "
                "as these quoted strings:"
            )
            lines.append(f"      {quoted}")
        lines.append("")
    lines.extend(
        [
            "# Remove at the same names: any other MX, any other TXT starting v=spf1 or",
            "# v=DMARC1, and any CNAME (a CNAME cannot sit beside other records).",
            "",
            "# At the hosting provider, not in this zone:",
            f"PTR   {params.public_ip} -> {params.mx_host}",
            "",
            "# Then: amx live preflight (it checks each record against the keys).",
        ]
    )
    return "\n".join(lines) + "\n"


def zone_file(params: LiveParams, nameservers: Sequence[str], origin: str | None = None) -> str:
    """A BIND zone of the records under ``origin``: by default the agent domain alone, for a
    delegation (NS) to a DNS host we control."""
    origin = origin or params.agent_domain
    local, _, domain = params.admin_contact.partition("@")
    hostmaster = f"{local.replace('.', chr(92) + '.')}.{domain}"
    lines = [
        f"$ORIGIN {origin}.",
        f"$TTL {params.dns_ttl}",
        f"@ IN SOA {nameservers[0]}. {hostmaster}. ({int(time.time())} 3600 600 1209600 300)",
        *(f"@ IN NS {server}." for server in nameservers),
    ]
    for record in dns_records(params):
        if record.name != origin and not record.name.endswith(f".{origin}"):
            continue  # e.g. the MX host's own records, which live in the parent zone
        name = record.relative(origin)
        if record.type == "MX":
            lines.append(f"{name} IN MX {record.priority} {record.data}.")
        elif record.type == "CAA":
            lines.append(f"{name} IN CAA {record.data}")
        elif record.type == "TXT":
            lines.append(
                f"{name} IN TXT " + " ".join(f'"{part}"' for part in txt_strings(record.data))
            )
        else:
            lines.append(f"{name} IN {record.type} {record.data}")
    return "\n".join(lines) + "\n"


# --- TLS -----------------------------------------------------------------------------------


def _openssl(*args: str) -> None:
    subprocess.run(["openssl", *args], check=True, capture_output=True)


def certificate_names(params: LiveParams) -> tuple[str, ...]:
    if params.mta == "stalwart":
        return tuple(
            dict.fromkeys(
                (
                    params.mx_host,
                    params.org_domain,
                    "autoconfig." + params.org_domain,
                    "autodiscover." + params.org_domain,
                    *params.tls_extra_names,
                )
            )
        )
    return (params.mx_host, *params.tls_extra_names)


def _san(name: str) -> str:
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return f"DNS:{name}"
    return f"IP:{name}"


def cert_info(path: Path) -> dict[str, Any]:
    """The first certificate's names, issuer, and expiry, as ``openssl x509`` prints them."""
    output = subprocess.run(
        ["openssl", "x509", "-in", str(path), "-noout", "-enddate", "-issuer", "-subject",
         "-ext", "subjectAltName", "-nameopt", "sep_multiline,utf8"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout  # fmt: skip
    fields: dict[str, dict[str, str]] = {"issuer": {}, "subject": {}}
    names: list[str] = []
    expires = datetime.now(UTC)
    section = ""
    for line in output.splitlines():
        if line.startswith("notAfter="):
            value = line.partition("=")[2].strip()
            expires = datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
        elif line.startswith(("issuer=", "subject=")):
            section = line.partition("=")[0]
        elif line.startswith("X509v3 Subject Alternative Name"):
            section = "san"
        elif section == "san":
            names += re.findall(r"(?:DNS|IP Address):([^,\s]+)", line)
        elif section in fields:
            key, _, value = line.strip().partition("=")
            fields[section][key] = value
    return {
        "names": names,
        "expires": expires,
        "issuer": fields["issuer"].get("CN", ""),
        "self_issued": fields["issuer"] == fields["subject"],
    }


def install_file_certificate(params: LiveParams) -> None:
    """Validate an immutable PEM snapshot before publishing into the mounted directory."""
    import ssl

    if params.tls_certificate is None or params.tls_private_key is None:
        raise ParamsError("files mode requires certificate and private_key paths")
    params.tls_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(dir=params.tls_dir) as directory:
        work = Path(directory)
        cert, key = work / "server.pem", work / "server-key.pem"
        write_private(cert, params.tls_certificate.read_bytes(), 0o644)
        write_private(key, params.tls_private_key.read_bytes())
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        info = cert_info(cert)
        if params.mx_host not in info["names"] or info["expires"] <= datetime.now(UTC):
            raise ParamsError("TLS certificate must be unexpired and cover mx_host in its SANs")
        ca = params.tls_ca_file.read_bytes() if params.tls_ca_file else None
        if ca is not None:
            ssl.create_default_context(cadata=ca.decode("ascii"))
        # No reload occurs until the complete pair is published. Mount the directory,
        # never individual inodes (renewal tools frequently replace symlinks/files).
        write_private(params.tls_dir / "server-key.pem", key.read_bytes())
        write_private(params.tls_dir / "server.pem", cert.read_bytes(), 0o644)
        if ca is not None:
            write_private(params.tls_dir / "ca.pem", ca, 0o644)
        else:
            (params.tls_dir / "ca.pem").unlink(missing_ok=True)


def reload_tls(params: LiveParams) -> None:
    """Explicit renewal hook: no restart fallback, and retry both halves on every call."""
    if params.mta != "stalwart":
        raise ParamsError("hot TLS reload requires mta: stalwart")
    commands = [
        compose(
            params,
            "exec",
            "-T",
            "stalwart-sync",
            "python",
            "/opt/amx/stalwart.py",
            "reload-tls",
            "--admin-file=/secrets/recovery-admin",
        ),
        compose(
            params,
            "exec",
            "-T",
            "gateway",
            "/app/.venv/bin/python",
            "-m",
            "amx.tls_reload",
            "--data-dir=/data",
        ),
    ]
    for command in commands:
        try:
            subprocess.run(
                command, env=compose_environment(), capture_output=True, check=True, timeout=90
            )
        except (OSError, subprocess.SubprocessError) as error:
            # Management errors may contain credentials. Do not forward stdout/stderr.
            raise ParamsError(
                "TLS reload failed; fix the cause and rerun `amx live certs`; no restart attempted"
            ) from error


@app.command("reload-tls")
def reload_tls_command(params_path: ParamsOption = DEFAULT_PARAMS) -> None:
    """Reload the already installed TLS files without renewing or restarting."""
    reload_tls(_params(params_path))
    typer.echo("Stalwart and gateway TLS reloaded without restart")


def ensure_self_signed(params: LiveParams, *, force: bool = False) -> bool:
    """A private CA and a server certificate for the MX host; returns whether it changed."""
    tls = params.tls_dir
    tls.mkdir(parents=True, exist_ok=True)
    # The CA's key stays out of secrets/tls, which the containers mount (handlers run in the
    # gateway), and the CA may sign only these names (and no IP address unless one is among
    # them): trusting ca.pem trusts no other name.
    private = params.secrets_dir / "ca"
    _mkdir(private, 0o700)
    ca, ca_key, ca_names = tls / "ca.pem", private / "ca-key.pem", private / "names"
    server, server_key = tls / "server.pem", tls / "server-key.pem"
    wanted = certificate_names(params)
    (tls / "ca-key.pem").unlink(missing_ok=True)  # where an earlier install kept it
    current = ca_names.read_text(encoding="utf-8").split() if ca_names.is_file() else []
    new_ca = not ca.is_file() or not ca_key.is_file() or current != list(wanted)
    if new_ca:
        constraints = [_name_constraint(name) for name in wanted]
        if not any(_san(name).startswith("IP:") for name in wanted):
            constraints += ["excluded;IP:0.0.0.0/0.0.0.0", f"excluded;IP:{_V6_ANY}/{_V6_ANY}"]
        permitted = ",".join(constraints)
        work = Path(tempfile.mkdtemp(dir=private))
        try:
            _openssl(
                "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
                "-subj", f"/CN=amx live self-signed CA ({params.agent_domain})",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-addext", f"nameConstraints=critical,{permitted}",
                "-keyout", str(work / "key.pem"), "-out", str(work / "ca.pem"),
            )  # fmt: skip
            write_private(ca_key, (work / "key.pem").read_bytes())
            write_private(ca, (work / "ca.pem").read_bytes(), 0o644)
        finally:
            shutil.rmtree(work)
        force = True
    if not force and server.is_file() and server_key.is_file():
        info = cert_info(server)
        fresh = (info["expires"] - datetime.now(UTC)).days > 30
        if fresh and all(name in info["names"] for name in wanted) and _chains(server, ca):
            return False
    work = Path(tempfile.mkdtemp(dir=private))
    try:
        (work / "ext").write_text(
            f"subjectAltName={','.join(_san(name) for name in wanted)}\n"
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\n",
            encoding="utf-8",
        )
        _openssl(
            "req", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={params.mx_host}",
            "-keyout", str(work / "key.pem"), "-out", str(work / "csr.pem"),
        )  # fmt: skip
        _openssl(
            "x509", "-req", "-days", "397", "-sha256", "-in", str(work / "csr.pem"),
            "-CA", str(ca), "-CAkey", str(ca_key), "-CAcreateserial",
            "-CAserial", str(work / "serial"), "-extfile", str(work / "ext"),
            "-out", str(work / "cert.pem"),
        )  # fmt: skip
        write_private(server_key, (work / "key.pem").read_bytes())
        write_private(server, (work / "cert.pem").read_bytes() + ca.read_bytes(), 0o644)
    finally:
        shutil.rmtree(work)
    if new_ca:
        # Last: a run that dies before this point makes a new CA and certificate next time.
        write_private(ca_names, " ".join(wanted) + "\n")
    return True


_V6_ANY = "0:0:0:0:0:0:0:0"


def _name_constraint(name: str) -> str:
    """A nameConstraints entry that permits exactly ``name``."""
    try:
        address = ipaddress.ip_address(name)
    except ValueError:
        return f"permitted;DNS:{name}"
    mask = "255.255.255.255" if address.version == 4 else ":".join(["ffff"] * 8)
    return f"permitted;IP:{name}/{mask}"


def _chains(certificate: Path, ca: Path) -> bool:
    """Whether ``certificate`` was issued by (the current) ``ca``."""
    result = subprocess.run(
        ["openssl", "verify", "-CAfile", str(ca), str(certificate)],
        capture_output=True,
        check=False,
    )
    return result.returncode == 0


def lineage_server(params: LiveParams) -> str | None:
    """The ACME server certbot's lineage was issued by, if there is a lineage."""
    renewal = params.secrets_dir / "acme" / "config" / "renewal" / f"{CERT_NAME}.conf"
    if not renewal.is_file():
        return None
    for line in renewal.read_text(encoding="utf-8").splitlines():
        key, equals, value = line.partition("=")
        if equals and key.strip() == "server":
            return value.strip()
    return ""


def certbot_command(params: LiveParams, *, renew: bool, replace: bool = False) -> list[str]:
    """The certbot run (docker) that issues or renews the MX host's certificate.

    ``replace`` issues a new certificate now, as when the parameters moved from the staging CA
    to the production one (``renew`` would keep the lineage's own server).
    """
    acme = params.secrets_dir / "acme"
    interactive = params.acme_challenge == "dns-01-manual"
    command = ["docker", "run", "--rm", *(["-it"] if interactive else [])]
    command += ["--user", f"{os.getuid()}:{os.getgid()}", "-v", f"{acme}:/acme"]
    if params.acme_challenge == "http-01":
        command += ["-p", f"{params.bind_address}:{params.ports['acme_http']}:8080"]
    command += [params.certbot_image]
    dirs = ["--config-dir", "/acme/config", "--work-dir", "/acme/work", "--logs-dir", "/acme/logs"]
    if renew:
        command += ["renew", *dirs, "--non-interactive", "--cert-name", CERT_NAME]
        if params.acme_challenge == "http-01":
            command += ["--http-01-port", "8080"]
        return command
    # --keep-until-expiring: a manual (DNS-01) lineage cannot `renew` unattended, so `certs`
    # asks again, and certbot only prompts once the certificate is due.
    command += ["certonly", *dirs, "--cert-name", CERT_NAME, "-d", params.mx_host]
    command += ["--force-renewal" if replace else "--keep-until-expiring"]
    command += ["--server", params.acme_server, "-m", params.admin_contact, "--agree-tos"]
    command += ["--key-type", "rsa", "--rsa-key-size", "2048"]
    if params.acme_challenge == "http-01":
        # Port 80 on the host reaches certbot's standalone listener on 8080 in the container, so
        # certbot needs no root. Nothing else in the bundle listens on 80.
        command += ["--non-interactive", "--standalone", "--http-01-port", "8080"]
    else:
        command += ["--manual", "--preferred-challenges", "dns"]
    return command


def install_acme_certificate(params: LiveParams) -> bool:
    """Copy certbot's current certificate into ``secrets/tls``; returns whether it changed."""
    live = params.secrets_dir / "acme" / "config" / "live" / CERT_NAME
    chain, key = live / "fullchain.pem", live / "privkey.pem"
    if not chain.is_file() or not key.is_file():
        raise FileNotFoundError(f"no certificate from certbot at {live}")
    target = params.tls_dir / "server.pem"
    if target.is_file() and target.read_bytes() == chain.read_bytes():
        return False
    write_private(params.tls_dir / "server-key.pem", key.read_bytes())
    write_private(target, chain.read_bytes(), 0o644)
    return True


# --- compose -------------------------------------------------------------------------------


def compose(params: LiveParams, *args: str) -> list[str]:
    command = ["docker", "compose", "--project-name", params.compose_project]
    command += ["--env-file", str(params.compose_env), "-f", str(BUNDLE / "compose.yaml")]
    if params.mta == "stalwart":
        command += ["-f", str(BUNDLE / "compose.stalwart.yaml")]
        if params.webmail:
            command += ["--profile", "webmail"]
    if params.profile == "private":
        command += ["-f", str(BUNDLE / f"compose.private.{params.mta}.yaml")]
    for override in params.compose_overrides:
        command += ["-f", str(override)]
    return [*command, *args]


COMPOSE_VARIABLES = (
    "MX_HOST", "AGENT_DOMAIN", "MAILHOST_IP", "GATEWAY_IP", "SUBNET", "BIND_ADDRESS", "SMTP_PORT",
    "SUBMISSION_PORT", "IMAPS_PORT", "SECRETS_DIR", "DATA_DIR", "AMX_UID", "AMX_GID",
    "ROLE_ADDRESSES", "ROLE_FORWARD", "MAX_BYTES", "GLOBAL_MAX_BYTES", "AMX_LLM_BASE_URL",
    "AMX_LLM_MODEL", "AMX_LLM_TIMEOUT", "LLM_BRIEFS",
)  # fmt: skip


def compose_environment() -> dict[str, str]:
    """The environment for compose: the caller's, with the judge chosen by TYPESAFE_API_KEY.

    The shell's copies of compose.env's own variables are dropped, since compose would prefer
    them to compose.env. API keys pass through: that is how they reach the gateway.
    """
    reserved = (
        *COMPOSE_VARIABLES,
        "STALWART_DIR",
        "WEBMAIL_PORT",
        "COMPOSE_PROFILES",
        "ADMIN_BIND_ADDRESS",
        "PEOPLE_SUBMISSION_PORT",
        "DISCOVERY_PORT",
    )
    environment = {key: value for key, value in os.environ.items() if key not in reserved}
    environment["AMX_CONTENT_JUDGE_BACKEND"] = (
        "jev" if environment.get("TYPESAFE_API_KEY") else "stub"
    )
    return environment


def run_compose(params: LiveParams, *args: str, check: bool = True) -> int:
    result = subprocess.run(compose(params, *args), env=compose_environment(), check=False)
    if check and result.returncode:
        raise typer.Exit(result.returncode)
    return result.returncode


class DockerUnavailable(RuntimeError):
    """Docker could not say whether a service runs (no daemon, no permission)."""


def running(params: LiveParams, service: str) -> bool:
    """Whether the service's container runs. A Docker failure raises, never reads as "no"."""
    try:
        result = subprocess.run(
            compose(params, "ps", "--status", "running", "--quiet", service),
            env=compose_environment(),
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        detail = (getattr(error, "stderr", None) or str(error)).strip()
        raise DockerUnavailable(f"cannot ask Docker about the {service}: {detail}") from error
    return bool(result.stdout.strip())


def reload_services(params: LiveParams, *, mailhost: bool, gateway: bool, why: str) -> None:
    """Restart what runs so it reads new certificates or credentials.

    Each restart is recorded first, whether or not Docker can be asked (:func:`record_restart`),
    and forgotten once the container has started again or is found stopped, so one that fails is
    retried by the next `certs` run.
    - The mailhost is recreated from the checkout's image: a plain restart keeps the image it was
      made from, and one older than the files install now writes reads its agents only from
      mail-users, so it would lose every registered agent's login. Its environment holds no
      secret.
    - The gateway is restarted, which keeps its environment: recreated by a caller without
      TYPESAFE_API_KEY (the renewal cron), it would lose the live judge and the LLM key.
    """
    for service, wanted in (("mailhost", mailhost), ("gateway", gateway)):
        if wanted:
            record_restart(params, service, why, origin="reload")
    if mailhost and running(params, "mailhost"):
        run_compose(
            params, "up", "-d", "--build", "--no-deps", "--force-recreate", "--wait", "mailhost"
        )
    if gateway and running(params, "gateway"):
        run_compose(params, "restart", "gateway")


# --- restarts owed -----------------------------------------------------------------------------

RESTART_MARKER = "restart-pending.json"


@dataclass(frozen=True, slots=True)
class OwedRestart:
    """A restart the lane owes: why, and who asked.

    ``origin`` is ``install`` (the gateway cannot apply agent changes until it restarts on this
    checkout's images: `amx live up`, then a restart) or ``reload`` (a new certificate or
    password that `certs` and `rotate` restart for themselves, and retry).
    """

    why: str
    origin: str


def started_at(params: LiveParams, service: str) -> datetime | None:
    """When the service's running container started; None only if Docker says it is not
    running. Any other failure raises: not knowing must never read as "restarted"."""
    if not running(params, service):
        return None
    try:
        container = subprocess.run(
            compose(params, "ps", "-q", "--status", "running", service),
            env=compose_environment(),
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        stamp = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.StartedAt}}", container],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as error:
        detail = (getattr(error, "stderr", None) or str(error)).strip()
        raise DockerUnavailable(f"cannot ask Docker about the {service}: {detail}") from error
    # RFC 3339 with nanoseconds: fromisoformat takes microseconds.
    return datetime.fromisoformat(re.sub(r"(\.\d{6})\d*", r"\1", stamp).replace("Z", "+00:00"))


def record_restart(params: LiveParams, service: str, why: str, *, origin: str) -> None:
    """Note that ``service`` must restart to read what was just written.

    The record keeps the container's start time as it is now, if Docker can say: the restart
    has happened once that changes, whatever the clocks say. Without it, the record falls back
    to comparing the start time with when it was written.
    """
    marker = params.state_dir / RESTART_MARKER
    pending = json.loads(marker.read_text(encoding="utf-8")) if marker.is_file() else {}
    try:
        before = started_at(params, service)
    except DockerUnavailable:
        before = None
    previous = pending.get(service) or {}
    pending[service] = {
        "at": datetime.now(UTC).isoformat(),
        "before": before.isoformat() if before else None,
        "why": why,
        # An install record outranks a reload one: only the former holds agent changes back.
        "origin": "install" if "install" in (origin, previous.get("origin")) else origin,
    }
    write_private(marker, json.dumps(pending, indent=2) + "\n", 0o644)


def pending_restarts(params: LiveParams) -> dict[str, OwedRestart]:
    """The restarts owed that have not happened, by service.

    A service found stopped (its next start reads the files), or one whose container has
    started since the record, owes none any more; the marker forgets it. If Docker cannot be
    asked, this raises :class:`DockerUnavailable` and the marker stays.
    """
    marker = params.state_dir / RESTART_MARKER
    if not marker.is_file():
        return {}
    pending = json.loads(marker.read_text(encoding="utf-8"))
    for service, entry in list(pending.items()):
        started = started_at(params, service)
        before = entry.get("before")
        if started is None:
            done = True
        elif before is not None:
            done = started != datetime.fromisoformat(before)
        else:
            done = started >= datetime.fromisoformat(entry["at"])
        if done:
            del pending[service]
    if pending:
        write_private(marker, json.dumps(pending, indent=2) + "\n", 0o644)
    else:
        marker.unlink(missing_ok=True)
    return {
        service: OwedRestart(str(entry["why"]), str(entry.get("origin", "install")))
        for service, entry in pending.items()
    }


def _loads(path: Path) -> Any:
    """The gateway configuration at ``path``, or None if there is none or it does not load."""
    try:
        return load_config(path) if path.is_file() else None
    except (OSError, ValueError, KeyError):
        return False  # something is there that this version cannot read


def _user_names(path: Path) -> list[str] | None:
    if not path.is_file():
        return None
    lines = path.read_text(encoding="utf-8").splitlines()
    return sorted(line.split("|", 1)[0] for line in lines if line and not line.startswith("#"))


# --- install -------------------------------------------------------------------------------


def _mkdir(path: Path, mode: int, *, ours: bool = True) -> None:
    """Create ``path``; set its mode if it is ours, or new (never widen a directory we found)."""
    existed = path.exists()
    path.mkdir(parents=True, exist_ok=True)
    if ours or not existed:
        path.chmod(mode)


def install(params: LiveParams) -> list[str]:
    """Create or refresh the state directory; keeps every existing secret, key, and agent.

    Agents are registered, not installed (`amx live agent add`). An earlier install's agents
    (``agents:`` in the parameters) are migrated into the registry here, once.
    """
    webui_data = None
    if params.mta == "stalwart" and params.webui_bundle:
        from amx.stalwart_webui import read_webui

        # Validate one immutable read before ANY generated state is changed.
        webui_data = read_webui(params.webui_bundle)
    _mkdir(params.state_dir, 0o755, ours=False)
    _mkdir(params.secrets_dir, 0o700)
    for sub in (
        "gateway",
        "gateway/keys",
        "gateway/registry",
        "mailhost",
        "mailhost/accounts",
        "agents",
        "tls",
        "ca",
        "acme",
    ):
        _mkdir(params.secrets_dir / sub, 0o700)
    _mkdir(params.data_dir, 0o700)
    notes: list[str] = []
    credentials = load_credentials(params)
    save_credentials(params, credentials)
    notes += migrate_legacy_agents(params, credentials)
    if params.tls_mode == "files":
        install_file_certificate(params)
    elif params.tls_mode == "self-signed" and ensure_self_signed(params):
        notes.append("self-signed certificate written (clients need secrets/tls/ca.pem)")
    elif params.tls_mode == "acme" and not (params.tls_dir / "server.pem").is_file():
        notes.append("no certificate yet: once DNS resolves, run `amx live certs`")
    users_path = params.secrets_dir / "mailhost" / "mail-users"
    before, users_before = _loads(params.gateway_config), _user_names(users_path)
    write_gateway_config(params, credentials)
    write_private(users_path, mail_users(params, credentials))
    if params.mta == "stalwart":
        from amx.live_stalwart import install_stalwart

        install_stalwart(params, credentials, webui_data=webui_data)
    notes += _restarts_needed(params, before, users_before, _user_names(users_path))
    write_private(params.secrets_dir / "logins.txt", logins(params, credentials))
    variables = compose_variables(params)
    write_private(
        params.compose_env,
        "".join(f"{key}={value}\n" for key, value in variables.items()),
        0o644,
    )
    # SH-44: one DKIM key for the domain. A new lane signs with it at once; a lane whose agents
    # sign with their own keys gets it staged, and `amx live dkim activate` switches once DNS
    # serves it (docs/selfhost-public.md §8).
    state = domain_dkim.ensure(registration_site(params))
    if state.active is None and state.pending is not None:
        notes.append(
            f"domain DKIM key {state.pending} staged: publish it (`amx live dns`), then "
            "`amx live dkim activate`; until then each agent signs with its own key"
        )
    # Last: the migrated agents' plaintext leaves the host's credentials only once the gateway
    # configuration that reads their hashes is in place.
    registered = registrations(params)
    migrated = sorted(name for name in credentials.agents if name in registered)
    if migrated:
        for name in migrated:
            del credentials.agents[name]
        save_credentials(params, credentials)
    (params.state_dir / "dns-records.txt").write_text(render_dns(params), encoding="utf-8")
    return notes


def _restarts_needed(
    params: LiveParams, before: Any, users_before: list[str] | None, users_after: list[str] | None
) -> list[str]:
    """Note what a running lane must restart for, and record it (`amx live agent` checks).

    The gateway's reload applies registry changes on top of listener, TLS, and mailbox changes
    (``amx.reload.KEEPABLE_FIELDS``), but not on top of a new domain, data directory, registry,
    or control address: until the gateway restarts, an agent's removal would not take effect.
    The mailhost reads its own users only at start.
    """
    notes: list[str] = []
    if before is not None:
        fields = (
            ["configuration"]
            if before is False
            else restart_needed(before, load_config(params.gateway_config))
        )
        blocking = [field for field in fields if field not in KEEPABLE_FIELDS]
        if fields:
            notes.append(
                f"the gateway reads {', '.join(fields)} only at start: if the lane runs, "
                "amx live up, then amx live compose restart gateway"
            )
        if blocking:
            record_restart(
                params, "gateway", f"install changed {', '.join(blocking)}", origin="install"
            )
    if users_before is not None and users_before != users_after:
        notes.append(
            "the mailhost's own users changed: if the lane runs, amx live up, then "
            "amx live compose restart mailhost"
        )
        record_restart(params, "mailhost", "install changed its users", origin="install")
    return notes


def write_gateway_config(params: LiveParams, credentials: Credentials) -> None:
    """Render the gateway YAML, and replace the old one only if the gateway would load it.

    It is checked where it will live (paths in it are relative to it), under another name, so
    a running gateway's watcher never sees a configuration that does not load.
    """
    config = gateway_config(params, credentials)
    header = (
        "# Generated by `amx live install` from the parameters file. Secret: 0600.\n"
        "# Agents are registered, not listed here: `amx live agent add` (PLAN §5.2, §11.5).\n"
    )
    candidate = params.gateway_config.with_name(f".{params.gateway_config.name}.new")
    write_private(candidate, header + yaml.safe_dump(config, sort_keys=False))
    try:
        load_config(candidate)  # the gateway's own validation, registered agents included
    except ValueError as error:
        candidate.unlink(missing_ok=True)
        raise ParamsError(
            f"the gateway would not load the rendered configuration: {error}"
        ) from error
    os.replace(candidate, params.gateway_config)


def migrate_legacy_agents(params: LiveParams, credentials: Credentials) -> list[str]:
    """Register the agents an install before PLAN §11.5 configured from ``agents:``.

    Each keeps what it had, so neither DNS nor the agent's host changes: its DKIM key and
    selector (its name), its submission token and IMAP password (hashed into the registry and
    the accounts file), its mode, handler, and limits. Its mailbox was made by the earlier
    mailhost and carries no generation, so the mailhost would delete it as another
    registration's: the adoption list names it first (``address:generation``), and
    amx-sync-accounts adopts exactly that home for exactly that registration.

    Returns what to tell the operator. The agents' plaintext leaves ``credentials.yaml`` in
    :func:`install`, once the new gateway configuration is written.
    """
    notes: list[str] = []
    with locked(params.registry_dir):
        registered = read_registrations(params.registry_dir)
        # An earlier install's agent that agents: no longer lists would be dropped from the
        # mailhost's users and never registered: its login gone, its plaintext left behind, and
        # its mailbox deleted when the name is registered again. Refuse, and say what to do.
        listed = {agent.name for agent in params.legacy_agents}
        orphans = sorted(set(credentials.agents) - listed - set(registered))
        if orphans:
            raise ParamsError(
                f"credentials.yaml holds {', '.join(orphans)} from an earlier install, but "
                "agents: does not list them. List each under agents: to move it into the registry "
                "with its key, credentials, and mailbox; or, for an agent that is gone, delete its "
                "entry from credentials.yaml (and keys/<name>.private.pem)"
            )
        if not params.legacy_agents:
            return []
        accounts = read_accounts(params.accounts_file)
        adopt = params.adopt_file
        for agent in params.legacy_agents:
            if agent.name in registered:
                continue
            stored = credentials.agents.get(agent.name) or {}
            if not {"submit_token", "imap_password"} <= set(stored):
                raise ParamsError(
                    f"agents: {agent.name} was never installed. Agents are registered now: "
                    f"`amx live agent add {agent.name}` (docs/selfhost-public.md §6); "
                    "remove it from agents:"
                )
            if agent.content_judge is not None:
                raise ParamsError(
                    f"agents: {agent.name} sets content_judge, which a registered agent does not "
                    "have (it follows content_judge.mode); remove it, then run install again"
                )
            key = params.keys_dir / f"{agent.name}.private.pem"
            if not key.is_file():
                raise ParamsError(f"agents: {agent.name} has no DKIM key at {key} to keep")
            address = params.address(agent.name)
            listed_for_adoption = adopt.read_text(encoding="utf-8") if adopt.is_file() else ""
            previous = accounts.get(address)
            resuming = previous is not None and previous.state != "purge"
            # A migration that stopped between the login and the registry entry left its own
            # line, adoption and all: finish it with the same generation. Any other line is not
            # this migration's.
            if resuming and f"{address}:{previous.generation}" not in listed_for_adoption.split():
                raise ParamsError(f"{address} already has a registered mail account")
            registration = Registration(
                name=agent.name,
                submit_token_hash=hash_token(stored["submit_token"]),
                mode=agent.mode,
                handler=agent.handler,
                watermark=agent.watermark,
                workers=agent.workers,
                external_per_day=agent.external_per_day,
                imap_endpoint=imap_url(params),
                submission_endpoint=submit_url(params),
                created_at=datetime.now(UTC).replace(microsecond=0),
            )
            if resuming:
                generation = previous.generation
            else:
                generation = new_generation()
                # The adoption first: a mailhost already running this image acts on the
                # accounts line within a second, and without it would delete the mailbox. Then
                # the login, then the registry entry (RCPT accepts the agent from then on), as
                # `add` orders it.
                write_private(adopt, listed_for_adoption + f"{address}:{generation}\n")
            set_account(
                params.accounts_file,
                Account(address, hash_password(stored["imap_password"]), "enabled", generation),
            )
            write_registration(params.registry_dir, registration)
            notes.append(
                f"migrated {agent.name} into the registry: its key (selector {agent.name}), "
                "token, and password are unchanged, and the mailhost keeps its mailbox"
            )
            legacy_env = params.bundles_dir / f"{agent.name}.env"
            if legacy_env.is_file():
                notes.append(
                    f"  {legacy_env} still holds its credentials: delete it once its host has them"
                )
            staged = params.keys_dir / "next" / f"{agent.name}.private.pem"
            if staged.is_file():
                notes.append(
                    f"  {staged} was staged by the old rotation and is not used: delete it, and "
                    f"rotate with `amx live agent rotate {agent.name}`"
                )
    if notes:
        notes.append(
            "agents: in the parameters file has done its job: delete it. Then restart the lane "
            "once so both containers read the registry: amx live up, then "
            "amx live compose restart mailhost gateway"
        )
    elif all(agent.name in registrations(params) for agent in params.legacy_agents):
        notes.append("agents: in the parameters file is no longer read (all registered): delete it")
    return notes


# --- rotation ------------------------------------------------------------------------------

# The host's own logins. An agent's credentials and DKIM keys rotate through the registry, with
# `amx live agent rotate` (PLAN §5.2, §11.5).
ROTATABLE = ("approver", "postmaster", "gateway-master")
AGENT_ROTATIONS = ("submit-token", "imap-password", "dkim")


def rotate(params: LiveParams, what: str) -> str:
    """Replace one of the host's own passwords and restart what reads it."""
    if params.mta == "stalwart":
        raise ParamsError(
            "Stalwart host credential rotation needs offline provisioning; this command "
            "is Postfix-only. Registered agents still rotate with `amx live agent rotate`."
        )
    if what in AGENT_ROTATIONS:
        raise ParamsError(
            "an agent's credentials and keys rotate through the registry, with no restart: "
            "`amx live agent rotate <name>` (both secrets, and a DKIM key under a new selector; "
            "docs/selfhost-public.md §8)"
        )
    if what not in ROTATABLE:
        raise ParamsError(f"--what must be one of {', '.join(ROTATABLE)}")
    credentials = load_credentials(params)
    if what == "approver":
        credentials.approver = new_secret()
    elif what == "postmaster":
        credentials.postmaster = new_secret()
    else:
        credentials.gateway_master = new_secret()
    save_credentials(params, credentials)
    install(params)
    reload_services(
        params, mailhost=True, gateway=what == "gateway-master", why=f"a new {what} password"
    )
    where = (
        params.credentials_path if what == "gateway-master" else params.secrets_dir / "logins.txt"
    )
    return f"Rotated {what}; the new value is in {where}."


# --- backup --------------------------------------------------------------------------------


def backup(params: LiveParams, out: Path | None, *, with_secrets: bool) -> Path:
    """Snapshot the journal (SQLite online backup), the data directory, and the mailboxes."""
    if params.mta == "stalwart":
        raise ParamsError(
            "Stalwart datastore backup is not implemented; stop the bundle and snapshot "
            "state_dir (including stalwart/ and secrets/) with your backup tool"
        )
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    target = out or params.state_dir / "backups" / stamp
    _mkdir(target, 0o700)
    data = target / "data"
    _mkdir(data, 0o700)
    source = params.data_dir / "journal.sqlite"
    if source.is_file():
        with sqlite3.connect(source) as live, sqlite3.connect(data / "journal.sqlite") as copy:
            live.backup(copy)
    # The raw store is content-addressed and append-only, so copying it after the snapshot can
    # only add files the snapshot does not name.
    for item in params.data_dir.iterdir():
        if item.name.startswith("journal.sqlite"):
            continue
        # The gateway recreates this private control socket; it is not backup data.
        # Do not follow symlinks or exempt any other name/type from the normal copy.
        if item.name == "tls-reload.sock" and stat.S_ISSOCK(item.lstat().st_mode):
            continue
        if item.is_dir():
            shutil.copytree(item, data / item.name, symlinks=True)
        else:
            shutil.copy2(item, data / item.name)
    verification = Journal(data, Store(data / "journal.sqlite")).verify()
    status = f"OK {verification.entries} entries" if verification.valid else verification.error
    (target / "journal-verify.txt").write_text(f"{status}\n", encoding="utf-8")
    if not verification.valid:
        raise RuntimeError(f"the backed-up journal does not verify: {verification.error}")
    volume = f"{params.compose_project}_mail"
    image = f"{params.compose_project}-mailhost"
    subprocess.run(
        [
            "docker", "run", "--rm", "--entrypoint", "tar",
            "-v", f"{volume}:/mail:ro", "-v", f"{target}:/out", image,
            "-czf", "/out/mail.tar.gz", "-C", "/mail", ".",
        ],
        check=True,
    )  # fmt: skip
    if with_secrets:
        shutil.copytree(params.secrets_dir, target / "secrets", symlinks=True)
    manifest = {
        "created": stamp,
        "agent_domain": params.agent_domain,
        "journal": status,
        "secrets": with_secrets,
        "sha256": {
            str(path.relative_to(target)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(target.rglob("*"))
            if path.is_file() and path.name != "manifest.json"
        },
    }
    write_private(target / "manifest.json", json.dumps(manifest, indent=2) + "\n")
    return target


# --- commands ------------------------------------------------------------------------------


def _params(path: Path | None) -> LiveParams:
    try:
        return load_params(path or DEFAULT_PARAMS)
    except ParamsError as error:
        raise typer.BadParameter(str(error)) from error


@app.command("install")
def install_command(params_path: ParamsOption = DEFAULT_PARAMS) -> None:
    """Validate the parameters and write the state directory (secrets, keys, configuration)."""
    params = _params(params_path)
    try:
        notes = install(params)
    except ParamsError as error:
        raise typer.BadParameter(str(error)) from error
    for note in notes:
        typer.echo(note)
    typer.echo(f"state: {params.state_dir}")
    typer.echo(f"DNS to request: {params.state_dir / 'dns-records.txt'} (or `amx live dns`)")


@app.command("dns")
def dns_command(
    params_path: ParamsOption = DEFAULT_PARAMS,
    zone_file_path: Annotated[
        Path | None, typer.Option("--zone-file", help="Also write a BIND zone for a delegation")
    ] = None,
    nameservers: Annotated[
        list[str] | None, typer.Option("--ns", help="Nameservers of the delegated zone")
    ] = None,
) -> None:
    """Print the DNS records to request, rendered from the parameters and the DKIM keys."""
    params = _params(params_path)
    typer.echo(render_dns(params), nl=False)
    if zone_file_path is not None:
        if not nameservers:
            raise typer.BadParameter("--zone-file needs the delegated zone's --ns servers")
        zone_file_path.write_text(zone_file(params, nameservers), encoding="utf-8")
        typer.echo(f"zone file: {zone_file_path}")


@app.command("certs")
def certs_command(params_path: ParamsOption = DEFAULT_PARAMS) -> None:
    """Issue or renew the MX host's certificate, and reload what runs if it changed."""
    params = _params(params_path)
    if params.tls_mode == "files":
        install_file_certificate(params)
        reload_tls(params)
        typer.echo("certificate files installed; Stalwart and gateway TLS reloaded without restart")
        return
    if params.tls_mode == "self-signed":
        changed = ensure_self_signed(params)
    else:
        _mkdir(params.secrets_dir / "acme", 0o700)
        issued_by = lineage_server(params)
        replace = issued_by is not None and issued_by != params.acme_server
        renew = issued_by is not None and not replace and params.acme_challenge == "http-01"
        if replace:
            typer.echo(f"the certificate came from {issued_by}: issuing a new one now")
        subprocess.run(certbot_command(params, renew=renew, replace=replace), check=True)
        changed = install_acme_certificate(params)
    info = cert_info(params.tls_dir / "server.pem")
    typer.echo(f"certificate for {', '.join(info['names'])}, expires {info['expires']:%Y-%m-%d}")
    if params.mta == "stalwart":
        reload_tls(params)
        typer.echo("Stalwart and gateway TLS reloaded without restart")
        return
    if changed:
        # Recorded before Docker is asked anything: if it cannot be, the next run still owes it.
        for service in ("mailhost", "gateway"):
            record_restart(params, service, "a new certificate", origin="reload")
    # A restart an earlier run could not finish is owed too: the certificate is already in place,
    # so this run would otherwise see nothing changed and leave the old one served. Only the
    # restarts certs and rotate owe are done here; one install owes wants `amx live up` first.
    try:
        owed = pending_restarts(params)
        ours = [service for service, restart in owed.items() if restart.origin == "reload"]
        if ours:
            reload_services(
                params,
                mailhost="mailhost" in ours,
                gateway="gateway" in ours,
                why="a new certificate" if changed else "a restart an earlier run left owed",
            )
    except DockerUnavailable as error:
        raise typer.BadParameter(f"{error}: the restart stays owed to the next run") from error
    if changed:
        typer.echo("new certificate installed")
    elif ours:
        typer.echo(f"restarted: {', '.join(ours)}")
    for service, restart in owed.items():
        if restart.origin == "install":
            typer.echo(
                f"owed by install: the {service} ({restart.why}); amx live up, then "
                f"amx live compose restart {service}"
            )


@app.command("up")
def up_command(params_path: ParamsOption = DEFAULT_PARAMS) -> None:
    """Build and start the lane. The judge is jev only if TYPESAFE_API_KEY is in the environment."""
    params = _params(params_path)
    missing = [
        path
        for path in (params.gateway_config, params.tls_dir / "server.pem", params.compose_env)
        if not path.is_file()
    ]
    if missing:
        raise typer.BadParameter(f"run install (and certs) first; missing {missing[0]}")
    backend = compose_environment()["AMX_CONTENT_JUDGE_BACKEND"]
    typer.echo(f"content judge: {backend} ({params.judge_mode})")
    if params.mta == "stalwart":
        from amx.stalwart_webui import prepare_webui

        prepare_webui(params.secrets_dir / "stalwart/webui.zip", staged=bool(params.webui_bundle))
        # Keep volumes/data. Stop the owned bundle before init opens RocksDB;
        # recreate init even for mounted-plan-only changes. --reapply repairs drift too.
        run_compose(params, "down")
        run_compose(params, "up", "-d", "--build", "--force-recreate", "--wait")
        return
    run_compose(params, "up", "-d", "--build", "--wait")


def queued_mail(params: LiveParams) -> int | None:
    """How many messages wait in Postfix's queue (None if the mailhost is not running)."""
    if params.mta == "stalwart":
        raise DockerUnavailable("Stalwart queue inspection is not implemented; refusing purge")
    if not running(params, "mailhost"):
        return None
    # Fixed docker compose exec/postqueue argv; validated operator paths stay separate tokens,
    # never shell text. No message content supplies an executable, verb or option.
    result = subprocess.run(  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
        compose(params, "exec", "-T", "mailhost", "postqueue", "-j"),
        env=compose_environment(),
        capture_output=True,
        text=True,
        check=True,
        shell=False,
        timeout=30,
    )
    return sum(1 for line in result.stdout.splitlines() if line.strip())


@app.command("down")
def down_command(
    params_path: ParamsOption = DEFAULT_PARAMS,
    purge: Annotated[
        bool, typer.Option(help="Also delete the mailboxes and the mail queue (the volumes)")
    ] = False,
    force: Annotated[bool, typer.Option(help="Purge even with mail in the queue")] = False,
) -> None:
    """Stop the lane. Keeps the state, the mailboxes, and the queue; --purge deletes the last two.

    Postfix's queue is a volume, so mail waiting to be retried survives `down` and `up`.
    """
    params = _params(params_path)
    if purge and params.mta == "stalwart":
        raise typer.BadParameter(
            "Stalwart --purge is unsupported, even with --force: the bind datastore is retained; "
            "use ordinary down and manage stopped-state backups separately"
        )
    if purge and not force:
        try:
            waiting = queued_mail(params)
        except DockerUnavailable as error:
            raise typer.BadParameter(f"{error}: --purge cannot see the queue") from error
        if waiting is None:
            raise typer.BadParameter("--purge cannot see the queue while the lane is down: --force")
        if waiting:
            raise typer.BadParameter(
                f"{waiting} messages wait in the queue (amx live compose exec mailhost mailq); "
                "--purge would delete them: --force"
            )
    run_compose(params, "down", *(["--volumes"] if purge else []))


@app.command("status")
def status_command(params_path: ParamsOption = DEFAULT_PARAMS) -> None:
    """Show the containers and the certificate's expiry."""
    params = _params(params_path)
    run_compose(params, "ps", check=False)
    server = params.tls_dir / "server.pem"
    if server.is_file():
        info = cert_info(server)
        days = (info["expires"] - datetime.now(UTC)).days
        typer.echo(f"certificate: {', '.join(info['names'])}, {days} days left")


@app.command("rotate")
def rotate_command(
    what: Annotated[str, typer.Option("--what", help=" | ".join(ROTATABLE))],
    params_path: ParamsOption = DEFAULT_PARAMS,
    # The options of the old per-agent rotation, kept so that an old command line gets the
    # pointer to `amx live agent rotate` rather than "no such option".
    _agent: Annotated[str | None, typer.Option("--agent", hidden=True)] = None,
    _commit: Annotated[bool, typer.Option("--commit", hidden=True)] = False,
) -> None:
    """Replace the approver's, the postmaster's, or the gateway's master password, then restart
    what uses it. Agents rotate with `amx live agent rotate`."""
    params = _params(params_path)
    try:
        typer.echo(rotate(params, what))
    except ParamsError as error:
        raise typer.BadParameter(str(error)) from error


@app.command("backup")
def backup_command(
    params_path: ParamsOption = DEFAULT_PARAMS,
    out: Annotated[
        Path | None, typer.Option(help="Directory (default state/backups/<time>)")
    ] = None,
    with_secrets: Annotated[
        bool, typer.Option(help="Also copy secrets/ (keys, passwords): guard the copy")
    ] = False,
) -> None:
    """Back up the journal (verified), the gateway's data, and the mailboxes."""
    params = _params(params_path)
    typer.echo(str(backup(params, out, with_secrets=with_secrets)))


@app.command(
    "compose",
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
def compose_command(ctx: typer.Context, params_path: ParamsOption = DEFAULT_PARAMS) -> None:
    """Run docker compose on the lane, e.g. `amx live compose logs -f gateway`."""
    params = _params(params_path)
    raise typer.Exit(run_compose(params, *ctx.args, check=False))


@app.command("preflight")
def preflight_command(
    params_path: ParamsOption = DEFAULT_PARAMS,
    resolver: Annotated[
        str | None, typer.Option(help="DNS server as ip or ip:port (default: the host's)")
    ] = None,
    probe: Annotated[
        str | None,
        typer.Option(help="ssh host that tests inbound ports from outside ('local' runs here)"),
    ] = None,
    outbound: Annotated[
        str | None,
        typer.Option(help="host:port for the outbound port-25 connect (default: gmail.com's MX)"),
    ] = None,
    skip_outbound: Annotated[bool, typer.Option(help="Skip the outbound port-25 test")] = False,
    local_host: Annotated[
        str, typer.Option(help="Where this host reaches the running lane for the TLS checks")
    ] = "127.0.0.1",
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Check DNS, reachability, and TLS without sending mail or changing anything."""
    from amx.preflight import Options, render, run_checks

    params = _params(params_path)
    results = run_checks(
        params,
        Options(
            resolver=resolver,
            probe=probe,
            outbound=outbound,
            skip_outbound=skip_outbound,
            local_host=local_host,
        ),
    )
    typer.echo(render(results, as_json=as_json), nl=False)
    if any(result.status == "FAIL" for result in results):
        raise typer.Exit(1)
