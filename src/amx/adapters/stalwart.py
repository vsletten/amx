"""Stalwart Community as one domain's mailhost (M6, PLAN §5.8).

The gateway talks to Stalwart through the same milter and LMTP adapters it uses with Postfix, so
nothing in this module runs inside the gateway. What Stalwart needs instead is provisioning.
Stalwart 0.16 keeps every setting as a JMAP object in its datastore, and ``stalwart-cli apply``
reconciles them from a declarative plan. This module renders that plan from ``deploy/dev-users``,
the same file the Postfix/Dovecot mailhost entrypoint reads. It then creates the hold queues over
IMAP with the gateway's master login.

The hold queues cannot live in the agents' own mailboxes as they do on Dovecot: a Stalwart owner
always has every right on its own folders. So each agent's queue is a folder tree in an account
the agents do not own (``holds@<domain>``, with no password), shared read-only to the agent and
read-write to a plain ``approver`` account (PLAN §5.8).

The ``provision`` command is the entrypoint of the one-shot ``stalwart-init-ct`` container. That
container carries the unmodified Stalwart binary and runs it privately on the mailhost's data
volume, with no network:
1. Boot the binary and apply the settings through the management port.
2. Boot it again, because listeners and the password policy load only at startup. Apply the
   accounts, then create the hold queues and their ACLs on 127.0.0.1:143.
3. Exit.

The mailhost container then starts from the pinned image on the provisioned volume.

The ``sync`` command is the other half (PLAN §5.2): agents an operator registers while the stack
runs (``amx agent add --live``) are lines in an accounts file (``amx.accounts``). ``sync --watch``
applies that file to the running mailhost through its management API, with the same account
shape as the plan, and gives each new agent its hold queue as ``ensure_mailboxes`` does.

This file is deliberately standard-library only. The init image copies it in as a script, without
the rest of the ``amx`` package.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import imaplib
import json
import os
import re
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

# The folders of one agent's hold queue, under its prefix (amx.holds.hold_queue).
HOLD_FOLDER_NAMES = ("Held", "Approved", "Rejected")
# Permissions for the accounts that must never act as someone else. An upsert on a volume
# provisioned before the shared layout existed, where the approver was a master, must take
# impersonate away, not merely leave it out. The hold owner also takes no mail: a full quota
# there would stop every hold from being filed.
NOT_A_MASTER = {
    "@type": "Merge",
    "enabledPermissions": {},
    "disabledPermissions": {"impersonate": True},
}
# The folders Dovecot subscribes for every user (dovecot.conf), less the hold queue.
SUBSCRIBED_FOLDERS = ("Sent", "Drafts", "Trash")
# The dev-users entries without a domain: Dovecot's two master logins. On Stalwart only the
# gateway is a master; the approver is an ordinary account (render_plan).
MASTER_USERS = ("gateway", "approver")
# Dovecot's master-login separator is "*" (user*master); Stalwart's is "%" (user%master).
MASTER_LOGIN = "{user}%{master}"
# Where Stalwart shows a user the folders another account shares with it: under
# "<Email.defaultFolders.shared name>/<owner address>/". The plan leaves the name at its default.
SHARED_FOLDERS = "Shared Folders"
# IMAP rights (RFC 4314) on each agent's three hold folders. The agent may look and read, which is
# what Dovecot's ACL leaves it on Outbox/*, less "s": Stalwart maps "s" and "w" to one right, and
# "w" would let it set the $AmxDone keyword that makes holdwatch skip a message. The approver has
# what Dovecot's approver has (deploy/mailhost/dovecot-acl): it may move messages out of Held and
# into Approved or Rejected, and no more. Nobody but the owner may create, rename, or delete a
# folder, or change an ACL. Each agent's tree root (Holds/<agent>) gets "l" for both, so a CREATE
# or RENAME inside the queue is judged on rights; without it Stalwart refuses one as a "root
# folder under shared folders" and the ACL goes untested. Folders above it, shared by every agent,
# get nothing: Stalwart allows only 10 grants on one folder (Sharing.maxShares), and a client
# shows the tree from the full names.
AGENT_RIGHTS = "lr"
APPROVER_RIGHTS = {"Held": "lrswte", "Approved": "lrswi", "Rejected": "lrswi"}
ROOT_RIGHTS = "l"
# Each agent's folder tree in the hold owner's mailbox (the gateway's mailbox.hold_prefix).
HOLD_PREFIX = "Holds/{agent}/"


@dataclass(frozen=True, slots=True)
class Site:
    """One amx domain's mailhost, as the compose stack wires it."""

    domain: str
    agent_domain: str
    hostname: str
    gateway_host: str
    # Stalwart resolves the milter's host once, when it builds its configuration, and drops a
    # milter it cannot resolve: every message is then accepted unfiltered. The gateway is not
    # running yet when the mailhost boots, so the milter is addressed by a fixed IP.
    gateway_ip: str
    milter_port: int = 8890
    people_milter_port: int = 0
    people_tls_certificate: str | None = None
    people_tls_key: str | None = None
    lmtp_port: int = 2424
    reinject_port: int = 10025
    # The compose network. Postfix's :10025 trusts it through mynetworks (PLAN §4.2).
    trusted_network: str = "172.30.0.0/24"
    # Postfix's allowed-recipients.pcre: the only domains a relay may reach.
    relay_domains: tuple[str, ...] = (
        "northwind.test",
        "agents.northwind.test",
        "contoso.test",
        "agents.contoso.test",
        "plainmail.test",
    )
    # Postfix: minimal_backoff_time 5s, maximal_backoff_time 30s, maximal_queue_lifetime 30s.
    retry_seconds: tuple[int, ...] = (5, 10, 20, 30)
    queue_lifetime_seconds: int = 30
    # The hold queues' owner (default holds@<domain>) and each agent's folder tree in it. The
    # gateway's mailbox.hold_owner and mailbox.hold_prefix must say the same
    # (compose.stalwart.yaml sets both).
    hold_owner: str | None = None
    hold_prefix: str = HOLD_PREFIX
    approvers: tuple[str, ...] = ()
    sibling_port: int = 10027
    sibling_milter_port: int = 8891

    @property
    def hold_mailbox(self) -> str:
        """The address of the account that owns every agent's hold queue."""
        return (self.hold_owner or f"holds@{self.domain}").casefold()


def read_dev_users(text: str) -> tuple[list[tuple[str, str]], dict[str, str]]:
    """Split a dev-users file into mail users and the master logins (gateway, approver)."""
    users: list[tuple[str, str]] = []
    masters: dict[str, str] = {}
    for line in text.splitlines():
        entry = line.strip()
        if not entry or entry.startswith("#") or "|" not in entry:
            continue
        name, password = entry.split("|", 1)
        if name in MASTER_USERS:
            masters[name] = password
        elif "@" in name:
            users.append((name.casefold(), password))
    return users, masters


def site_users(users: Iterable[tuple[str, str]], site: Site) -> list[tuple[str, str]]:
    """The users whose mailboxes live on this mailhost: its domain and its agent domain."""
    return [
        (address, password)
        for address, password in users
        if address.rpartition("@")[2] in {site.domain, site.agent_domain}
    ]


def expression(otherwise: str, *cases: tuple[str, str]) -> dict[str, Any]:
    """A Stalwart expression: the first matching ``if`` wins, else ``otherwise``."""
    return {
        "else": otherwise,
        "match": {
            str(index): {"if": test, "then": then} for index, (test, then) in enumerate(cases)
        },
    }


def _flags(*names: str) -> dict[str, bool]:
    return dict.fromkeys(names, True)


def _schedule(name: str, site: Site, description: str) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "retry": {
            "@type": "Custom",
            "intervals": {
                str(index): {"duration": seconds * 1000}
                for index, seconds in enumerate(site.retry_seconds)
            },
        },
        "expiry": {"@type": "Ttl", "expire": site.queue_lifetime_seconds * 1000},
        "notify": {"@type": "Default"},
    }


def _listener(name: str, protocol: str, port: int) -> dict[str, Any]:
    return {"name": name, "protocol": protocol, "bind": _flags(f"[::]:{port}"), "useTls": False}


def _account(
    ref_domain: str, local_part: str, password: str | None, **extra: Any
) -> dict[str, Any]:
    account: dict[str, Any] = {"@type": "User", "name": local_part, "domainId": f"#{ref_domain}"}
    if password is not None:  # none: no direct login at all
        account["credentials"] = {"0": {"@type": "Password", "secret": password}}
    return account | extra


def hold_folders(site: Site, agent: str) -> tuple[str, ...]:
    """One agent's hold-queue folders, as their owner (and the gateway) names them."""
    prefix = site.hold_prefix.format(agent=agent)
    return tuple(prefix + name for name in HOLD_FOLDER_NAMES)


def hold_parents(site: Site, agent: str) -> tuple[str, ...]:
    """The folders above one agent's hold queue, outermost first ("Holds", "Holds/intake")."""
    parts = site.hold_prefix.format(agent=agent).rstrip("/").split("/")
    return tuple("/".join(parts[: index + 1]) for index in range(len(parts)))


def hold_layout(
    site: Site, users: Sequence[str]
) -> tuple[list[str], dict[str, dict[str, str]], dict[str, list[str]]]:
    """The hold owner's folders (parents first), their exact grants, and everyone's subscriptions.

    ``ensure_mailboxes`` provisions exactly this, and the provisioning hash covers it.
    """
    approver = f"approver@{site.domain}"
    approvers = (approver, *site.approvers)
    agents = [user for user in users if user.rpartition("@")[2] == site.agent_domain]
    folders: list[str] = []
    grants: dict[str, dict[str, str]] = {}
    subscriptions = {user: list(SUBSCRIBED_FOLDERS) for user in [*users, *approvers]}
    for agent in agents:
        name = agent.partition("@")[0]
        *above, root = hold_parents(site, name)
        for parent in above:
            if parent not in folders:
                folders.append(parent)
                grants[parent] = {}  # none: any grant an older layout left there goes
        folders.append(root)
        grants[root] = {agent: ROOT_RIGHTS, **dict.fromkeys(approvers, ROOT_RIGHTS)}
        for folder, kind in zip(hold_folders(site, name), HOLD_FOLDER_NAMES, strict=True):
            folders.append(folder)
            grants[folder] = {
                agent: AGENT_RIGHTS,
                **dict.fromkeys(approvers, APPROVER_RIGHTS[kind]),
            }
            subscriptions[agent].append(shared_name(site, folder))
            for person in approvers:
                subscriptions[person].append(shared_name(site, folder))
    return folders, grants, subscriptions


def shared_name(site: Site, folder: str) -> str:
    """How an account a hold folder is shared with (the agent, the approver) names it."""
    return f"{SHARED_FOLDERS}/{site.hold_mailbox}/{folder}"


def check_hold_layout(site: Site) -> None:
    """The owner is an account on this mailhost, and every agent gets its own folder tree."""
    domain = site.hold_mailbox.rpartition("@")[2]
    # Not the agent domain: an agent that owned the queues could approve every one of them.
    if domain != site.domain:
        raise ValueError(f"hold owner {site.hold_mailbox} is not on {site.domain}")
    first, second = hold_folders(site, "a"), hold_folders(site, "b")
    if first == second or not site.hold_prefix.endswith("/") or site.hold_prefix.startswith("/"):
        raise ValueError(f"hold prefix {site.hold_prefix!r} must be a folder path with {{agent}}")


def render_plan(
    site: Site, users: Sequence[tuple[str, str]], masters: dict[str, str]
) -> list[dict[str, Any]]:
    """Render the ``stalwart-cli apply`` plan that makes Stalwart stand in for Postfix+Dovecot.

    Each operation mirrors one piece of the Postfix/Dovecot mailhost (docs/findings-stalwart.md
    lists them side by side). Upserts keyed on names make a rerun on the same volume idempotent.
    """
    missing = [name for name in MASTER_USERS if name not in masters]
    if missing:
        raise ValueError(f"dev-users has no {', '.join(missing)} master login")
    check_hold_layout(site)
    local = site_users(users, site)
    if not local:
        raise ValueError(f"no development users for {site.domain} or {site.agent_domain}")
    reinject = f"local_port == {site.reinject_port}"
    plan: list[dict[str, Any]] = [
        # Dovecot: passwd-file users with SHA512-CRYPT and no password policy (dev passwords only).
        {
            "@type": "update",
            "object": "Authentication",
            "value": {"passwordMinLength": 1, "passwordMinStrength": "zero"},
        },
        # Dovecot: disable_plaintext_auth = no; ssl = no.
        {"@type": "update", "object": "Imap", "value": {"allowPlainTextAuth": True}},
        # Postfix runs no spam filter, and no SPF, DKIM, or DMARC check: the gateway decides.
        {
            "@type": "update",
            "object": "SpamSettings",
            "value": {"enable": False, "spamFilterRulesUrl": None},
        },
        # Nothing may reach outside the .test network: no Pyzor lookups, no ASN/geo or web UI
        # downloads (the stack's DNS answers only .test, so these would fail anyway).
        {"@type": "update", "object": "SpamPyzor", "value": {"enable": False}},
        {"@type": "update", "object": "Asn", "value": {"@type": "Disabled"}},
        {
            "@type": "upsert",
            "object": "Application",
            "matchOn": ["description"],
            "value": {"app-webui": {"description": "Stalwart Web Interface", "enabled": False}},
        },
        # CVE-2026-81036 (docs/findings-stalwart.md): by default, Stalwart's authorization and
        # token endpoints accept any redirect_uri for any client id that is not a self-describing
        # public-client id, so a login can be sent an authorization code for an attacker's URL.
        # Nothing on the dev stack uses OAuth, but the mailhost's HTTP listener serves the
        # endpoints to the compose network. Requiring a registration makes an unregistered
        # client id, or a redirect_uri the registration does not list, an error (unless the
        # account holds oAuthClientOverride, which only the superuser role does). Anonymous
        # registration, on by default, would let anyone mint a public-client id; off, only an
        # account with oAuthClientRegistration (the superuser role) may. Still open upstream at
        # v0.16.24.
        {
            "@type": "update",
            "object": "OidcProvider",
            "value": {"requireClientRegistration": True, "anonymousClientRegistration": False},
        },
        # Dovecot's folder names (dovecot.conf: Drafts, Sent, Trash). Stalwart would create
        # "Sent Items", and the gateway files released and signed mail in "Sent" (amx.holds).
        {
            "@type": "update",
            "object": "Email",
            "value": {
                "defaultFolders": {
                    use: {"name": name, "create": True, "subscribe": True}
                    for use, name in (
                        ("inbox", "INBOX"),
                        ("drafts", "Drafts"),
                        ("sent", "Sent"),
                        ("trash", "Trash"),
                        ("junk", "Junk"),
                    )
                }
            },
        },
        {
            "@type": "update",
            "object": "SenderAuth",
            "value": {
                name: expression("disable")
                for name in (
                    "dkimVerify",
                    "spfEhloVerify",
                    "spfFromVerify",
                    "dmarcVerify",
                    "arcVerify",
                    "reverseIpVerify",
                )
            }
            # The gateway signs per agent (PLAN §4.2); Stalwart must not add its own signature.
            | {"dkimSignDomain": expression("false")},
        },
        # Postfix's smtpd has no per-session message cap; Stalwart allows 10 by default, which
        # northwind's connection reuse would hit.
        {
            "@type": "update",
            "object": "MtaStageData",
            "value": {"enableSpamFilter": expression("false"), "maxMessages": expression("1000")},
        },
        # Postfix: no anvil rate limits (smtpd_client_*_rate_limit = 0). Stalwart ships two
        # inbound throttles (5/s per IP; 25/h per sender domain and recipient) and bans IPs after
        # repeated refusals; S04 alone sends six messages in a second from one IP.
        {
            "@type": "upsert",
            "object": "MtaInboundThrottle",
            "matchOn": ["description"],
            "value": {
                f"throttle-{index}": {"description": description, "enable": False}
                for index, description in enumerate(
                    ("Sender IP throttle", "Sender address to recipient throttle")
                )
            },
        },
        # reconcile, not upsert: the plan owns the whole list, so a changed network replaces the
        # old entry instead of adding a second one.
        {
            "@type": "reconcile",
            "object": "AllowedIp",
            "matchOn": ["address"],
            "value": {
                "allowed-network": {
                    "address": site.trusted_network,
                    "reason": "amx compose network (Postfix mynetworks)",
                }
            },
        },
        # Postfix: smtpd_helo_required = no and no reject_non_fqdn_helo_hostname (the defaults).
        {
            "@type": "update",
            "object": "MtaStageEhlo",
            "value": {"require": expression("false"), "rejectNonFqdn": expression("false")},
        },
        # Postfix: myhostname.
        {
            "@type": "update",
            "object": "MtaStageConnect",
            "value": {
                "hostname": expression(f"'{site.hostname}'"),
                "smtpGreeting": expression(f"'{site.hostname} ESMTP'"),
                "script": expression(
                    "false",
                    (
                        f"listener == 'sibling-in' && remote_ip != '{site.gateway_ip}'",
                        "'amx-deny-sibling'",
                    ),
                    (
                        "listener == 'sibling' && remote_ip != '127.0.0.1'",
                        "'amx-deny-sibling'",
                    ),
                ),
            },
        },
        # Postfix's :10025 takes no SASL; Stalwart requires AUTH on every port but 25 by default.
        {
            "@type": "update",
            "object": "MtaStageAuth",
            "value": {
                "require": expression(
                    f"local_port != 25 && !({reinject}) && "
                    "listener != 'sibling-in' && listener != 'sibling'"
                ),
                "mustMatchSender": expression("true"),
            },
        },
        # Postfix: mynetworks = the compose network, permit_mynetworks, and
        # allowed-recipients.pcre. Clients on the compose network (the gateway's reinjection on
        # :10025, and the other mailhosts and host-published ports on :25) may relay, and only to
        # the prototype's five domains. The agent domain is accepted from anyone through its own
        # allowRelaying flag below.
        {
            "@type": "update",
            "object": "MtaStageRcpt",
            "value": {
                "allowRelaying": expression(
                    "false",
                    (
                        f"is_ip_in_cidr(remote_ip, '{site.trusted_network}') && ("
                        + " || ".join(f"rcpt_domain == '{domain}'" for domain in site.relay_domains)
                        + ")",
                        "true",
                    ),
                ),
                # Postfix: smtpd_error_sleep_time = 1s, smtpd_hard_error_limit = 20.
                "waitOnFail": expression("1s"),
                "maxFailures": expression("20"),
            },
        },
        # Postfix: inet_interfaces (port 25) and master.cf's 10025 listener; Dovecot: imap on 143.
        # No TLS on any of them (PLAN §8).
        {
            "@type": "upsert",
            "object": "NetworkListener",
            "matchOn": ["name"],
            "value": {
                "smtp": _listener("smtp", "smtp", 25),
                "reinject": _listener("reinject", "smtp", site.reinject_port),
                "sibling-in": _listener("sibling-in", "smtp", site.sibling_port),
                "sibling": {
                    **_listener("sibling", "smtp", 10028),
                    "bind": _flags("127.0.0.1:10028"),
                },
                "imap": _listener("imap", "imap", 143),
            },
        },
        # Postfix: virtual_mailbox_domains = $mydomain, $agent_domain. The agent domain turns off
        # sub-addressing, which in Stalwart rewrites intake+<task>@ to intake@ before routing and
        # would drop the task token; allowRelaying then accepts intake+<task>@ unchanged, the way
        # Postfix's recipient_delimiter keeps it in the envelope. Unknown agents never get this
        # far: the milter refuses them at RCPT first.
        {
            "@type": "upsert",
            "object": "Domain",
            "matchOn": ["name"],
            "value": {
                "domain-site": {
                    "name": site.domain,
                    "dkimManagement": {"@type": "Manual"},
                },
                "domain-agents": {
                    "name": site.agent_domain,
                    "subAddressing": {"@type": "Disabled"},
                    "allowRelaying": True,
                    "dkimManagement": {"@type": "Manual"},
                },
            },
        },
        {
            "@type": "update",
            "object": "SystemSettings",
            "value": {"defaultHostname": site.hostname, "defaultDomainId": "#domain-site"},
        },
    ]
    accounts: dict[str, dict[str, Any]] = {}
    addresses: dict[str, str] = {}

    def add(address: str, password: str | None, **extra: Any) -> None:
        local_part, _, domain = address.partition("@")
        key = "account-" + re.sub(r"[^a-z0-9]+", "-", address)
        if key in addresses:
            other = addresses[key]
            raise ValueError(
                f"{address} is listed twice"
                if other == address
                else f"{address} and {other} both make the plan key {key}"
            )
        addresses[key] = address
        reference = "domain-agents" if domain == site.agent_domain else "domain-site"
        accounts[key] = _account(reference, local_part, password, **extra)

    for address, password in local:
        add(address, password)
    # Dovecot: the gateway's master user (dovecot.conf passdb master = yes). Stalwart's master
    # login is an account holding the impersonate permission; it then acts with the target's full
    # rights, which is what the gateway needs.
    add(
        f"gateway@{site.domain}",
        masters["gateway"],
        permissions={
            "@type": "Merge",
            "enabledPermissions": _flags("impersonate"),
            "disabledPermissions": {},
        },
    )
    # Dovecot's approver is a master login limited by ACL to Outbox moves, and it can read every
    # mailbox on the host (PLAN §8). Here it is an ordinary account: it can act only on the hold
    # folders shared with it (APPROVER_RIGHTS), because a Stalwart master would act as the owner.
    add(f"approver@{site.domain}", masters["approver"], permissions=NOT_A_MASTER)
    # The hold queues' owner. With no password, only the gateway's master login opens it.
    add(
        site.hold_mailbox,
        None,
        permissions=NOT_A_MASTER
        | {"disabledPermissions": NOT_A_MASTER["disabledPermissions"] | {"emailReceive": True}},
    )
    # Account names are local parts, so an account is matched on its name within its domain.
    plan.append(
        {
            "@type": "upsert",
            "object": "Account",
            "matchOn": ["name", "domainId"],
            "value": accounts,
        }
    )
    plan += [
        # Postfix: transport_maps (agents.<domain> → lmtp:inet:gateway:2424).
        {
            "@type": "upsert",
            "object": "MtaRoute",
            "matchOn": ["name"],
            "value": {
                "route-gateway": {
                    "@type": "Relay",
                    "name": "gateway",
                    "description": "amx gateway LMTP (Postfix transport_maps)",
                    "address": site.gateway_host,
                    "port": site.lmtp_port,
                    "protocol": "lmtp",
                    "implicitTls": False,
                },
                "route-sibling": {
                    "@type": "Relay",
                    "name": "sibling-loop",
                    "description": "amx trusted sibling self-relay",
                    "address": "127.0.0.1",
                    "port": 10028,
                    "protocol": "smtp",
                    "implicitTls": False,
                },
            },
        },
        {
            "@type": "update",
            "object": "MtaOutboundStrategy",
            "value": {
                "route": expression(
                    "'mx'",
                    (f"received_via_port == {site.sibling_port}", "'sibling-loop'"),
                    (f"rcpt_domain == '{site.agent_domain}'", "'gateway'"),
                    ("is_local_domain(rcpt_domain)", "'local'"),
                )
            },
        },
        # Postfix: queue_run_delay, minimal/maximal_backoff_time, maximal_queue_lifetime,
        # bounce_queue_lifetime.
        {
            "@type": "upsert",
            "object": "MtaDeliverySchedule",
            "matchOn": ["name"],
            "value": {
                name: _schedule(name, site, description)
                for name, description in (
                    ("local", "Local and gateway delivery (dev: Postfix's 30 s lifetime)"),
                    ("remote", "Remote delivery (dev: Postfix's 30 s lifetime)"),
                    ("dsn", "Bounces (dev: Postfix's bounce_queue_lifetime)"),
                )
            },
        },
        # Postfix: smtpd_milters (port 25 only), milter_default_action = tempfail,
        # milter_protocol = 6, and the milter timeouts. Stalwart calls the milter afresh at each
        # listed stage (see docs/findings-stalwart.md).
        # reconcile: the plan owns the milter list. A milter has no name, so an upsert keyed on
        # its address would leave the old one (still failing closed) beside a new one whenever
        # the gateway's IP changes.
        {
            "@type": "reconcile",
            "object": "MtaMilter",
            "matchOn": ["hostname", "port"],
            "value": {
                "milter-gateway": {
                    "hostname": site.gateway_ip,
                    "port": site.milter_port,
                    "enable": expression("false", ("local_port == 25", "true")),
                    "stages": _flags("mail", "rcpt", "data"),
                    "protocolVersion": "v6",
                    "tempFailOnError": True,
                    # Stalwart bounds the TCP connect and each write with timeoutCommand (it
                    # never reads timeoutConnect, so the plan leaves that at its default) and
                    # each reply with timeoutData. So: milter_connect_timeout 5s ->
                    # timeoutCommand; milter_command_timeout and milter_content_timeout (the
                    # judge answers at end of data) -> timeoutData. With 30 s, a stopped gateway
                    # cost northwind 30 s per attempt, and its 30 s queue lifetime bounced the
                    # message (S04b).
                    "timeoutCommand": 5000,
                    "timeoutData": 60000,
                    "useTls": False,
                }
            },
        },
        # Bounces are unsigned, as Postfix's are.
        {
            "@type": "update",
            "object": "DsnReportSettings",
            "value": {
                "fromAddress": expression(f"'MAILER-DAEMON@{site.domain}'"),
                "dkimSignDomain": expression("false"),
            },
        },
        # Postfix: maillog_file = /dev/stdout, so `docker compose logs` feeds amx trace.
        {
            "@type": "upsert",
            "object": "Tracer",
            "matchOn": ["@type"],
            "value": {
                "tracer-stdout": {
                    "@type": "Stdout",
                    "level": "info",
                    "ansi": False,
                    "buffered": False,
                    "multiline": False,
                    "enable": True,
                },
                # The image's default file tracer writes to /var/log/stalwart, which is absent.
                "tracer-log": {"@type": "Log", "enable": False},
            },
        },
    ]
    if site.people_milter_port:
        auth = next(op for op in plan if op["object"] == "MtaStageAuth")["value"]
        # v0.16.25 defaults to OAuth bearer AUTH even before TLS (upstream
        # registry/src/schema/structs_impl.rs, MtaStageAuth::ctx_sasl_mechanisms).
        # Bearer tokens need transport protection too, not only PLAIN/LOGIN.
        auth["saslMechanisms"] = expression(
            "false", ("local_port != 25 && is_tls", "[plain, login, oauthbearer, xoauth2]")
        )
        operation = next(op for op in plan if op["object"] == "MtaMilter")
        operation["matchOn"] = ["hostname", "port"]
        milter = operation["value"]
        milter["milter-people"] = {
            **milter["milter-gateway"],
            "port": site.people_milter_port,
            "enable": expression("false", ("local_port == 465 || local_port == 587", "true")),
        }
        listeners = next(op for op in plan if op["object"] == "NetworkListener")["value"]
        for name, port in (("submissions", 465), ("submission", 587)):
            listeners[name] = {
                **_listener(name, "smtp", port),
                "useTls": True,
                "tlsImplicit": port == 465,
            }
        plan.append(
            {
                "@type": "update",
                "object": "MtaStageMail",
                "value": {
                    "isSenderAllowed": expression(
                        "!is_empty(authenticated_as) || !key_exists('spam-block', sender_domain)",
                        (
                            "local_port == 465 || local_port == 587",
                            f"ends_with(authenticated_as, '@{site.domain}')",
                        ),
                    )
                },
            }
        )
        if site.people_tls_certificate and site.people_tls_key:
            plan.append(
                {
                    "@type": "upsert",
                    "object": "Certificate",
                    "matchOn": ["certificate"],
                    "value": {
                        "people-cert": {
                            "certificate": {
                                "@type": "File",
                                "filePath": site.people_tls_certificate,
                            },
                            "privateKey": {"@type": "File", "filePath": site.people_tls_key},
                        }
                    },
                }
            )
    operations = {operation["object"]: operation for operation in plan}
    milters = operations["MtaMilter"]["value"]
    milters["milter-sibling"] = milters["milter-gateway"] | {
        "port": site.sibling_milter_port,
        "enable": expression("false", ("listener == 'sibling'", "true")),
    }
    plan.append(
        {
            "@type": "upsert",
            "object": "SieveSystemScript",
            "matchOn": ["name"],
            "value": {
                "deny-sibling": {
                    "name": "amx-deny-sibling",
                    "isActive": True,
                    "contents": 'require ["reject"]; reject "550 5.7.1 trusted sibling only";',
                }
            },
        }
    )
    return plan


# The registered agents' accounts file (amx.accounts): address:hash:state:generation.
ACCOUNT_STATES = ("enabled", "disabled", "purge")
_LOCAL_PART = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_GENERATION = re.compile(r"^[0-9a-f]{16}$")
_CRYPT_PREFIX = "{SHA512-CRYPT}"
_CRYPT = re.compile(r"^\$6\$[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{86}$")  # amx.credentials


def registered_accounts(
    text: str, site: Site, skip: Iterable[str] = ()
) -> list[tuple[str, str, str, str]]:
    """The accounts file's agents on this mailhost: (address, secret, state, generation).

    Only addresses in the agent domain count, so a registration never creates or changes a
    person's login; a dev user of the same address keeps its own. The secret is the crypt hash
    without Dovecot's scheme prefix: Stalwart verifies a ``$6$`` hash as given (measured).
    """
    skipped = set(skip)
    accounts = []
    for line in text.splitlines():
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        address, _, rest = entry.partition(":")
        fields = rest.rsplit(":", 2)
        if len(fields) != 3:
            print("amx: skipping a malformed accounts line", file=sys.stderr)
            continue
        secret, state, generation = fields
        local, _, domain = address.partition("@")
        if domain != site.agent_domain or not _LOCAL_PART.match(local) or address in skipped:
            print(f"amx: skipping {address}: not a registrable agent here", file=sys.stderr)
            continue
        if state not in ACCOUNT_STATES:
            print(f"amx: skipping {address}: unknown state {state!r}", file=sys.stderr)
            continue
        if not _GENERATION.match(generation):
            print(f"amx: skipping {address}: bad generation", file=sys.stderr)
            continue
        if state != "purge":
            secret = secret.removeprefix(_CRYPT_PREFIX)
            if not _CRYPT.match(secret):
                print(f"amx: skipping {address}: not a SHA512-CRYPT hash", file=sys.stderr)
                continue
        accounts.append((address, secret, state, generation))
    return accounts


def generation_note(generation: str) -> str:
    """The account description that records which registration made it."""
    return f"amx generation {generation}"


def account_plan(site: Site, accounts: Sequence[tuple[str, str, str, str]]) -> list[dict[str, Any]]:
    """Upsert every enabled or disabled registered agent, the plan's way (keyed on the name).

    A disabled agent loses the ``authenticate`` permission, which refuses its own login and the
    gateway's master login alike (measured), as Dovecot's ``nologin`` does.
    """
    values = {}
    for address, secret, state, generation in accounts:
        if state == "purge":
            continue
        local_part = address.partition("@")[0]
        values["account-" + re.sub(r"[^a-z0-9]+", "-", address)] = _account(
            "domain-agents",
            local_part,
            secret,
            description=generation_note(generation),
            permissions={
                "@type": "Merge",
                "enabledPermissions": {},
                "disabledPermissions": {"authenticate": state == "disabled"},
            },
        )
    if not values:
        return []
    return [
        {
            "@type": "upsert",
            "object": "Domain",
            "matchOn": ["name"],
            "value": {"domain-agents": {"name": site.agent_domain}},
        },
        {"@type": "upsert", "object": "Account", "matchOn": ["name", "domainId"], "value": values},
    ]


def phases(plan: Sequence[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split a plan into settings and accounts.

    Stalwart checks a new password against the policy it loaded at startup, so the accounts can
    be created only after a restart with the relaxed dev policy. The accounts phase repeats the
    (idempotent) domain upsert, because a plan can refer only to objects it names itself.
    """
    settings = [operation for operation in plan if operation["object"] != "Account"]
    accounts = [operation for operation in plan if operation["object"] in {"Domain", "Account"}]
    return settings, accounts


def plan_text(plan: Iterable[dict[str, Any]]) -> str:
    """Serialize a plan as the newline-delimited JSON ``stalwart-cli apply`` reads."""
    return "".join(json.dumps(operation, sort_keys=True) + "\n" for operation in plan)


def master_login(user: str, master: str, site: Site) -> str:
    """Stalwart's master login: ``user%master@domain`` (Dovecot: ``user*master``)."""
    return MASTER_LOGIN.format(user=user, master=f"{master}@{site.domain}")


def ensure_mailboxes(
    client_factory: Callable[[], imaplib.IMAP4],
    site: Site,
    users: Sequence[str],
    login: Callable[[str], str],
    password: str,
    *,
    inactive: Sequence[str] = (),
) -> dict[str, list[str]]:
    """Create the hold queues, set their ACLs, and subscribe everyone; return what was created.

    Dovecot's entrypoint creates each user's ``Outbox/*`` with ``doveadm mailbox create``, and a
    global ACL file restricts them. Stalwart has neither, so this runs over IMAP as the gateway's
    master login, which acts as each account:
    1. Every user keeps Dovecot's subscriptions (Sent, Drafts, Trash).
    2. The hold owner gets each agent's folders, and their ACLs are set to exactly the agent's and
       the approver's rights; any other grant is removed.
    3. Each agent, and the approver, subscribes the folders shared with it, so Roundcube (which
       lists only subscriptions, PR #11) shows them.

    Existing folders are kept, so a rerun on the same volume changes nothing.
    """
    owner = site.hold_mailbox
    approver = f"approver@{site.domain}"
    reserved = sorted({owner, approver} & set(users))
    if reserved:
        raise ValueError(f"{', '.join(reserved)}: reserved for the hold queue on Stalwart")
    folders, grants, subscriptions = hold_layout(site, [*users, *inactive])
    for user in inactive:
        subscriptions.pop(user, None)
    created: dict[str, list[str]] = {}
    with _session(client_factory, login(owner), password) as client:
        created[owner] = _create_missing(client, owner, folders)
    # A new session: Stalwart's session can miss a folder it created itself (a GETACL on the last
    # one answered "Mailbox does not exist").
    with _session(client_factory, login(owner), password) as client:
        for folder, expected in grants.items():
            _set_acl(client, folder, expected, owner)
    for user, wanted in subscriptions.items():
        with _session(client_factory, login(user), password) as client:
            _subscribe(client, user, wanted)
    return created


@contextlib.contextmanager
def _session(
    client_factory: Callable[[], imaplib.IMAP4], login: str, password: str
) -> Iterator[imaplib.IMAP4]:
    client = client_factory()
    try:
        client.login(login, password)
        yield client
    finally:
        with contextlib.suppress(OSError, imaplib.IMAP4.error):
            client.logout()


def _create_missing(client: imaplib.IMAP4, user: str, folders: Sequence[str]) -> list[str]:
    """Create each folder that does not exist yet, in order (parents first)."""
    status, listing = client.list()
    if status != "OK":
        raise RuntimeError(f"cannot list folders for {user}: {listing!r}")
    existing = {_listed_name(line) for line in listing if isinstance(line, bytes)}
    created = []
    for folder in folders:
        if folder in existing:
            continue
        status, detail = client.create(_quoted(folder))
        if status != "OK":
            raise RuntimeError(f"cannot create {folder} for {user}: {detail!r}")
        created.append(folder)
    return created


def _set_acl(client: imaplib.IMAP4, folder: str, expected: dict[str, str], owner: str) -> None:
    """Make a folder's ACL exactly ``expected`` (grantee -> rights), then read it back."""
    for grantee in set(_acl(client, folder)) - set(expected) - {owner}:
        status, detail = client.deleteacl(_quoted(folder), grantee)
        if status != "OK":
            raise RuntimeError(f"cannot remove {grantee} from {folder}: {detail!r}")
    for grantee, rights in expected.items():
        status, detail = client.setacl(_quoted(folder), grantee, rights)
        if status != "OK":
            raise RuntimeError(f"cannot grant {grantee} {rights} on {folder}: {detail!r}")
    # Compare as sets: Stalwart reports rights in its own order, and "s" and "w" as a pair.
    actual = {grantee: frozenset(rights) for grantee, rights in _acl(client, folder).items()}
    actual.pop(owner, None)
    wanted = {grantee: frozenset(_normalized(rights)) for grantee, rights in expected.items()}
    if actual != wanted:
        raise RuntimeError(f"{folder}: ACL is {actual}, not {wanted}")


def _normalized(rights: str) -> str:
    """Rights as Stalwart stores them: it has one right for "s" and "w"."""
    return rights + ("sw" if set(rights) & {"s", "w"} else "")


def _acl(client: imaplib.IMAP4, folder: str) -> dict[str, str]:
    """One folder's ACL (grantee -> rights), from an untagged ``* ACL`` response."""
    status, data = client.getacl(_quoted(folder))
    if status != "OK":
        raise RuntimeError(f"cannot read the ACL of {folder}: {data!r}")
    line = next((item for item in data if isinstance(item, bytes)), b"")
    tokens = _astrings(line.decode("utf-8", "replace"))[1:]  # the first is the folder
    return dict(zip(tokens[0::2], tokens[1::2], strict=True))


def _subscribe(client: imaplib.IMAP4, user: str, folders: Sequence[str]) -> None:
    """Subscribe what is missing, then check the result.

    Unsubscribed folders are invisible in Roundcube (PR #11), and Stalwart refuses to subscribe
    a folder twice.
    """
    for folder in sorted(set(folders) - _subscribed(client, user)):
        client.subscribe(_quoted(folder))
    missing = set(folders) - _subscribed(client, user)
    if missing:
        raise RuntimeError(f"{user}: not subscribed: {', '.join(sorted(missing))}")


def _subscribed(client: imaplib.IMAP4, user: str) -> set[str]:
    status, listing = client.lsub()
    if status != "OK":
        raise RuntimeError(f"cannot list subscriptions for {user}: {listing!r}")
    return {_listed_name(line) for line in listing if isinstance(line, bytes)}


def _listed_name(line: bytes) -> str:
    """The mailbox name from one IMAP LIST response line."""
    text = line.decode("utf-8", "replace").strip()
    if text.endswith('"'):
        return _astrings(text)[-1]
    return text.rsplit(" ", 1)[-1]


def _astrings(text: str) -> list[str]:
    """Split an IMAP response line into atoms and (unescaped) quoted strings."""
    tokens: list[str] = []
    index = 0
    while index < len(text):
        if text[index] == " ":
            index += 1
        elif text[index] == '"':
            index += 1
            token = []
            while index < len(text) and text[index] != '"':
                if text[index] == "\\" and index + 1 < len(text):
                    index += 1
                token.append(text[index])
                index += 1
            tokens.append("".join(token))
            index += 1
        else:
            end = text.find(" ", index)
            end = len(text) if end < 0 else end
            tokens.append(text[index:end])
            index = end
    return tokens


def _quoted(folder: str) -> str:
    """A folder name as an IMAP quoted string (imaplib sends arguments as they are)."""
    return '"' + folder.replace("\\", "\\\\").replace('"', '\\"') + '"'


def wait_for(probe: Callable[[], bool], timeout: float, what: str) -> None:
    """Poll ``probe`` every 0.2 s until it returns true, or fail after ``timeout`` seconds."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if probe():
            return
        time.sleep(0.2)
    raise TimeoutError(f"timed out waiting for {what}")


def port_open(port: int, host: str = "127.0.0.1") -> bool:
    try:
        socket.create_connection((host, port), 1).close()
    except OSError:
        return False
    return True


def http_ok(url: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=2) as response:  # nosec B310 (loopback only)
            return 200 <= response.status < 300
    except (OSError, urllib.error.URLError):
        return False


class PrivateServer:
    """Run the Stalwart binary in the foreground of this container, for provisioning only."""

    def __init__(self, binary: str, config: str) -> None:
        self.command = [binary, "--config", config]
        self.process: subprocess.Popen[bytes] | None = None

    def __enter__(self) -> PrivateServer:
        self.process = subprocess.Popen(  # nosec B603 (fixed argv)
            self.command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        return self

    def running(self) -> bool:
        """True while the server runs; raise at once if it has exited."""
        code = None if self.process is None else self.process.poll()
        if code is not None:
            raise RuntimeError(
                f"stalwart exited with code {code}; if the mailhost is running on this volume, "
                "its datastore is locked (make down first)"
            )
        return True

    def __exit__(self, *_exc: object) -> None:
        if self.process is None:
            return
        self.process.send_signal(signal.SIGTERM)
        try:
            self.process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()


def _site(arguments: argparse.Namespace) -> Site:
    if getattr(arguments, "bundle", None):
        return Site(**json.loads(Path(arguments.bundle).read_text(encoding="utf-8"))["site"])
    people_port = getattr(arguments, "people_milter_port", 0)
    return Site(
        domain=arguments.domain,
        agent_domain=arguments.agent_domain,
        hostname=arguments.hostname,
        gateway_host=arguments.gateway_host,
        gateway_ip=arguments.gateway_ip,
        people_milter_port=people_port,
        people_tls_certificate="/tls/server.pem" if people_port else None,
        people_tls_key="/tls/server-key.pem" if people_port else None,
        hold_owner=arguments.hold_owner,
        hold_prefix=arguments.hold_prefix,
    )


def layout_text(site: Site, users: Sequence[str]) -> str:
    """What the IMAP phase provisions beyond the plan: folders, exact grants, subscriptions."""
    folders, grants, subscriptions = hold_layout(site, users)
    layout = {
        "owner": site.hold_mailbox,
        "folders": folders,
        "grants": grants,
        "subscriptions": subscriptions,
    }
    return json.dumps(layout, sort_keys=True) + "\n"


CLI_TIMEOUT = 60
SNAPSHOT_QUERY_TIMEOUT = 10
# Six sequential queries, the two-second HTTP probe and Compose startup margin.
SNAPSHOT_TIMEOUT = 80
PREFLIGHT_TIMEOUT = 180

# Only configuration, never Account/credentials. Output is a safe preflight
# snapshot, not a generic management proxy.
HARDENING_FIELDS = {
    "OidcProvider": ("requireClientRegistration", "anonymousClientRegistration"),
    "Imap": ("allowPlainTextAuth",),
    "MtaInboundThrottle": ("description", "enable", "key", "match", "rate"),
    "AllowedIp": ("address",),
    "Application": ("enabled", "resourceUrl", "urlPrefix", "unpackDirectory"),
    "NetworkListener": ("name", "protocol", "bind", "useTls", "tlsImplicit"),
}

# Source vocabulary only, shared with the hosted log filter. Never derive this
# allowlist from management output or the operator's plan.
BOOTSTRAP_OPERATIONS = ("update", "upsert", "reconcile")
BOOTSTRAP_OBJECTS = (
    "Authentication",
    "Imap",
    "SpamSettings",
    "SpamPyzor",
    "Asn",
    "Application",
    "OidcProvider",
    "Email",
    "SenderAuth",
    "MtaStageData",
    "MtaInboundThrottle",
    "AllowedIp",
    "MtaStageEhlo",
    "MtaStageConnect",
    "SieveSystemScript",
    "MtaStageAuth",
    "MtaStageRcpt",
    "NetworkListener",
    "Domain",
    "SystemSettings",
    "Account",
    "MtaRoute",
    "MtaOutboundStrategy",
    "MtaDeliverySchedule",
    "MtaMilter",
    "DsnReportSettings",
    "Tracer",
    "MtaStageMail",
    "Certificate",
)
BOOTSTRAP_PROPERTIES = (
    "unknown",
    "certificate",
    "privateKey",
    "filePath",
    "resourceUrl",
    "urlPrefix",
    "unpackDirectory",
    "name",
    "domainId",
    "description",
    "credentials",
    "credentialId",
    "secret",
    "permissions",
    "enabledPermissions",
    "disabledPermissions",
    "authenticate",
    "impersonate",
    "bind",
    "protocol",
    "useTls",
    "tlsImplicit",
    "address",
    "enable",
    "rate",
    "key",
    "match",
    "passwordMinLength",
    "allowPlainTextAuth",
    "requireClientRegistration",
    "anonymousClientRegistration",
)


def bootstrap_failure_diagnostic(stdout: str | None, plan: list[dict[str, Any]]) -> str | None:
    """Reduce CLI v1.0.12 Reporter::op_err NDJSON to bounded source fields.

    The error string may embed secrets. Parse only its enum code/property names;
    never return descriptions, object IDs, values or arbitrary stdout/stderr.
    Reporter indices are zero-based and must name this exact plan operation.
    """
    if not isinstance(stdout, str):
        return None
    for line in stdout[:65536].splitlines():
        if len(line) > 16384:
            continue
        try:
            record = json.loads(line)
        except (ValueError, RecursionError):
            continue
        if not isinstance(record, dict) or record.get("status") != "error":
            continue
        index = record.get("index")
        if type(index) is not int or not 0 <= index < min(len(plan), 128):
            continue
        operation, object_name = record.get("op"), record.get("object")
        if (
            operation not in BOOTSTRAP_OPERATIONS
            or object_name not in BOOTSTRAP_OBJECTS
            or operation != plan[index].get("@type")
            or object_name != plan[index].get("object")
        ):
            continue
        detail = record.get("error")
        detail = detail[:16384] if isinstance(detail, str) else ""
        code, _ = management_failure_fields(subprocess.CalledProcessError(1, [], stderr=detail))
        match = re.search(r"(?:^|\|)\s*Properties: ([^|\n]*)", detail)
        leaves = {p.strip().rsplit("/", 1)[-1] for p in match[1].split(",")} if match else set()
        property_name = next(iter(sorted(leaves & set(BOOTSTRAP_PROPERTIES))), "unknown")
        return (
            f"operation={operation} object={object_name} index={index} status=error "
            f"code={code} property={property_name}"
        )
    return None


def hardening_snapshot(cli: str, env: dict[str, str]) -> dict:
    if cli != "/usr/local/bin/stalwart-cli":
        raise ValueError("hardening snapshot requires the pinned management executable")
    result = {}
    for name, fields in HARDENING_FIELDS.items():
        verb = "get" if name in {"OidcProvider", "Imap"} else "query"
        # Executable admitted above; operation/object/fields are source allowlists only.
        # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
        response = subprocess.run(
            [cli, "--no-color", verb, name, "--fields", ",".join(fields), "--json"],
            check=True,
            env=env,
            capture_output=True,
            text=True,
            shell=False,
            timeout=SNAPSHOT_QUERY_TIMEOUT,
        )
        try:
            decoded = json.loads(response.stdout)
            records = decoded if isinstance(decoded, list) else [decoded]
        except json.JSONDecodeError:
            records = [json.loads(line) for line in response.stdout.splitlines() if line.strip()]
        result[name] = [{k: record[k] for k in fields if k in record} for record in records]
    result["WebUiStatus"] = [{"ready": http_ok(env["STALWART_URL"].rstrip("/") + "/admin/")}]
    return result


def provision(arguments: argparse.Namespace) -> int:
    site = _site(arguments)
    users, masters, plan = provisioning_inputs(arguments, site)
    local = site_users(users, site)
    settings, accounts = phases(plan)
    # A second `make up` on a running stack must not boot a second server on the mailhost's
    # (locked) datastore: an unchanged plan that was applied before is a no-op.
    marker = Path(arguments.state_dir) / "amx-provisioned.sha256"
    layout = layout_text(site, [address for address, _password in local])
    digest = hashlib.sha256((plan_text(plan) + layout).encode()).hexdigest()
    if (
        not getattr(arguments, "reapply", False)
        and marker.exists()
        and marker.read_text(encoding="utf-8").strip() == digest
    ):
        print(f"amx: {site.domain} already provisioned with this plan ({digest[:12]})")
        return 0
    admin_user, _, admin_password = os.environ["STALWART_RECOVERY_ADMIN"].partition(":")
    cli_env = os.environ | {
        "STALWART_URL": "http://127.0.0.1:8080",
        "STALWART_USER": admin_user,
        "STALWART_PASSWORD": admin_password,
    }

    def apply(server: PrivateServer, name: str, plan: list[dict[str, Any]]) -> None:
        # The plan carries the dev passwords: it stays in this container, off the shared volume.
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / f"amx-{name}.ndjson"
            path.write_text(plan_text(plan), encoding="utf-8")
            wait_for(
                lambda: server.running() and http_ok("http://127.0.0.1:8080/healthz/ready"),
                60,
                "management port",
            )
            print(f"amx: bootstrap stage={name}-ready status=ok", flush=True)
            try:
                subprocess.run(  # nosec B603 (fixed argv)
                    [arguments.cli, "--no-color", "apply", "--json", "--file", str(path)],
                    check=True,
                    env=cli_env,
                    timeout=CLI_TIMEOUT,
                    capture_output=True,
                    text=True,
                )
            except subprocess.CalledProcessError as error:
                # Fixed code only: CLI diagnostics may contain authentication payloads.
                unauthorized = bool(re.search(r"\b401\b", error.stderr or ""))
                code = "http401" if unauthorized else "management-error"
                print(f"amx: bootstrap stage={name}-apply status={code}", flush=True)
                diagnostic = bootstrap_failure_diagnostic(error.stdout, plan)
                if diagnostic:
                    print(f"amx: bootstrap {diagnostic}", flush=True)
                raise RuntimeError(f"bootstrap {name} apply failed ({code})") from None
            print(f"amx: bootstrap stage={name}-apply status=ok", flush=True)

    with PrivateServer(arguments.stalwart, arguments.config) as server:
        apply(server, "settings", settings)
    # Listeners and the password policy load only at startup: boot again with the settings.
    with PrivateServer(arguments.stalwart, arguments.config) as server:
        apply(server, "accounts", accounts)
        live_bundle = bool(getattr(arguments, "bundle", None))
        imap_port = 993 if live_bundle else 143
        wait_for(lambda: server.running() and port_open(imap_port), 60, "IMAP listener")
        created = ensure_mailboxes(
            lambda: (
                _imap_client("127.0.0.1", 993, "/tls/ca.pem", site.hostname)
                if live_bundle
                else imaplib.IMAP4("127.0.0.1", 143, timeout=10)
            ),
            site,
            [address for address, _password in local],
            lambda user: master_login(user, "gateway", site),
            masters["gateway"],
        )
    marker.write_text(digest + "\n", encoding="utf-8")
    for user, folders in created.items():
        print(f"amx: {user}: created {', '.join(folders) or 'nothing (already present)'}")
    print(f"amx: provisioned {site.domain} and {site.agent_domain} ({len(local)} users)")
    return 0


def _cli_env(url: str) -> dict[str, str]:
    admin_user, _, admin_password = os.environ["STALWART_RECOVERY_ADMIN"].partition(":")
    return os.environ | {
        "STALWART_URL": url,
        "STALWART_USER": admin_user,
        "STALWART_PASSWORD": admin_password,
    }


def _existing_accounts(cli: str, env: dict[str, str]) -> dict[str, tuple[str, str | None]]:
    """Every account on the running server: address -> (id, description)."""
    result = subprocess.run(  # nosec B603 (fixed argv)
        [cli, "--no-color", "query", "Account", "--json"],
        check=True,
        env=env,
        capture_output=True,
        text=True,
        timeout=CLI_TIMEOUT,
    )
    existing = {}
    for line in result.stdout.splitlines():
        if line.strip():
            record = json.loads(line)
            description = record.get("description")
            existing[str(record.get("emailAddress", "")).casefold()] = (
                str(record["id"]),
                None if description is None else str(description),
            )
    return existing


def _delete_hold_queue(client: imaplib.IMAP4, site: Site, agent: str) -> list[str]:
    """Delete a purged agent's hold folders from the hold owner's mailbox, children first."""
    deleted = []
    status, listing = client.list()
    existing = {_listed_name(line) for line in listing if isinstance(line, bytes)}
    root = site.hold_prefix.format(agent=agent).rstrip("/")
    for folder in (*hold_folders(site, agent), root):
        if folder in existing:
            status, detail = client.delete(_quoted(folder))
            if status != "OK":
                raise RuntimeError(f"cannot delete {folder}: {detail!r}")
            deleted.append(folder)
    return deleted


def _imap_client(
    host: str, port: int, ca_file: str | None = None, server_hostname: str | None = None
) -> imaplib.IMAP4:
    if ca_file:
        context = ssl.create_default_context(cafile=ca_file if Path(ca_file).exists() else None)

        class NamedIMAP(imaplib.IMAP4_SSL):
            def _create_socket(self, timeout):
                raw = imaplib.IMAP4._create_socket(self, timeout)
                return self.ssl_context.wrap_socket(raw, server_hostname=server_hostname or host)

        return NamedIMAP(host, port, ssl_context=context, timeout=10)
    return imaplib.IMAP4(host, port, timeout=10)


def _accounts_snapshot(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except FileNotFoundError:
        return b""


def management_failure_fields(error: subprocess.CalledProcessError) -> tuple[str, str]:
    """Reduce pinned CLI v1.0.12's rendered set error to fixed vocabulary only.

    Its descriptions, object IDs and validation values can contain credentials.
    Never forward stderr, even when it looks like a structured error message.
    """
    codes = {
        "forbidden",
        "overQuota",
        "tooLarge",
        "rateLimit",
        "notFound",
        "invalidPatch",
        "invalidProperties",
        "alreadyExists",
        "invalidForeignKey",
        "primaryKeyViolation",
        "validationFailed",
    }
    properties = {
        "credentialId",
        "credentials",
        "secret",
        "name",
        "domainId",
        "description",
        "permissions",
        "enabledPermissions",
        "disabledPermissions",
        "authenticate",
        "impersonate",
    }
    stderr = error.stderr if isinstance(error.stderr, str) else ""
    stderr = stderr[:16384]
    code_match = re.search(r"\berror: ([A-Za-z]+)(?=\s*(?:\||\n|$))", stderr)
    code = code_match[1] if code_match and code_match[1] in codes else "unknown"
    property_match = re.search(r"(?:^|\|)\s*Properties: ([^|\n]*)", stderr)
    leaves = (
        {path.strip().rsplit("/", 1)[-1] for path in property_match[1].split(",")}
        if property_match
        else set()
    )
    # Emit one deterministic allowlisted leaf, never an arbitrary path or list key.
    property_name = next(iter(sorted(leaves & properties)), "unknown")
    return code, property_name


def sync_accounts(
    arguments: argparse.Namespace,
    *,
    snapshot: bytes | None = None,
    people_snapshot: bytes | None = None,
) -> None:
    """Apply the accounts file to the running mailhost once (PLAN §5.2).

    First, delete what must not survive, together with its hold folders:
    - a purged agent's account;
    - an account made for another generation under the same address, which belonged to an
      earlier agent of that name.

    Then upsert the rest, and give each enabled agent its hold queue.
    """
    site = _site(arguments)
    users, masters, _plan = provisioning_inputs(arguments, site)
    dev = [address for address, _password in site_users(users, site)]
    if snapshot is None:
        snapshot = _accounts_snapshot(Path(arguments.accounts))
    accounts = registered_accounts(snapshot.decode("utf-8"), site, dev)
    env = _cli_env(arguments.url)
    people_path = getattr(arguments, "people", None)
    if people_snapshot is None:
        people_snapshot = Path(people_path).read_bytes() if people_path else b""
    people = json.loads(people_snapshot) if people_path or people_snapshot else {}
    owners = tuple(
        address for address, person in people.items() if person["enabled"] and person["owner"]
    )
    site = replace(site, approvers=owners)
    if people:
        # Trusted operator-selected installed CLI; fixed query argv, shell=False by default,
        # and a finite timeout. No shell interpolation or credential arguments.
        # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
        queried = subprocess.run(
            [arguments.cli, "--no-color", "query", "Account", "--json"],
            check=True,
            env=env,
            capture_output=True,
            text=True,
            timeout=CLI_TIMEOUT,
        )
        records = [json.loads(line) for line in queried.stdout.splitlines() if line.strip()]
        print(
            f"amx: people stage=query status=ok records={len(records)} desired={len(people)}",
            flush=True,
        )
        existing_people = {record["emailAddress"]: record for record in records}
        values = {}
        for address, person in people.items():
            local, _, domain = address.partition("@")
            if (
                domain != site.domain
                or not re.fullmatch(r"[a-z0-9]+(?:[._-][a-z0-9]+)*", local)
                or len(local) > 64
                or local
                in {
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
            ):
                raise ValueError("invalid managed person identity")
            previous = existing_people.get(address, {})
            ownership = person["ownership"]
            if not re.fullmatch(r"[0-9a-f]{32}", ownership):
                raise ValueError("invalid person ownership token")
            marker = f"amx managed person {ownership} {person['generation']}"
            trusted = {
                f"amx managed person {ownership} {generation}"
                for generation in person["generations"]
            }
            if previous and previous.get("description") not in trusted:
                raise ValueError("refuse to adopt an unmanaged principal")
            # credentialId is server-set, including inside a Password object. The CLI
            # only strips top-level server-set fields. Use the working _account payload
            # for new/rotated passwords, and omit credentials entirely on routine sync:
            # Account/set preserves omitted properties, including native app passwords.
            # Replaying query output would send server-set IDs and masked secrets.
            password = person["secret"] if previous.get("description") != marker else None
            values["person-" + local] = _account(
                "domain-people",
                local,
                password,
                description=marker,
                permissions={
                    "@type": "Merge",
                    "enabledPermissions": {},
                    "disabledPermissions": {
                        "impersonate": True,
                        "authenticate": not person["enabled"],
                    },
                },
            )
        people_plan = [
            {
                "@type": "upsert",
                "object": "Domain",
                "matchOn": ["name"],
                "value": {"domain-people": {"name": site.domain}},
            },
            {
                "@type": "upsert",
                "object": "Account",
                "matchOn": ["name", "domainId"],
                "value": values,
            },
        ]
        try:
            # Trusted operator-selected installed CLI; fixed apply argv, shell=False by default,
            # hashes serialized on stdin (not shell input), and a finite timeout.
            # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
            subprocess.run(
                [arguments.cli, "--no-color", "apply", "--stdin", "--quiet"],
                input=plan_text(people_plan),
                check=True,
                env=env,
                text=True,
                capture_output=True,
                timeout=CLI_TIMEOUT,
            )
        except subprocess.CalledProcessError as error:
            code, property_name = management_failure_fields(error)
            print(
                f"amx: people stage=apply status=error code={code} property={property_name}",
                file=sys.stderr,
                flush=True,
            )
            raise
        print(f"amx: people stage=apply status=ok desired={len(values)}", flush=True)

    def imap() -> imaplib.IMAP4:
        if getattr(arguments, "imap_tls", False):
            return _imap_client(
                arguments.imap_host, arguments.imap_port, arguments.imap_ca_file, site.hostname
            )
        return _imap_client(arguments.imap_host, arguments.imap_port)

    def login(user: str) -> str:
        return master_login(user, "gateway", site)

    existing = _existing_accounts(arguments.cli, env) if accounts else {}
    doomed = [
        address
        for address, _secret, state, generation in accounts
        if address in existing
        and (state == "purge" or existing[address][1] != generation_note(generation))
    ]
    if doomed:
        with _session(imap, login(site.hold_mailbox), masters["gateway"]) as client:
            for address in doomed:
                deleted = _delete_hold_queue(client, site, address.partition("@")[0])
                if deleted:
                    print(f"amx: {address}: deleted {', '.join(deleted)}")
        ids = ",".join(existing[address][0] for address in doomed)
        subprocess.run(  # nosec B603 (fixed argv)
            [arguments.cli, "--no-color", "delete", "Account", "--ids", ids],
            check=True,
            env=env,
            timeout=CLI_TIMEOUT,
        )
        print(f"amx: purged {', '.join(doomed)}")
    plan = account_plan(site, accounts)
    if plan:
        subprocess.run(  # nosec B603 (fixed argv; the plan, hashes only, goes on stdin)
            [arguments.cli, "--no-color", "apply", "--stdin", "--quiet"],
            input=plan_text(plan),
            check=True,
            env=env,
            text=True,
            timeout=CLI_TIMEOUT,
        )
    # Every active agent's hold queue, ACLs, and subscriptions (idempotent). A disabled agent
    # cannot be logged in as, so its folders stay as they are until it is enabled or purged.
    active = [address for address, _secret, state, _generation in accounts if state == "enabled"]
    people_active = [address for address, person in people.items() if person["enabled"]]
    inactive = [address for address, _secret, state, _generation in accounts if state == "disabled"]
    mailbox_args = (imap, site, [*dev, *active, *people_active], login, masters["gateway"])
    created = (
        ensure_mailboxes(*mailbox_args, inactive=inactive)
        if people
        else ensure_mailboxes(*mailbox_args)
    )
    for user, folders in created.items():
        if folders:
            print(f"amx: {user}: created {', '.join(folders)}")


def sync(arguments: argparse.Namespace) -> int:
    """``sync``: apply the accounts file once, or each time it changes (``--watch``)."""
    if not arguments.watch:
        sync_accounts(arguments)
        return 0
    path = Path(arguments.accounts)
    applied: str | None = None
    while True:
        stage = "snapshot"
        try:
            # Hash and apply the very same immutable bytes, not two reads of a mutable file.
            # Changes during application (including A -> B -> A) cannot mislabel the result.
            snapshot = _accounts_snapshot(path)
            people_path = getattr(arguments, "people", None)
            people_snapshot = Path(people_path).read_bytes() if people_path else b""
            current = hashlib.sha256(
                snapshot + b"\0" + people_snapshot if people_path else snapshot
            ).hexdigest()
            if current != applied:
                stage = "apply"
                if people_path:
                    sync_accounts(arguments, snapshot=snapshot, people_snapshot=people_snapshot)
                else:
                    sync_accounts(arguments, snapshot=snapshot)
                applied = current
                print(f"amx: accounts applied ({current[:12]})", flush=True)
        except Exception as error:  # retried a second later; the mailhost may be restarting
            # Exceptions can contain CLI stdin (credential hashes) or server payloads.
            status = error.returncode if isinstance(error, subprocess.CalledProcessError) else "n/a"
            print(
                f"amx: accounts sync failed stage={stage} type={type(error).__name__} "
                f"status={status}; retrying",
                file=sys.stderr,
                flush=True,
            )
        time.sleep(1)


def provisioning_inputs(arguments: argparse.Namespace, site: Site) -> tuple[list, dict, list]:
    """Live parameters are rendered on the host; the dev CLI remains compatible."""
    if getattr(arguments, "bundle", None):
        bundle = json.loads(Path(arguments.bundle).read_text(encoding="utf-8"))
        return bundle["users"], bundle["masters"], bundle["plan"]
    users, masters = read_dev_users(Path(arguments.dev_users).read_text(encoding="utf-8"))
    return users, masters, render_plan(site, users, masters)


def reload_tls_certificates(cli: str, env: dict[str, str]) -> None:
    """Pinned CLI v1.0.12 maps this create to Action/set, checking notCreated."""
    if cli != "/usr/local/bin/stalwart-cli":
        raise ValueError("TLS reload requires the pinned management executable")
    subprocess.run(
        [cli, "--no-color", "create", "Action/ReloadTlsCertificates", "--json", "{}"],
        env=env,
        check=True,
        capture_output=True,
        text=True,
        timeout=CLI_TIMEOUT,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Provision Stalwart as an amx mailhost (M6)")
    commands = parser.add_subparsers(dest="command", required=True)
    audit_parser = commands.add_parser("hardening-snapshot")
    audit_parser.add_argument("--admin-file", required=True)
    audit_parser.add_argument("--url", default="http://mailhost:8080")
    audit_parser.add_argument("--cli", default="/usr/local/bin/stalwart-cli")
    reload_parser = commands.add_parser("reload-tls")
    reload_parser.add_argument("--admin-file", required=True)
    reload_parser.add_argument("--url", default="http://mailhost:8080")
    for name in ("plan", "provision", "sync"):
        command = commands.add_parser(name)
        command.add_argument("--bundle", help="generated live bundle JSON (instead of dev-users)")
        command.add_argument("--admin-file", help="0600 recovery-admin file")
        command.add_argument("--domain")
        command.add_argument("--agent-domain")
        command.add_argument("--hostname")
        command.add_argument("--gateway-host")
        command.add_argument("--gateway-ip")
        command.add_argument("--people-milter-port", type=int, default=0)
        command.add_argument("--dev-users")
        # The gateway's AMX_MAILBOX_HOLD_OWNER and AMX_MAILBOX_HOLD_PREFIX (PLAN §5.8).
        command.add_argument("--hold-owner", help="default: holds@<domain>")
        command.add_argument("--hold-prefix", default=HOLD_PREFIX)
    provision_parser = commands.choices["provision"]
    provision_parser.add_argument("--stalwart", default="/usr/local/bin/stalwart")
    provision_parser.add_argument("--cli", default="/usr/local/bin/stalwart-cli")
    provision_parser.add_argument("--config", default="/etc/stalwart/config.json")
    provision_parser.add_argument("--state-dir", default="/var/lib/stalwart")
    provision_parser.add_argument(
        "--reapply", action="store_true", help="reapply with runtime stopped"
    )
    sync_parser = commands.choices["sync"]
    sync_parser.add_argument("--accounts", required=True, help="the amx accounts file")
    sync_parser.add_argument("--people", help="hash-only managed people desired state")
    sync_parser.add_argument("--url", required=True, help="the running mailhost's management URL")
    sync_parser.add_argument("--imap-host", required=True)
    sync_parser.add_argument("--imap-port", type=int, default=143)
    sync_parser.add_argument("--imap-tls", action="store_true")
    sync_parser.add_argument("--imap-ca-file")
    sync_parser.add_argument("--cli", default="/usr/local/bin/stalwart-cli")
    sync_parser.add_argument("--watch", action="store_true", help="apply each change, forever")
    arguments = parser.parse_args(argv)
    if arguments.command == "reload-tls":
        try:
            os.environ["STALWART_RECOVERY_ADMIN"] = Path(arguments.admin_file).read_text().strip()
            reload_tls_certificates("/usr/local/bin/stalwart-cli", _cli_env(arguments.url))
        except (OSError, ValueError, subprocess.SubprocessError):
            print("amx: Stalwart TLS reload failed", file=sys.stderr)
            return 1
        print("amx: Stalwart TLS reloaded")
        return 0
    if arguments.command == "hardening-snapshot":
        os.environ["STALWART_RECOVERY_ADMIN"] = Path(arguments.admin_file).read_text().strip()
        print(json.dumps(hardening_snapshot(arguments.cli, _cli_env(arguments.url))))
        return 0
    if not arguments.bundle and not all(
        getattr(arguments, name)
        for name in (
            "domain",
            "agent_domain",
            "hostname",
            "gateway_host",
            "gateway_ip",
            "dev_users",
        )
    ):
        parser.error(
            "provide --bundle or all of --domain/--agent-domain/--hostname/"
            "--gateway-host/--gateway-ip/--dev-users"
        )
    if arguments.admin_file:
        os.environ["STALWART_RECOVERY_ADMIN"] = Path(arguments.admin_file).read_text().strip()
    if arguments.command == "provision":
        return provision(arguments)
    if arguments.command == "sync":
        return sync(arguments)
    site = _site(arguments)
    _users, _masters, plan = provisioning_inputs(arguments, site)
    sys.stdout.write(plan_text(plan))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
