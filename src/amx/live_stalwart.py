"""Parameter-driven Stalwart rendering for the live bundle (SH-10).

The provisioner's development plan supplies the shared milter/LMTP and hold ACL
contract. This renderer replaces site-specific settings; it never reads dev-users.
SH-10b owns the next hardening pass; SH-11/20/30 own people and edge policy.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import asdict
from typing import TYPE_CHECKING

from amx.adapters.stalwart import SNAPSHOT_TIMEOUT, Site, expression, render_plan
from amx.credentials import hash_password
from amx.provision import write_private
from amx.stalwart_webui import WEBUI_RESOURCE, publish_webui, read_webui

if TYPE_CHECKING:
    from amx.live import Credentials, LiveParams


def install_stalwart(
    params: LiveParams, credentials: Credentials, *, webui_data: bytes | None = None
) -> None:
    from amx.live import _mkdir, new_secret

    if params.webui_bundle and webui_data is None:
        webui_data = read_webui(params.webui_bundle)
    directory = params.secrets_dir / "stalwart"
    _mkdir(directory, 0o700)
    people = directory / "people.json"
    if not people.exists():
        write_private(people, "{}\n")
    _mkdir(params.state_dir / "stalwart", 0o700)
    admin = directory / "recovery-admin"
    if not admin.exists():
        write_private(admin, "admin:" + new_secret() + "\n")
    site = Site(
        domain=params.org_domain,
        agent_domain=params.agent_domain,
        hostname=params.mx_host,
        gateway_host=params.gateway_ip,
        gateway_ip=params.gateway_ip,
        people_milter_port=8892,
        trusted_network=params.gateway_ip + "/32",
        relay_domains=(params.org_domain, params.agent_domain),
        retry_seconds=(60, 300, 900, 3600),
        queue_lifetime_seconds=5 * 24 * 3600,
    )
    # Hashes are stable on reinstall. Only the gateway master needs plaintext
    # for the provisioning/sync IMAP session; all of this file is 0600.
    previous = directory / "bundle.json"
    old = json.loads(previous.read_text()) if previous.exists() else {}
    old_users = dict(old.get("users", []))
    address = f"postmaster@{params.org_domain}"
    old_secret = old_users.get(address, "")
    salt = old_secret.split("$")[2] if old_secret.startswith("$6$") else None
    users = [
        (address, hash_password(credentials.postmaster, salt=salt).removeprefix("{SHA512-CRYPT}"))
    ]
    masters = {"gateway": credentials.gateway_master, "approver": credentials.approver}
    plan = render_plan(site, users, masters)
    operations = {op["object"]: op for op in plan}
    operations["Authentication"]["value"] = {"passwordMinLength": 16}
    operations["Imap"]["value"] = {"allowPlainTextAuth": False}
    operations["MtaInboundThrottle"]["@type"] = "reconcile"
    operations["MtaInboundThrottle"]["value"] = household_throttles()
    # v0.16.25 IpAddrOrMask serializes a /32 host without the mask. The
    # pinned CLI matches exact JSON, so replaying "host/32" misses "host"
    # and attempts a duplicate create against AllowedIp's unique address.
    # Use the native DTO spelling; a bare IPv4 address still trusts one host.
    operations["AllowedIp"]["value"]["allowed-network"]["address"] = params.gateway_ip
    if webui_data is not None:
        publish_webui(directory / "webui.zip", webui_data)
    operations["Application"]["value"]["app-webui"].update(
        enabled=True,
        resourceUrl=WEBUI_RESOURCE,
        urlPrefix={"/admin": True, "/account": True},
        unpackDirectory="/var/lib/stalwart/webui",
    )
    listeners = operations["NetworkListener"]
    listeners["@type"] = "reconcile"
    listeners["value"].update(
        {
            "management": {
                "name": "management",
                "protocol": "http",
                "bind": {"[::]:8080": True},
                "useTls": False,
            },
            "imaps": {
                "name": "imaps",
                "protocol": "imap",
                "bind": {"[::]:993": True},
                "useTls": True,
                "tlsImplicit": True,
            },
            "submission": {
                "name": "submission",
                "protocol": "smtp",
                "bind": {"[::]:587": True},
                "useTls": True,
                "tlsImplicit": False,
            },
            "submissions": {
                "name": "submissions",
                "protocol": "smtp",
                "bind": {"[::]:465": True},
                "useTls": True,
                "tlsImplicit": True,
            },
            "discovery": {
                "name": "discovery",
                "protocol": "http",
                "bind": {"[::]:443": True},
                "useTls": True,
                "tlsImplicit": True,
            },
        }
    )
    listeners["value"]["smtp"]["useTls"] = True
    # Native submission must not let an agent's IMAP credential bypass the
    # gateway's signing/hold policy, even for local recipients. Stalwart 0.16
    # MtaStageMail.isSenderAllowed rejects at MAIL, before relay/local RCPT
    # handling. Preserve its default spam-block check on other listeners.
    operations["MtaStageAuth"]["value"]["mustMatchSender"] = expression("true")
    # Never grant relay authority merely because a session authenticated. Only
    # the internal reinjection and trusted sibling listeners may relay.
    # Local RCPT does not require relay authority.
    operations["MtaStageRcpt"]["value"]["allowRelaying"] = expression(
        "false",
        (f"local_port == 10025 && remote_ip == '{params.gateway_ip}'", "true"),
        (f"listener == 'sibling-in' && remote_ip == '{params.gateway_ip}'", "true"),
        ("listener == 'sibling' && remote_ip == '127.0.0.1'", "true"),
    )
    if params.profile == "private":
        # Keep the trusted sibling hop through its listener-bound milter before
        # LMTP. Only the default remote MX route becomes local in this profile.
        operations["MtaOutboundStrategy"]["value"]["route"] = expression(
            "'local'",
            (f"received_via_port == {site.sibling_port}", "'sibling-loop'"),
            (f"rcpt_domain == '{params.agent_domain}'", "'gateway'"),
        )

    plan.append(
        {
            "@type": "upsert",
            "object": "Certificate",
            "matchOn": ["certificate"],
            "value": {
                "amx-live": {
                    "certificate": {"@type": "File", "filePath": "/tls/server.pem"},
                    "privateKey": {"@type": "File", "filePath": "/tls/server-key.pem"},
                }
            },
        }
    )
    bundle = {"site": asdict(site), "users": users, "masters": masters, "plan": plan}
    write_private(previous, json.dumps(bundle, indent=2) + "\n")
    write_private(
        directory / "config.json", '{"@type":"RocksDb","path":"/var/lib/stalwart/data"}\n'
    )


def household_throttles() -> dict:
    """Finite household bursts, not the dev plan's disabled limits (durations ms)."""
    return {
        "throttle-ip": {
            "description": "Sender IP throttle",
            "enable": True,
            "key": {"remoteIp": True},
            "match": expression("true"),
            "rate": {"count": 30, "period": 1000},
        },
        "throttle-recipient": {
            "description": "Sender address to recipient throttle",
            "enable": True,
            "key": {"sender": True, "rcpt": True},
            "match": expression("true"),
            "rate": {"count": 200, "period": 3600000},
        },
    }


def hardening_checks(params: LiveParams, effective: dict) -> list:
    """Validate management readback, never infer effective defaults from bundle.json."""
    from amx.preflight import Result

    def singleton(name):
        records = effective.get(name, [])
        return records[0] if len(records) == 1 else {}

    oidc = singleton("OidcProvider")
    imap = singleton("Imap")
    throttles = effective.get("MtaInboundThrottle", [])
    throttle_ok = len(throttles) == len(household_throttles()) and all(
        any(
            all(record.get(k) == v for k, v in expected.items() if k != "match")
            and (record.get("match") or {}).get("else") == "true"
            and not (record.get("match") or {}).get("match")
            for record in throttles
        )
        for expected in household_throttles().values()
    )
    allowed = effective.get("AllowedIp", [])

    apps = effective.get("Application", [])
    webui = any(
        app.get("enabled") is True
        and app.get("resourceUrl") == WEBUI_RESOURCE
        and app.get("urlPrefix", {}).get("/admin") is True
        and app.get("urlPrefix", {}).get("/account") is True
        and app.get("unpackDirectory") == "/var/lib/stalwart/webui"
        for app in apps
    )
    webui = webui and singleton("WebUiStatus").get("ready") is True
    listeners = effective.get("NetworkListener", [])
    imaps = any(
        listener.get("protocol") == "imap"
        and listener.get("useTls") is True
        and listener.get("tlsImplicit") is True
        and listener.get("bind", {}).get("[::]:993") is True
        for listener in listeners
    )
    checks = {
        "oidc": oidc.get("requireClientRegistration") is True
        and oidc.get("anonymousClientRegistration") is False,
        "imap": imap.get("allowPlainTextAuth") is False and imaps,
        "throttles": throttle_ok,
        "trusted-gateway": len(allowed) == 1
        and ipaddress.ip_network(allowed[0].get("address", "0.0.0.0/0"))
        == ipaddress.ip_network(params.gateway_ip + "/32"),
        "webui": webui,
    }
    return [
        Result(
            "PASS" if ok else "FAIL",
            "stalwart:" + name,
            "effective hardening present" if ok else "missing or unsafe effective default",
        )
        for name, ok in checks.items()
    ]


def preflight_checks(params: LiveParams) -> list:
    """Read the running datastore and actual Docker publications; errors fail closed."""
    import subprocess

    from amx.config import load_config
    from amx.live import compose, compose_environment
    from amx.preflight import Result

    def run(command, *, timeout=30):
        # Only fixed readback/ps or inspect argv below; no shell or content-selected verbs.
        return (
            subprocess.run(  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
                command,
                env=compose_environment(),
                capture_output=True,
                text=True,
                check=True,
                shell=False,
                timeout=timeout,
            ).stdout
        )

    try:
        effective = json.loads(
            run(
                compose(
                    params,
                    "exec",
                    "-T",
                    "stalwart-sync",
                    "python",
                    "/opt/amx/stalwart.py",
                    "hardening-snapshot",
                    "--admin-file=/secrets/recovery-admin",
                ),
                timeout=SNAPSHOT_TIMEOUT,
            )
        )
        results = hardening_checks(params, effective)
        try:
            read_webui(params.secrets_dir / "stalwart/webui.zip")
            verified_bundle = True
        except (OSError, ValueError):
            verified_bundle = False
        results.append(
            Result(
                "PASS" if verified_bundle else "FAIL",
                "stalwart:webui-bundle",
                "native WebUI file must match the source-pinned digest and ZIP",
            )
        )
        containers = run(compose(params, "ps", "--quiet")).split()
        if not containers or not all(re.fullmatch(r"[0-9a-f]{12,64}", c) for c in containers):
            raise ValueError("no valid running container IDs")
        publications = [
            json.loads(line)
            for line in run(
                ["docker", "inspect", "--format", "{{json .NetworkSettings.Ports}}", *containers]
            ).splitlines()
        ]
        http_ports = set()
        for listener in effective.get("NetworkListener", []):
            if listener.get("protocol") == "http":
                http_ports.update(
                    bind.rsplit(":", 1)[-1] + "/tcp"
                    for bind, enabled in listener.get("bind", {}).items()
                    if enabled
                )
        bindings = [
            binding
            for ports in publications
            for port in http_ports
            for binding in ports.get(port) or []
        ]
        management_unpublished = all(not ports.get("8080/tcp") for ports in publications)
        safe = (
            management_unpublished
            and bool(bindings)
            and all(
                ipaddress.ip_address(binding["HostIp"]).is_loopback
                or ipaddress.ip_address(binding["HostIp"]) in ipaddress.ip_network("100.64.0.0/10")
                for binding in bindings
            )
        )
        results.append(
            Result(
                "PASS" if safe else "FAIL",
                "stalwart:admin-bind",
                "management8080 must be unpublished; HTTP must be loopback or tailnet only",
            )
        )
        config = load_config(params.gateway_config)
        mailbox = config.mailbox
        tls = mailbox.tls and mailbox.port == 993 and mailbox.host == params.mailhost_ip
        tls = tls and mailbox.tls_server_name == params.mx_host
        tls = tls and (
            not (params.tls_mode == "self-signed" or params.tls_ca_file)
            or mailbox.tls_ca_file == "/tls/ca.pem"
        )
        results.append(
            Result(
                "PASS" if tls else "FAIL",
                "stalwart:gateway-imaps",
                "gateway must use verified IMAPS to the mailhost",
            )
        )
        return results
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        # Never forward CLI stderr: a failed management call can include credentials.
        return [Result("FAIL", "stalwart:readback", "cannot read running hardening state")]
