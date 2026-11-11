"""Fresh SH-10 Stalwart fixture, called only inside live-validate's lease.

A separate internal-only network and loopback ports; no external DNS or mail.
This proves the bundle, dynamic registration, TLS, signing, SH-11 people and
approval and SH-12 signed-in owner round trips, not SH-13 sibling routing.
No preexisting live resources are adopted.
"""

from __future__ import annotations

import contextlib
import hashlib
import http.client
import imaplib
import json
import re
import shutil
import signal
import smtplib
import socket
import ssl
import subprocess
import tempfile
import time
import uuid
from dataclasses import replace
from email.message import EmailMessage
from email.parser import BytesParser
from email.policy import default
from pathlib import Path

import dkim
import yaml
from stalwart_probe_fixture import require_lock_custody

from amx import domain_dkim
from amx.adapters.stalwart import (
    BOOTSTRAP_OBJECTS,
    BOOTSTRAP_OPERATIONS,
    BOOTSTRAP_PROPERTIES,
    PREFLIGHT_TIMEOUT,
    SNAPSHOT_TIMEOUT,
    expression,
)
from amx.live import compose, compose_environment, ensure_self_signed, load_params
from amx.mail_client import MailClient, discover, issue_app_password
from amx.mailbox import quote_mailbox
from amx.preflight import _leaf_der
from amx.provision import dkim_public_key
from amx.sdk import Agent
from amx.stalwart_webui import fetch_webui, publish_webui

ROOT = Path(__file__).resolve().parents[1]
PROJECT = "amx-live"
SINK_IP = "172.31.250.60"
PORTS = {
    "smtp": 12525,
    "submission": 12587,
    "imaps": 12993,
    "people_submission": 12465,
    "discovery": 12443,
}
# Process-local authority, established only by the admitted fresh creator below.
# Caller-supplied files and environment markers cannot establish this context.
_active_fixture = None


def require_fixture_state(state: Path):
    require_lock_custody()
    if _active_fixture is None or state != _active_fixture[0] or state.resolve() != state:
        raise RuntimeError("sink control requires the active fresh sealed fixture")
    _, identity, files = _active_fixture
    current = state.stat()
    if (current.st_dev, current.st_ino) != identity:
        raise RuntimeError("active fixture state was replaced")
    for path, contents in files.items():
        if path.resolve() != path or path.read_bytes() != contents:
            raise RuntimeError("active fixture parameters or sealed overrides changed")
    params = load_params(state / "live.yaml")
    if any(
        path.resolve() != path
        for path in (params.state_dir, params.secrets_dir, state / "lane/sink-out")
    ):
        raise RuntimeError("active fixture storage differs")
    return params


class Terminated(BaseException):
    def __init__(self, signum: int):
        self.signum = signum


def terminate(signum: int, _frame: object) -> None:
    raise Terminated(signum)


@contextlib.contextmanager
def admitted_call():
    require_lock_custody()
    handlers = {
        sig: signal.signal(sig, terminate) for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
    }
    try:
        yield
    finally:
        for sig, handler in handlers.items():
            signal.signal(sig, handler)


def inventory() -> list[str]:
    resources = []
    for command in (("ps", "-a"), ("volume", "ls"), ("network", "ls")):
        result = subprocess.run(
            ["docker", *command, "-q", "--filter", f"label=com.docker.compose.project={PROJECT}"],
            check=True,
            capture_output=True,
            text=True,
            timeout=20,
        )
        resources.extend(result.stdout.split())
    return resources


def cli(state: Path, *args: str, timeout: int = 300) -> str:
    env = compose_environment()
    for name in ("TYPESAFE_API_KEY", "AMX_LLM_API_KEY"):
        env.pop(name, None)
    result = subprocess.run(
        [
            "uv",
            "run",
            "--group",
            "gateway",
            "amx",
            "live",
            *args,
            "--params",
            str(state / "live.yaml"),
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode:
        if args[0] == "preflight":
            try:
                for check in json.loads(result.stdout):
                    if re.fullmatch(r"[a-z0-9:-]+", check["check"]) and check["status"] in {
                        "PASS",
                        "FAIL",
                        "SKIP",
                        "WARN",
                        "INFO",
                    }:
                        print(
                            f"DIAG  preflight check={check['check']} status={check['status']}",
                            flush=True,
                        )
            except (ValueError, KeyError, TypeError):
                pass
        raise RuntimeError(f"live {args[0]} failed status={result.returncode}")
    return result.stdout


def wait_for(probe, description: str, timeout: int = 45):
    deadline = time.monotonic() + timeout
    last_error = "probe returned false"
    while time.monotonic() < deadline:
        try:
            result = probe()
            if result:
                return result
        except (OSError, imaplib.IMAP4.error) as error:
            last_error = f"{type(error).__name__}: {error}"
        time.sleep(0.5)
    raise TimeoutError(f"{description}: {last_error}")


def user_cli(state: Path, *args: str) -> str:
    result = subprocess.run(
        [
            "uv",
            "run",
            "--group",
            "gateway",
            "amx",
            "user",
            *args,
            "--params",
            str(state / "live.yaml"),
        ],
        cwd=ROOT,
        env=compose_environment(),
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode:
        raise RuntimeError("fixture user command failed: " + args[0])
    return result.stdout


def native_request(host, port, path, context, *, body=None, headers=None):
    """Fixture-only DNS/port mapping, retaining actual TLS SNI/hostname checks."""
    if host not in {
        "home.arpa",
        "mail.home.arpa",
        "autoconfig.home.arpa",
        "autodiscover.home.arpa",
    }:
        raise ValueError("refuse off-fixture discovery host")
    if port not in {443, PORTS["discovery"]}:
        raise ValueError("refuse off-fixture discovery port")
    from amx.mail_client import https_request

    def connection_factory(host, port, *, context, timeout):
        connection = http.client.HTTPSConnection(host, port, context=context, timeout=timeout)
        connection.sock = context.wrap_socket(
            socket.create_connection(("127.0.0.1", PORTS["discovery"]), timeout=timeout),
            server_hostname=host,
        )
        return connection

    return https_request(
        host,
        port,
        path,
        context,
        body=body,
        headers=headers,
        connection_factory=connection_factory,
    )


def safe_sync_diagnostics(logs: str) -> list[str]:
    """Only fixed diagnostic fields, never arbitrary container lines or credentials."""
    pattern = re.compile(
        r"amx: (?:people stage=query status=ok records=\d+ desired=\d+"
        r"|people stage=apply status=ok desired=\d+"
        r"|people stage=apply status=error "
        r"code=(?:unknown|forbidden|overQuota|tooLarge|rateLimit|notFound|invalidPatch|"
        r"invalidProperties|alreadyExists|invalidForeignKey|primaryKeyViolation|validationFailed) "
        r"property=(?:unknown|credentialId|credentials|secret|name|domainId|description|"
        r"permissions|enabledPermissions|disabledPermissions|authenticate|impersonate)"
        r"|accounts sync failed stage=(?:snapshot|apply) type=[A-Za-z]+ "
        r"status=(?:n/a|-?\d+); retrying)$"
    )
    return [match[0] for line in logs.splitlines() if (match := pattern.search(line))][-10:]


def safe_bootstrap_diagnostics(logs: str) -> list[str]:
    pattern = re.compile(
        r"amx: bootstrap (?:stage=(?:settings|accounts)-(?:ready|apply) "
        r"status=(?:ok|http401|management-error)"
        r"|operation=(?:" + "|".join(map(re.escape, BOOTSTRAP_OPERATIONS)) + r") "
        r"object=(?:" + "|".join(map(re.escape, BOOTSTRAP_OBJECTS)) + r") "
        r"index=(?:[0-9]|[1-9][0-9]|1[01][0-9]|12[0-7]) status=error "
        r"code=(?:unknown|forbidden|overQuota|tooLarge|rateLimit|notFound|invalidPatch|"
        r"invalidProperties|alreadyExists|invalidForeignKey|primaryKeyViolation|validationFailed) "
        r"property=(?:" + "|".join(map(re.escape, BOOTSTRAP_PROPERTIES)) + r"))$"
    )
    return [match[0] for line in logs.splitlines() if (match := pattern.search(line))]


class FixtureIMAP(imaplib.IMAP4_SSL):
    def _create_socket(self, timeout):
        if self.host != "mail.home.arpa" or self.port != 993:
            raise ValueError("refuse unexpected discovered IMAP endpoint")
        return self.ssl_context.wrap_socket(
            socket.create_connection(("127.0.0.1", PORTS["imaps"]), timeout),
            server_hostname=self.host,
        )


class FixtureSMTP(smtplib.SMTP_SSL):
    def _get_socket(self, host, port, timeout):
        if host != "mail.home.arpa" or port != 465:
            raise ValueError("refuse unexpected discovered submission endpoint")
        return self.context.wrap_socket(
            socket.create_connection(("127.0.0.1", PORTS["people_submission"]), timeout),
            server_hostname=host,
        )


def native_agent_submission_refused(agent, owner, context):
    """Try real agent credentials and local RCPT; return IDs to check over IMAP."""
    message_ids = []
    # Also try a person envelope sender: the guard must key on authenticated_as.
    for sender in (agent["address"], owner):
        message = EmailMessage()
        message["From"] = sender
        message["To"] = owner
        message["Subject"] = "SH-11 forbidden native agent submission"
        message["Message-ID"] = f"<{uuid.uuid4().hex}@home.arpa>"
        message.set_content("Synthetic bypass attempt; must never be delivered.\n")
        message_ids.append(str(message["Message-ID"]))
        with FixtureSMTP("mail.home.arpa", 465, context=context, timeout=10) as smtp:
            smtp.ehlo()
            try:
                smtp.login(agent["address"], agent["password"])
            except smtplib.SMTPAuthenticationError as error:
                assert error.smtp_code == 535, "unexpected native authentication failure"
                continue
            try:
                smtp.send_message(message)
            except smtplib.SMTPSenderRefused as error:
                assert error.smtp_code == 550, "expected native MAIL policy refusal"
            else:
                raise AssertionError("enabled agent bypassed gateway via native submission")
    return message_ids


def write_fixture(state: Path, *, agent_hosts: bool = False) -> None:
    global _active_fixture
    require_lock_custody()
    if (
        _active_fixture is not None
        or state.resolve() != state
        or inventory()
        or (state / "live.yaml").exists()
        or (state / "sealed.json").exists()
        or (state / "lane").exists()
    ):
        raise RuntimeError("fixture creator requires fresh state and an empty project")
    # Override is validation-only. Internal networking prevents even a routing
    # regression from sending outside the fixture. No public resolver is used.
    overlay = state / "sealed.json"
    overlay.write_text(
        json.dumps(
            {
                "services": {"mailhost": {"dns": ["127.0.0.1"]}, "gateway": {"dns": ["127.0.0.1"]}},
                "networks": {"live": {"internal": True}},
            }
        )
    )
    raw = {
        "mta": "stalwart",
        "profile": "private",
        "compose_project": PROJECT,
        "stalwart": {"webui_bundle": str(state / "webui.zip")},
        "state_dir": str(state / "lane"),
        "network": {"bind_address": "127.0.0.1", "subnet": "172.31.250.0/24", "ports": PORTS},
        "tls": {"mode": "self-signed", "extra_names": ["localhost", "127.0.0.1"]},
        "compose_overrides": [
            str(ROOT / "deploy/live/validate/compose.stalwart.yaml"),
            str(overlay),
        ],
    }
    if agent_hosts:
        raw["compose_overrides"].append(str(ROOT / "deploy/live/validate/compose.selfhost.yaml"))
        raw["tls"]["extra_names"].append("gateway.home.arpa")
    (state / "live.yaml").write_text(yaml.safe_dump(raw))
    (state / "lane/sink-out").mkdir(parents=True)
    identity = state.stat()
    _active_fixture = (
        state,
        (identity.st_dev, identity.st_ino),
        {
            path: path.read_bytes()
            for path in (state / "live.yaml", overlay, *map(Path, raw["compose_overrides"]))
        },
    )


def foreign_submission_refused(agent, owner, password, context, sdk):
    """Require successful AUTH, then refusal on each supported submission path."""
    with FixtureSMTP("mail.home.arpa", 465, context=context, timeout=10) as smtp:
        smtp.ehlo()
        smtp.login(owner, password)
        assert smtp.mail(owner)[0] == 250
        assert smtp.rcpt("x@example.com")[0] == 550, "person relayed foreign RCPT"
    try:
        sdk.send(
            to="x@example.com",
            subject="SH-20 forbidden outbound",
            intent="request",
            text="Synthetic private fixture; must never leave.",
        )
    except smtplib.SMTPDataError as error:
        assert error.smtp_code == 550
    else:
        raise AssertionError("authenticated agent submitted foreign mail")


def sink_snapshot(state):
    require_fixture_state(state)
    return {path.name: path.read_bytes() for path in (state / "lane/sink-out").iterdir()}


def check_sink_snapshot(state, baseline):
    assert sink_snapshot(state) == baseline, "private mail reached foreign sink"


def fixture_smtp(state, *, probe=None, routed=False):
    """Fixed internal endpoints only; no host SMTP, external DNS or credential output."""
    params = require_fixture_state(state)
    host, port = (params.mailhost_ip, 10025) if routed else (SINK_IP, 25)
    script = (
        "import smtplib,sys; "
        f"smtp=smtplib.SMTP({host!r},{port},timeout=5); "
        "assert smtp.ehlo()[0]==250; "
        + (
            "assert not smtp.sendmail('postmaster@home.arpa', "
            "['x@example.com'],sys.stdin.buffer.read()); "
            if probe is not None
            else "assert smtp.noop()[0]==250; "
        )
        + "smtp.quit()"
    )
    # Admitted sealed fixture, fixed executable/endpoints; synthetic bytes on stdin.
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
    result = subprocess.run(
        compose(params, "exec", "-T", "gateway", "/app/.venv/bin/python", "-c", script),
        input=probe,
        capture_output=True,
        env=compose_environment(),
        timeout=20,
        shell=False,
    )
    if result.returncode:
        raise RuntimeError("fixture route probe failed" if routed else "private sink unreachable")


def assert_sink_unchanged(state, baseline):
    fixture_smtp(state)
    check_sink_snapshot(state, baseline)


def wait_fixture_smtp(state, *, routed=False):
    def ready():
        try:
            fixture_smtp(state, routed=routed)
        except RuntimeError:
            return False
        return True

    wait_for(ready, "fixture SMTP ready")


def sink_probe_paths(state, message_id):
    return [
        state / "lane/sink-out" / name
        for name, raw in sink_snapshot(state).items()
        if str(BytesParser(policy=default).parsebytes(raw)["Message-ID"]) == message_id
    ]


def remove_sink_probe(state, message_id):
    paths = sink_probe_paths(state, message_id)
    assert len(paths) == 1, "expected exactly one accepted sink probe"
    paths[0].unlink()
    assert not sink_probe_paths(state, message_id), "sink probe cleanup failed"


def apply_fixture_operations(state, operations):
    params = require_fixture_state(state)
    script = (
        "import pathlib,subprocess,sys; "
        "user,password=pathlib.Path('/secrets/recovery-admin').read_text().strip().split(':',1); "
        "env={'PATH':'/usr/local/bin:/usr/bin:/bin','HOME':'/tmp', "
        "'STALWART_URL':'http://mailhost:8080','STALWART_USER':user,'STALWART_PASSWORD':password}; "
        "r=subprocess.run(['/usr/local/bin/stalwart-cli','--no-color',"
        "'apply','--stdin','--quiet'], "
        "input=sys.stdin.read(),env=env,capture_output=True,text=True,timeout=60); "
        "sys.exit(r.returncode)"
    )
    # Fixed management command; only source-owned fixture operations travel on stdin.
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
    result = subprocess.run(
        compose(params, "exec", "-T", "stalwart-sync", "python", "-c", script),
        input="".join(json.dumps(op) + "\n" for op in operations),
        env=compose_environment(),
        capture_output=True,
        text=True,
        timeout=90,
        shell=False,
    )
    if result.returncode:
        raise RuntimeError("fixture sink route mutation failed")


@contextlib.contextmanager
def sink_route_control(state):
    """Temporary exact-domain route, never change production rendering or RCPT policy."""
    params = require_fixture_state(state)
    plan = json.loads((params.secrets_dir / "stalwart/bundle.json").read_text())["plan"]
    original = next(op for op in plan if op["object"] == "MtaOutboundStrategy")
    route = {
        "@type": "upsert",
        "object": "MtaRoute",
        "matchOn": ["name"],
        "value": {
            "route-private-sink": {
                "@type": "Relay",
                "name": "private-sink",
                "address": SINK_IP,
                "port": 25,
                "protocol": "smtp",
                "implicitTls": False,
            }
        },
    }
    strategy = json.loads(json.dumps(original))
    strategy["value"]["route"] = expression(
        "'local'",
        ("rcpt_domain == 'example.com'", "'private-sink'"),
        ("rcpt_domain == 'agents.home.arpa'", "'gateway'"),
    )
    try:
        apply_fixture_operations(state, [route, strategy])
        # Native routing is loaded on startup; never assume an API write is live.
        require_fixture_state(state)
        cli(state, "compose", "restart", "mailhost")
        wait_fixture_smtp(state, routed=True)
        yield
    finally:
        apply_fixture_operations(state, [original])
        require_fixture_state(state)
        cli(state, "compose", "restart", "mailhost")
        wait_fixture_smtp(state, routed=True)


def sink_controls(state, record):
    """Negative reachability and real DATA/route controls all precede the baseline."""
    require_fixture_state(state)
    cli(state, "compose", "stop", "sink")
    try:
        try:
            fixture_smtp(state)
        except RuntimeError as error:
            assert str(error) == "private sink unreachable"
        else:
            raise AssertionError("stopped private sink reported reachable")
    finally:
        require_fixture_state(state)
        cli(state, "compose", "start", "sink")

    wait_fixture_smtp(state)
    record("SH-20: stopped sink fails explicitly; restarted sink accepts SMTP")
    before = sink_snapshot(state)
    for routed in (False, True):
        message = EmailMessage()
        message["From"] = "postmaster@home.arpa"
        message["To"] = "x@example.com"
        message["Message-ID"] = f"<{uuid.uuid4().hex}@home.arpa>"
        message.set_content("Synthetic sealed sink control only.\n")
        message_id = str(message["Message-ID"])
        if routed:
            with sink_route_control(state):
                fixture_smtp(state, probe=message.as_bytes(), routed=True)
                wait_for(lambda mid=message_id: sink_probe_paths(state, mid), "route escape")
        else:
            fixture_smtp(state, probe=message.as_bytes())
            wait_for(lambda mid=message_id: sink_probe_paths(state, mid), "accepted sink probe")
        try:
            assert_sink_unchanged(state, before)
        except AssertionError as error:
            assert str(error) == "private mail reached foreign sink"
        else:
            raise AssertionError("sink canary missed intentional fixture escape")
        remove_sink_probe(state, message_id)
        assert_sink_unchanged(state, before)
    record(
        "SH-20: accepted probe and native sealed route escape detected; "
        "probes removed before baseline"
    )


def stage_webui(state: Path) -> None:
    """Fetch the genuine UI before sealed runtime; exercise native file:// loading.

    Build/image downloads already require host egress. The running mail network
    cannot fetch anything, so it uses the supported no-egress staged-file path.
    """
    require_lock_custody()
    publish_webui(state / "webui.zip", fetch_webui())


def bootstrap_diagnostics(state: Path) -> None:
    require_lock_custody()
    params = load_params(state / "live.yaml")
    # Admitted fixture; fixed logs executable/operation/options, no content-derived argv.
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
    bootstrap = subprocess.run(
        compose(params, "logs", "--no-color", "stalwart-init"),
        capture_output=True,
        text=True,
        env=compose_environment(),
        timeout=30,
        check=True,
        shell=False,
    )
    for diagnostic in safe_bootstrap_diagnostics(bootstrap.stdout):
        print("DIAG  " + diagnostic, flush=True)


def functional_checks(state: Path, record) -> None:
    with admitted_call():
        _functional_checks(state, record)


def negative_hardening_checks(state: Path, record, *, repair_via_up: bool = False) -> None:
    """Mutate only this admitted sealed fixture; prove management drift is refused."""
    require_lock_custody()
    params = load_params(state / "live.yaml")
    bundle = json.loads((params.secrets_dir / "stalwart/bundle.json").read_text())
    operations = {op["object"]: op for op in bundle["plan"]}
    script = (
        "import os, pathlib, subprocess, sys; "
        "user, password = pathlib.Path('/secrets/recovery-admin')"
        ".read_text().strip().split(':', 1); "
        "env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/tmp', "
        "'STALWART_URL': 'http://mailhost:8080', 'STALWART_USER': user, "
        "'STALWART_PASSWORD': password}; "
        "result = subprocess.run(['/usr/local/bin/stalwart-cli', '--no-color', 'apply', "
        "'--stdin', '--quiet'], input=sys.stdin.read(), env=env, capture_output=True, "
        "text=True, timeout=60); sys.exit(result.returncode)"
    )

    def apply(operation):
        # Fixed Python script/CLI apply argv; source-selected operations travel on stdin.
        # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
        result = subprocess.run(
            compose(params, "exec", "-T", "stalwart-sync", "python", "-c", script),
            input=json.dumps(operation) + "\n",
            env=compose_environment(),
            capture_output=True,
            text=True,
            timeout=90,
            shell=False,
        )
        if result.returncode:
            raise RuntimeError("fixture hardening mutation failed")

    mutations = {
        "OidcProvider": ("oidc", {"requireClientRegistration": False}),
        "Imap": ("imap", {"allowPlainTextAuth": True}),
        "MtaInboundThrottle": ("throttles", {}),
        "AllowedIp": ("trusted-gateway", {}),
        "Application": ("webui", {}),
    }
    if repair_via_up:
        mutations = {"Imap": mutations["Imap"]}
    for name, (check, value) in mutations.items():
        original = operations[name]
        mutated = json.loads(json.dumps(original))
        if name in {"OidcProvider", "Imap"}:
            mutated["value"] = value
        elif name == "AllowedIp":
            mutated["value"] = {}
        else:
            for item in mutated["value"].values():
                item["enabled" if name == "Application" else "enable"] = False
        try:
            apply(mutated)
            result = subprocess.run(
                [
                    "uv",
                    "run",
                    "--group",
                    "gateway",
                    "amx",
                    "live",
                    "preflight",
                    "--params",
                    str(state / "live.yaml"),
                    "--json",
                ],
                cwd=ROOT,
                env=compose_environment(),
                capture_output=True,
                text=True,
                timeout=PREFLIGHT_TIMEOUT,
            )
            checks = json.loads(result.stdout)
            assert result.returncode != 0 and any(
                row["check"] == "stalwart:" + check and row["status"] == "FAIL" for row in checks
            ), "preflight accepted mutated effective hardening"
            record("SH-10b: preflight refuses mutated effective " + check)
            if repair_via_up:
                cli(state, "install")
                cli(state, "up", timeout=600)
                repaired = json.loads(cli(state, "preflight", "--json", timeout=PREFLIGHT_TIMEOUT))
                assert not any(row["status"] == "FAIL" for row in repaired)
                assert any(
                    row["check"] == "stalwart:imap" and row["status"] == "PASS" for row in repaired
                )
                record("SH-10b: canonical reinstall/up reapplies drifted effective IMAP settings")
        finally:
            if not repair_via_up:
                apply(original)


def _functional_checks(state: Path, record) -> None:
    require_lock_custody()
    params = load_params(state / "live.yaml")
    credentials = yaml.safe_load(params.credentials_path.read_text())
    bundle = params.bundles_dir / "intake.json"
    cli(state, "agent", "add", "intake", "--bundle", str(bundle))
    agent = json.loads(bundle.read_text())
    context = ssl.create_default_context(cafile=str(params.tls_dir / "ca.pem"))

    def imap(user, password):
        client = imaplib.IMAP4_SSL("localhost", PORTS["imaps"], ssl_context=context, timeout=10)
        try:
            client.login(user, password)
        except BaseException:
            client.shutdown()
            raise
        return client

    def registered():
        with imap(agent["address"], agent["password"]):
            return True

    wait_for(registered, "dynamic registration login")
    record("registration: new agent logs in over verified IMAPS without restart")
    owner = "alice@home.arpa"
    owner_primary, owner_app = state / "alice-primary", state / "alice-app"
    user_cli(state, "add", "alice", "--owner", "--password-out", str(owner_primary))
    # Logical origins stay canonical; native_request alone maps them to loopback.
    # Stalwart advertises https://<defaultHostname>, not the published port.
    native_params = replace(params, ports={**params.ports, "discovery": 443})
    issue_app_password(
        native_params, owner, owner_primary.read_text().strip(), owner_app, request=native_request
    )
    owner_password = owner_app.read_text().strip()
    settings = discover(params.mx_host, owner, context, request=native_request)
    person = MailClient(
        settings, owner_password, context, imap_factory=FixtureIMAP, smtp_ssl_factory=FixtureSMTP
    )
    with person.imap() as client:
        assert client.select("INBOX")[0] == "OK"
    user_cli(state, "profile", "alice", "--output", str(state / "alice.mobileconfig"))
    record("SH-11: owner uses native app password, native autoconfig and verified hostname TLS")
    # A new registration must retain the owner's app credential and grant the new tree.
    cli(state, "agent", "add", "future", "--bundle", str(params.bundles_dir / "future.json"))

    def future_shared():
        with person.imap() as client:
            return (
                client.select(quote_mailbox("Shared Folders/holds@home.arpa/Holds/future/Held"))[0]
                == "OK"
            )

    wait_for(future_shared, "owner's future agent ACL")
    record("SH-11: existing owner's app password survives sync and future agent hold ACLs appear")
    # Admitted fixture, fixed snapshot operation and source-owned field allowlists.
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
    snapshot = subprocess.run(
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
        capture_output=True,
        text=True,
        env=compose_environment(),
        timeout=SNAPSHOT_TIMEOUT,
        check=True,
        shell=False,
    )
    (state / "hardening.json").write_text(snapshot.stdout)
    preflight = json.loads(cli(state, "preflight", "--probe", "local", "--json"))
    required = {"tls:file", "tls:submission", "tls:imaps"}
    passed = {r["check"] for r in preflight if r["status"] == "PASS"}
    if any(r["status"] == "FAIL" for r in preflight) or not required <= passed:
        raise AssertionError(f"preflight failed: {preflight}")
    record("preflight: all required live TLS checks PASS, no public DNS/MX probe")
    with smtplib.SMTP("localhost", PORTS["submission"], timeout=10) as smtp:
        smtp.ehlo()
        if smtp.has_extn("auth"):
            raise AssertionError("AUTH before TLS")
        smtp.starttls(context=context)
        smtp.ehlo()
        try:
            smtp.login("intake", "incorrect-token")
        except smtplib.SMTPAuthenticationError as error:
            assert error.smtp_code == 535
        else:
            raise AssertionError("incorrect token accepted")
    record("submission: verified STARTTLS required; incorrect token refused")
    sdk = Agent(
        agent["address"],
        f"smtp://localhost:{PORTS['submission']}",
        agent["token"],
        tls_ca_file=str(params.tls_dir / "ca.pem"),
    )
    sink_controls(state, record)
    sink_before = sink_snapshot(state)
    foreign_submission_refused(agent, owner, owner_password, context, sdk)
    record("SH-20: authenticated person RCPT and agent submission refuse x@example.com")
    sent = sdk.send(
        to=owner,
        subject="SH-10 sealed fixture",
        intent="request",
        text="Fixture invoice for USD 1.00; no real payment or internet recipient.",
        schema="https://evtmail.ai/schema/0.1/payment-request.json",
        payload={
            "@context": "https://schema.org",
            "@type": "Invoice",
            "price": "1.00",
            "priceCurrency": "USD",
            "amx:payee": "synthetic fixture",
        },
    )
    # SH-12 makes the people domain known. Approval must still be proven with
    # a real policy hold, not by turning first-contact back on for the owner.
    assert sent.held == "commits-money", sent.held
    held = "Shared Folders/holds@home.arpa/Holds/intake/Held"
    approved = "Shared Folders/holds@home.arpa/Holds/intake/Approved"

    def find(user, password, folder, message_id=sent.message_id):
        with imap(user, password) as client:
            status, _ = client.select(quote_mailbox(folder), readonly=True)
            if status != "OK":
                raise AssertionError(f"cannot select fixture folder {folder}")
            # As in S06c: Stalwart's SEARCH HEADER Message-ID returns no
            # match. Fetch exact headers instead; never accept an arbitrary UID.
            status, data = client.uid("SEARCH", None, "ALL")
            assert status == "OK"
            for uid in (data[0] or b"").split():
                status, fetched = client.uid(
                    "FETCH", uid, "(BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])"
                )
                assert status == "OK"
                raw = next((item[1] for item in fetched if isinstance(item, tuple)), b"")
                if str(BytesParser(policy=default).parsebytes(raw)["Message-ID"]) == message_id:
                    return uid
            return None

    uid = wait_for(lambda: find(owner, owner_password, held), "owner hold queue")
    forbidden_ids = native_agent_submission_refused(agent, owner, context)
    with imap(agent["address"], agent["password"]) as client:
        client.select(quote_mailbox(held))
        status, _ = client.uid("MOVE", uid, quote_mailbox(approved))
        assert status == "NO", "agent approved its own hold"
    record("hold: agent cannot approve its own shared hold")
    person.approve(held, approved, uid)

    delivered = wait_for(
        lambda: find(owner, owner_password, "INBOX"),
        "approved delivery to local postmaster",
        timeout=60,
    )
    with person.imap() as client:
        client.select("INBOX", readonly=True)
        _, fetched = client.uid("FETCH", delivered, "(BODY.PEEK[])")
        raw = fetched[0][1]
    selector = domain_dkim.signature_selector(raw)  # SH-44: the domain's one key
    assert selector is not None and domain_dkim.is_domain_selector(selector), selector
    public = dkim_public_key(params.keys_dir / f"{selector}.private.pem")
    assert dkim.verify(raw, dnsfunc=lambda *_a, **_kw: f"v=DKIM1; k=rsa; p={public}".encode())
    assert len(BytesParser(policy=default).parsebytes(raw).get_all("DKIM-Signature", [])) == 1
    record(
        "SH-11: owner MOVE releases real gateway hold; signed delivery read over discovered IMAPS"
    )
    person_message = EmailMessage()
    person_message["From"] = owner
    person_message["To"] = "postmaster@home.arpa"
    person_message["Subject"] = "SH-11 sealed person submission"
    person_message["Message-ID"] = f"<{uuid.uuid4().hex}@home.arpa>"
    person_message.set_content("Synthetic local account mail only.\n")
    person.send(person_message)
    wait_for(
        lambda: find(
            "postmaster@home.arpa",
            credentials["postmaster"],
            "INBOX",
            str(person_message["Message-ID"]),
        ),
        "person authenticated send",
    )
    record("SH-11: native-discovered TLS submission with app password delivers to local person")
    opener = EmailMessage()
    opener["From"] = owner
    opener["To"] = agent["address"]
    opener["Subject"] = "S23 signed-in person opens an agent task"
    opener["Message-ID"] = f"<{uuid.uuid4().hex}@home.arpa>"
    opener.set_content("Could you help with this ordinary human request?\n")
    person.send(opener)
    incoming_uid = wait_for(
        lambda: find(agent["address"], agent["password"], "INBOX", str(opener["Message-ID"])),
        "S23 authenticated owner delivery",
    )
    with imap(agent["address"], agent["password"]) as client:
        client.select("INBOX", readonly=True)
        _, fetched = client.uid("FETCH", incoming_uid, "(BODY.PEEK[])")
        incoming_raw = fetched[0][1]
    incoming = BytesParser(policy=default).parsebytes(incoming_raw)
    assert incoming["Agent-Lane"] == "human"
    assert incoming["Agent-Trust"] == "high"
    assert incoming["Agent-Grant-Role"] == "owner"
    assert incoming["Agent-Grant-Can-Open-Tasks"] == "true"
    received = sdk.parse(incoming_raw)
    assert received.task == incoming["Agent-Task-Assigned"] and received.task
    answer = received.reply(text="Synthetic agent answer to signed-in owner.")
    assert answer.held is None, "local owner reply must not trigger first-contact hold"
    answer_uid = wait_for(
        lambda: find(owner, owner_password, "INBOX", answer.message_id), "S23 owner answer"
    )
    with person.imap() as client:
        client.select("INBOX", readonly=True)
        _, fetched = client.uid("FETCH", answer_uid, "(BODY.PEEK[])")
        answer_headers = BytesParser(policy=default).parsebytes(fetched[0][1])
    assert answer_headers["In-Reply-To"] == opener["Message-ID"]
    assert str(opener["Message-ID"]) in str(answer_headers["References"]).split()
    assert answer_headers["Agent-Task"] == received.task
    record(
        "S23: signed-in owner opens task over native submission; same-thread agent answer on IMAPS"
    )
    # Same admitted fixture, not another fresh-install attempt. Deliberately drift
    # effective IMAP settings through the management API, then canonical install/up.
    # Keep owner/app credentials and existing mail to verify RocksDB data survives.
    negative_hardening_checks(state, record, repair_via_up=True)
    retained_uid = find(owner, owner_password, "INBOX")
    assert retained_uid is not None
    with person.imap() as client:
        client.select("INBOX", readonly=True)
        _, retained = client.uid("FETCH", retained_uid, "(BODY.PEEK[])")
        assert retained[0][1] == raw, "reinstall changed existing mailbox content"
    assert (
        find(
            "postmaster@home.arpa",
            credentials["postmaster"],
            "INBOX",
            str(person_message["Message-ID"]),
        )
        is not None
    )
    with person.imap() as client:
        assert client.select("INBOX")[0] == "OK"
    record("SH-10b: reinstall/up repairs drift; owner app credential and existing mail survive")
    # Check after successful positive deliveries and over a bounded quiet window;
    # local recipients do not need relay permission, so relay denial is no proof.
    deadline = time.monotonic() + 5
    while True:
        for message_id in forbidden_ids:
            assert find(owner, owner_password, "INBOX", message_id) is None, (
                "native agent bypass delivered to local person"
            )
        if time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    record("SH-11: enabled agent mailbox credential refused on native465; no local delivery")
    message = EmailMessage()
    message["From"] = "postmaster@home.arpa"
    message["To"] = agent["address"]
    message["Subject"] = "SH-10 local inbound fixture"
    message["Message-ID"] = f"<{uuid.uuid4().hex}@home.arpa>"
    message.set_content("Synthetic local mail through the milter and gateway LMTP.\n")
    # Private profile publishes no port 25. Exercise internal SMTP through the
    # admitted gateway container, never add a host-facing SMTP escape hatch.
    script = (
        "import smtplib,sys; "
        "smtp=smtplib.SMTP('mailhost',25,timeout=10); "
        "assert not smtp.sendmail('postmaster@home.arpa', "
        "['intake@agents.home.arpa'],sys.stdin.buffer.read()); smtp.quit()"
    )
    # Trusted fixture params only select Compose paths/project; executable, exec verb,
    # container, Python and script are fixed argv. Mail bytes are stdin, never code.
    subprocess.run(  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
        compose(params, "exec", "-T", "gateway", "/app/.venv/bin/python", "-c", script),
        input=message.as_bytes(),
        env=compose_environment(),
        shell=False,
        check=True,
        timeout=30,
        capture_output=True,
    )
    wait_for(
        lambda: find(agent["address"], agent["password"], "INBOX", str(message["Message-ID"])),
        "inbound milter/LMTP delivery",
    )
    record("inbound: local fixture traverses Stalwart milter and gateway LMTP to agent IMAPS")
    for _ in range(10):
        assert_sink_unchanged(state, sink_before)
        time.sleep(0.5)
    record("SH-20: sink unchanged after refused foreign submissions and positive local deliveries")
    cli(state, "agent", "remove", "intake")

    def revoked():
        try:
            with imap(agent["address"], agent["password"]):
                return False
        except imaplib.IMAP4.error:
            return True

    wait_for(revoked, "revoked login")
    record("sync: removed agent login refused without restarting mailhost")
    user_cli(state, "passwd", "alice", "--password-out", str(state / "alice-rotated"))

    def owner_revoked():
        try:
            with person.imap():
                return False
        except imaplib.IMAP4.error:
            return True

    wait_for(owner_revoked, "old owner app password revoked after rotation")
    user_cli(state, "remove", "alice")
    cli(state, "agent", "remove", "future")
    record("SH-11: password rotation revokes old app password; owner removal queued")
    negative_hardening_checks(state, record)
    certificate_renewal_checks(state, record)


def certificate_renewal_checks(state: Path, record) -> None:
    """SH-22: genuine file replacement and native fingerprints, with stable PIDs.

    Called only on the existing admitted fresh fixture, after account/hold checks.
    Initial self-signed mode remains exercised; renewal uses files mode and its CLI.
    """
    require_lock_custody()
    params = load_params(state / "live.yaml")
    context = ssl.create_default_context(cafile=str(params.tls_dir / "ca.pem"))

    def processes():
        ids = subprocess.run(
            compose(params, "ps", "--quiet", "mailhost", "gateway"),
            env=compose_environment(),
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        ).stdout.split()
        assert len(ids) == 2 and all(re.fullmatch(r"[0-9a-f]{12,64}", c) for c in ids)
        rows = json.loads(
            subprocess.run(
                ["docker", "inspect", *ids],
                env=compose_environment(),
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            ).stdout
        )
        assert all(row["State"]["Running"] and row["State"]["Pid"] > 0 for row in rows)
        return {
            row["Id"]: (row["State"]["Pid"], row["State"]["StartedAt"], row["RestartCount"])
            for row in rows
        }

    def fingerprints():
        found = {}
        for name in ("imaps", "people_submission"):
            with context.wrap_socket(
                socket.create_connection(("127.0.0.1", PORTS[name]), timeout=10),
                server_hostname=params.mx_host,
            ) as client:
                found[name] = hashlib.sha256(client.getpeercert(binary_form=True)).hexdigest()
        with smtplib.SMTP("localhost", PORTS["submission"], timeout=10) as client:
            client._host = params.mx_host
            client.starttls(context=context)
            found["submission"] = hashlib.sha256(
                client.sock.getpeercert(binary_form=True)
            ).hexdigest()
        return found

    before_processes, before = processes(), fingerprints()
    original = hashlib.sha256(_leaf_der(params.tls_dir / "server.pem")).hexdigest()
    assert set(before.values()) == {original}
    source = replace(params, state_dir=state / "renewal-source")
    shutil.copytree(params.secrets_dir / "ca", source.secrets_dir / "ca")
    source.tls_dir.mkdir(parents=True)
    shutil.copyfile(params.tls_dir / "ca.pem", source.tls_dir / "ca.pem")
    ensure_self_signed(source, force=True)
    raw = yaml.safe_load(params.path.read_text())
    raw["tls"] = {
        "mode": "files",
        "certificate": str(source.tls_dir / "server.pem"),
        "private_key": str(source.tls_dir / "server-key.pem"),
        "ca_file": str(source.tls_dir / "ca.pem"),
    }
    params.path.write_text(yaml.safe_dump(raw))
    expected = hashlib.sha256(_leaf_der(source.tls_dir / "server.pem")).hexdigest()
    assert expected != original
    # Merely replacing operator inputs must not magically reload either daemon.
    assert fingerprints() == before
    cli(state, "certs")
    after = fingerprints()
    assert set(after.values()) == {expected}, "native listener did not serve renewed certificate"
    assert processes() == before_processes, "TLS renewal restarted a process/container"
    cli(state, "certs")  # unchanged files still retry/acknowledge both reloads
    assert fingerprints() == after and processes() == before_processes
    (state / "tls-renewal.json").write_text(
        json.dumps(
            {
                "before": before,
                "after": after,
                "processes": before_processes,
                "expected": expected,
                "stable_processes": True,
            },
            indent=2,
        )
        + "\n"
    )
    record("SH-22: files hook rotates Stalwart993/465 and gateway2587 fingerprints; PIDs unchanged")
    files_people_app_password_checks(state, record)


def files_people_app_password_checks(state: Path, record) -> None:
    """Issue and use genuine people credentials after switching to files/private CA."""
    require_lock_custody()
    params = load_params(state / "live.yaml")
    assert params.tls_mode == "files" and params.tls_ca_file
    native_params = replace(params, ports={**params.ports, "discovery": 443})
    context = ssl.create_default_context(cafile=str(params.tls_dir / "ca.pem"))
    address = "renewal-person@" + params.org_domain
    for action in ("add", "passwd"):
        primary, app = state / f"renewal-{action}-primary", state / f"renewal-{action}-app"
        user_cli(state, action, "renewal-person", "--password-out", str(primary))
        # The fixture maps only the logical HTTPS origin, not SSLContext selection.
        issue_app_password(
            native_params, address, primary.read_text().strip(), app, request=native_request
        )
        password = app.read_text().strip()
        settings = discover(params.mx_host, address, context, request=native_request)
        person = MailClient(
            settings, password, context, imap_factory=FixtureIMAP, smtp_ssl_factory=FixtureSMTP
        )
        with person.imap() as client:
            assert client.select("INBOX")[0] == "OK"
        with FixtureSMTP(params.mx_host, settings.smtp_port, context=context, timeout=10) as smtp:
            smtp.ehlo()
            smtp.login(address, password)
        record(
            f"SH-22: files/private CA people {action} issues app password usable over IMAPS/SMTPS"
        )
    user_cli(state, "remove", "renewal-person")


def validate_stalwart(args) -> int:
    global _active_fixture
    try:
        with admitted_call():
            return _validate_stalwart(args)
    except Terminated as error:
        return 128 + error.signum
    finally:
        _active_fixture = None


def _validate_stalwart(args) -> int:
    if inventory():
        print(
            "REFUSE: amx-live already has resources; no adoption or cleanup attempted", flush=True
        )
        return 2
    state = (args.state or Path(tempfile.mkdtemp(prefix="amx-stalwart-validate-"))).resolve()
    state.mkdir(parents=True, exist_ok=True)
    if (state / "live.yaml").exists() or (state / "lane").exists():
        print("REFUSE: validation state is not fresh", flush=True)
        return 2
    write_fixture(state)
    results = []

    def record(check):
        results.append({"passed": True, "check": check})
        print("PASS  " + check, flush=True)

    try:
        stage_webui(state)
        cli(state, "install")
        record("fresh install: parameter-generated Stalwart state")
        cli(state, "up", timeout=600)
        record("fresh up: pinned Stalwart/init/sync/gateway running")
        bootstrap_diagnostics(state)
        functional_checks(state, record)
    except Exception as error:
        results.append({"passed": False, "check": str(error)})
        print(f"FAIL  {type(error).__name__}: {error}", flush=True)
        params = load_params(state / "live.yaml")
        # Fixed docker compose logs argv; fixture-generated validated paths are separate
        # tokens, never shell text, and no mail content supplies command arguments.
        logs = subprocess.run(  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit  # noqa: E501
            compose(params, "logs", "--no-color", "--tail", "100"),
            capture_output=True,
            text=True,
            env=compose_environment(),
            timeout=30,
            shell=False,
        )
        for diagnostic in [
            *safe_bootstrap_diagnostics(logs.stdout),
            *safe_sync_diagnostics(logs.stdout),
        ]:
            print("DIAG  " + diagnostic, flush=True)
    finally:
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(sig, signal.SIG_IGN)
        if not args.keep:
            cli(state, "down", timeout=60)
            if inventory():
                raise RuntimeError("validation cleanup left amx-live resources")
        (state / "validation.json").write_text(json.dumps(results, indent=2) + "\n")
        print(f"Stalwart validation state: {state}", flush=True)
    return int(any(not r["passed"] for r in results))
