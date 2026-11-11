"""Integrated SH-26 private fixture. Invoke only through stack_suite.py lock."""

from __future__ import annotations

import argparse
import imaplib
import json
import signal
import ssl
import subprocess
import tempfile
import time
import uuid
from dataclasses import replace
from email.message import EmailMessage
from email.parser import BytesParser
from email.policy import default
from enum import StrEnum
from pathlib import Path

import dkim
import live_validate_stalwart as fixture
from stalwart_probe_fixture import require_lock_custody

from amx import domain_dkim, identity
from amx.live import compose, compose_environment
from amx.mail_client import MailClient, discover, issue_app_password
from amx.mailbox import HANDLED_KEYWORD, TAKEN_KEYWORD, quote_mailbox
from amx.provision import dkim_public_key
from amx.sdk import Agent

ROOT = Path(__file__).resolve().parents[1]


class Stage(StrEnum):
    WEBUI = "fixture-webui"
    INSTALL = "fixture-install"
    UP = "fixture-up"
    SINK = "sink-controls"
    REGISTER = "agent-registration"
    LOGIN = "agent-login"
    PERSON = "person-setup"
    HOSTS = "host-startup"
    AX_PERSON = "person-ax-roundtrip"
    MCP_PERSON = "person-mcp-roundtrip"
    NO_DNS = "sibling-no-dns"
    SEND = "sibling-mcp-send"
    DELIVERY = "sibling-delivery"
    VERIFY = "sibling-verification"
    AX_RECEIPT = "sibling-ax-receipt"
    REPLY = "sibling-ax-reply"
    THREAD = "sibling-mcp-thread"
    DONE = "sibling-mcp-done"
    HOLD_SEND = "hold-send"
    HOLD_QUEUE = "hold-owner-queue"
    HOLD_DENIED = "hold-agent-denied"
    HOLD_APPROVE = "hold-owner-move"
    HOLD_DELIVERY = "hold-approved-delivery"
    EGRESS = "foreign-submission-refusal"
    FINAL = "sink-and-host-final"


def prepare(state: Path) -> None:
    require_lock_custody()
    fixture.write_fixture(state, agent_hosts=True)


def command(state: Path, *args: str, timeout: int = 300) -> str:
    fixture.require_fixture_state(state)
    if args == ("down",):
        # Explicitly activate the host profile during teardown too: inactive
        # profiled services must not survive an interrupted checks/startup run.
        return fixture.cli(state, "compose", "--profile", "agent-hosts", "down", timeout=timeout)
    return fixture.cli(state, *args, timeout=timeout)


def checks(state: Path, record, *, stage=lambda _: None) -> None:
    params = fixture.require_fixture_state(state)
    # Genuine positive DATA/route controls, removed before the zero-escape baseline.
    stage(Stage.SINK)
    fixture.sink_controls(state, record)
    baseline = fixture.sink_snapshot(state)
    assert not baseline, "private sink must be empty after control removal"
    stage(Stage.REGISTER)
    bundles = {name: register(state, name) for name in ("ax", "mcp")}
    context = ssl.create_default_context(cafile=str(params.tls_dir / "ca.pem"))
    stage(Stage.LOGIN)
    for bundle in bundles.values():
        fixture.wait_for(
            lambda b=bundle: mailbox(state, b["address"], b["password"]), "agent IMAPS login"
        )
    record("two remote agents registered by amx agent add; separate CLI-written bundles")
    stage(Stage.PERSON)
    fixture.user_cli(state, "add", "alice", "--owner", "--password-out", str(state / "primary"))
    issue_app_password(
        replace(params, ports={**params.ports, "discovery": 443}),
        "alice@home.arpa",
        (state / "primary").read_text().strip(),
        state / "app",
        request=fixture.native_request,
    )
    password = (state / "app").read_text().strip()
    person = MailClient(
        discover(params.mx_host, "alice@home.arpa", context, request=fixture.native_request),
        password,
        context,
        imap_factory=fixture.FixtureIMAP,
        smtp_ssl_factory=fixture.FixtureSMTP,
    )
    with person.imap() as client:
        assert client.select("INBOX")[0] == "OK"
    stage(Stage.HOSTS)
    command(state, "compose", "up", "-d", "--build", "host-ax", "host-mcp", timeout=600)
    for name in bundles:
        fixture.wait_for(lambda n=name: host_ready(state, n), "agent host readiness", timeout=90)
    hosts = host_topology(state)
    # Both brokers exist, but only host-ax starts an attached target. The other
    # host polls actual amx-mcp stdio while amx-runner leaves its INBOX untaken.
    record(
        "two separate running agent-host containers: AX attached / no AX session with MCP polling"
    )
    for name, bundle in bundles.items():
        stage(Stage.AX_PERSON if name == "ax" else Stage.MCP_PERSON)
        opener = EmailMessage()
        opener["From"], opener["To"] = "alice@home.arpa", bundle["address"]
        opener["Subject"] = "Private fixture request"
        opener["Message-ID"] = f"<{uuid.uuid4().hex}@home.arpa>"
        opener.set_content("Please confirm this synthetic local request.\n")
        person.send(opener)
        mid = str(opener["Message-ID"])
        incoming = fixture.wait_for(
            lambda b=bundle, m=mid: mailbox(state, b["address"], b["password"], message_id=m),
            "person to agent",
        )
        headers = BytesParser(policy=default).parsebytes(incoming[1])
        assert headers["Agent-Lane"] == "human" and headers["Agent-Trust"] == "high"
        assert headers["Agent-Grant-Role"] == "owner" and headers["Agent-Task-Assigned"]
        if name == "mcp":
            messages = host_mcp(state, "list_inbox", {"limit": 100})
            [taken] = [m for m in messages if m["message_id"] == mid]
            assert taken["taken"] and not taken["seen"] and not taken["handled"]
            reply = host_mcp(state, "reply", {"message_id": mid, "text": "Private MCP received."})
            assert reply["held"] is None
            assert host_mcp(state, "done", {"message_id": mid})["status"] == "handled"
        else:
            fixture.wait_for(lambda m=mid: ax_received(state, m), "AX in-session delivery")
        answer = fixture.wait_for(
            lambda m=mid: mailbox(state, "alice@home.arpa", password, in_reply_to=m),
            "same-thread agent to person reply",
            timeout=90,
        )
        reply_headers = BytesParser(policy=default).parsebytes(answer[1])
        assert mid in str(reply_headers["References"]).split()
        assert reply_headers["Agent-Task"] == headers["Agent-Task-Assigned"]
        verify_signed(state, name, answer[1])
        flags = fixture.wait_for(
            lambda b=bundle, m=mid: handled(state, b, m), "custody handled keyword"
        )
        assert (TAKEN_KEYWORD in flags) == (name == "mcp")
        assert ("\\Seen" in flags) == (name == "ax")
        record(f"person SASL -> {name} host -> person IMAPS: real reply/thread/custody verified")

    # No public/local DNS zone: each container's resolver is loopback with no
    # server. Only /etc/hosts maps TLS endpoints; DKIM selectors cannot use it.
    stage(Stage.NO_DNS)
    for service in ("gateway", "mailhost", "host-ax", "host-mcp"):
        no_dns(state, service)
    stage(Stage.SEND)
    sent = host_mcp(
        state,
        "send",
        {
            "to": [bundles["ax"]["address"]],
            "subject": "Private sibling request",
            "text": "Please confirm the local signed sibling path.",
        },
    )
    assert sent["held"] is None
    stage(Stage.DELIVERY)
    sibling = fixture.wait_for(
        lambda: mailbox(
            state,
            bundles["ax"]["address"],
            bundles["ax"]["password"],
            message_id=sent["message_id"],
        ),
        "signed sibling delivery",
    )
    stage(Stage.VERIFY)
    headers = BytesParser(policy=default).parsebytes(sibling[1])
    assert headers["Agent-Lane"] == "agent"
    assert headers["Agent-Verified-Domain"] == params.agent_domain
    assert headers["Agent-Verified-Selector"] == "mcp"
    verify_signed(state, "mcp", sibling[1])
    stage(Stage.AX_RECEIPT)
    fixture.wait_for(lambda: ax_received(state, sent["message_id"]), "sibling in AX session")
    stage(Stage.REPLY)
    response = fixture.wait_for(
        lambda: mailbox(
            state,
            bundles["mcp"]["address"],
            bundles["mcp"]["password"],
            in_reply_to=sent["message_id"],
        ),
        "AX sibling reply",
    )
    stage(Stage.THREAD)
    response_headers = BytesParser(policy=default).parsebytes(response[1])
    thread = host_mcp(state, "read_thread", {"task": sent["task"]})
    [received] = [m for m in thread if m["message_id"] == response_headers["Message-ID"]]
    assert received["taken"] and not received["seen"]
    assert received["verified"] == params.agent_domain + "/ax" and received["lane"] == "agent"
    verify_signed(state, "ax", response[1])
    stage(Stage.DONE)
    assert (
        host_mcp(state, "done", {"message_id": str(response_headers["Message-ID"])})["status"]
        == "handled"
    )
    record("signed two-host sibling round trip verified via local key store, with no DNS zone")

    stage(Stage.HOLD_SEND)
    held = host_mcp(
        state,
        "send",
        {
            "to": ["alice@home.arpa"],
            "subject": "Private approval fixture",
            "intent": "request",
            "text": "Synthetic invoice USD 1.00; no real payment.",
            "schema": "https://evtmail.ai/schema/0.1/payment-request.json",
            "payload": {
                "@context": "https://schema.org",
                "@type": "Invoice",
                "price": "1.00",
                "priceCurrency": "USD",
                "amx:payee": "synthetic fixture",
            },
        },
    )
    assert held["held"] == "commits-money"
    folder = "Shared Folders/holds@home.arpa/Holds/mcp/"
    stage(Stage.HOLD_QUEUE)
    held_copy = fixture.wait_for(
        lambda: mailbox(
            state,
            "alice@home.arpa",
            password,
            folder=folder + "Held",
            message_id=held["message_id"],
        ),
        "owner hold queue",
    )
    assert mailbox(state, "alice@home.arpa", password, message_id=held["message_id"]) is None
    stage(Stage.HOLD_DENIED)
    approve(
        state,
        bundles["mcp"]["address"],
        bundles["mcp"]["password"],
        folder,
        held_copy[0],
        expected="NO",
    )
    # Ordinary person's native IMAP MOVE, not an operator approval bypass.
    fixture.require_fixture_state(state)
    stage(Stage.HOLD_APPROVE)
    person.approve(folder + "Held", folder + "Approved", held_copy[0])
    stage(Stage.HOLD_DELIVERY)
    approved = fixture.wait_for(
        lambda: mailbox(state, "alice@home.arpa", password, message_id=held["message_id"]),
        "owner-approved delivery",
        timeout=90,
    )
    verify_signed(state, "mcp", approved[1])
    record(
        "real policy hold: agent denied approval; owner IMAP MOVE releases signed local delivery"
    )
    stage(Stage.EGRESS)
    sdk = Agent(
        bundles["mcp"]["address"],
        f"smtp://localhost:{fixture.PORTS['submission']}",
        bundles["mcp"]["token"],
        tls_ca_file=str(params.tls_dir / "ca.pem"),
    )
    fixture.foreign_submission_refused(bundles["mcp"], "alice@home.arpa", password, context, sdk)
    record("authenticated person and agent foreign submissions refused")
    stage(Stage.FINAL)
    for _ in range(10):
        fixture.assert_sink_unchanged(state, baseline)
        assert all(host_ready(state, n) for n in bundles)
        time.sleep(0.5)
    assert host_topology(state) == hosts, "agent hosts were replaced during validation"
    record("zero sink escape after all positive paths; both host runners remain live")


def register(state: Path, name: str) -> dict:
    params = fixture.require_fixture_state(state)
    if name not in {"ax", "mcp"}:
        raise ValueError("unknown fixture agent")
    directory = params.state_dir / "hosts" / name
    directory.mkdir(parents=True, mode=0o700)
    bundle = directory / "credentials.json"
    result = subprocess.run(
        [
            "uv",
            "run",
            "--group",
            "gateway",
            "amx",
            "agent",
            "add",
            name,
            "--live",
            "--config",
            str(params.gateway_config),
            "--mode",
            "remote",
            "--bundle",
            str(bundle),
            "--imap",
            "imaps://mail.home.arpa:993",
            "--submission",
            "smtp://gateway.home.arpa:2587",
        ],
        cwd=ROOT,
        env=compose_environment(),
        capture_output=True,
        timeout=60,
    )
    if result.returncode:
        raise RuntimeError("fixture registration failed")
    return json.loads(bundle.read_text())


def host_mcp(state: Path, tool: str, arguments: dict):
    params = fixture.require_fixture_state(state)
    result = subprocess.run(
        compose(
            params,
            "exec",
            "-T",
            "host-mcp",
            "/app/.venv/bin/python",
            "/fixture/selfhost_agent_host.py",
            "mcp",
        ),
        input=json.dumps({"tool": tool, "arguments": arguments}),
        cwd=ROOT,
        env=compose_environment(),
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode:
        raise RuntimeError("fixture MCP operation failed")
    return json.loads(result.stdout)


def mailbox(state, user, password, *, folder="INBOX", message_id=None, in_reply_to=None):
    params = fixture.require_fixture_state(state)
    context = ssl.create_default_context(cafile=str(params.tls_dir / "ca.pem"))
    with imaplib.IMAP4_SSL(
        "localhost", fixture.PORTS["imaps"], ssl_context=context, timeout=10
    ) as client:
        client.login(user, password)
        if message_id is None and in_reply_to is None:
            return True
        if client.select(quote_mailbox(folder), readonly=True)[0] != "OK":
            return None
        status, data = client.uid("SEARCH", None, "ALL")
        assert status == "OK"
        matches = []
        for uid in (data[0] or b"").split():
            status, fetched = client.uid("FETCH", uid, "(FLAGS BODY.PEEK[])")
            assert status == "OK"
            raw = next(item[1] for item in fetched if isinstance(item, tuple))
            headers = BytesParser(policy=default).parsebytes(raw)
            if (message_id and headers["Message-ID"] == message_id) or (
                in_reply_to and headers["In-Reply-To"] == in_reply_to
            ):
                flags = {
                    f.decode()
                    for part in fetched
                    if isinstance(part, (bytes, tuple))
                    for f in imaplib.ParseFlags(part[0] if isinstance(part, tuple) else part)
                }
                matches.append((uid, raw, flags))
        assert len(matches) <= 1, "duplicate fixture message"
        return matches[0] if matches else None


def handled(state, bundle, message_id):
    copy = mailbox(state, bundle["address"], bundle["password"], message_id=message_id)
    return copy[2] if copy and HANDLED_KEYWORD in copy[2] else None


def approve(state, user, password, folder, uid, *, expected):
    params = fixture.require_fixture_state(state)
    context = ssl.create_default_context(cafile=str(params.tls_dir / "ca.pem"))
    with imaplib.IMAP4_SSL(
        "localhost", fixture.PORTS["imaps"], ssl_context=context, timeout=10
    ) as client:
        client.login(user, password)
        client.select(quote_mailbox(folder + "Held"))
        assert client.uid("MOVE", uid, quote_mailbox(folder + "Approved"))[0] == expected


def verify_signed(state, name, raw):
    """Signed by the gateway with the domain's one key (SH-44), for the From agent ``name``."""
    params = fixture.require_fixture_state(state)
    selector = domain_dkim.signature_selector(raw)
    assert selector is not None and domain_dkim.is_domain_selector(selector), selector
    headers = BytesParser(policy=default).parsebytes(raw, headersonly=True)
    assert identity.from_agent(str(headers.get("From", ""))) == name
    public = dkim_public_key(params.keys_dir / f"{selector}.private.pem")
    assert dkim.verify(raw, dnsfunc=lambda *_a, **_kw: f"v=DKIM1; k=rsa; p={public}".encode())


def ax_received(state, message_id):
    params = fixture.require_fixture_state(state)
    path = params.state_dir / "hosts/ax/received.jsonl"
    if not path.exists():
        return False
    matches = [
        json.loads(line)
        for line in path.read_text().splitlines()
        if json.loads(line)["message_id"] == message_id
    ]
    assert len(matches) <= 1, "duplicate AX session delivery"
    return bool(matches)


def host_ready(state, name):
    params = fixture.require_fixture_state(state)
    if name not in {"ax", "mcp"}:
        raise ValueError("unknown fixture host")
    path = params.state_dir / "hosts" / name / "ready.json"
    if not path.exists():
        return False
    script = (
        "import json,os,pathlib,time; "
        "row=json.loads(pathlib.Path('/state/ready.json').read_text()); "
        f"assert row['mode']=={name!r} and row['session']=={name == 'ax'!r}; "
        "[os.kill(row[key],0) for key in ('runner','broker','client')]; "
        + (
            "assert time.time()-pathlib.Path('/state/mcp-ready').stat().st_mtime<10; "
            "assert not pathlib.Path('/state/target-ready').exists(); "
            "import hashlib,sqlite3; "
            "path=pathlib.Path('/state/custody/amx/custody')/"
            "(hashlib.sha256(b'mcp@agents.home.arpa').hexdigest()+'.sqlite'); "
            "db=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True); "
            "custody=json.loads(db.execute('SELECT data FROM state WHERE id=1').fetchone()[0]); "
            "db.close(); assert custody.get('ax_until',0)<time.time(); "
            "assert 0<=time.time()-custody['mcp_poll']<10; "
            if name == "mcp"
            else "assert pathlib.Path('/state/target-ready').exists(); "
        )
    )
    try:
        command(
            state, "compose", "exec", "-T", "host-" + name, "/app/.venv/bin/python", "-c", script
        )
    except RuntimeError:
        return False
    return True


def host_topology(state):
    params = fixture.require_fixture_state(state)
    ids = command(state, "compose", "ps", "-q", "host-ax", "host-mcp").split()
    assert len(ids) == len(set(ids)) == 2, "expected two distinct agent containers"
    result = subprocess.run(
        ["docker", "inspect", *ids], capture_output=True, text=True, check=True, timeout=15
    )
    hosts = {}
    for row in json.loads(result.stdout):
        name = row["Config"]["Labels"]["com.docker.compose.service"]
        assert name in {"host-ax", "host-mcp"} and name not in hosts
        assert row["State"]["Running"] and row["State"]["Pid"] > 0
        assert row["HostConfig"]["Dns"] == ["127.0.0.1"]
        assert row["HostConfig"]["NetworkMode"] not in {"host", "none"}
        assert not row["HostConfig"]["PortBindings"]
        assert len(row["NetworkSettings"]["Networks"]) == 1
        [mount] = [m for m in row["Mounts"] if m["Destination"] == "/state"]
        assert mount["Source"] == str(params.state_dir / "hosts" / name.removeprefix("host-"))
        hosts[name] = row["Id"]
    return hosts


def no_dns(state, service):
    fixture.require_fixture_state(state)
    if service not in {"gateway", "mailhost", "host-ax", "host-mcp"}:
        raise ValueError("unknown fixture service")
    ids = command(state, "compose", "ps", "-q", service).split()
    assert len(ids) == 1
    result = subprocess.run(
        ["docker", "inspect", "--format", "{{json .HostConfig.Dns}}", ids[0]],
        capture_output=True,
        text=True,
        check=True,
        timeout=15,
    )
    assert json.loads(result.stdout) == ["127.0.0.1"]
    # Query the actual container resolver; endpoint /etc/hosts entries are not a
    # DNS zone. No external nameserver or forwarder is configured or contacted.
    script = (
        "import dns.resolver; r=dns.resolver.Resolver(configure=False); "
        "r.nameservers=['127.0.0.1']; "
        "r.timeout=.2; r.lifetime=.4; "
        "\ntry: r.resolve('mcp._domainkey.agents.home.arpa','TXT')"
        "\nexcept dns.exception.DNSException: pass"
        "\nelse: raise AssertionError('unexpected agent DNS zone')"
    )
    # Stalwart's upstream image has no Python; query its effective DNS settings
    # through inspect instead. Gateway/agent-hosts perform the actual TXT query.
    if service != "mailhost":
        command(state, "compose", "exec", "-T", service, "/app/.venv/bin/python", "-c", script)


def _validate(state: Path | None = None) -> int:
    """Refuse foreign resources before writes; finally stays under the same lease."""
    require_lock_custody()
    with fixture.admitted_call():
        if fixture.inventory():
            print("REFUSE: amx-live resources already exist; no adoption/cleanup", flush=True)
            return 2
        state = (state or Path(tempfile.mkdtemp(prefix="amx-selfhost-"))).resolve()
        state.mkdir(parents=True, exist_ok=True)
        prepare(state)
        results = []
        current_stage = Stage.WEBUI

        def stage(value):
            nonlocal current_stage
            if not isinstance(value, Stage):
                raise ValueError("unknown validation stage")
            current_stage = value
            print("STAGE " + value.value, flush=True)

        def record(check):
            results.append({"passed": True, "check": check})
            print("PASS  " + check, flush=True)

        try:
            stage(Stage.WEBUI)
            fixture.stage_webui(state)
            stage(Stage.INSTALL)
            command(state, "install")
            stage(Stage.UP)
            command(state, "up", timeout=600)
            checks(state, record, stage=stage)
        except fixture.Terminated:
            results.append({"passed": False, "check": "cancelled", "stage": current_stage.value})
            raise
        except Exception as error:
            # Exception messages/Compose logs may include credentials/private mail.
            results.append(
                {
                    "passed": False,
                    "check": "native validation step",
                    "stage": current_stage.value,
                    "type": type(error).__name__,
                }
            )
            print("FAIL  native validation step: " + current_stage.value, flush=True)
        finally:
            for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
                signal.signal(sig, signal.SIG_IGN)
            try:
                command(state, "down", timeout=60)
                if fixture.inventory():
                    raise RuntimeError("selfhost cleanup left resources")
            except Exception:
                results.append({"passed": False, "check": "cleanup failed"})
                raise
            finally:
                fixture.require_fixture_state(state)
                (state / "validation.json").write_text(json.dumps(results, indent=2) + "\n")
                print("Selfhost validation report: " + str(state / "validation.json"), flush=True)
        return int(any(not row["passed"] for row in results))


def validate(state: Path | None = None) -> int:
    require_lock_custody()
    try:
        return _validate(state)
    finally:
        fixture._active_fixture = None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, help="fresh private fixture state directory")
    args = parser.parse_args()
    try:
        return validate(args.state)
    except fixture.Terminated as error:
        return 128 + error.signum
    finally:
        fixture._active_fixture = None


if __name__ == "__main__":
    raise SystemExit(main())
