"""Validate the live bundle on this machine, with nothing leaving it (docs/selfhost-public.md).

    uv run python tools/live_validate.py [--state DIR] [--keep]

Runs deploy/live in self-signed mode for the fake domain agents.example.test, as its own
compose project (amx-live) on ports bound to 127.0.0.1 that do not clash with the dev stack. It
seeds and purges that project's volumes, so it refuses to start while the project has any
containers or volumes: a --keep run's, or a real lane's on the same host. The
host's resolver is replaced by a CoreDNS that answers only the fake zones (and forwards nothing),
and the fake outside domain client.example.test has an SMTP sink for its MX. Then it proves:

- the upgrade: an agent an earlier install configured from the parameters file (intake, queued)
  moves into the registry with its key, token, password, and mailbox (PLAN §11.5);
- a local SMTP client delivers to an agent (STARTTLS on 25) and gets its reply through the
  bundle: held on first contact, approved over IMAPS, DKIM-signed, delivered over TLS;
- submission requires TLS, then AUTH, and accepts no master login;
- port 25 relays for nobody (from the host, from the bundle's network, as the agent domain), and
  :10025 accepts only the gateway;
- IMAPS accepts the approver's master login but not the gateway's; the agent's own login cannot
  approve its hold; an approver's forged APPEND to Outbox/Approved releases nothing;
- registration on the running lane, with no restart (PLAN §5.2): `amx agent add --live` adds a
  remote agent (outpost), whose runner, from its bundle alone, answers over IMAPS 993 and 587;
  `amx live agent rotate` replaces its credentials (the old token gets 535), then stages and
  activates a DKIM key under a new selector; `remove` makes RCPT answer 550 5.1.1, `enable`
  undoes it, and `remove --purge` deletes its mailbox and keys;
- preflight passes against the zone the bundle rendered, and fails sensibly against a broken one;
- SH-44: the upgrade's install stages one domain DKIM key while the agents keep signing with
  their own; `amx live dkim activate` switches only once DNS serves it, every agent's mail is
  then signed with it, and an agent registered afterwards needs no DNS record;
- a verified journal backup;
- mail deferred in Postfix's queue survives `down` and `up`, and `down --purge` refuses to
  delete it.
"""

from __future__ import annotations

import argparse
import imaplib
import json
import os
import secrets
import signal
import smtplib
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Callable
from email.message import EmailMessage
from email.parser import BytesParser
from email.policy import default as default_policy
from pathlib import Path

import dkim
import dns.resolver
import yaml

from amx import domain_dkim
from amx.live import LiveParams, load_params, zone_file
from amx.provision import generate_dkim_key, write_private
from amx.sdk import Agent

ROOT = Path(__file__).resolve().parents[1]
AGENT_DOMAIN = "agents.example.test"
MX_HOST = "mail.example.test"
CLIENT = "tester@client.example.test"
PORTS = {"smtp": 12525, "submission": 12587, "imaps": 12993}
DNS_PORT, BROKEN_DNS_PORT = 15353, 15354
# The live bundle's default project: the validation seeds and purges its volumes, so it runs
# only where no lane of that name exists (main refuses otherwise).
PROJECT = "amx-live"
SUBNET = "172.31.250.0/24"

RESULTS: list[tuple[bool, str, str]] = []


def record(passed: bool, name: str, detail: str = "") -> bool:
    RESULTS.append((passed, name, detail))
    print(f"{'PASS' if passed else 'FAIL'}  {name}  {detail}", flush=True)
    return passed


def amx_live(
    state: Path, *args: str, env: dict[str, str] | None = None, timeout: float | None = None
) -> str:
    command = ["uv", "run", "--quiet", "amx", "live", *args, "--params", str(state / "live.yaml")]
    # Fixed local uv/amx/live prefix, repository-owned args and task-local params;
    # argv stays literal (no shell), with no remote executable-input path.
    result = subprocess.run(  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
        command, cwd=ROOT, env=env, capture_output=True, text=True, check=False, timeout=timeout
    )
    if result.returncode not in (0, 1) or (result.returncode and args[0] != "preflight"):
        raise RuntimeError(
            f"amx live {' '.join(args[:2])} failed:\n{result.stdout}\n{result.stderr}"
        )
    return result.stdout


def amx(*args: str) -> str:
    """The plain operator's CLI (`amx agent ...`), as on any gateway."""
    command = ["uv", "run", "--quiet", "amx", *args]
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
    if result.returncode:
        raise RuntimeError(f"amx {' '.join(args[:2])} failed:\n{result.stdout}\n{result.stderr}")
    return result.stdout


def wait_for(what: str, probe: Callable[[], object], timeout: float = 60.0) -> object:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = probe()
        if value:
            return value
        time.sleep(0.5)
    raise TimeoutError(f"timed out waiting for {what}")


def write_params(state: Path) -> None:
    params = {
        "agent_domain": AGENT_DOMAIN,
        "mx_host": MX_HOST,
        "public_ip": "127.0.0.1",
        "admin_contact": "ops@example.test",
        # What an install before registration listed: install migrates it (PLAN §11.5).
        "agents": [{"name": "intake", "handler": "amx.examples.intake:handle", "mode": "queued"}],
        "compose_project": PROJECT,
        "state_dir": str(state / "lane"),
        "network": {"bind_address": "127.0.0.1", "subnet": SUBNET, "ports": PORTS},
        "tls": {"mode": "self-signed", "extra_names": ["localhost", "127.0.0.1"]},
        "dns": {"manage_apex": True},
        # A domain whose MX answers nothing, known so that a send there is not held: its mail
        # waits in the queue (the queue-survival check).
        "known_domains": ["deferred.example.test"],
        "compose_overrides": [str(ROOT / "deploy" / "live" / "validate" / "compose.validate.yaml")],
    }
    (state / "live.yaml").write_text(yaml.safe_dump(params, sort_keys=False), encoding="utf-8")


def seed_earlier_install(state: Path) -> dict[str, str]:
    """What an install before registration left for intake: its secrets in credentials.yaml,
    and its key. Returns intake's password and token (install moves them into the registry)."""
    params = load_params(state / "live.yaml")
    intake = {"imap_password": secrets.token_urlsafe(24), "submit_token": secrets.token_urlsafe(24)}
    generate_dkim_key(params.keys_dir / "intake.private.pem")
    body = {
        "gateway_master": secrets.token_urlsafe(24),
        "approver": secrets.token_urlsafe(24),
        "postmaster": secrets.token_urlsafe(24),
        "agents": {"intake": intake},
    }
    write_private(params.credentials_path, yaml.safe_dump(body))
    return intake


def seed_earlier_mailbox(state: Path, env: dict[str, str]) -> None:
    """intake's mailbox as the earlier mailhost made it: a home with mail and no generation."""
    home = f"/var/mail/vhosts/{AGENT_DOMAIN}/intake"
    message = (
        "From: tester@client.example.test\\nTo: intake@agents.example.test\\n"
        "Subject: kept across the upgrade\\nMessage-ID: <seed@client.example.test>\\n\\n"
        "Mail from before registration.\\n"
    )
    script = (
        f"install -d -o 5000 -g 5000 {home} {home}/Maildir {home}/Maildir/cur {home}/Maildir/tmp "
        f"{home}/Maildir/new && printf '{message}' >{home}/Maildir/new/1727000000.seed.example "
        f"&& chown 5000:5000 {home}/Maildir/new/1727000000.seed.example"
    )
    for args in (("build", "mailhost"), ("run", "--rm", "--no-deps", "-T", "--entrypoint", "sh",
                                          "mailhost", "-c", script)):  # fmt: skip
        subprocess.run([*compose(state), *args], cwd=ROOT, env=env, check=True, capture_output=True)


def write_zones(params: LiveParams, validate: Path) -> None:
    """The fake agent zone as `amx live dns` renders it now (the good copy), and a broken copy.

    Rendered again after each registration change, as an operator publishes the records; CoreDNS
    reloads a zone whose serial (the time) grew, so this waits for the next second first.
    """
    time.sleep(1.1)
    coredns = validate / "coredns"
    for sub in ("good", "broken"):
        (coredns / sub).mkdir(parents=True, exist_ok=True)
    good = zone_file(params, ["ns.example.test"], origin="example.test")
    (coredns / "good" / "example.test.zone").write_text(good, encoding="utf-8")
    # Broken: no DMARC for the agents, intake publishes another agent's key, and no PTR.
    lines = good.splitlines()
    intake = next(line for line in lines if line.startswith("intake._domainkey."))
    other = next(
        (line for line in lines if "._domainkey." in line and not line.startswith("intake.")),
        None,
    )
    broken = [
        (intake.split()[0] + " " + other.split(None, 1)[1]) if other and line == intake else line
        for line in lines
        if not line.startswith("_dmarc.agents")
    ]
    (coredns / "broken" / "example.test.zone").write_text("\n".join(broken) + "\n", "utf-8")


def write_validation_files(params: LiveParams, validate: Path) -> dict[str, str]:
    """CoreDNS zones (the bundle's own rendered records, and a broken copy) and the sink's TLS."""
    network = params.subnet.network_address
    dns_ip, sink_ip = str(network + 53), str(network + 60)
    coredns = validate / "coredns"
    write_zones(params, validate)
    serial = int(time.time())
    client = (
        "$ORIGIN client.example.test.\n$TTL 30\n"
        f"@ IN SOA ns.example.test. hostmaster.example.test. ({serial} 30 30 300 30)\n"
        "@ IN NS ns.example.test.\n@ IN MX 10 sink.client.example.test.\n"
        f'sink IN A {sink_ip}\n@ IN TXT "v=spf1 -all"\n'
    )
    deferred = (
        "$ORIGIN deferred.example.test.\n$TTL 30\n"
        f"@ IN SOA ns.example.test. hostmaster.example.test. ({serial} 30 30 300 30)\n"
        "@ IN NS ns.example.test.\n@ IN MX 10 mx.deferred.example.test.\n"
        f"mx IN A {network + 99}\n"
    )
    reverse = (
        "$ORIGIN 127.in-addr.arpa.\n$TTL 30\n"
        f"@ IN SOA ns.example.test. hostmaster.example.test. ({serial} 30 30 300 30)\n"
        f"@ IN NS ns.example.test.\n1.0.0 IN PTR {MX_HOST}.\n"
    )
    for sub in ("good", "broken"):
        (coredns / sub / "client.example.test.zone").write_text(client, "utf-8")
        (coredns / sub / "deferred.example.test.zone").write_text(deferred, "utf-8")
        if sub == "good":
            (coredns / sub / "127.in-addr.arpa.zone").write_text(reverse, "utf-8")
    blocks = []
    for port, sub in ((53, "good"), (54, "broken")):
        zones = ["example.test", "client.example.test", "deferred.example.test"] + (
            ["127.in-addr.arpa"] if sub == "good" else []
        )
        for zone in zones:
            # reload 1s: a DKIM record published mid-run (write_zones) is served within seconds.
            blocks.append(
                f"{zone}:{port} {{\n  file /etc/coredns/{sub}/{zone}.zone {{\n    reload 1s\n"
                "  }\n}\n"
            )
    # No "." block and no forward plugin: every other name is REFUSED, and nothing leaves.
    (coredns / "Corefile").write_text("\n".join(blocks), encoding="utf-8")
    tls = validate / "sink-tls"
    tls.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30",
         "-subj", "/CN=sink.client.example.test", "-keyout", str(tls / "sink-key.pem"),
         "-out", str(tls / "sink.pem")],
        check=True, capture_output=True,
    )  # fmt: skip
    (tls / "sink-key.pem").chmod(0o644)  # a throwaway key the sink container must read
    out = validate / "sink-out"
    out.mkdir(parents=True, exist_ok=True)
    out.chmod(0o777)
    return {
        "VALIDATE_DIR": str(validate),
        "VALIDATE_DNS_IP": dns_ip,
        "VALIDATE_SINK_IP": sink_ip,
        "VALIDATE_DNS_PORT": str(DNS_PORT),
        "VALIDATE_BROKEN_DNS_PORT": str(BROKEN_DNS_PORT),
    }


class Lane:
    """Clients for the running lane, as a person or a remote agent would reach it."""

    def __init__(self, params: LiveParams, validate: Path, intake: dict[str, str]) -> None:
        self.params = params
        self.validate = validate
        self.ca = str(params.tls_dir / "ca.pem")
        self.context = ssl.create_default_context(cafile=self.ca)
        self.credentials = yaml.safe_load(params.credentials_path.read_text("utf-8"))
        # Each agent's own two secrets, as its host holds them: intake's from the earlier
        # install, a registered agent's from its bundle (use_bundle).
        self.passwords = {"intake": intake["imap_password"]}
        self.tokens = {"intake": intake["submit_token"]}

    def use_bundle(self, agent: str, bundle: Path) -> dict[str, str]:
        values = json.loads(bundle.read_text("utf-8"))
        self.passwords[agent], self.tokens[agent] = values["password"], values["token"]
        return values

    def smtp(self, port: int, *, tls: bool = True) -> smtplib.SMTP:
        client = smtplib.SMTP("127.0.0.1", port, timeout=20)
        client._host = MX_HOST  # verify the certificate as the MX host's
        client.ehlo("client.example.test")
        if tls:
            client.starttls(context=self.context)
            client.ehlo("client.example.test")
        return client

    def imap(self, user: str, password: str) -> imaplib.IMAP4_SSL:
        client = imaplib.IMAP4_SSL(
            "localhost", self.params.ports["imaps"], ssl_context=self.context, timeout=20
        )
        client.login(user, password)
        return client

    def approver(self, agent: str) -> imaplib.IMAP4_SSL:
        return self.imap(f"{agent}@{AGENT_DOMAIN}*approver", self.credentials["approver"])

    def agent_login(self, agent: str, password: str | None = None) -> imaplib.IMAP4_SSL:
        return self.imap(f"{agent}@{AGENT_DOMAIN}", password or self.passwords[agent])

    def logs_in(self, agent: str, password: str | None = None) -> bool:
        try:
            self.agent_login(agent, password).logout()
        except imaplib.IMAP4.error:
            return False
        return True

    def auth(self, agent: str, token: str) -> int:
        """What submission answers AUTH with ``token`` (235, or 535)."""
        with self.smtp(self.params.ports["submission"]) as client:
            try:
                return client.login(agent, token)[0]
            except smtplib.SMTPAuthenticationError as error:
                return error.smtp_code

    def rcpt(self, address: str) -> tuple[int, str]:
        """What port 25 answers a person's RCPT to ``address`` (the transaction is then reset)."""
        with self.smtp(self.params.ports["smtp"]) as client:
            client.mail(CLIENT)
            code, text = client.rcpt(address)
        return code, text.decode()

    def sdk(self, agent: str) -> Agent:
        submit = f"smtp://localhost:{self.params.ports['submission']}"
        return Agent(f"{agent}@{AGENT_DOMAIN}", submit, self.tokens[agent], tls_ca_file=self.ca)

    def sink(self) -> list[tuple[dict, bytes]]:
        out = self.validate / "sink-out"
        return [
            (json.loads(meta.read_text("utf-8")), meta.with_suffix(".eml").read_bytes())
            for meta in sorted(out.glob("*.json"))
            if meta.with_suffix(".eml").is_file()
        ]

    def sink_message(self, predicate: Callable[[EmailMessage], bool]) -> tuple[dict, bytes] | None:
        for meta, raw in self.sink():
            headers = BytesParser(policy=default_policy).parsebytes(raw, headersonly=True)
            if predicate(headers):
                return meta, raw
        return None

    def journal(self, event: str) -> int:
        path = self.params.data_dir / "journal.sqlite"
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as connection:
            return connection.execute(
                "SELECT count(*) FROM journal WHERE event = ?", (event,)
            ).fetchone()[0]

    def held(self, agent: str, predicate: Callable[[EmailMessage], bool]) -> str | None:
        with self.approver(agent) as client:
            client.select("Outbox/Held")
            _, data = client.uid("SEARCH", None, "ALL")
            for uid in (data[0] or b"").split():
                _, fetched = client.uid("FETCH", uid, "(BODY.PEEK[HEADER])")
                headers = BytesParser(policy=default_policy).parsebytes(fetched[0][1])
                if predicate(headers):
                    return uid.decode()
        return None

    def move_held(self, agent: str, uid: str, folder: str) -> str:
        with self.approver(agent) as client:
            client.select("Outbox/Held")
            status, detail = client.uid("MOVE", uid, folder)
            return f"{status} {detail}"


def dnsfunc(name: bytes, timeout: float = 5) -> bytes:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers, resolver.port = ["127.0.0.1"], DNS_PORT
    answer = resolver.resolve(name.decode().rstrip("."), "TXT", lifetime=timeout)
    return b"".join(answer[0].strings)


def served(name: str) -> bool:
    """Whether the fake zone's CoreDNS serves a TXT at ``name`` yet."""
    try:
        return bool(dnsfunc(name.encode(), timeout=2))
    except dns.exception.DNSException:
        return False


def person_mail(to: str, subject: str) -> EmailMessage:
    message = EmailMessage()
    message["From"] = CLIENT
    message["To"] = to
    message["Subject"] = subject
    message["Message-ID"] = f"<{uuid.uuid4().hex}@client.example.test>"
    message.set_content("Hello from a person on the fake outside domain.\n")
    return message


def check_reply_round_trip(lane: Lane, agent: str, handler_log: Path) -> None:
    """The agent writes first (held, approved over IMAPS, delivered); the person replies to its
    sub-address on port 25; the agent's answer comes back through the bundle.

    A person's unsolicited mail opens no task (the human lane cannot, PLAN §2 S12), so this is
    the order M7 measures: the agent's message, then the person's reply.
    """
    opener = lane.sdk(agent).send(
        to=CLIENT, subject=f"live validation {agent}", intent="request", text="Can we talk?"
    )
    record(opener.held == "first-contact-domain", f"{agent}: first contact held", str(opener.held))
    uid = wait_for(
        f"{agent}'s held opener",
        lambda: lane.held(agent, lambda h: str(h.get("Message-ID", "")) == opener.message_id),
    )
    status = lane.move_held(agent, str(uid), "Outbox/Approved")
    record(status.startswith("OK"), f"{agent}: approver moved it to Outbox/Approved", status)
    meta, raw = wait_for(
        f"{agent}'s opener at the sink",
        lambda: lane.sink_message(lambda h: str(h.get("Message-ID", "")) == opener.message_id),
    )
    check_delivered(agent, "opener", meta, raw)
    headers = BytesParser(policy=default_policy).parsebytes(raw, headersonly=True)
    reply = person_mail(str(headers["Reply-To"]), f"[reply] Re: live validation {agent}")
    reply["In-Reply-To"] = opener.message_id
    reply["References"] = opener.message_id
    reply_id = str(reply["Message-ID"])
    with lane.smtp(lane.params.ports["smtp"]) as client:
        cipher = client.sock.cipher()[1]  # type: ignore[union-attr]
        refused = client.send_message(reply)
    record(
        not refused, f"{agent}: the person's reply accepted on 25 over STARTTLS ({cipher})",
        str(headers["Reply-To"]),
    )  # fmt: skip
    wait_for(
        f"{agent}'s handler",
        lambda: handler_log.is_file() and reply_id in handler_log.read_text("utf-8"),
    )
    record(True, f"{agent}: handler ran on the reply", handler_log.name)
    meta, raw = wait_for(
        f"{agent}'s answer at the sink",
        lambda: lane.sink_message(lambda h: str(h.get("In-Reply-To", "")).strip() == reply_id),
    )
    check_delivered(agent, "answer (domain now seen: not held)", meta, raw)


def check_delivered(
    agent: str, what: str, meta: dict, raw: bytes, selector: str | None = None
) -> None:
    selector = selector or agent
    headers = BytesParser(policy=default_policy).parsebytes(raw, headersonly=True)
    signature = str(headers.get("DKIM-Signature", ""))
    verified = dkim.verify(raw, dnsfunc=dnsfunc)
    record(
        verified and f"s={selector};" in signature and f"d={AGENT_DOMAIN}" in signature,
        f"{agent}: {what} delivered DKIM-signed d={AGENT_DOMAIN} s={selector}, verified",
    )
    record(
        meta["tls"] and meta["helo"] == MX_HOST,
        f"{agent}: {what} reached the outside MX over TLS, HELO {meta['helo']}",
    )


class Terminated(BaseException):
    def __init__(self, signum: int):
        self.signum = signum


def terminate(signum: int, _frame: object) -> None:
    raise Terminated(signum)


def main() -> int:
    signals = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
    handlers = {sig: signal.signal(sig, terminate) for sig in signals}
    try:
        return validate()
    except Terminated as error:
        return 128 + error.signum
    finally:
        for sig, handler in handlers.items():
            signal.signal(sig, handler)


def validate() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--state", type=Path, help="state directory (default: a temporary one)")
    parser.add_argument("--keep", action="store_true", help="leave the lane running")
    parser.add_argument("--mta", choices=("postfix", "stalwart"), default="postfix")
    args = parser.parse_args()
    if args.mta == "stalwart":
        from live_validate_stalwart import validate_stalwart

        return validate_stalwart(args)
    leftovers = [
        name
        for kind in ("ps", "volume")
        for name in subprocess.run(
            ["docker", *([kind, "-a"] if kind == "ps" else [kind, "ls"]), "-q", "--filter",
             f"label=com.docker.compose.project={PROJECT}"],
            capture_output=True, text=True, check=True,
        ).stdout.split()
    ]  # fmt: skip
    if leftovers:
        print(
            f"compose project {PROJECT} already has containers or volumes: a real lane (never "
            "validate on the live host), or a --keep run's (take it down first with "
            "`amx live down --purge --force --params <its live.yaml>`)",
            file=sys.stderr,
        )
        return 2
    state = (args.state or Path(tempfile.mkdtemp(prefix="amx-live-validate-"))).resolve()
    state.mkdir(parents=True, exist_ok=True)
    validate = state / "validate"
    write_params(state)
    intake = seed_earlier_install(state)
    installed = amx_live(state, "install")
    print(installed, end="")
    record("migrated intake" in installed, "install: moved intake from agents: into the registry")
    params = load_params(state / "live.yaml")
    env = {**os.environ, **write_validation_files(params, validate)}
    env.pop("TYPESAFE_API_KEY", None)  # the stub judge: the validation calls nothing outside
    runner: subprocess.Popen[bytes] | None = None
    try:
        # Seeding and startup can already create containers/volumes. They need
        # the same finally as the checks, including on handled termination.
        seed_earlier_mailbox(state, env)
        print(amx_live(state, "up", env=env), end="")
        lane = Lane(params, validate, intake)
        check_migration(lane, state)
        run_checks(lane, state, env)
        runner = check_registration(lane, state, env, validate)
        check_preflight(state, env)
        runner = check_rotation(lane, state, env, validate, runner)
        check_removal(lane, state, env)
        check_mailhost_restart(lane, state, env)
        check_domain_dkim(lane, state, env, validate)
        out = amx_live(state, "backup", env=env).strip().splitlines()[-1]
        verify = (Path(out) / "journal-verify.txt").read_text("utf-8").strip()
        record(verify.startswith("OK") and (Path(out) / "mail.tar.gz").is_file(), "backup", verify)
        check_queue_survives(lane, state, env)
    except Exception as error:  # a failed step is a failed validation, reported with the rest
        record(False, "validation step raised", f"{error.__class__.__name__}: {error}")
    finally:
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(sig, signal.SIG_IGN)
        try:
            if runner is not None:
                stop_runner(runner)
        finally:
            if not args.keep:
                amx_live(state, "down", "--purge", "--force", env=env, timeout=60)
    failed = [name for passed, name, _ in RESULTS if not passed]
    print(f"\n{len(RESULTS) - len(failed)} passed, {len(failed)} failed; state {state}")
    (state / "validation.json").write_text(
        json.dumps([{"passed": p, "check": n, "detail": d} for p, n, d in RESULTS], indent=2),
        encoding="utf-8",
    )
    return 1 if failed else 0


def check_migration(lane: Lane, state: Path) -> None:
    """intake, configured the old way, now runs from the registry with what it had."""
    listed = amx("agent", "list", "--config", str(lane.params.gateway_config))
    record(
        "intake: registered, queued, enabled; intake (active)" in listed,
        "migration: the gateway runs intake from the registry, selector unchanged",
        listed.strip(),
    )
    record(lane.auth("intake", lane.tokens["intake"]) == 235, "migration: its old token works")
    with lane.agent_login("intake") as client:
        client.select("INBOX", readonly=True)
        _, found = client.search(None, "SUBJECT", '"kept across the upgrade"')
    record(
        bool(found[0]),
        "migration: its old password works, and the mailbox the earlier install made kept its mail",
    )
    credentials = yaml.safe_load(lane.params.credentials_path.read_text("utf-8"))
    record("agents" not in credentials, "migration: no agent secret left in credentials.yaml")


def mailhost(state: Path, env: dict[str, str], script: str) -> str:
    """Run a shell script in the mailhost container; its output."""
    return subprocess.run(
        [*compose(state), "exec", "-T", "mailhost", "sh", "-c", script],
        cwd=ROOT, env=env, capture_output=True, text=True, check=True,
    ).stdout  # fmt: skip


def started(state: Path, env: dict[str, str]) -> dict[str, str]:
    """When the gateway and mailhost containers last started (a restart changes it)."""
    times = {}
    for service in ("gateway", "mailhost"):
        container = subprocess.run(
            [*compose(state), "ps", "-q", service], cwd=ROOT, env=env, capture_output=True,
            text=True, check=True,
        ).stdout.strip()  # fmt: skip
        times[service] = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.StartedAt}}", container],
            capture_output=True, text=True, check=True,
        ).stdout.strip()  # fmt: skip
    return times


def check_registration(
    lane: Lane, state: Path, env: dict[str, str], validate: Path
) -> subprocess.Popen[bytes]:
    """`amx agent add --live` on the running lane: the agent is live within seconds, with no
    restart, and its runner works from its bundle alone (PLAN §5.2, §11.5)."""
    params = lane.params
    state_file = state / "started.json"
    state_file.write_text(json.dumps(started(state, env)), encoding="utf-8")
    bundle = params.bundles_dir / "outpost.json"
    begun = time.monotonic()
    amx(
        "agent", "add", "outpost", "--live", "--config", str(params.gateway_config),
        "--bundle", str(bundle), "--imap", f"imaps://{MX_HOST}:{PORTS['imaps']}",
        "--submission", f"smtp://{MX_HOST}:{PORTS['submission']}",
    )  # fmt: skip
    values = lane.use_bundle("outpost", bundle)
    record(
        values["imap"] == f"imaps://{MX_HOST}:{PORTS['imaps']}",
        "add: `amx agent add --live` wrote a bundle for IMAPS on the live port",
        values["imap"],
    )
    wait_for("outpost's login", lambda: lane.logs_in("outpost"), timeout=30)
    code, text = wait_for(
        "outpost at RCPT",
        lambda: (lambda answer: answer if answer[0] == 250 else None)(
            lane.rcpt(f"outpost@{AGENT_DOMAIN}")
        ),
        timeout=30,
    )
    record(
        code == 250,
        f"add: outpost's login works and RCPT accepts it {time.monotonic() - begun:.1f} s later",
        f"{code} {text}",
    )
    # Passes run by hand beside watch's wait for each other (they build the same files).
    snapshot = "cat /etc/dovecot/users /etc/postfix/vmailbox | cut -d: -f1 | sort"
    before = mailhost(state, env, snapshot)
    mailhost(state, env, "for i in 1 2 3 4 5; do amx-sync-accounts once & done; wait")
    after = mailhost(state, env, snapshot)
    record(
        after == before and f"outpost@{AGENT_DOMAIN} OK" in after and lane.logs_in("outpost"),
        "sync: five passes at once leave the users file and Postfix's table whole",
        f"{len(before.splitlines())} lines before, {len(after.splitlines())} after",
    )
    with lane.agent_login("outpost") as client:
        client.select("Outbox/Held")
        status, detail = client.append(
            "INBOX", None, None, person_mail("x@example.test", "forged").as_bytes()
        )
    record(status == "NO", "add: outpost cannot insert into its own INBOX", f"{status} {detail}")
    write_zones(params, validate)  # the operator publishes its DKIM record
    wait_for("outpost's DKIM record", lambda: served(f"outpost._domainkey.{AGENT_DOMAIN}"))
    runner = start_runner(lane, state, bundle)
    check_reply_round_trip(lane, "outpost", state / "runner" / "handler.jsonl")
    return runner


def check_rotation(
    lane: Lane,
    state: Path,
    env: dict[str, str],
    validate: Path,
    runner: subprocess.Popen[bytes],
) -> subprocess.Popen[bytes]:
    """New credentials (the old token gets 535), then a DKIM key under a new selector."""
    stop_runner(runner)
    old_token, old_password = lane.tokens["outpost"], lane.passwords["outpost"]
    before = set(lane.params.bundles_dir.glob("outpost-*.json"))
    amx_live(state, "agent", "rotate", "outpost", "--no-dkim", env=env)
    [bundle] = set(lane.params.bundles_dir.glob("outpost-*.json")) - before
    lane.use_bundle("outpost", bundle)
    outcomes = wait_for(
        "the rotated token",
        lambda: (lambda pair: pair if pair == [535, 235] else None)(
            [lane.auth("outpost", old_token), lane.auth("outpost", lane.tokens["outpost"])]
        ),
        timeout=30,
    )
    record(outcomes == [535, 235], "rotate: the old token gets 535, the new one 235", str(outcomes))
    wait_for("the rotated password", lambda: not lane.logs_in("outpost", old_password), timeout=30)
    record(
        lane.logs_in("outpost") and not lane.logs_in("outpost", old_password),
        "rotate: the old IMAP password is refused, the new one works",
    )
    runner = start_runner(lane, state, bundle)

    amx_live(state, "agent", "rotate", "outpost", "--no-credentials", env=env)
    write_zones(lane.params, validate)  # publish the staged selector
    wait_for("the staged DKIM record", lambda: served(f"outpost.k2._domainkey.{AGENT_DOMAIN}"))
    activated = amx_live(
        state, "agent", "rotate", "outpost", "--activate", "--dns-server",
        f"127.0.0.1:{DNS_PORT}", env=env,
    )  # fmt: skip
    record(
        "now signs with s=outpost.k2" in activated,
        "dkim: outpost.k2 staged, published, and activated (checked in DNS first)",
        activated.strip().splitlines()[0],
    )
    time.sleep(3)  # the gateway's reload polls once a second
    sent = lane.sdk("outpost").send(
        to=CLIENT, subject="signed with the new key", intent="request", text="New key."
    )
    meta, raw = wait_for(
        "outpost's message signed with the new key",
        lambda: lane.sink_message(lambda h: str(h.get("Message-ID", "")) == sent.message_id),
    )
    check_delivered("outpost", "a message after activation", meta, raw, selector="outpost.k2")
    return runner


def check_mailhost_restart(lane: Lane, state: Path, env: dict[str, str]) -> None:
    """An in-place restart (the unless-stopped policy, a reboot, `compose restart`) keeps the
    registered agents: the entrypoint resets Postfix's table to its own users, and the first
    sync pass must build it again although its saved state survived the restart."""
    before = lane.rcpt(f"intake@{AGENT_DOMAIN}")
    subprocess.run(
        [*compose(state), "restart", "mailhost"], cwd=ROOT, env=env, capture_output=True, check=True
    )

    def healthy() -> bool:
        container = subprocess.run(
            [*compose(state), "ps", "-q", "mailhost"], cwd=ROOT, env=env, capture_output=True,
            text=True, check=True,
        ).stdout.strip()  # fmt: skip
        health = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Health.Status}}", container],
            capture_output=True, text=True, check=False,
        ).stdout.strip()  # fmt: skip
        return health == "healthy"

    wait_for("the mailhost to report healthy (a sync pass included)", healthy, timeout=180)
    code, text = lane.rcpt(f"intake@{AGENT_DOMAIN}")
    record(
        before[0] == 250 and code == 250 and lane.logs_in("intake"),
        "restart: after an in-place mailhost restart, a registered agent is accepted and logs in",
        f"{code} {text}",
    )


def check_removal(lane: Lane, state: Path, env: dict[str, str]) -> None:
    """remove: 550 5.1.1 and no login; enable undoes it; --purge deletes the mailbox and keys.
    Then: nothing restarted since the agent was added."""
    address = f"outpost@{AGENT_DOMAIN}"

    def refused() -> tuple[int, str] | None:
        answer = lane.rcpt(address)
        return answer if answer[0] == 550 else None

    amx_live(state, "agent", "remove", "outpost", env=env)
    code, text = wait_for("RCPT to refuse outpost", refused, timeout=30)
    wait_for("outpost's login to stop", lambda: not lane.logs_in("outpost"), timeout=30)
    record(
        code == 550 and "5.1.1" in text,
        "remove: RCPT answers 550 5.1.1, and the agent's login is refused",
        f"{code} {text}",
    )
    amx_live(state, "agent", "enable", "outpost", env=env)
    wait_for("outpost's login again", lambda: lane.logs_in("outpost"), timeout=30)
    code, text = wait_for(
        "RCPT to accept outpost again",
        lambda: (lambda answer: answer if answer[0] == 250 else None)(lane.rcpt(address)),
        timeout=30,
    )
    record(code == 250, "enable: RCPT accepts it again, and its login works", f"{code} {text}")
    amx_live(state, "agent", "remove", "outpost", env=env)
    purged = amx_live(state, "agent", "remove", "outpost", "--purge", "--now", env=env)
    home = f"/var/mail/vhosts/{AGENT_DOMAIN}/outpost"

    def gone() -> bool:
        result = subprocess.run(
            [*compose(state), "exec", "-T", "mailhost", "test", "-e", home],
            cwd=ROOT, env=env, capture_output=True, check=False,
        )  # fmt: skip
        return result.returncode == 1

    wait_for("outpost's mailbox to go", gone, timeout=30)
    code, text = lane.rcpt(address)
    keys = sorted(path.name for path in lane.params.keys_dir.glob("outpost*.private.pem"))
    registered = (lane.params.registry_dir / "agents" / "outpost.yaml").exists()
    record(
        code == 550 and "5.1.1" in text and not keys and not registered and "purged" in purged,
        "purge: the mailbox, the keys, and the registry entry are gone; RCPT 550 5.1.1",
        f"{code} {text}; keys {keys}",
    )
    before = json.loads((state / "started.json").read_text("utf-8"))
    after = started(state, env)
    record(
        after == before,
        "no restart: the gateway and mailhost ran throughout add, rotate, activate, remove, "
        "enable, and purge",
        json.dumps(after),
    )


def run_checks(lane: Lane, state: Path, env: dict[str, str]) -> None:
    params = lane.params
    smtp_port, submission = params.ports["smtp"], params.ports["submission"]

    # Submission: TLS first, then AUTH, and no master login.
    with lane.smtp(submission, tls=False) as client:
        features = set(client.esmtp_features)
        record(
            "starttls" in features and "auth" not in features,
            "587: STARTTLS offered, AUTH not offered before TLS",
            str(sorted(features)),
        )
        code, text = client.mail(f"intake@{AGENT_DOMAIN}")
        record(code == 530, "587: MAIL before STARTTLS refused", f"{code} {text.decode()}")
    with lane.smtp(submission) as client:
        code, text = client.mail(f"intake@{AGENT_DOMAIN}")
        record(
            code == 530, "587: MAIL after STARTTLS without AUTH refused", f"{code} {text.decode()}"
        )
    for user, password, name in (
        ("intake", "not-the-token", "a wrong token"),
        ("gateway", lane.credentials["gateway_master"], "the gateway's master credential"),
        ("approver", lane.credentials["approver"], "the approver's master credential"),
    ):
        with lane.smtp(submission) as client:
            try:
                client.login(user, password)
                record(False, f"587: AUTH with {name} refused", "accepted")
            except smtplib.SMTPAuthenticationError as error:
                record(
                    error.smtp_code == 535, f"587: AUTH with {name} refused", str(error.smtp_code)
                )

    # Port 25 relays for nobody.
    for sender in (CLIENT, f"intake@{AGENT_DOMAIN}"):
        with lane.smtp(smtp_port) as client:
            client.mail(sender)
            code, text = client.rcpt("victim@elsewhere.example.test")
            record(
                code == 554, f"25: relay refused (MAIL FROM {sender})", f"{code} {text.decode()}"
            )
    with lane.smtp(smtp_port) as client:
        client.mail(CLIENT)
        code, text = client.rcpt(f"nobody@{AGENT_DOMAIN}")
        record(code == 550, "25: unknown agent refused", f"{code} {text.decode()}")
    inside = f"""
import smtplib
out = []
for port, rcpt in ((25, "victim@elsewhere.example.test"), (10025, "victim@elsewhere.example.test"),
                   (10025, "intake@{AGENT_DOMAIN}")):
    with smtplib.SMTP("{params.mailhost_ip}", port, timeout=10) as client:
        client.ehlo("sink.client.example.test")
        client.mail("{CLIENT}")
        out.append((port, rcpt) + client.rcpt(rcpt))
print(out)
"""
    result = subprocess.run(
        [*compose(state), "exec", "-T", "sink", "/app/.venv/bin/python", "-c", inside],
        cwd=ROOT, env=env, capture_output=True, text=True, check=False,
    )  # fmt: skip
    record(
        result.stdout.count(", 554, ") == 3,
        "private network: 25 relays for no container; :10025 refuses all but the gateway",
        (result.stdout or result.stderr).strip()[:400],
    )
    with smtplib.SMTP(params.mailhost_ip, 10025, timeout=10) as client:
        client.ehlo("host.invalid")
        client.mail(CLIENT)
        code, text = client.rcpt(f"intake@{AGENT_DOMAIN}")
    record(code == 554, "host: :10025 refuses the Docker host too", f"{code} {text.decode()}")
    published = subprocess.run(
        [*compose(state), "port", "mailhost", "143"], cwd=ROOT, env=env, capture_output=True,
        text=True, check=False,
    )  # fmt: skip
    record(published.returncode != 0 or not published.stdout.strip(), "143 is not published")

    # IMAPS: the approver's master login works, the gateway's does not.
    try:
        lane.imap(f"intake@{AGENT_DOMAIN}*gateway", lane.credentials["gateway_master"]).logout()
        record(False, "993: the gateway's master login refused", "accepted")
    except imaplib.IMAP4.error as error:
        record(True, "993: the gateway's master login refused", str(error)[:80])
    with lane.approver("intake") as client:
        record(client.state == "AUTH", "993: the approver's master login accepted")
    with lane.agent_login("intake") as client:
        status, detail = client.append(
            "INBOX", None, None, person_mail("x@example.test", "forged").as_bytes()
        )
        record(
            status == "NO", "993: an agent cannot insert into its own INBOX", f"{status} {detail}"
        )

    check_reply_round_trip(lane, "intake", params.data_dir / "handler.jsonl")

    # Authenticated submission to an outside domain intake has now sent to: delivered.
    sent = lane.sdk("intake").send(
        to=CLIENT, subject="authenticated send", intent="request", text="Authenticated send."
    )
    delivered = wait_for(
        "the authenticated send at the sink",
        lambda: any(sent.message_id in raw.decode("utf-8", "replace") for _, raw in lane.sink()),
    )
    record(
        bool(delivered) and sent.held is None, "587: authenticated send relayed outside", sent.task
    )

    # A first contact the agent itself cannot approve; the approver rejects it.
    held = lane.sdk("intake").send(
        to="someone@new.example.test", subject="needs approval", intent="request", text="Hold me."
    )
    record(held.held == "first-contact-domain", "587: send to a new domain held", str(held.held))
    uid = wait_for(
        "the held send",
        lambda: lane.held("intake", lambda h: str(h.get("Message-ID", "")) == held.message_id),
    )
    with lane.agent_login("intake") as client:
        client.select("Outbox/Held")
        status, detail = client.uid("MOVE", str(uid), "Outbox/Approved")
    record(
        status == "NO", "993: the agent's own login cannot approve its hold", f"{status} {detail}"
    )
    rejected = lane.journal("hold-rejected")
    record(
        lane.move_held("intake", str(uid), "Outbox/Rejected").startswith("OK"), "approver rejects"
    )
    wait_for("hold-rejected", lambda: lane.journal("hold-rejected") > rejected)
    record(True, "rejection journaled (hold-rejected)")

    # An approver's forged APPEND to Outbox/Approved releases nothing (holdwatch matches bytes).
    released, delivered_count = lane.journal("released"), len(lane.sink())
    forged = person_mail("victim@client.example.test", "forged approval").as_bytes()
    with lane.approver("intake") as client:
        status, _ = client.append("Outbox/Approved", None, None, forged)
    time.sleep(25)  # holdwatch re-scans every 20 s
    record(
        status == "OK"
        and lane.journal("released") == released
        and len(lane.sink()) == delivered_count,
        "a forged APPEND to Outbox/Approved (IMAP accepts it) releases nothing after 25 s",
    )


def check_domain_dkim(lane: Lane, state: Path, env: dict[str, str], validate: Path) -> None:
    """SH-44: the upgrade staged one domain key; once DNS serves it, every agent signs with it,
    and an agent registered afterwards needs no DNS record of its own."""
    params = lane.params
    status = amx_live(state, "dkim", "status", env=env)
    staged = [line.split(":")[0] for line in status.splitlines() if line.endswith(": pending")]
    record(
        len(staged) == 1 and domain_dkim.is_domain_selector(staged[0]),
        "dkim: the upgrade's install staged one domain key; the agents kept their own",
        status.strip(),
    )
    selector = staged[0]
    write_zones(params, validate)  # the operator publishes the one record
    wait_for("the domain's DKIM record", lambda: served(f"{selector}._domainkey.{AGENT_DOMAIN}"))
    activated = amx_live(
        state, "dkim", "activate", "--dns-server", f"127.0.0.1:{DNS_PORT}", env=env
    )  # fmt: skip
    record(
        f"now signs with {selector}" in activated,
        f"dkim: {selector} activated for every agent (checked in DNS first)",
        activated.strip().splitlines()[0],
    )
    time.sleep(3)  # the gateway's reload polls once a second
    sent = lane.sdk("intake").send(
        to=CLIENT, subject="signed with the domain key", intent="request", text="Domain key."
    )
    meta, raw = wait_for(
        "intake's message signed with the domain key",
        lambda: lane.sink_message(lambda h: str(h.get("Message-ID", "")) == sent.message_id),
    )
    check_delivered("intake", "a message after the switch", meta, raw, selector=selector)

    bundle = params.bundles_dir / "late.json"
    added = amx_live(state, "agent", "add", "late", "--bundle", str(bundle), env=env)
    lane.use_bundle("late", bundle)
    rendered = amx_live(state, "dns", env=env)
    record(
        "no DNS change" in added and "late._domainkey" not in added + rendered,
        "dkim: an agent registered after the switch adds no DNS record",
        added.strip().splitlines()[-1],
    )
    wait_for("late's login", lambda: lane.logs_in("late"), timeout=30)
    time.sleep(2)  # the gateway's registry reload
    opener = lane.sdk("late").send(
        to=CLIENT, subject="first words from late", intent="request", text="Hello."
    )
    uid = wait_for(
        "late's held opener",
        lambda: lane.held("late", lambda h: str(h.get("Message-ID", "")) == opener.message_id),
    )
    lane.move_held("late", str(uid), "Outbox/Approved")
    meta, raw = wait_for(
        "late's opener at the sink",
        lambda: lane.sink_message(lambda h: str(h.get("Message-ID", "")) == opener.message_id),
    )
    check_delivered("late", "its first message, with no record of its own", meta, raw, selector)


def compose(state: Path) -> list[str]:
    from amx.live import compose as live_compose

    return live_compose(load_params(state / "live.yaml"))


def start_runner(lane: Lane, state: Path, bundle: Path) -> subprocess.Popen[bytes]:
    """outpost's runner on this host, from its bundle alone: nothing in its environment.

    The bundle names the MX host, which only the fake zone resolves; this host reaches the lane
    on localhost, a name the self-signed certificate also carries.
    """
    runner_dir = state / "runner"
    runner_dir.mkdir(exist_ok=True)
    env = {
        "PATH": os.environ["PATH"],
        "HOME": os.environ.get("HOME", "/tmp"),
        "AMX_HANDLER_LOG": str(runner_dir / "handler.jsonl"),
    }
    log_path = runner_dir / "runner.log"
    offset = log_path.stat().st_size if log_path.exists() else 0
    command = [
        "uv", "run", "--quiet", "amx-runner",
        f"--credentials={bundle}",
        f"--imap=imaps://localhost:{lane.params.ports['imaps']}",
        f"--submit=smtp://localhost:{lane.params.ports['submission']}",
        f"--ca={lane.ca}",
        "--handler=amx.examples.intake:handle",
        f"--state={runner_dir}",
    ]  # fmt: skip
    with log_path.open("ab") as log:
        process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
    wait_for(
        "the runner's IMAPS login",
        lambda: b"watching INBOX" in log_path.read_bytes()[offset:],
        timeout=90,
    )
    record(True, f"outpost's runner logged in over IMAPS 993 from its bundle ({bundle.name})")
    return process


def stop_runner(runner: subprocess.Popen[bytes]) -> None:
    runner.send_signal(signal.SIGTERM)
    try:
        runner.wait(timeout=30)
    except subprocess.TimeoutExpired:
        runner.kill()
        runner.wait(timeout=5)


def preflight(state: Path, env: dict[str, str], port: int, outbound: str, *extra: str) -> str:
    resolver = f"127.0.0.1:{port}"
    return amx_live(
        state, "preflight", "--resolver", resolver, "--outbound", outbound, *extra, env=env
    )


def check_preflight(state: Path, env: dict[str, str]) -> None:
    own_port = f"127.0.0.1:{PORTS['smtp']}"
    results = json.loads(preflight(state, env, DNS_PORT, own_port, "--probe", "local", "--json"))
    failed = [item for item in results if item["status"] == "FAIL"]
    record(
        not failed,
        f"preflight: {len(results)} checks, no FAIL against the rendered zone",
        json.dumps(failed)[:300],
    )
    print(preflight(state, env, DNS_PORT, own_port, "--probe", "local"), end="")
    broken = json.loads(preflight(state, env, BROKEN_DNS_PORT, "127.0.0.1:1", "--json"))
    failing = {item["check"] for item in broken if item["status"] == "FAIL"}
    wanted = {"dns:dkim:intake", "dns:dmarc", "dns:ptr", "reach:outbound-25"}
    record(
        wanted <= failing,
        "preflight: the broken zone fails where it is broken",
        str(sorted(failing)),
    )
    print(preflight(state, env, BROKEN_DNS_PORT, "127.0.0.1:1"), end="")


def queued(state: Path, env: dict[str, str]) -> list[dict]:
    result = subprocess.run(
        [*compose(state), "exec", "-T", "mailhost", "postqueue", "-j"],
        cwd=ROOT, env=env, capture_output=True, text=True, check=False,
    )  # fmt: skip
    return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]


def check_queue_survives(lane: Lane, state: Path, env: dict[str, str]) -> None:
    """Deferred outbound mail outlives `down` and `up`; `down --purge` will not delete it."""
    sent = lane.sdk("intake").send(
        to="someone@deferred.example.test", subject="queued", intent="request", text="Wait."
    )

    def waiting() -> list[dict]:
        return [
            item
            for item in queued(state, env)
            if any(r["address"] == "someone@deferred.example.test" for r in item["recipients"])
        ]

    before = wait_for("the deferred message in the queue", waiting, timeout=90)
    record(sent.held is None and bool(before), "a send to an unreachable MX waits in the queue")
    amx_live(state, "down", env=env)
    amx_live(state, "up", env=env)
    after = waiting()
    record(
        [item["queue_id"] for item in after] == [item["queue_id"] for item in before],
        "the queued message survives `down` and `up` (the queue is a volume)",
        str([item["queue_id"] for item in after]),
    )
    try:
        amx_live(state, "down", "--purge", env=env)
        record(False, "`down --purge` refuses while mail waits", "it purged")
    except RuntimeError as error:
        record("wait in the queue" in str(error), "`down --purge` refuses while mail waits")


if __name__ == "__main__":
    sys.exit(main())
