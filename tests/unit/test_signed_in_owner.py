"""SH-12: submission-bound owner grant; public ingress never confers ownership."""

from dataclasses import replace
from email import policy
from email.parser import BytesParser

import pytest

from amx.adapters.people_milter import DAEMON, submission_macro
from amx.config import TrustGrant
from amx.policy import Stage, State, TxnContext, evaluate
from amx.transport import bind_transport


def context(header="Person <pat@home.arpa>", **changes):
    raw = (
        f"From: {header}\r\nTo: intake@agents.home.arpa\r\n"
        "Message-ID: <owner@home.arpa>\r\nSubject: Hello\r\n\r\nPlease help.\r\n"
    ).encode()
    return replace(
        TxnContext(
            raw=raw, mail_from="pat@home.arpa", auth_authen="pat@home.arpa", submission=True
        ),
        **changes,
    )


def state(**changes):
    return State(
        agent_domain="agents.home.arpa",
        people_domain="home.arpa",
        grants=(TrustGrant(lane="human", trust="low"),),
        **changes,
    )


def test_owner_grant_binds_through_transport_and_is_not_greylisted():
    ctx = context()
    result = evaluate(Stage.EOD, ctx, state(greylisting=True))
    assert result.accepted
    headers = dict(result.headers)
    assert headers["Agent-Lane"] == "human"
    assert headers["Agent-Trust"] == "high"
    assert headers["Agent-Grant-Role"] == "owner"
    assert headers["Agent-Grant-Can-Open-Tasks"] == "true"
    delivered = b"".join(f"{k}: {v}\r\n".encode() for k, v in result.headers) + ctx.raw
    assert (
        bind_transport(
            delivered, BytesParser(policy=policy.default).parsebytes(delivered), set()
        ).trust
        == "high"
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"submission": False},  # public25, even if a macro purports to authenticate
        {"auth_authen": None},
        {
            "auth_authen": "pat@outside.test",
            "mail_from": "pat@outside.test",
            "raw": context("pat@outside.test").raw,
        },
    ],
)
def test_no_owner_outside_authenticated_people_submission(changes):
    result = evaluate(Stage.EOD, context(**changes), state())
    assert result.accepted
    headers = dict(result.headers)
    assert headers["Agent-Trust"] == "low"
    assert headers["Agent-Grant-Can-Open-Tasks"] == "false"
    assert "Agent-Grant-Role" not in headers


@pytest.mark.parametrize(
    "header",
    [
        "other@home.arpa",
        "pat@home.arpa, other@home.arpa",
        "pat@home.arpa\r\nFrom: pat@home.arpa",
        "pat@home.arpa <evil@outside.test>",
        "bad <",
        "",
    ],
)
def test_forged_or_ambiguous_from_is_refused(header):
    result = evaluate(Stage.EOD, context(header), state())
    assert (result.action, result.rule, result.code) == (
        "reject",
        "submission-sender-mismatch",
        "550 5.7.1",
    )


def test_envelope_must_also_match_login():
    result = evaluate(Stage.EOD, context(mail_from="other@home.arpa"), state())
    assert result.rule == "submission-sender-mismatch"


@pytest.mark.parametrize(
    "name", ["Agent-Grant-Role: owner", "Agent-Trust: high", "Agent-Grant-Can-Open-Tasks: true"]
)
def test_public25_cannot_supply_owner_transport_results(name):
    result = evaluate(
        Stage.EOD, context(raw=name.encode() + b"\r\n" + context().raw, submission=False), state()
    )
    assert result.rule == "reserved-transport-header"


def test_people_endpoint_overwrites_only_connect_daemon_macro():
    frame = b"DC{daemon_name}\0forged\0j\0mail.home.arpa\0"
    assert submission_macro(frame) == b"DCj\0mail.home.arpa\0{daemon_name}\0" + DAEMON + b"\0"
    mail = b"DM{auth_authen}\0pat@home.arpa\0"
    assert submission_macro(mail) == mail
    with pytest.raises(ValueError):
        submission_macro(b"DCmalformed")


def test_adapter_captures_login_per_transaction_and_journals_owner(tmp_path):
    Milter = pytest.importorskip("Milter")
    from amx.adapters.milter import build_milter
    from amx.config import GatewayConfig, LimitsConfig, MailboxConfig
    from amx.runtime import HandlerRegistry
    from amx.store import Store

    config = GatewayConfig(
        domain="home.arpa",
        agent_domain="agents.home.arpa",
        data_dir=tmp_path,
        agents={},
        trust=state().grants,
        limits=LimitsConfig(),
        mailbox=MailboxConfig(host="unused.invalid"),
        people_domain="home.arpa",
    )
    store = Store(tmp_path / "journal.sqlite")
    cls = build_milter(config, store, HandlerRegistry())
    milter = cls()
    macros = {"{daemon_name}": "amx-submission", "{auth_authen}": "pat@home.arpa"}
    milter.getsymval = macros.get
    milter.setreply = lambda *args: None
    milter.chgheader = lambda *args: None
    added = []
    milter.addheader = lambda *args: added.append(args)
    milter.connect("mail", 2, ("127.0.0.1", 1234))
    assert milter.envfrom("<pat@home.arpa>") == Milter.CONTINUE
    message = BytesParser(policy=policy.default).parsebytes(context().raw)
    for key, value in message.items():
        milter.header(key, str(value).encode())
    milter.body(b"Please help.\r\n")
    assert milter.eom() == Milter.ACCEPT
    assert dict(added)["Agent-Grant-Role"] == "owner"
    with store.connection() as connection:
        rows = connection.execute("SELECT detail FROM policy_events WHERE stage='eod'").fetchall()
    assert "grant=owner trust=high can_open_tasks=true" in rows[-1][0]
    macros.pop("{auth_authen}")
    milter.envfrom("<pat@home.arpa>")
    assert milter.auth_authen is None
    milter.close()


def test_owner_grant_still_obeys_size_limit():
    from amx.config import LimitsConfig

    result = evaluate(Stage.EOD, context(), state(limits=LimitsConfig(max_bytes=1)))
    assert result.rule == "size-or-attachment" and not result.accepted


def test_owner_does_not_bypass_content_taint_or_reply_holds(tmp_path):
    from test_lmtp import _deliver
    from test_submission import RecordingMailbox, _config

    from amx.adapters.lmtp import LmtpHandler
    from amx.adapters.submission import SubmissionService
    from amx.config import ContentJudgeConfig, HoldRule
    from amx.journal import Journal
    from amx.judge import Judgment
    from amx.policy import apply_judgment
    from amx.runtime import HandlerRegistry
    from amx.sdk import Agent
    from amx.store import Store

    config = replace(
        _config(tmp_path),
        domain="agents.northwind.test",
        people_domain="home.arpa",
        hold_rules=(HoldRule(name="first-contact-domain", recipient_domain_seen=False),),
        known_domains=frozenset(),
    )
    store = Store(tmp_path / "journal.sqlite")
    journal = Journal(tmp_path, store)
    mailbox = RecordingMailbox()
    sent = []
    service = SubmissionService(
        config, journal, mailbox=mailbox, reinject=lambda *args: sent.append(args)
    )
    assert "home.arpa" in service._seen_domains("scheduler")
    assert "outside.test" not in service._seen_domains("scheduler")
    identity = evaluate(Stage.EOD, context(), state())
    verdict = apply_judgment(
        identity,
        Judgment(directs_recipient=0.99),
        None,
        mode="enforce",
        lane="human",
        grant=None,
        config=ContentJudgeConfig(),
    )
    assert dict(verdict.headers)["Agent-Trust"] == "high"
    assert dict(verdict.headers)["Agent-Taint"]
    raw = b"".join(f"{key}: {value}\r\n".encode() for key, value in verdict.headers)
    raw += context().raw.replace(b"intake@agents.home.arpa", b"scheduler@agents.northwind.test")
    outbound = Agent("scheduler@agents.northwind.test", "smtp://localhost", "fixture")
    outbound._transmit = lambda sender, recipients, data: (
        service.submit("scheduler", "secret-scheduler-token", data) and "2.0.0 sent"
    )
    seen = []
    registry = HandlerRegistry()

    def handle(message, ctx):
        seen.append(message)
        ctx.reply(text="Thanks")

    registry.register("scheduler", handle)
    handler = LmtpHandler(config, store, journal, registry, mailbox, {"scheduler": outbound})
    try:
        result = _deliver(handler, raw, ["scheduler@agents.northwind.test"])
        assert result.values[0].startswith("250")
        assert seen[0].trust == "high" and seen[0].tainted
        assert valid_owner_task(seen[0].task)
        assert not sent
        assert store.rows("SELECT rule FROM holds")[0]["rule"] == "tainted-input"
    finally:
        registry.stop()


def valid_owner_task(token):
    from amx.tasks import valid_token

    return token is not None and valid_token(token)


def test_live_stalwart_owner_plumbing_and_postfix_opt_out(tmp_path):
    import json

    import yaml

    from amx import live
    from amx.adapters.stalwart import expression
    from amx.config import load_config

    for mta in ("postfix", "stalwart"):
        path = tmp_path / f"{mta}.yaml"
        path.write_text(
            yaml.safe_dump(
                {
                    "mta": mta,
                    "profile": "private",
                    "org_domain": "home.arpa",
                    "state_dir": str(tmp_path / mta),
                }
            )
        )
        params = live.load_params(path)
        live.install(params)
        config = load_config(params.gateway_config)
        if mta == "postfix":
            assert config.people_domain is None and config.people_milter_port == 0
            continue
        assert config.people_domain == "home.arpa" and config.people_milter_port == 8892
        assert "home.arpa" in config.known_domains
        bundle = json.loads((params.secrets_dir / "stalwart/bundle.json").read_text())
        settings = {op["object"]: op for op in bundle["plan"]}
        milters = settings["MtaMilter"]
        assert milters["matchOn"] == ["hostname", "port"]
        assert milters["value"]["milter-gateway"]["enable"] == expression(
            "false", ("local_port == 25", "true")
        )
        assert milters["value"]["milter-people"]["port"] == 8892
        assert milters["value"]["milter-people"]["enable"] == expression(
            "false", ("local_port == 465 || local_port == 587", "true")
        )
        assert settings["MtaStageAuth"]["value"]["mustMatchSender"] == expression("true")
