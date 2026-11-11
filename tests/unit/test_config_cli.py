from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from amx.cli import app
from amx.config import load_config
from amx.journal import Journal
from amx.store import Store


def _config(path: Path) -> None:
    path.write_text(
        """
domain: example.test
agent_domain: agents.example.test
data_dir: data
mailbox: {host: mail.example.test}
agents: {}
trust: []
""".lstrip(),
        encoding="utf-8",
    )


def test_agent_add_generates_key_mailbox_and_dns_record(tmp_path) -> None:
    config_path = tmp_path / "gateway.yaml"
    users = tmp_path / "dev-users"
    users.write_text("gateway|dev-gateway\n", encoding="utf-8")
    _config(config_path)
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "agent",
            "add",
            "intake",
            "--config",
            str(config_path),
            "--handler",
            "amx.examples.intake:handle",
            "--keys-dir",
            str(tmp_path / "keys"),
            "--dev-users",
            str(users),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "intake._domainkey.agents.example.test" in result.output
    private_key = tmp_path / "keys" / "intake.private.pem"
    assert private_key.is_file()
    assert private_key.stat().st_mode & 0o777 == 0o600
    assert "intake@agents.example.test|dev-intake" in users.read_text(encoding="utf-8")
    loaded = load_config(config_path)
    assert loaded.agents["intake"].handler == "amx.examples.intake:handle"

    dns = runner.invoke(
        app,
        [
            "dns",
            "render",
            "--config",
            str(config_path),
            "--keys-dir",
            str(tmp_path / "keys"),
        ],
    )
    assert dns.exit_code == 0, dns.output
    assert '_dmarc IN TXT "v=DMARC1; p=reject"' in dns.output
    assert "intake._domainkey IN TXT" in dns.output
    assert "intake._agents IN TXT" in dns.output


def test_config_rejects_non_mapping_trust(tmp_path) -> None:
    path = tmp_path / "bad.yaml"
    values = {
        "domain": "example.test",
        "agent_domain": "agents.example.test",
        "mailbox": {"host": "mail.example.test"},
        "trust": {},
    }
    path.write_text(yaml.safe_dump(values), encoding="utf-8")
    try:
        load_config(path)
    except ValueError as error:
        assert str(error) == "trust must be a list"
    else:
        raise AssertionError("invalid trust value was accepted")


def test_trace_merges_two_gateway_stores_and_repeatable_postfix_logs(tmp_path) -> None:
    config_paths: list[Path] = []
    data_dirs: list[Path] = []
    task = "t_trace"
    for name in ("northwind", "contoso"):
        root = tmp_path / name
        root.mkdir()
        config_path = root / "gateway.yaml"
        _config(config_path)
        data_dir = root / "host-state"
        store = Store(data_dir / "journal.sqlite")
        store.record_policy("rcpt", f"{name}-rule", "accept", None, task, "policy detail")
        Journal(data_dir, store).append(
            f"Message-ID: <{name}@test>\r\n\r\nbody\r\n".encode(),
            direction="inbound",
            task=task,
            message_id=f"<{name}@test>",
            event="test-event",
            detail="journal detail",
        )
        if name == "northwind":
            journal = Journal(data_dir, store)
            for event in ("held", "released"):
                journal.append(
                    f"Message-ID: <held@{name}>\r\n\r\nbody\r\n".encode(),
                    direction="outbound",
                    task=task,
                    message_id=f"<held@{name}>",
                    event=event,
                    detail="rule=first-contact-domain",
                )
            store.record_policy("hold", "hold-not-pending", "ignore", None, task, "not pending")
        config_paths.append(config_path)
        data_dirs.append(data_dir)
    postfix_log = tmp_path / "compose.log"
    postfix_log.write_text(
        "mailhost-ct-1 | 2026-09-24T12:00:00.123Z postfix/smtpd[1]: "
        "to=<intake+t_trace@agents.example.test>, status=sent\n"
        "mailhost-ct-1 | 2026-09-24T12:00:01.123Z postfix/smtpd[1]: unrelated\n",
        encoding="utf-8",
    )
    arguments = ["trace", task]
    for config_path in config_paths:
        arguments.extend(("--config", str(config_path)))
    for data_dir in data_dirs:
        arguments.extend(("--data-dir", str(data_dir)))
    arguments.extend(("--postfix-log", str(postfix_log)))

    result = CliRunner().invoke(app, arguments)
    assert result.exit_code == 0, result.output
    assert "northwind-rule" in result.output
    assert "contoso-rule" in result.output
    assert result.output.count("lmtp test-event") == 2
    assert "submission held" in result.output
    assert "holdwatch released" in result.output
    assert "holdwatch HOLD hold-not-pending -> ignore" in result.output
    assert "mailhost-ct-1 postfix postfix/smtpd[1]" in result.output
    assert "unrelated" not in result.output


def test_installed_gateway_entry_point_imports_and_renders_help() -> None:
    executable = Path(sys.executable).parent / "amx-gateway"
    result = subprocess.run(
        [str(executable), "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "run an AMX milter + LMTP gateway" in result.stdout


def test_mailbox_master_login_defaults_to_dovecot_and_follows_yaml_or_environment(
    tmp_path, monkeypatch
) -> None:
    path = tmp_path / "gateway.yaml"
    _config(path)
    monkeypatch.delenv("AMX_MAILBOX_MASTER_LOGIN", raising=False)
    mailbox = load_config(path).mailbox
    assert mailbox.login_for("intake@agents.example.test") == "intake@agents.example.test*gateway"

    values = yaml.safe_load(path.read_text(encoding="utf-8"))
    values["mailbox"]["master_login"] = "{user}%{master}@example.test"
    path.write_text(yaml.safe_dump(values), encoding="utf-8")
    assert load_config(path).mailbox.login_for("a@agents.example.test") == (
        "a@agents.example.test%gateway@example.test"
    )

    # compose.stalwart.yaml points contoso's gateway at Stalwart without a second YAML (M6).
    monkeypatch.setenv("AMX_MAILBOX_MASTER_LOGIN", "{user}%{master}@contoso.test")
    assert load_config(path).mailbox.login_for("a@agents.contoso.test") == (
        "a@agents.contoso.test%gateway@contoso.test"
    )
    monkeypatch.setenv("AMX_MAILBOX_MASTER_LOGIN", "gateway")
    with pytest.raises(ValueError, match=r"\{user\}"):
        load_config(path)


def test_mailbox_append_logs_in_with_the_configured_master_login(monkeypatch) -> None:
    import imaplib

    from amx.config import MailboxConfig
    from amx.mailbox import MailboxAppender

    calls: list[tuple[str, ...]] = []

    class FakeImap:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            calls.append(("connect", host, str(port)))

        def __enter__(self):
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def login(self, user: str, password: str) -> None:
            calls.append(("login", user, password))

        def append(self, folder: str, _flags, _date, _raw: bytes):
            calls.append(("append", folder))
            return "OK", [b"done"]

    monkeypatch.setattr(imaplib, "IMAP4", FakeImap)
    config = MailboxConfig(
        host="mailhost-ct", master_password="pw", master_login="{user}%{master}@contoso.test"
    )
    MailboxAppender(config).append("intake@agents.contoso.test", b"raw", folder="Sent")
    assert calls == [
        ("connect", "mailhost-ct", "143"),
        ("login", "intake@agents.contoso.test%gateway@contoso.test", "pw"),
        ("append", "Sent"),
    ]


def test_trace_includes_condensed_stalwart_lines_for_the_task(tmp_path) -> None:
    config_path = tmp_path / "gateway.yaml"
    _config(config_path)
    log = tmp_path / "compose.log"
    log.write_text(
        "mailhost-ct-1  | 2026-09-26T05:21:37.100Z 2026-09-26T05:21:37Z INFO Queued message for "
        'delivery (queue.message-queued) queueId = 1, from = "scheduler+t_st@agents.n.test", '
        'to = ["intake+t_st@agents.example.test"], size = 228\n'
        "mailhost-ct-1  | 2026-09-26T05:21:37.200Z 2026-09-26T05:21:37Z INFO SMTP EHLO command "
        '(smtp.ehlo) domain = "t_st.example"\n'
        "mailhost-ct-1  | 2026-09-26T05:21:37.300Z 2026-09-26T05:21:37Z INFO DSN success "
        'notification (delivery.dsn-success) to = ["intake+t_st@agents.example.test"], '
        'to = "intake+t_st@agents.example.test", hostname = "gateway-ct", code = 250, '
        'details = "2.0.0 queued"\n',
        encoding="utf-8",
    )
    result = CliRunner().invoke(
        app,
        [
            *("trace", "t_st", "--config", str(config_path)),
            *("--data-dir", str(tmp_path), "--mta-log", str(log)),
        ],
    )
    assert result.exit_code == 0, result.output
    lines = result.output.splitlines()
    assert lines == [
        "2026-09-26T05:21:37.100Z mailhost-ct stalwart queue.message-queued "
        'to=["intake+t_st@agents.example.test"]',
        "2026-09-26T05:21:37.300Z mailhost-ct stalwart delivery.dsn-success "
        "to=intake+t_st@agents.example.test hostname=gateway-ct code=250 details=2.0.0 queued",
    ]


def test_a_master_login_template_with_an_unknown_placeholder_fails_at_load(
    tmp_path, monkeypatch
) -> None:
    path = tmp_path / "gateway.yaml"
    _config(path)
    for template in (
        "{user}%{master}@{domain}",
        "{user}{user.name}*{master}",
        "{user}{user.upper}*{master}",
        "{user}{user[x]}*{master}",
        "{user!r}*{master}",
        "{user:>20}*{master}",
        "{user}*{0}",
        "{user}*{master",
    ):
        monkeypatch.setenv("AMX_MAILBOX_MASTER_LOGIN", template)
        with pytest.raises(ValueError, match="bad template"):
            load_config(path)


def test_hold_queue_defaults_to_the_agents_own_outbox(tmp_path, monkeypatch) -> None:
    from amx.holds import APPROVED_FOLDER, HELD_FOLDER, REJECTED_FOLDER, hold_queue

    path = tmp_path / "gateway.yaml"
    _config(path)
    monkeypatch.delenv("AMX_MAILBOX_HOLD_OWNER", raising=False)
    monkeypatch.delenv("AMX_MAILBOX_HOLD_PREFIX", raising=False)
    config = load_config(path)
    assert (config.mailbox.hold_owner, config.mailbox.hold_prefix) == (None, "Outbox/")
    queue = hold_queue(config, "intake")
    assert queue.mailbox == "intake@agents.example.test"
    assert (queue.held, queue.approved, queue.rejected) == (
        HELD_FOLDER,
        APPROVED_FOLDER,
        REJECTED_FOLDER,
    )
    assert queue.own is True


def test_hold_owner_and_prefix_follow_yaml_or_environment(tmp_path, monkeypatch) -> None:
    from amx.holds import hold_queue

    path = tmp_path / "gateway.yaml"
    _config(path)
    monkeypatch.delenv("AMX_MAILBOX_HOLD_OWNER", raising=False)
    monkeypatch.delenv("AMX_MAILBOX_HOLD_PREFIX", raising=False)
    values = yaml.safe_load(path.read_text(encoding="utf-8"))
    values["mailbox"] |= {"hold_owner": "Holds@Example.test", "hold_prefix": "Queue/{agent}/"}
    path.write_text(yaml.safe_dump(values), encoding="utf-8")
    queue = hold_queue(load_config(path), "intake")
    assert (queue.mailbox, queue.held, queue.own) == (
        "holds@example.test",
        "Queue/intake/Held",
        False,
    )

    # compose.stalwart.yaml moves contoso's queues off the agents without a second YAML (PLAN §5.8).
    monkeypatch.setenv("AMX_MAILBOX_HOLD_OWNER", "holds@contoso.test")
    monkeypatch.setenv("AMX_MAILBOX_HOLD_PREFIX", "Holds/{agent}/")
    queue = hold_queue(load_config(path), "inspections")
    assert (queue.mailbox, queue.approved, queue.rejected) == (
        "holds@contoso.test",
        "Holds/inspections/Approved",
        "Holds/inspections/Rejected",
    )
    # An agent that owned the queues could approve every one of them (a Stalwart owner may do
    # anything in its own folders), so no owner in the agent domain loads.
    for owner in ("intake@agents.example.test", "Queue@Agents.Example.test"):
        monkeypatch.setenv("AMX_MAILBOX_HOLD_OWNER", owner)
        with pytest.raises(ValueError, match="must not be in the agent domain"):
            load_config(path)


def test_a_bad_hold_location_fails_at_load(tmp_path, monkeypatch) -> None:
    path = tmp_path / "gateway.yaml"
    _config(path)
    monkeypatch.delenv("AMX_MAILBOX_HOLD_OWNER", raising=False)
    for prefix, message in (
        ("Outbox", "ending in '/'"),
        ("/Outbox/", "ending in '/'"),
        ("Outbox//", "ending in '/'"),
        ("Holds/{name}/", "bad template"),
        ("Holds/{agent!r}/", "bad template"),
        ("Holds/{agent/", "bad template"),
    ):
        monkeypatch.setenv("AMX_MAILBOX_HOLD_PREFIX", prefix)
        with pytest.raises(ValueError, match=message):
            load_config(path)
    # Without an owner the queue must be the Outbox/* Dovecot's ACL covers: the agent could
    # create any other folder in its own mailbox, and approve from it.
    for prefix in ("Queue/", "Holds/{agent}/"):
        monkeypatch.setenv("AMX_MAILBOX_HOLD_PREFIX", prefix)
        with pytest.raises(ValueError, match=r"needs a mailbox\.hold_owner"):
            load_config(path)
    # A shared owner needs one folder tree per agent, or each watcher would flag the others' mail.
    monkeypatch.setenv("AMX_MAILBOX_HOLD_OWNER", "holds@example.test")
    monkeypatch.setenv("AMX_MAILBOX_HOLD_PREFIX", "Holds/")
    with pytest.raises(ValueError, match=r"must contain \{agent\}"):
        load_config(path)
    monkeypatch.setenv("AMX_MAILBOX_HOLD_PREFIX", "Holds/{agent}/")
    for owner in ("holds", "holds@", "@example.test"):
        monkeypatch.setenv("AMX_MAILBOX_HOLD_OWNER", owner)
        with pytest.raises(ValueError, match="must be an address"):
            load_config(path)


def test_quote_mailbox_leaves_atoms_and_quotes_the_rest() -> None:
    from amx.mailbox import quote_mailbox

    assert quote_mailbox("Outbox/Held") == "Outbox/Held"
    assert quote_mailbox("INBOX") == "INBOX"
    assert quote_mailbox("Shared Folders/holds@contoso.test/Holds/intake/Held") == (
        '"Shared Folders/holds@contoso.test/Holds/intake/Held"'
    )
    assert quote_mailbox('a"b\\c') == '"a\\"b\\\\c"'
    assert quote_mailbox("") == '""'
    for special in "(){%*":
        assert quote_mailbox(f"a{special}b") == f'"a{special}b"'


def test_mailbox_append_quotes_a_shared_folder_name(monkeypatch) -> None:
    import imaplib

    from amx.config import MailboxConfig
    from amx.mailbox import MailboxAppender

    appended: list[str] = []

    class FakeImap:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def login(self, _user: str, _password: str) -> None:
            return None

        def append(self, folder: str, _flags, _date, _raw: bytes):
            appended.append(folder)
            return "OK", [b"done"]

    monkeypatch.setattr(imaplib, "IMAP4", FakeImap)
    MailboxAppender(MailboxConfig(host="mail")).append("a@b", b"raw", folder="Shared Folders/x")
    assert appended == ['"Shared Folders/x"']


def test_dns_zone_names_the_zone_records_go_in(tmp_path) -> None:
    """The live YAML's domain is the agent domain; its records are named for the org's zone."""
    path = tmp_path / "gateway.yaml"
    base = {"domain": "agents.example.com", "agent_domain": "agents.example.com"}
    path.write_text(yaml.safe_dump(base), encoding="utf-8")
    assert load_config(path).zone == "agents.example.com"
    path.write_text(yaml.safe_dump({**base, "dns_zone": "ExAmPlE.CoM."}), encoding="utf-8")
    assert load_config(path).zone == "example.com"
    path.write_text(yaml.safe_dump({**base, "dns_zone": "other.test"}), encoding="utf-8")
    with pytest.raises(ValueError, match=r"not inside dns_zone other\.test"):
        load_config(path)
