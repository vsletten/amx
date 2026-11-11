from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from amx.journal import Journal
from amx.narrate import Gateway, Narrator, mta_line, postfix_line, scenario_files, stalwart_line
from amx.store import Store


def _scenarios(tmp_path: Path) -> Path:
    directory = tmp_path / "scenarios"
    directory.mkdir()
    for name in ("test_s04_backpressure.py", "test_s11_llm_agents.py", "support.py"):
        (directory / name).write_text("", encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize("scenario", ["S04", "s4", "4", "S04b"])
def test_scenario_ids_map_to_their_files(tmp_path, scenario) -> None:
    root = _scenarios(tmp_path)
    assert scenario_files(root, [scenario], False) == [
        root / "scenarios" / "test_s04_backpressure.py"
    ]


def test_all_runs_every_numbered_scenario_file(tmp_path) -> None:
    root = _scenarios(tmp_path)
    assert [path.name for path in scenario_files(root, [], True)] == [
        "test_s04_backpressure.py",
        "test_s11_llm_agents.py",
    ]


@pytest.mark.parametrize("scenario", ["S99", "backpressure", ""])
def test_unknown_scenarios_are_errors(tmp_path, scenario) -> None:
    with pytest.raises(ValueError):
        scenario_files(_scenarios(tmp_path), [scenario], False)


def test_postfix_lines_are_condensed_to_deliveries_and_refusals() -> None:
    sent = (
        "mailhost-nw-1  | 2026-09-25T21:56:53.902704421Z Sep 25 21:56:53 mail "
        "postfix/smtp[2905]: AB09C2E435A9: to=<intake+t_1@agents.contoso.test>, "
        "relay=mail.contoso.test[172.30.0.20]:25, delay=6.2, delays=6/0/0.03/0.15, dsn=2.0.0, "
        "status=sent (250 2.0.0 Ok: queued as BEFA82E450D5)"
    )
    assert postfix_line(sent) == (
        "2026-09-25T21:56:53.902704421Z",
        "2026-09-25T21:56:53.902704421Z mailhost-nw postfix/smtp "
        "to=<intake+t_1@agents.contoso.test> sent (250 2.0.0 Ok: queued as BEFA82E450D5)",
    )
    refused = (
        "mailhost-ct-1  | 2026-09-25T21:56:47.709136446Z Sep 25 21:56:47 mail "
        "postfix/smtpd[2822]: NOQUEUE: milter-reject: MAIL from x[172.30.0.10]: 451 4.7.1 "
        "Service unavailable - try again later; from=<a@b.test> proto=ESMTP helo=<x>"
    )
    rendered = postfix_line(refused)
    assert rendered is not None
    assert rendered[1].endswith(
        "refused: MAIL from x[172.30.0.10]: 451 4.7.1 Service unavailable - try again later"
    )
    queue = (
        "mailhost-nw-1  | 2026-09-25T21:56:53.721861586Z Sep 25 21:56:53 mail "
        "postfix/qmgr[195]: AB09C2E435A9: from=<a@b.test>, size=1731, nrcpt=1 (queue active)"
    )
    assert postfix_line(queue) is None
    assert postfix_line("not a compose line") is None


def test_stalwart_lines_are_condensed_to_queue_delivery_and_milter_events() -> None:
    prefix = "mailhost-ct-1  | 2026-09-26T05:22:07.123456789Z 2026-09-26T05:22:07Z INFO "
    failed = (
        prefix + "DSN temporary failure notification (delivery.dsn-temp-fail) queueId = 3, "
        'queueName = "local", from = "scheduler+t_1@agents.northwind.test", '
        'to = ["intake+t_1@agents.contoso.test"], size = 228, total = 1, '
        'to = "intake+t_1@agents.contoso.test", hostname = "gateway-ct", code = 450, '
        'details = "4.2.1 agent busy", total = 3'
    )
    assert stalwart_line(failed) == (
        "2026-09-26T05:22:07.123456789Z",
        "2026-09-26T05:22:07.123456789Z mailhost-ct stalwart delivery.dsn-temp-fail "
        "to=intake+t_1@agents.contoso.test hostname=gateway-ct code=450 details=4.2.1 agent busy",
    )
    milter = (
        prefix.replace("INFO", "WARN") + 'Milter I/O error (milter.io-error) listenerId = "smtp", '
        'localPort = 25, details = "Network is unreachable (os error 101)", elapsed = 0ms'
    )
    rendered = stalwart_line(milter)
    assert rendered is not None
    assert rendered[1].endswith(
        "stalwart milter.io-error details=Network is unreachable (os error 101)"
    )
    noise = prefix + 'SMTP EHLO command (smtp.ehlo) listenerId = "smtp", domain = "x"'
    assert stalwart_line(noise) is None
    accept = prefix + 'Milter action accept (milter.action-accept) id = "m", elapsed = 1ms'
    assert stalwart_line(accept) is None
    assert stalwart_line("mailhost-ct-1  | 2026-09-26T05:22:07Z plain text") is None
    # The runner follows both kinds of mailhost through one condenser.
    assert mta_line(failed) == stalwart_line(failed)
    postfix = (
        "mailhost-nw-1  | 2026-09-25T21:56:53.9Z Sep 25 21:56:53 mail postfix/smtp[2905]: "
        "AB: to=<a@b.test>, relay=x, status=sent (250 ok)"
    )
    assert mta_line(postfix) == postfix_line(postfix)


def test_narrator_reports_only_events_after_it_started(tmp_path) -> None:
    state = tmp_path / "nw"
    state.mkdir()
    store = Store(state / "journal.sqlite")
    journal = Journal(state, store)
    store.record_policy("rcpt", "recipient-ok", "accept", None, "t_old", "before the run")
    journal.append(
        b"old",
        direction="inbound",
        identity=None,
        task="t_old",
        message_id="<o@x>",
        event="lmtp-received",
        detail="before the run",
    )
    log = state / "handler.jsonl"
    log.write_text(json.dumps({"kind": "llm", "at": time.time() - 60, "agent": "planner"}) + "\n")

    narrator = Narrator([Gateway("agents.northwind.test", state)])
    assert narrator.poll() == []

    store.record_policy("connect", "connect-ok", "accept", None, None, "healthcheck")
    store.record_policy("rcpt", "agent-watermark", "tempfail", "450 4.2.1", "t_1", "busy")
    journal.append(
        b"new",
        direction="inbound",
        identity=None,
        task="t_1",
        message_id="<n@x>",
        event="lmtp-received",
        detail="recipient=intake",
    )
    with log.open("a", encoding="utf-8") as stream:
        record = {
            "kind": "llm",
            "at": time.time(),
            "agent": "planner",
            "lane": "agent",
            "tool": "reply",
            "decision": "accept",
            "slots": ["tue-0900"],
            "latency_ms": 900,
        }
        stream.write(json.dumps(record) + "\n")
        stream.write('{"kind": "llm", "half-written')  # an append still in flight

    lines = [line for _at, line in narrator.poll()]
    assert len(lines) == 3, lines
    assert any("milter RCPT agent-watermark -> tempfail 450 4.2.1 busy" in line for line in lines)
    assert any("lmtp lmtp-received journal #2" in line for line in lines)
    assert any("llm planner (agent) -> reply accept tue-0900 900 ms" in line for line in lines)
    assert not any("healthcheck" in line for line in lines)
    assert narrator.poll() == []
