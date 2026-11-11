from __future__ import annotations

import time
import uuid

import pytest

from amx.sdk import Agent, Sent
from amx.store import Store
from amx.testkit import read_jsonl
from scenarios.support import (
    CT_DB,
    DEV_TLS_CA,
    HANDLER_LOG,
    MILTER_DOWN_REPLY,
    NW_HANDLER_LOG,
    compose,
    ct_lmtp_deferrals,
    mta_ct,
    postfix_log,
    queued_at,
    trace_task,
    wait_for_handler,
    wait_for_task,
)


def _scheduler() -> Agent:
    return Agent(
        "scheduler@agents.northwind.test",
        "smtp://127.0.0.1:2587",
        "dev-scheduler-token",
        tls_ca_file=str(DEV_TLS_CA),
    )


def _deferred(log: str, needle: str, code: str) -> list[str]:
    return [
        line
        for line in log.splitlines()
        if needle in line and "status=deferred" in line and code in line
    ]


def _wait(predicate, timeout: float, what: str) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.25)
    raise TimeoutError(what)


@pytest.mark.integration
def test_s04a_watermark_defers_excess_at_rcpt_and_loses_nothing() -> None:
    started = time.monotonic()
    suffix = uuid.uuid4().hex[:8]
    prefix = f"t_s04a_{suffix}_"
    scheduler = _scheduler()
    sent: list[Sent] = [
        scheduler.send(
            to="intake@agents.contoso.test",
            subject=f"[slow] S04a {suffix} request {index}",
            intent="request",
            task=f"{prefix}{index}",
            text=f"Slow request {index} of six.",
        )
        for index in range(6)
    ]
    submitted = time.monotonic() - started

    for message in sent:
        wait_for_handler(message.message_id, timeout=110 - (time.monotonic() - started))
    handled = time.monotonic() - started

    store = Store(CT_DB)
    _wait(
        lambda: all(
            store.rows("SELECT 1 FROM deliveries WHERE message_id = ?", (message.message_id,))
            for message in sent
        ),
        timeout=15,
        what="queued deliveries did not all complete",
    )
    rows = read_jsonl(HANDLER_LOG)
    for message in sent:
        assert [row["message_id"] for row in rows].count(message.message_id) == 1
        assert len(store.rows("SELECT 1 FROM journal WHERE message_id = ?", (message.message_id,)))
        assert len(
            store.rows("SELECT 1 FROM deliveries WHERE message_id = ?", (message.message_id,))
        )
    for message in sent:
        assert wait_for_task(message.task, path=NW_HANDLER_LOG, intent="response")
        assert not [
            row
            for row in read_jsonl(NW_HANDLER_LOG)
            if row.get("task") == message.task and row.get("intent") == "error"
        ]

    busy_at_rcpt = store.rows(
        "SELECT task FROM policy_events WHERE rule = 'agent-watermark' AND task LIKE ?",
        (f"{prefix}%",),
    )
    deferred = _deferred(postfix_log("mailhost-nw"), prefix, "450 4.2.1")
    assert busy_at_rcpt, "no RCPT was refused with the watermark"
    assert deferred, "northwind's Postfix never logged a 450 4.2.1 deferral"
    # The admission a message won at RCPT holds to its end of DATA. Stalwart replays the RCPTs
    # on a new milter connection at the DATA stage; the gateway ties it to the RCPT stage's
    # (PLAN §5.8), so there too every deferral is at RCPT and each RCPT is recorded once.
    at_data = [line for line in deferred if "in reply to end of DATA command" in line]
    assert not at_data, at_data[:1]
    admitted = store.rows(
        "SELECT task, COUNT(*) AS n FROM policy_events"
        " WHERE rule = 'recipient-ok' AND task LIKE ? GROUP BY task",
        (f"{prefix}%",),
    )
    assert sorted(int(row["n"]) for row in admitted) == [1] * 6, [tuple(r) for r in admitted]
    # Admission accounting is exact: every excess message waited at the sender, none at contoso.
    assert not ct_lmtp_deferrals(prefix, "4.2.1"), "LMTP had to refuse"
    _wait(lambda: not queued_at("mailhost-nw", prefix), 30, "northwind queue did not drain")
    elapsed = time.monotonic() - started
    assert elapsed < 120

    starts = sorted(
        float(row["started_at"])
        for row in rows
        if row["message_id"] in {message.message_id for message in sent}
    )
    print(
        f"S04a TIMING: submit6={submitted:.1f}s all-handled={handled:.1f}s "
        f"drained={elapsed:.1f}s handler-span={starts[-1] - starts[0]:.1f}s"
    )
    print(
        f"S04a BACKPRESSURE ({mta_ct()}): rcpt-450s={len(busy_at_rcpt)} "
        f"nw-deferrals={len(deferred)} at-rcpt={len(deferred) - len(at_data)} "
        f"at-end-of-data={len(at_data)} recipient-ok-rows={sum(int(r['n']) for r in admitted)} "
        f"handled=6/6 journal=6 deliveries=6 lost=0"
    )
    print(f"S04a NW POSTFIX: {deferred[0].split(' postfix/', 1)[-1]}")
    trace_task(str(busy_at_rcpt[0]["task"]))


@pytest.mark.integration
def test_s04b_gateway_outage_tempfails_queues_at_sender_and_drains() -> None:
    started = time.monotonic()
    task = f"t_s04b_{uuid.uuid4().hex[:10]}"
    milter_down = MILTER_DOWN_REPLY[mta_ct()]
    compose("stop", "-t", "2", "gateway-ct")
    stopped = time.monotonic() - started
    try:
        sent = _scheduler().send(
            to="intake@agents.contoso.test",
            subject=f"S04b outage {task}",
            intent="request",
            task=task,
            text="Please process this request once your gateway is back.",
        )
        _wait(
            lambda: bool(_deferred(postfix_log("mailhost-nw"), task, milter_down)),
            timeout=20,
            what=f"northwind never logged the {milter_down} tempfail",
        )
        tempfailed = time.monotonic() - started
        assert queued_at("mailhost-nw", task)
    finally:
        compose("start", "gateway-ct")
    restarted = time.monotonic() - started

    wait_for_handler(sent.message_id, timeout=90)
    delivered = time.monotonic() - started
    _wait(lambda: not queued_at("mailhost-nw", task), 30, "northwind queue did not drain")
    assert wait_for_task(task, path=NW_HANDLER_LOG, intent="response")
    deferral = _deferred(postfix_log("mailhost-nw"), task, milter_down)[0]
    print(
        f"S04b TIMING: stop={stopped:.1f}s 451={tempfailed:.1f}s restart={restarted:.1f}s "
        f"delivered={delivered:.1f}s"
    )
    print(f"S04b NW POSTFIX: {deferral.split(' postfix/', 1)[-1]}")
    trace_task(task)
