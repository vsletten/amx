from __future__ import annotations

import json
from pathlib import Path

import pytest

from amx.testkit import read_jsonl


def test_read_jsonl_ignores_only_an_incomplete_final_append(tmp_path) -> None:
    path = tmp_path / "handler.jsonl"
    path.write_text('{"task":"complete"}\n{"task":', encoding="utf-8")

    assert read_jsonl(path) == [{"task": "complete"}]

    path.write_text('{"task": nope}\n', encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        read_jsonl(path)


ROOT = Path(__file__).resolve().parents[2]


def test_scenario_compose_subprocesses_clear_inherited_profiles(monkeypatch):
    import runpy
    from unittest.mock import Mock

    monkeypatch.setenv("COMPOSE_PROFILES", "test")
    support = runpy.run_path(str(ROOT / "scenarios/support.py"))
    run = Mock()
    monkeypatch.setattr(support["subprocess"], "run", run)
    support["compose"]("up", "-d", "runner-ct")
    support["compose_exec"]("runner-ct", "true")
    assert run.call_count == 2
    for invocation in run.call_args_list:
        assert "COMPOSE_PROFILES" not in invocation.kwargs["env"]
        assert invocation.kwargs["shell"] is False


@pytest.mark.parametrize("helper", ["compose", "compose_exec", "trace_task"])
def test_scenario_compose_subprocesses_use_current_environment(monkeypatch, helper) -> None:
    import os
    import runpy
    from unittest.mock import Mock

    monkeypatch.setenv("AMX_RUNNER_AX_TARGET", "original-target")
    support = runpy.run_path(str(ROOT / "scenarios/support.py"))
    # Module fixtures change the runner target after support has been imported.
    monkeypatch.setenv("COMPOSE_PROFILES", "test")
    run = Mock(return_value=Mock(stdout=""))
    monkeypatch.setattr(support["subprocess"], "run", run)
    arguments = {
        "compose": ("up", "-d", "--no-deps", "runner-ct"),
        "compose_exec": ("runner-ct", "true"),
        "trace_task": ("t_current_env",),
    }
    for target in ("", "restored-target", None):
        if target is None:
            monkeypatch.delenv("AMX_RUNNER_AX_TARGET")
        else:
            monkeypatch.setenv("AMX_RUNNER_AX_TARGET", target)
        run.reset_mock()
        support[helper](*arguments[helper])
        invocation = run.call_args_list[0]
        assert invocation.kwargs["env"] == {
            key: value for key, value in os.environ.items() if key != "COMPOSE_PROFILES"
        }
        assert invocation.kwargs["shell"] is False


def test_mta_ct_follows_the_mailhost_image_and_never_guesses(monkeypatch) -> None:
    monkeypatch.syspath_prepend(str(ROOT))
    import pytest

    from scenarios import support

    images = {"image": "amx-mailhost-ct"}
    calls: list[tuple[str, ...]] = []

    class Result:
        @property
        def stdout(self) -> str:
            return images["image"] + "\n"

    def compose(*arguments: str) -> Result:
        calls.append(arguments)
        return Result()

    monkeypatch.setattr(support, "compose", compose)
    monkeypatch.delenv("AMX_MTA_CT", raising=False)
    try:
        support.mta_ct.cache_clear()
        assert support.mta_ct() == "postfix"
        assert "-a" in calls[-1]  # a stopped or restarting mailhost still counts
        support.mta_ct.cache_clear()
        images["image"] = "stalwartlabs/stalwart:v0.16.23@sha256:be21"
        assert support.mta_ct() == "stalwart"
        support.mta_ct.cache_clear()
        images["image"] = ""
        with pytest.raises(RuntimeError, match="cannot tell"):
            support.mta_ct()
        monkeypatch.setenv("AMX_MTA_CT", "postfix")
        assert support.mta_ct() == "postfix"
        support.mta_ct.cache_clear()
        monkeypatch.setenv("AMX_MTA_CT", "Stalwart")
        with pytest.raises(ValueError, match="AMX_MTA_CT"):
            support.mta_ct()
    finally:
        support.mta_ct.cache_clear()


def test_mta_line_for_ct_reads_contosos_lines_only(monkeypatch) -> None:
    monkeypatch.syspath_prepend(str(ROOT))
    from scenarios import support

    postfix = (
        "2026-09-26T20:56:46Z mailhost-nw-1 postfix Sep 26 mail postfix/smtp: to=<a>\n"
        "2026-09-26T20:56:47Z mailhost-ct-1 postfix Sep 26 mail postfix/lmtp: to=<b>\n"
    )
    stalwart = "2026-09-26T20:56:47Z mailhost-ct stalwart queue.message-queued to=[b]\n"
    assert support.mta_line_for_ct(postfix) == "postfix"
    assert support.mta_line_for_ct(postfix.splitlines()[0]) is None  # northwind's only
    assert support.mta_line_for_ct(stalwart) == "stalwart"


def test_ct_lmtp_deferrals_read_each_mtas_deferral_lines(monkeypatch) -> None:
    monkeypatch.syspath_prepend(str(ROOT))
    from scenarios import support

    log = "\n".join(
        (
            "mailhost-ct-1 | postfix/lmtp: to=<intake+t_a_1@x>, status=deferred (450 4.2.1 busy)",
            "mailhost-ct-1 | postfix/lmtp: to=<intake+t_a_2@x>, status=sent (250 ok)",
            'mailhost-ct-1 | Z INFO x (delivery.dsn-temp-fail) to = "intake+t_a_3@x", '
            'code = 450, details = "4.2.1 busy"',
        )
    )

    class Result:
        stdout = log

    monkeypatch.setattr(support, "compose", lambda *_args: Result())
    monkeypatch.setattr(support, "mta_ct", lambda: "postfix")
    assert [line[-16:] for line in support.ct_lmtp_deferrals("t_a_", "4.2.1")] == [
        "(450 4.2.1 busy)"
    ]
    monkeypatch.setattr(support, "mta_ct", lambda: "stalwart")
    assert len(support.ct_lmtp_deferrals("t_a_", "4.2.1")) == 1
    assert support.ct_lmtp_deferrals("t_a_", "4.7.1") == []
    assert support.MILTER_DOWN_REPLY == {"postfix": "451 4.7.1", "stalwart": "451 4.3.5"}


def test_lmtp_redeliver_replays_the_journaled_bytes_inside_gateway_ct(monkeypatch) -> None:
    monkeypatch.syspath_prepend(str(ROOT))
    from scenarios import support

    calls: list[tuple[str, ...]] = []

    class Result:
        stdout = "250 2.0.0 duplicate already delivered\n"

    def compose_exec(*arguments: str) -> Result:
        calls.append(arguments)
        return Result()

    monkeypatch.setattr(support, "compose_exec", compose_exec)
    digest = "ab" + "0" * 62
    reply = support.lmtp_redeliver(digest, "scheduler+t_a@x", "intake+t_a@y")

    assert reply == "250 2.0.0 duplicate already delivered"
    service, python, flag, script, *argv = calls[0]
    assert (service, python, flag) == ("gateway-ct", "/app/.venv/bin/python", "-c")
    assert argv == [
        "127.0.0.1",
        "2424",
        f"/data/raw/ab/{digest}.eml",
        "scheduler+t_a@x",
        "intake+t_a@y",
    ]
    assert script == support.LMTP_CLIENT


def test_lmtp_client_greets_and_prints_the_recipients_reply(tmp_path, monkeypatch) -> None:
    monkeypatch.syspath_prepend(str(ROOT))
    import socket
    import subprocess
    import sys

    from amx.adapters.lmtp import LmtpController
    from scenarios import support

    seen: list[tuple[str | None, str, list[str], bytes]] = []

    class Handler:
        async def handle_DATA(self, _server, session, envelope) -> str:
            seen.append(
                (session.host_name, envelope.mail_from, envelope.rcpt_tos, envelope.content)
            )
            return "250 2.0.0 duplicate already delivered"

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    raw = b"Subject: S10\r\nMessage-ID: <s10@x>\r\n\r\nbody\r\n"
    path = tmp_path / "raw.eml"
    path.write_bytes(raw)
    controller = LmtpController(Handler(), hostname="127.0.0.1", port=port)
    controller.start()
    try:
        client = [sys.executable, "-c", support.LMTP_CLIENT, "127.0.0.1", str(port)]
        result = subprocess.run(
            [*client, str(path), "scheduler+t_a@x", "intake+t_a@y"],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
    finally:
        controller.stop()

    assert result.stdout.strip() == "250 2.0.0 duplicate already delivered"
    [(greeted_as, sender, recipients, content)] = seen
    assert greeted_as  # it sent LHLO; aiosmtpd answers 503 to a MAIL before one
    assert (sender, recipients, content) == ("scheduler+t_a@x", ["intake+t_a@y"], raw)


@pytest.mark.parametrize("mta", ["postfix", "stalwart"])
@pytest.mark.parametrize("state", ["queued", "delivered"])
def test_wait_for_lmtp_duplicate_waits_for_the_matching_success(monkeypatch, mta, state) -> None:
    monkeypatch.syspath_prepend(str(ROOT))
    from scenarios import support

    recipient = "intake+t_replay@agents.contoso.test"
    prefix = "mailhost-ct-1 | 2026-09-27T01:00:00Z "
    if mta == "postfix":
        receipt = (
            prefix + "Sep 27 mail postfix/lmtp[1]: ABC: "
            f"to=<{recipient}>, status=sent (250 2.0.0 duplicate already {state})"
        )
    else:
        receipt = (
            prefix + "2026-09-27T01:00:00Z INFO DSN success (delivery.dsn-success) "
            f'to = ["{recipient}"], to = "{recipient}", hostname = "gateway-ct", '
            f'code = 250, details = "duplicate already {state}"'
        )
    snapshots = iter([receipt.replace(recipient, "intake+t_other@agents.contoso.test"), receipt])
    slept = []
    monkeypatch.setattr(support, "postfix_log", lambda _service: next(snapshots))
    monkeypatch.setattr(support.time, "sleep", slept.append)

    result = support.wait_for_lmtp_duplicate(recipient)

    assert f"duplicate already {state}" in result
    assert slept == [0.25]  # the unrelated receipt did not finish the barrier


@pytest.mark.parametrize(
    "line",
    [
        "postfix/lmtp[1]: ABC: to=<intake+t_replay@x>, status=sent (250 2.0.0 queued)",
        "postfix/lmtp[1]: ABC: to=<intake+t_replay@x>, status=deferred "
        "(450 4.2.1 duplicate already queued)",
        '2026-09-27T01:00:00Z INFO queued (queue.message-queued) to = "intake+t_replay@x", '
        'code = 250, details = "duplicate already queued"',
        '2026-09-27T01:00:00Z INFO failure (delivery.dsn-temp-fail) to = "intake+t_replay@x", '
        'code = 450, details = "duplicate already queued"',
    ],
)
def test_wait_for_lmtp_duplicate_times_out_without_a_duplicate_receipt(monkeypatch, line) -> None:
    monkeypatch.syspath_prepend(str(ROOT))
    from scenarios import support

    times = iter([0.0, 0.0, 1.0])
    monkeypatch.setattr(support.time, "monotonic", lambda: next(times))
    monkeypatch.setattr(support.time, "sleep", lambda _delay: None)
    monkeypatch.setattr(
        support, "postfix_log", lambda _service: f"mailhost-ct-1 | 2026-09-27T01:00:00Z {line}"
    )

    with pytest.raises(TimeoutError, match="MX did not report an LMTP duplicate"):
        support.wait_for_lmtp_duplicate("intake+t_replay@x", timeout=0.5)


@pytest.mark.parametrize(
    "image,expected",
    [
        ("amx-mailhost-ct", "postfix"),
        ("stalwartlabs/stalwart:v0.16.23", "stalwart"),
    ],
)
def test_mta_ct_resolves_compose_image_ids_from_actual_container(monkeypatch, image, expected):
    from types import SimpleNamespace

    monkeypatch.syspath_prepend(str(ROOT))
    from scenarios import support

    monkeypatch.delenv("AMX_MTA_CT", raising=False)
    monkeypatch.setattr(
        support,
        "compose",
        lambda *args: SimpleNamespace(
            stdout="container-id" if "-q" in args else "sha256:actual-image",
        ),
    )

    def inspect(args, **kwargs):
        assert args == ["docker", "inspect", "--format", "{{.Config.Image}}", "container-id"]
        assert kwargs["check"]
        return SimpleNamespace(stdout=image)

    monkeypatch.setattr(support.subprocess, "run", inspect)
    support.mta_ct.cache_clear()
    try:
        assert support.mta_ct() == expected
    finally:
        support.mta_ct.cache_clear()
