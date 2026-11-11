"""Native milter callbacks: true bytes and exact encoded ingress boundaries (SH-42)."""

from email import policy
from email.parser import BytesParser

import pytest
from test_attachments import PDF
from test_milter import _agent_request, _feed, _milter, _verified

from amx.attachments import DEFAULT_BLOCKED_TYPES
from amx.config import LimitsConfig, load_config

Milter = pytest.importorskip("Milter")


@pytest.mark.parametrize("content", [b"MZfake", b"\x7fELFfake", b"\xfe\xed\xfa\xcf", b"#!/bin/sh"])
def test_eod_refuses_disguised_executable_by_true_type(tmp_path, monkeypatch, content):
    _verified(monkeypatch)
    make, _, replies = _milter(tmp_path)
    milter = make()
    assert milter.envrcpt("<intake+t_1@agents.example.test>") == Milter.CONTINUE
    parsed = BytesParser(policy=policy.SMTP).parsebytes(
        _agent_request(["intake+t_1@agents.example.test"])
    )
    parsed.add_attachment(content, maintype="application", subtype="pdf", filename="safe.pdf")
    _feed(milter, parsed.as_bytes(policy=policy.SMTP))
    assert milter.eom() == Milter.REJECT
    assert replies[-1][:2] == ("552", "5.3.4")
    assert "attachment" in replies[-1][-1]


@pytest.mark.parametrize("over", [False, True])
def test_eod_exact_size_boundary_with_pdf(tmp_path, monkeypatch, over):
    _verified(monkeypatch)
    parsed = BytesParser(policy=policy.SMTP).parsebytes(
        _agent_request(["intake+t_1@agents.example.test"])
    )
    parsed.add_attachment(PDF, maintype="application", subtype="pdf", filename="a.pdf")
    raw = parsed.as_bytes(policy=policy.SMTP)
    make, _, replies = _milter(tmp_path, limits=LimitsConfig(max_bytes=len(raw) - int(over)))
    milter = make()
    assert milter.envrcpt("<intake+t_1@agents.example.test>") == Milter.CONTINUE
    _feed(milter, raw)
    assert milter.eom() == (Milter.REJECT if over else Milter.ACCEPT)
    if over:
        assert replies[-1][:2] == ("552", "5.3.4")


def test_loaded_defaults_and_examples_block_executables(tmp_path):
    config = tmp_path / "gateway.yaml"
    config.write_text("domain: example.test\nagent_domain: agents.example.test\nagents: {}\n")
    assert load_config(config).limits.blocked_attachment_types == DEFAULT_BLOCKED_TYPES
    for path in ("deploy/gateway/northwind.yaml", "deploy/gateway/contoso.yaml"):
        assert load_config(path).limits.blocked_attachment_types == DEFAULT_BLOCKED_TYPES


@pytest.mark.parametrize("over", [False, True])
def test_sibling_milter_allows_internal_headroom_but_still_has_a_cap(tmp_path, monkeypatch, over):
    _verified(monkeypatch)
    raw = _agent_request(["intake+t_1@agents.example.test"])
    # The gateway's signed/rendered copy may exceed ingress size; its trusted hop has 3x room.
    limit = (len(raw) - 1) // 3 if over else (len(raw) + 2) // 3
    make, _, replies = _milter(
        tmp_path, limits=LimitsConfig(max_bytes=limit), listener_sibling=lambda _: True
    )
    milter = make(None)
    milter.getsymval = lambda _: "amx-sibling"
    assert milter.connect("fixture", 2, ("127.0.0.1", 12345)) == Milter.CONTINUE
    milter.envfrom("<scheduler@agents.sender.test>")
    assert milter.envrcpt("<intake+t_1@agents.example.test>") == Milter.CONTINUE
    _feed(milter, raw)
    assert milter.eom() == (Milter.REJECT if over else Milter.ACCEPT)
    if over:
        assert replies[-1][:2] == ("552", "5.3.4")


def test_live_hop_limits_follow_lane_configuration(tmp_path):
    from pathlib import Path

    from test_live import _params_file
    from test_submission import _config

    from amx import live
    from amx.adapters.lmtp import controller as lmtp_controller
    from amx.adapters.submission import SubmissionService, controller
    from amx.journal import Journal
    from amx.store import Store

    params = live.load_params(
        _params_file(
            tmp_path,
            limits={
                "max_bytes": 10485760,
                "blocked_attachment_types": sorted(DEFAULT_BLOCKED_TYPES),
            },
        )
    )
    variables = live.compose_variables(params)
    assert variables["MAX_BYTES"] == "10485760"
    assert variables["GLOBAL_MAX_BYTES"] == "31457280"
    config = _config(tmp_path)
    service = SubmissionService(config, Journal(tmp_path, Store(tmp_path / "size.sqlite")))
    import ssl
    from dataclasses import replace

    service.config = replace(
        config, submission_tls_cert=Path("fixture"), submission_tls_key=Path("fixture")
    )
    listener = controller(service, tls_context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER))
    assert listener.SMTP_kwargs["data_size_limit"] == config.limits.max_bytes
    # Source-only checks bind the internal/outbound transport caps to the generated values.
    master = Path("deploy/live/mailhost/master.cf.template").read_text()
    main = Path("deploy/live/mailhost/main.cf.template").read_text()
    assert "-o message_size_limit=${MAX_BYTES}" in master
    assert "message_size_limit = ${GLOBAL_MAX_BYTES}" in main
    assert "smtp      unix" in master and "relay     unix" in master
    internal = lmtp_controller(None, config)
    assert internal.SMTP_kwargs["data_size_limit"] == 3 * config.limits.max_bytes
    assert internal.factory().data_size_limit == 3 * config.limits.max_bytes


def test_true_type_wins_even_when_declared_type_is_blocked(tmp_path, monkeypatch):
    _verified(monkeypatch)
    make, _, _ = _milter(tmp_path)
    milter = make()
    assert milter.envrcpt("<intake+t_1@agents.example.test>") == Milter.CONTINUE
    parsed = BytesParser(policy=policy.SMTP).parsebytes(
        _agent_request(["intake+t_1@agents.example.test"])
    )
    parsed.add_attachment(PDF, maintype="application", subtype="x-msdownload", filename="a.exe")
    _feed(milter, parsed.as_bytes(policy=policy.SMTP))
    assert milter.eom() == Milter.ACCEPT


def test_in_process_sdk_uses_lane_size_limit(tmp_path):
    from dataclasses import replace

    from test_submission import _config

    from amx.gateway import outbound_agent

    config = _config(tmp_path)
    config = replace(config, limits=replace(config.limits, max_bytes=123456))
    client = outbound_agent(config, "scheduler", config.agents["scheduler"])
    assert client.max_bytes == 123456
