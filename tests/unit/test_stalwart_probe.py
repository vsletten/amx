"""SH-00 probe mechanics only; these are not native Stalwart acceptance results."""

from __future__ import annotations

import importlib.util
import io
import json
import socket
import struct
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("stalwart_probe", ROOT / "tools/stalwart_probe.py")
assert SPEC is not None and SPEC.loader is not None
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


def test_probe_plan_keeps_experiments_out_of_the_normal_adapter() -> None:
    plan = probe.probe_plan()
    operation = probe.operation
    listeners = operation(plan, "NetworkListener")["value"]
    assert listeners["sibling-in"]["bind"] == {"127.0.0.1:10027": True}
    assert listeners["sibling"]["bind"] == {"127.0.0.1:10028": True}
    assert listeners["submissions"]["tlsImplicit"] is True
    assert listeners["submission"]["useTls"] is True
    assert operation(plan, "MtaStageAuth")["value"]["require"]["else"] == (
        "local_port == 465 || local_port == 587"
    )
    routes = operation(plan, "MtaOutboundStrategy")["value"]["route"]["match"]
    assert routes["0"] == {"if": "received_via_port == 10027", "then": "'sibling-loop'"}
    assert routes["1"]["then"] == "'gateway'"
    milters = operation(plan, "MtaMilter")
    assert milters["matchOn"] == ["hostname", "port"]
    sibling = milters["value"]["milter-sibling"]
    assert sibling["port"] == 8891
    assert sibling["enable"]["match"]["0"]["if"] == "listener == 'sibling'"
    # Still no signing/spam on sibling-in; no authorization or gateway policy change.
    assert operation(plan, "SenderAuth")["value"]["dkimSignDomain"]["else"] == "false"
    assert operation(plan, "MtaStageData")["value"]["enableSpamFilter"]["else"] == "false"
    normal = probe.stalwart.render_plan(probe.SITE, probe.USERS, probe.MASTERS)
    assert "sibling-in" in operation(normal, "NetworkListener")["value"]
    assert len(operation(normal, "MtaMilter")["value"]) == 2


def test_certificate_uses_release_schema_file_path_not_invalid_path() -> None:
    certificate = probe.operation(probe.probe_plan(), "Certificate")["value"]["probe-cert"]
    assert certificate == {
        "certificate": {"@type": "File", "filePath": "/tls/server.pem"},
        "privateKey": {"@type": "File", "filePath": "/tls/server-key.pem"},
    }


def test_fixture_reads_exact_journal_bytes_not_imap_representation(tmp_path):
    import hashlib
    import sqlite3

    spec = importlib.util.spec_from_file_location(
        "fixture", ROOT / "tools/stalwart_probe_fixture.py"
    )
    assert spec and spec.loader
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    raw = b"From: intake@agents.contoso.test\r\n\r\nExact wire bytes.\r\n"
    digest = hashlib.sha256(raw).hexdigest()
    with sqlite3.connect(tmp_path / "journal.sqlite") as connection:
        connection.execute("CREATE TABLE journal(message_id, direction, event, raw_sha256)")
        connection.execute(
            "INSERT INTO journal VALUES (?, ?, ?, ?)",
            ("<fixture>", "outbound", "submission", digest),
        )
    directory = tmp_path / "raw" / digest[:2]
    directory.mkdir(parents=True)
    path = directory / f"{digest}.eml"
    path.write_bytes(raw)
    assert fixture.journal_copy(tmp_path, "<fixture>") == raw
    path.write_bytes(raw + b"changed")
    with pytest.raises(RuntimeError, match="content address mismatch"):
        fixture.journal_copy(tmp_path, "<fixture>")


def test_read_exact_handles_short_reads_and_refuses_truncation() -> None:
    class Short(io.BytesIO):
        def read(self, count=-1):
            return super().read(min(count, 2))

    assert probe.read_exact(Short(b"abcdef"), 6) == b"abcdef"
    with pytest.raises(EOFError):
        probe.read_exact(Short(b"abc"), 4)
    assert probe.frame(b"c") == b"\0\0\0\x01c"


def test_recorder_observes_stage_macros_without_recording_secrets() -> None:
    with probe.serving(0, probe.MilterRecorder) as server:
        with socket.create_connection(server.server_address, timeout=2) as client:
            stream = client.makefile("rwb", buffering=0)
            stream.write(probe.frame(b"O" + struct.pack("!III", 6, 0, 0xFFFFFFFF)))
            size = struct.unpack("!I", probe.read_exact(stream, 4))[0]
            assert probe.read_exact(stream, size) == b"O" + struct.pack("!III", 6, 0, 0)
            stream.write(
                probe.frame(
                    b"DM{auth_authen}\0ops@contoso.test\0{password}\0DO-NOT-RECORD\0{empty}\0\0"
                )
            )
            stream.write(probe.frame(b"Mops@contoso.test\0"))
            assert probe.read_exact(stream, 5) == probe.frame(b"c")
            stream.write(probe.frame(b"LFrom\0ops@contoso.test\0"))
            assert probe.read_exact(stream, 5) == probe.frame(b"c")
            stream.write(probe.frame(b"Bsecret-body"))
            assert probe.read_exact(stream, 5) == probe.frame(b"c")
            stream.write(probe.frame(b"E"))
            assert probe.read_exact(stream, 5) == probe.frame(b"c")
            stream.write(probe.frame(b"Q"))
            probe.stalwart.wait_for(lambda: bool(server.snapshot()), 2, "recorder completion")
        (row,) = server.snapshot()
        assert row["macros"] == {"M": {"{auth_authen}": "ops@contoso.test"}}
        assert row["headers"] == ["From"]
        assert row["body_bytes"] == len(b"secret-body")
        assert "E" in row["commands"]
        assert "DO-NOT-RECORD" not in json.dumps(row)
        assert "secret-body" not in json.dumps(row)


def test_lmtp_sink_records_delivery_and_deliberately_refuses_dsn_recipient() -> None:
    import smtplib

    with probe.serving(0, probe.LmtpSink) as server:
        with smtplib.LMTP(*server.server_address, timeout=2) as client:
            client.ehlo("localhost")
            assert (
                client.sendmail(
                    "ops@contoso.test", ["intake@agents.contoso.test"], probe.message("unit")
                )
                == {}
            )
            with pytest.raises(smtplib.SMTPRecipientsRefused):
                client.sendmail(
                    "ops@contoso.test", ["fail@agents.contoso.test"], probe.message("failure")
                )
        (row,) = server.snapshot()
        assert row["message_id"] == "<sh00-unit@contoso.test>"
        assert row["recipients"] == ["intake@agents.contoso.test"]


def test_discovery_order_is_local_and_does_not_claim_full_client_setup() -> None:
    assert probe.discovery_candidates("mail.contoso.test") == [
        (scheme, host, path)
        for scheme in ("https", "http")
        for host, path in (
            ("autoconfig.contoso.test", "/mail/config-v1.1.xml"),
            ("contoso.test", "/.well-known/autoconfig/mail/config-v1.1.xml"),
        )
    ]
    assert (
        probe.NoRedirect().redirect_request(None, None, 302, "", {}, "https://example.com") is None
    )


def test_domain_apply_failure_is_not_reported_as_validation_rejection(
    tmp_path, monkeypatch
) -> None:
    import subprocess

    def fail(_plan, _path):
        raise subprocess.CalledProcessError(1, ["fixture-cli"])

    monkeypatch.setattr(probe, "apply", fail)
    rows = probe.private_domains(tmp_path / "fixture-plan")["candidates"]
    assert len(rows) == len(probe.PRIVATE_DOMAINS)
    assert all(row["accepted"] is None and row["apply_exit"] == 1 for row in rows)


def test_native_xml_is_parsed_without_synthesizing_or_contacting_external_hosts():
    from xml.etree.ElementTree import fromstring

    xml = (
        '<clientConfig><emailProvider><incomingServer type="imap">'
        "<hostname>mail.contoso.test</hostname><port>993</port><socketType>SSL</socketType>"
        '<username>%EMAILADDRESS%</username></incomingServer><outgoingServer type="smtp">'
        "<hostname>mail.contoso.test</hostname><port>465</port><socketType>SSL</socketType>"
        "<username>%EMAILADDRESS%</username></outgoingServer></emailProvider></clientConfig>"
    )
    configuration = probe.client_configuration(fromstring(xml))
    assert configuration["imap"]["port"] == 993
    assert configuration["smtp"]["port"] == 465
    assert configuration["imap"]["username"] == "%EMAILADDRESS%"
    assert probe.client_configuration(fromstring("<html/>")) is None
    with pytest.raises(RuntimeError, match="unexpected host"):
        probe.client_configuration(fromstring(xml.replace("mail.contoso.test", "external.example")))


def test_missing_discovery_never_claims_direct_settings_were_discovered(monkeypatch):
    monkeypatch.setattr(probe, "discovery", lambda: {"http_observations": []})
    monkeypatch.setattr(probe, "client_protocol", lambda: {"status": "pass"})
    result = probe.client_checks()
    assert result["status"] == "measured-discovery-unavailable"
    assert "directly_configured_protocol" in result


def test_discovered_settings_are_passed_to_protocol_client(monkeypatch):
    configuration = {"imap": {"port": 993}, "smtp": {"port": 465}}
    monkeypatch.setattr(
        probe,
        "discovery",
        lambda: {"http_observations": [{"client_config": True, "configuration": configuration}]},
    )
    used = []
    monkeypatch.setattr(
        probe, "client_protocol", lambda value: used.append(value) or {"status": "pass"}
    )
    result = probe.client_checks()
    assert used == [configuration]
    assert result["status"] == "pass"


def test_domain_acceptance_requires_query_readback(tmp_path, monkeypatch) -> None:
    import subprocess

    monkeypatch.setattr(probe, "apply", lambda *_args: None)
    monkeypatch.setattr(
        probe.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args, 0, stdout='{"name":"home.arpa"}\n'
        ),
    )
    rows = probe.private_domains(tmp_path / "fixture-plan")["candidates"]
    # A zero apply without both people and agents names isn't successful readback.
    assert all(row["accepted"] is False for row in rows)


def test_entrypoint_refuses_unlocked_direct_execution(monkeypatch) -> None:
    monkeypatch.setattr(probe.sys, "argv", ["stalwart_probe.py"])
    monkeypatch.delenv("AMX_SH00_PROBE", raising=False)
    with pytest.raises(SystemExit) as error:
        probe.main()
    assert error.value.code == 2


@pytest.mark.parametrize("tamper", ["none", "body", "second-signature", "fake-signature"])
def test_signing_probe_requires_real_dkim_and_unchanged_reinjection(tmp_path, monkeypatch, tamper):
    import base64
    import subprocess

    import dkim

    key = tmp_path / "private.pem"
    subprocess.run(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:1024",
            "-out",
            str(key),
        ],
        check=True,
        capture_output=True,
    )
    public = subprocess.run(
        ["openssl", "pkey", "-in", str(key), "-pubout", "-outform", "DER"],
        check=True,
        capture_output=True,
    ).stdout
    record = "v=DKIM1; k=rsa; p=" + base64.b64encode(public).decode()
    (tmp_path / "public.json").write_text(
        json.dumps(
            {
                "sh00._domainkey.contoso.test": record,
                "intake._domainkey.agents.contoso.test": record,
            }
        )
    )

    def signed(raw, domain, selector):
        return dkim.sign(raw, selector.encode(), domain.encode(), key.read_bytes()) + raw

    people = signed(probe.message("port-587"), "contoso.test", "sh00")
    agent = signed(probe.message("signed-agent"), "agents.contoso.test", "intake")
    (tmp_path / "agent.eml").write_bytes(agent)
    with probe.Server(0, probe.LmtpSink) as sink:
        sink.messages["<sh00-port-587@contoso.test>"] = people

        def reinject(_port, _label, *, raw, sender):
            assert sender == "intake@agents.contoso.test"
            result = b"Received: by unit fixture\r\n" + raw
            if tamper == "body":
                result += b"altered\r\n"
            elif tamper == "second-signature":
                result = b"DKIM-Signature: forged\r\n" + result
            elif tamper == "fake-signature":
                result = result.replace(b"b=", b"b=x", 1)
            sink.messages["<sh00-signed-agent@contoso.test>"] = result

        monkeypatch.setattr(probe, "send", reinject)
        if tamper == "none":
            result = probe.signing_split(sink, tmp_path)
            assert result["agent_dkim_verified_before_and_after"]
            assert result["agent_signature_count"] == 1
        else:
            with pytest.raises(RuntimeError):
                probe.signing_split(sink, tmp_path)


def test_body_observation_reports_only_exact_appended_crlf_as_canonical_delta():
    before = b"Loopback-only signing probe; no external recipient.\r\n"
    result = probe.body_observation(before, before + b"\r\n")
    assert result["equal"] is False
    assert result["before_bytes"] == len(before)
    assert result["after_bytes"] == len(before) + 2
    assert result["before_sha256"] != result["after_sha256"]
    assert result["dkim_relaxed_canonical_equal"] is True
    assert result["delta"] == "appended CRLF (one trailing empty line)"
    assert probe.body_observation(before, before)["equal"] is True
    for changed in (before + b"altered\r\n", before + b"\r\n\r\n", before.replace(b" ", b"  ")):
        with pytest.raises(RuntimeError):
            probe.body_observation(before, changed)


def test_autodiscover_post_requires_structural_settings_not_just_xml_or_http_200():
    from xml.etree.ElementTree import fromstring

    xml = (
        '<Autodiscover xmlns="urn:response"><Response xmlns="urn:outlook"><Account>'
        "<Action>settings</Action><Protocol><Type>IMAP</Type><Server>mail.contoso.test</Server>"
        "<Port>993</Port><SSL>on</SSL></Protocol><Protocol><Type>SMTP</Type>"
        "<Server>mail.contoso.test</Server><Port>465</Port><SSL>on</SSL></Protocol>"
        "</Account></Response></Autodiscover>"
    )
    parsed = probe.autodiscover_configuration(fromstring(xml))
    assert parsed["settings_response"] is True
    assert parsed["schemas"] == ["urn:outlook", "urn:response"]
    assert [(p["Type"], p["Port"]) for p in parsed["protocols"]] == [
        ("IMAP", "993"),
        ("SMTP", "465"),
    ]
    assert (
        probe.autodiscover_configuration(fromstring("<Autodiscover/>"))["settings_response"]
        is False
    )
    assert probe.autodiscover_configuration(fromstring("<html/>"))["settings_response"] is False


def test_compose_probe_has_no_network_ports_or_persistent_datastore() -> None:
    class Loader(yaml.SafeLoader):
        pass

    Loader.add_constructor("!reset", lambda loader, node: None)
    Loader.add_constructor(
        "!override",
        lambda loader, node: (
            loader.construct_mapping(node, deep=True)
            if isinstance(node, yaml.MappingNode)
            else loader.construct_sequence(node)
        ),
    )
    services = yaml.load((ROOT / "deploy/compose.stalwart.yaml").read_text(), Loader=Loader)[
        "services"
    ]
    service = services["stalwart-probe"]
    assert service["network_mode"] == "none"
    assert service["profiles"] == ["sh00"]
    assert "ports" not in service and "networks" not in service
    assert all(volume.endswith(":ro") for volume in service["volumes"])
    assert service["volumes"][-1] == "./generated/state/sh00:/fixture:ro"
    assert service["build"]["target"] == "probe"
    assert services["stalwart-init-ct"]["build"]["target"] == "provisioner"
    assert services["stalwart-sync-ct"]["build"]["target"] == "provisioner"
    assert set(service["environment"]) == {
        "STALWART_RECOVERY_ADMIN",
        "STALWART_HOSTNAME",
        "AMX_SH00_PROBE",
    }
    makefile = (ROOT / "Makefile").read_text()
    assert 'test -n "$(AMX_SUITE_OVERRIDE)"' in makefile
    assert 'test "$(AMX_SUITE_MTA)" = stalwart' in makefile
    assert "run --build --rm --no-deps stalwart-probe" in makefile
