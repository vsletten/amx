"""``amx live preflight``: each check reports what it saw, without sending or changing anything."""

from __future__ import annotations

import socket
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from amx import live, preflight
from amx.cli import app
from amx.live import load_params
from amx.preflight import Lookup, dns_checks, outbound_check, probe_checks, spf_verdict
from amx.provision import dkim_public_key, dkim_txt_value

EXAMPLE = Path(__file__).resolve().parents[2] / "deploy" / "live" / "live.example.yaml"


class FakeLookup(Lookup):
    """A zone as a dict of (name, type) -> answers; anything absent is NXDOMAIN."""

    def __init__(self, records: dict[tuple[str, str], list[str]]) -> None:
        self.records = records

    def query(self, name: str, rdtype: str) -> list[str]:
        return list(self.records.get((name.rstrip(".").casefold(), rdtype), []))


def _live_agent(path: Path, *arguments: str) -> None:
    result = CliRunner().invoke(app, ["live", "agent", *arguments, "--params", str(path)])
    assert result.exit_code == 0, result.output


def _params(tmp_path: Path, **changes: object):
    """An installed lane with two registered agents: queued intake and remote outpost."""
    raw = yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))
    raw["state_dir"] = str(tmp_path / "state")
    raw.update(changes)
    path = tmp_path / "live.yaml"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    params = load_params(path)
    live.install(params)
    _live_agent(
        path, "add", "intake", "--mode", "queued", "--handler", "amx.examples.intake:handle"
    )
    _live_agent(path, "add", "outpost")
    return params


def _zone(params) -> dict[tuple[str, str], list[str]]:
    """What a correct zone serves: the bundle's own rendered records, plus the PTR."""
    records: dict[tuple[str, str], list[str]] = {}
    for record in live.dns_records(params):
        value = f"{record.priority} {record.data}." if record.type == "MX" else record.data
        records.setdefault((record.name, record.type), []).append(value)
    records[("10.113.0.203.in-addr.arpa", "PTR")] = [f"{params.mx_host}."]
    return records


def _statuses(results) -> dict[str, str]:
    return {result.check: result.status for result in results}


@pytest.mark.usefixtures("per_agent_dkim")
def test_a_zone_rendered_by_the_bundle_passes_every_dns_check(tmp_path: Path) -> None:
    params = _params(tmp_path)
    statuses = _statuses(dns_checks(params, FakeLookup(_zone(params))))
    assert set(statuses.values()) <= {"PASS", "INFO"}, statuses
    assert {"dns:dkim:intake", "dns:dkim:outpost", "dns:spf-helo", "dns:dmarc-apex"} <= set(
        statuses
    )


@pytest.mark.usefixtures("per_agent_dkim")
def test_each_broken_record_fails_its_own_check(tmp_path: Path) -> None:
    params = _params(tmp_path)
    zone = _zone(params)
    outpost = dkim_txt_value(dkim_public_key(params.keys_dir / "outpost.private.pem"))
    zone[("intake._domainkey.agents.example.com", "TXT")] = [outpost]
    zone[("outpost._domainkey.agents.example.com", "TXT")] = [outpost[:255]]  # cut by an editor
    del zone[("_dmarc.agents.example.com", "TXT")]
    zone[("_dmarc.example.com", "TXT")] = ["v=DMARC1; p=quarantine; adkim=r"]
    zone[("10.113.0.203.in-addr.arpa", "PTR")] = ["vps-1234.provider.example."]
    zone[("mail.example.com", "A")] = ["198.51.100.7"]
    zone[("agents.example.com", "TXT")] = ["v=spf1 ip4:198.51.100.7 -all"]
    zone[("mail.example.com", "AAAA")] = ["2001:db8::1"]
    zone[("example.com", "CAA")] = ['0 issue "pki.goog"']
    results = {result.check: result for result in dns_checks(params, FakeLookup(zone))}
    assert results["dns:dkim:intake"].status == "FAIL"
    assert "cut short" in results["dns:dkim:outpost"].detail
    assert results["dns:dmarc"].status == "FAIL"
    assert "governs it with p=quarantine" in results["dns:dmarc"].detail
    assert results["dns:dmarc-apex"].status == "WARN"  # present, but not the chosen p=none
    assert results["dns:ptr"].status == "FAIL"
    assert results["dns:a"].status == "FAIL"
    assert results["dns:spf"].status == "FAIL"
    assert results["dns:aaaa"].status == "WARN"
    assert results["dns:caa"].status == "FAIL"  # acme mode needs letsencrypt.org


def test_spf_evaluation_follows_a_mx_include_and_redirect() -> None:
    ip = "203.0.113.10"
    lookup = FakeLookup(
        {
            ("a.test", "TXT"): ["v=spf1 a -all"],
            ("a.test", "A"): [ip],
            ("mx.test", "TXT"): ["v=spf1 mx ~all"],
            ("mx.test", "MX"): ["10 mail.mx.test."],
            ("mail.mx.test", "A"): [ip],
            ("inc.test", "TXT"): ["v=spf1 include:a.test -all"],
            ("red.test", "TXT"): ["v=spf1 redirect=a.test"],
            ("net.test", "TXT"): ["v=spf1 ip4:203.0.113.0/24 -all"],
            ("no.test", "TXT"): ["v=spf1 ip4:198.51.100.1 -all"],
            ("two.test", "TXT"): ["v=spf1 -all", "v=spf1 +all"],
        }
    )
    for domain in ("a.test", "mx.test", "inc.test", "red.test", "net.test"):
        assert spf_verdict(lookup, domain, ip)[0] == "pass", domain
    assert spf_verdict(lookup, "no.test", ip)[0] == "fail"
    assert spf_verdict(lookup, "two.test", ip)[0] == "unknown"
    assert spf_verdict(lookup, "none.test", ip)[0] == "unknown"


def test_outbound_is_a_bare_tcp_connect_to_the_lowest_mx(monkeypatch, tmp_path: Path) -> None:
    params = _params(tmp_path)
    lookup = FakeLookup(
        {
            ("gmail.com", "MX"): ["20 alt1.mx.example.", "5 first.mx.example.", "10 b.mx.example."],
            ("first.mx.example", "A"): ["192.0.2.25"],
            ("first.mx.example", "AAAA"): ["2001:db8::25"],
        }
    )
    connected: list[tuple[str, int]] = []

    class Closed:
        def __enter__(self):
            return self

        def __exit__(self, *_args) -> None:
            return None

    def fake_connect(address, timeout):
        connected.append(address)
        return Closed()

    monkeypatch.setattr(preflight.socket, "create_connection", fake_connect)
    result = outbound_check(params, lookup, None)
    # IPv4 only, as Postfix sends: never the AAAA.
    assert result.status == "PASS" and connected == [("192.0.2.25", 25)]
    assert outbound_check(params, FakeLookup({}), "no-a.example:25").status == "FAIL"

    def refuse(address, timeout):
        raise ConnectionRefusedError(111, "Connection refused")

    monkeypatch.setattr(preflight.socket, "create_connection", refuse)
    blocked = outbound_check(params, lookup, None)
    assert blocked.status == "FAIL" and "block outbound 25" in blocked.detail


def test_the_local_probe_reports_open_and_closed_ports(tmp_path: Path) -> None:
    listeners = [socket.create_server(("127.0.0.1", 0)) for _ in range(2)]
    closed = socket.create_server(("127.0.0.1", 0))
    closed_port = closed.getsockname()[1]
    closed.close()
    try:
        ports = [listener.getsockname()[1] for listener in listeners]
        params = _params(
            tmp_path,
            public_ip="127.0.0.1",
            network={"ports": {"smtp": ports[0], "submission": ports[1], "imaps": closed_port}},
        )
        results = probe_checks(params, "local")
    finally:
        for listener in listeners:
            listener.close()
    assert [result.status for result in results] == ["PASS", "PASS", "FAIL"]
    assert "not an outside view" in results[0].detail


def test_tls_checks_read_the_certificate_and_skip_a_lane_that_is_down(tmp_path: Path) -> None:
    unused = socket.create_server(("127.0.0.1", 0))
    port = unused.getsockname()[1]
    unused.close()
    params = _params(
        tmp_path,
        tls={"mode": "self-signed"},
        network={"ports": {"smtp": port, "submission": port, "imaps": port}},
    )
    results = {result.check: result for result in preflight.tls_checks(params, "127.0.0.1")}
    assert results["tls:file"].status == "PASS"
    assert "mail.example.com" in results["tls:file"].detail
    assert {results[name].status for name in ("tls:smtp-starttls", "tls:imaps")} == {"SKIP"}


def test_render_counts_failures_and_offers_json() -> None:
    results = [
        preflight.Result("PASS", "dns:a", "ok"),
        preflight.Result("FAIL", "dns:mx", "missing"),
        preflight.Result("WARN", "dns:aaaa", "v6"),
    ]
    text = preflight.render(results)
    assert "FAIL  dns:mx" in text and "1 failed, 1 warnings, 3 checks" in text
    assert '"status": "FAIL"' in preflight.render(results, as_json=True)


@pytest.mark.parametrize(
    ("server", "nameserver", "port"),
    [("127.0.0.1:15353", "127.0.0.1", 15353), ("192.0.2.53", "192.0.2.53", 53)],
)
def test_the_resolver_option_takes_an_address_and_port(server, nameserver, port) -> None:
    lookup = Lookup(server)
    assert lookup.resolver.nameservers == [nameserver]
    assert lookup.resolver.port == port


@pytest.mark.usefixtures("per_agent_dkim")
def test_a_rotation_checks_each_selector_by_its_role(tmp_path: Path) -> None:
    """The signing key must be served exactly (FAIL); a staged one not yet published, or a
    retiring one taken down early, is a WARN that says what to do (PLAN §5.2, §11.5)."""
    params = _params(tmp_path)
    _live_agent(params.path, "rotate", "intake", "--no-credentials")
    zone = _zone(params)
    staged = zone.pop(("intake.k2._domainkey.agents.example.com", "TXT"))
    zone[("_dmarc.agents.example.com", "TXT")].append("v=DMARC1; p=reject")
    results = {result.check: result for result in dns_checks(params, FakeLookup(zone))}
    assert results["dns:dkim:intake"].status == "PASS"
    assert results["dns:dkim:intake.k2"].status == "WARN"
    assert "amx live agent rotate intake --activate" in results["dns:dkim:intake.k2"].detail
    assert (
        results["dns:dmarc"].status == "FAIL" and "2 DMARC records" in results["dns:dmarc"].detail
    )
    zone[("intake.k2._domainkey.agents.example.com", "TXT")] = staged
    results = {result.check: result for result in dns_checks(params, FakeLookup(zone))}
    assert results["dns:dkim:intake.k2"].status == "PASS"
    assert "--activate" in results["dns:dkim:intake.k2"].detail
    _live_agent(params.path, "rotate", "intake", "--activate", "--no-dns-check")
    del zone[("intake._domainkey.agents.example.com", "TXT")]  # the old record, taken down early
    results = {result.check: result for result in dns_checks(params, FakeLookup(zone))}
    assert results["dns:dkim:intake.k2"].status == "PASS"
    assert results["dns:dkim:intake"].status == "WARN"
    assert "retiring until" in results["dns:dkim:intake"].detail
    zone[("intake._domainkey.agents.example.com", "TXT")] = staged  # the wrong key
    del zone[("intake.k2._domainkey.agents.example.com", "TXT")]
    results = {result.check: result for result in dns_checks(params, FakeLookup(zone))}
    assert results["dns:dkim:intake.k2"].status == "FAIL"  # the key it signs with is missing


def test_a_probe_that_looks_like_an_ssh_option_is_refused(tmp_path: Path, monkeypatch) -> None:
    params = _params(tmp_path)
    ran: list[list[str]] = []
    monkeypatch.setattr(preflight.subprocess, "run", lambda command, **_kw: ran.append(command))
    [result] = probe_checks(params, "-oProxyCommand=touch /tmp/x")
    assert result.status == "FAIL" and "must name a host" in result.detail
    assert ran == []
