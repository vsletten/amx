"""SH-13: measured self-relay settings and listener-bound milter provenance."""

from dataclasses import replace

import pytest

from amx.adapters.stalwart import Site, render_plan
from amx.config import load_config


def _operations():
    site = Site("home.arpa", "agents.home.arpa", "mail.home.arpa", "gateway", "172.30.0.21")
    plan = render_plan(
        site,
        [("ops@home.arpa", "fixture")],
        {"gateway": "fixture-gateway", "approver": "fixture-approver"},
    )
    return {item["object"]: item for item in plan}


def test_stalwart_sibling_self_relay_is_gateway_only_and_filtered_once():
    ops = _operations()
    listeners = ops["NetworkListener"]["value"]
    assert listeners["sibling-in"]["bind"] == {"[::]:10027": True}
    assert listeners["sibling"]["bind"] == {"127.0.0.1:10028": True}
    connect = ops["MtaStageConnect"]["value"]["script"]["match"]
    assert "remote_ip != '172.30.0.21'" in connect["0"]["if"]
    assert "remote_ip != '127.0.0.1'" in connect["1"]["if"]
    assert ops["MtaStageAuth"]["value"]["require"]["else"] == (
        "local_port != 25 && !(local_port == 10025) && "
        "listener != 'sibling-in' && listener != 'sibling'"
    )
    routes = ops["MtaOutboundStrategy"]["value"]["route"]["match"]
    assert routes["0"] == {"if": "received_via_port == 10027", "then": "'sibling-loop'"}
    relay = ops["MtaRoute"]["value"]["route-sibling"]
    assert (relay["address"], relay["port"], relay["protocol"]) == ("127.0.0.1", 10028, "smtp")
    milters = ops["MtaMilter"]
    assert milters["matchOn"] == ["hostname", "port"]
    sibling = milters["value"]["milter-sibling"]
    assert sibling["port"] == 8891
    assert sibling["enable"]["match"]["0"]["if"] == "listener == 'sibling'"
    assert sibling["tempFailOnError"] is True
    assert ops["SenderAuth"]["value"]["dkimSignDomain"]["else"] == "false"
    assert ops["DsnReportSettings"]["value"]["dkimSignDomain"]["else"] == "false"


@pytest.mark.parametrize("legacy", [False, True])
def test_sibling_config_aliases_and_explicit_disable(tmp_path, monkeypatch, legacy):
    path = tmp_path / "gateway.yaml"
    key = "postfix_sibling_port" if legacy else "sibling_port"
    path.write_text(f"domain: home.arpa\n{key}: 10027\nlisteners:\n  sibling_milter_port: 8891\n")
    assert load_config(path).sibling_port == 10027
    assert load_config(path).sibling_milter_port == 8891
    monkeypatch.setenv("AMX_POSTFIX_SIBLING_PORT", "10029")
    assert load_config(path).sibling_port == 10029
    monkeypatch.setenv("AMX_SIBLING_PORT", "0")
    assert load_config(path).sibling_port == 0
    assert replace(load_config(path), sibling_port=10027).sibling_port == 10027


def test_new_config_key_wins_over_legacy_key(tmp_path):
    path = tmp_path / "gateway.yaml"
    path.write_text("domain: home.arpa\npostfix_sibling_port: 10027\nsibling_port: 0\n")
    assert load_config(path).sibling_port == 0
