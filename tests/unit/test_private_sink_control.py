"""Offline controls; native delivery evidence must come from make live-validate."""

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def validator(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "tools"))
    spec = importlib.util.spec_from_file_location(
        "sink_validator", ROOT / "tools/live_validate_stalwart.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def admitted(validator, monkeypatch, tmp_path):
    monkeypatch.setattr(validator, "require_lock_custody", lambda: None)
    monkeypatch.setattr(validator, "inventory", lambda: [])
    validator.write_fixture(tmp_path)
    return validator


@pytest.mark.parametrize("custody", [False, True])
@pytest.mark.parametrize("entry", ["controls", "route", "smtp", "management", "snapshot", "remove"])
def test_unadmitted_state_has_zero_effects(validator, monkeypatch, tmp_path, custody, entry):
    def lease():
        if not custody:
            raise RuntimeError("no custody")

    monkeypatch.setattr(validator, "require_lock_custody", lease)
    monkeypatch.setattr(validator, "cli", lambda *_a, **_kw: pytest.fail("compose effect"))
    monkeypatch.setattr(validator.subprocess, "run", lambda *_a, **_kw: pytest.fail("effect"))
    monkeypatch.setattr(validator, "load_params", lambda *_: pytest.fail("foreign state read"))
    with pytest.raises(RuntimeError):
        if entry == "controls":
            validator.sink_controls(tmp_path, lambda _: None)
        elif entry == "route":
            with validator.sink_route_control(tmp_path):
                pytest.fail("foreign route admitted")
        elif entry == "smtp":
            validator.fixture_smtp(tmp_path)
        elif entry == "management":
            validator.apply_fixture_operations(tmp_path, [])
        elif entry == "snapshot":
            validator.sink_snapshot(tmp_path)
        else:
            validator.remove_sink_probe(tmp_path, "<probe@home.arpa>")


def test_unreachable_sink_is_not_a_clean_canary(admitted, monkeypatch, tmp_path):
    validator = admitted
    monkeypatch.setattr(validator, "compose", lambda *_: ["fixture-only"])
    monkeypatch.setattr(
        validator.subprocess, "run", lambda *_a, **_kw: SimpleNamespace(returncode=1)
    )
    with pytest.raises(RuntimeError, match="sink unreachable"):
        validator.assert_sink_unchanged(tmp_path, {})


def test_escape_is_detected_and_only_exact_probe_is_removed(admitted, tmp_path):
    validator = admitted
    out = tmp_path / "lane/sink-out"
    probe = b"Message-ID: <control@home.arpa>\r\n\r\nsynthetic\r\n"
    (out / "control.eml").write_bytes(probe)
    (out / "unexpected.eml").write_bytes(b"unrelated")
    with pytest.raises(AssertionError, match="private mail reached foreign sink"):
        validator.check_sink_snapshot(tmp_path, {})
    validator.remove_sink_probe(tmp_path, "<control@home.arpa>")
    assert validator.sink_snapshot(tmp_path) == {"unexpected.eml": b"unrelated"}
    with pytest.raises(AssertionError, match="exactly one"):
        validator.remove_sink_probe(tmp_path, "<absent@home.arpa>")


def test_fixture_route_is_exact_foreign_domain_and_restored(admitted, monkeypatch, tmp_path):
    import json

    validator = admitted
    secrets = tmp_path / "lane/secrets"
    (secrets / "stalwart").mkdir(parents=True)
    original = {"@type": "update", "object": "MtaOutboundStrategy", "value": {"route": "original"}}
    (secrets / "stalwart/bundle.json").write_text(json.dumps({"plan": [original]}))
    applied = []
    monkeypatch.setattr(validator, "cli", lambda *_: None)
    monkeypatch.setattr(validator, "wait_fixture_smtp", lambda *_a, **_kw: None)
    monkeypatch.setattr(validator, "apply_fixture_operations", lambda _s, ops: applied.append(ops))
    with pytest.raises(RuntimeError, match="interrupted"), validator.sink_route_control(tmp_path):
        raise RuntimeError("interrupted")
    route, strategy = applied[0]
    assert route["object"] == "MtaRoute"
    assert route["value"]["route-private-sink"]["address"] == validator.SINK_IP
    assert strategy["value"]["route"]["match"]["0"]["if"] == "rcpt_domain == 'example.com'"
    assert applied[-1] == [original]


def test_same_created_fixture_allows_fixed_smtp_and_management(admitted, monkeypatch, tmp_path):
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(admitted.subprocess, "run", run)
    admitted.fixture_smtp(tmp_path)
    admitted.fixture_smtp(tmp_path, probe=b"synthetic", routed=True)
    admitted.apply_fixture_operations(tmp_path, [])
    assert len(calls) == 3
    for argv, _ in calls:
        assert argv[:5] == ["docker", "compose", "--project-name", "amx-live", "--env-file"]
        assert str(tmp_path / "sealed.json") in argv
    assert "172.31.250.60" in calls[0][0][-1]
    assert "172.31.250.10" in calls[1][0][-1]


def test_copy_of_fixture_is_not_admitted_under_generic_lease(admitted, monkeypatch, tmp_path):
    import shutil

    foreign = tmp_path / "copied"
    shutil.copytree(tmp_path / "lane", foreign / "lane")
    shutil.copyfile(tmp_path / "live.yaml", foreign / "live.yaml")
    shutil.copyfile(tmp_path / "sealed.json", foreign / "sealed.json")
    monkeypatch.setattr(admitted, "cli", lambda *_a, **_kw: pytest.fail("foreign mutation"))
    monkeypatch.setattr(admitted, "load_params", lambda *_: pytest.fail("foreign bundle read"))
    with pytest.raises(RuntimeError, match="active fresh sealed fixture"):
        admitted.sink_controls(foreign, lambda _: None)
    with pytest.raises(RuntimeError), admitted.sink_route_control(foreign):
        pytest.fail("foreign route admitted")


@pytest.mark.parametrize("file", ["live.yaml", "sealed.json"])
def test_changed_fixture_refused_before_effects(admitted, monkeypatch, tmp_path, file):
    (tmp_path / file).write_text("caller-selected target")
    monkeypatch.setattr(admitted, "cli", lambda *_a, **_kw: pytest.fail("mutation after drift"))
    with pytest.raises(RuntimeError, match="sealed overrides changed"):
        admitted.sink_controls(tmp_path, lambda _: None)


def test_creator_refuses_preexisting_state(admitted, tmp_path):
    admitted._active_fixture = None
    with pytest.raises(RuntimeError, match="fresh state"):
        admitted.write_fixture(tmp_path)
