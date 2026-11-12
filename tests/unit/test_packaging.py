"""Client dependency and release-boundary contracts (SH-03)."""

import re
import shlex
import stat
import sys
import tomllib
from pathlib import Path

import pytest
import yaml

from amx.custody import Custody

ROOT = Path(__file__).resolve().parents[2]


def _numeric_version(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def _runner_image_contract():
    runner = yaml.safe_load((ROOT / "deploy/compose.yaml").read_text())["services"]["runner-ct"]
    dockerfile = (ROOT / runner["build"]["dockerfile"]).read_text()
    runtime = dockerfile.rsplit("FROM ", 1)[1]
    environment = dict(
        field.split("=", 1)
        for line in runtime.splitlines()
        if line.startswith("ENV ")
        for field in shlex.split(line.removeprefix("ENV "))
    )
    return runner, runtime, environment


def test_runner_image_places_shared_custody_on_its_private_owned_state_volume():
    runner, runtime, environment = _runner_image_contract()
    assert environment.get("XDG_STATE_HOME") == "/state"
    assert "mkdir /state" in runtime
    assert "chown ${AMX_UID}:${AMX_GID} /state" in runtime
    assert "chmod 0700 /state" in runtime
    assert runner["user"] == "${AMX_UID:-1000}:${AMX_GID:-1000}"
    assert runner["build"]["args"] == {"AMX_UID": "${AMX_UID:-1000}", "AMX_GID": "${AMX_GID:-1000}"}
    assert "runner-state:/state" in runner["volumes"]
    assert runner["environment"].get("XDG_STATE_HOME", environment["XDG_STATE_HOME"]) == "/state"


@pytest.mark.parametrize("home", ["/", None])
def test_image_state_is_writable_private_and_shared_without_a_usable_home(
    tmp_path, monkeypatch, home
):
    _, _, environment = _runner_image_contract()
    assert environment.get("XDG_STATE_HOME") == "/state"
    # Model the image's owned /state volume inside pytest's private fixture.
    # Never create anything under the real /state, / or account home.
    volume = tmp_path / environment["XDG_STATE_HOME"].lstrip("/")
    volume.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_STATE_HOME", str(volume))
    if home is None:
        monkeypatch.delenv("HOME", raising=False)

        # An arbitrary container UID may have no passwd entry either. Do not
        # let the host account's home hide eager default evaluation.
        def no_home():
            raise RuntimeError("Could not determine home directory.")

        monkeypatch.setattr(Path, "home", no_home)
    else:
        monkeypatch.setenv("HOME", home)
    runner = Custody("container@fixture.test")
    mcp = Custody("container@fixture.test")
    assert runner.path == mcp.path
    assert runner.path.is_relative_to(volume)
    assert stat.S_IMODE(volume.stat().st_mode) == 0o700
    assert stat.S_IMODE(runner.path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(runner.path.stat().st_mode) == 0o600
    runner.poll()
    assert mcp.recent(10)
    with mcp.locked() as state:
        state["claims"]["message"] = "mcp"
    with runner.locked() as state:
        assert state["claims"]["message"] == "mcp"


def test_missing_container_state_configuration_reproduces_home_root_error_without_writes(
    monkeypatch,
):
    monkeypatch.setenv("HOME", "/")
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    attempted = []

    def denied(path, *args, **kwargs):
        attempted.append(path)
        raise PermissionError("fixture refuses a root-home state write")

    monkeypatch.setattr(Path, "mkdir", denied)
    with pytest.raises(PermissionError, match="root-home"):
        Custody("container@fixture.test")
    assert attempted == [Path("/.local/state/amx/custody")]


def test_native_custody_home_default_is_unchanged(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    custody = Custody("native@fixture.test")
    assert custody.path.parent == tmp_path / ".local/state/amx/custody"


@pytest.mark.parametrize("configured", ["xdg", "directory", "directory-over-xdg"])
def test_explicit_custody_paths_do_not_resolve_home(tmp_path, monkeypatch, configured):
    def no_home():
        raise RuntimeError("Could not determine home directory.")

    monkeypatch.setattr(Path, "home", no_home)
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    directory = tmp_path / "explicit"
    if configured != "directory":
        monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg"))
    custody = Custody("nohome@fixture.test", directory=None if configured == "xdg" else directory)
    expected = tmp_path / "xdg/amx/custody" if configured == "xdg" else directory
    assert custody.path.parent == expected
    custody.poll()
    assert custody.recent(10)


def test_custody_without_configured_path_or_home_fails_closed(monkeypatch):
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)

    def no_home():
        raise RuntimeError("Could not determine home directory.")

    def no_write(*args, **kwargs):
        pytest.fail("must not create fallback state when no home or configured path exists")

    monkeypatch.setattr(Path, "home", no_home)
    monkeypatch.setattr(Path, "mkdir", no_write)
    with pytest.raises(RuntimeError, match="Could not determine home directory"):
        Custody("nohome@fixture.test")


def test_client_install_includes_mcp_but_not_native_milter():
    manifest = tomllib.loads((ROOT / "pyproject.toml").read_text())
    project = manifest["project"]
    assert project["name"] == "agent-mail-exchange"
    assert any(dep.startswith("mcp>=") for dep in project["dependencies"])
    assert not any("milter" in dep for dep in project["dependencies"])
    assert "gateway" not in project["optional-dependencies"]
    assert manifest["dependency-groups"]["gateway"] == ["pymilter>=1.0.5,<2"]
    assert manifest["tool"]["uv"]["sources"]["pymilter"] == {"path": "third_party/pymilter"}
    assert {"amx", "amx-runner", "amx-mcp", "amx-gateway"} <= project["scripts"].keys()
    assert project["license"] == {"file": "LICENSE"}


def test_runtime_lock_stays_above_security_floors():
    lock = tomllib.loads((ROOT / "uv.lock").read_text())
    versions = {package["name"]: package["version"] for package in lock["package"]}
    assert _numeric_version(versions["certifi"]) >= (2026, 10, 18)
    assert _numeric_version(versions["dnspython"]) >= (2, 9, 0)


def test_gateway_and_ci_explicitly_install_native_group():
    dockerfile = (ROOT / "deploy/gateway/Dockerfile").read_text()
    assert "uv sync --frozen --no-dev --group gateway" in dockerfile
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    for name, job in workflow["jobs"].items():
        assert job["runs-on"] == "${{ fromJSON(vars.AMX_CI_RUNS_ON || '\"ubuntu-24.04\"') }}"
        if name != "hygiene":
            assert any(
                step.get("run") == "uv sync --locked --group gateway" for step in job["steps"]
            )
    hygiene = workflow["jobs"]["hygiene"]["steps"]
    assert hygiene[1]["uses"].startswith("astral-sh/setup-uv@")
    assert hygiene[1]["with"]["python-version"] == "3.13"
    assert hygiene[-1]["run"] == "uv run --no-project --python 3.13 python tools/hygiene_check.py"
    assert any(
        step.get("run") == "uv run --group gateway pytest tests/unit -q"
        for step in workflow["jobs"]["unit"]["steps"]
    )
    # AX is a client, not a gateway; it must not need the native build toolchain.
    ax = (ROOT / "deploy/ax/Dockerfile").read_text()
    assert "libmilter" not in ax
    assert "build-essential" not in ax


def test_tag_release_publishes_only_gateway():
    workflow = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
    # PyYAML's YAML 1.1 parser calls the key `on` True.
    assert workflow[True] == {"push": {"tags": ["v*"]}}
    assert set(workflow["jobs"]) == {"gateway"}
    job = workflow["jobs"]["gateway"]
    assert job["permissions"] == {
        "contents": "read",
        "packages": "write",
        "checks": "read",
        "pull-requests": "read",
    }
    actions = [step["uses"] for step in job["steps"] if "uses" in step]
    assert len(actions) == 4
    assert all(re.fullmatch(r"[\w/-]+@[0-9a-f]{40}", action) for action in actions)
    checkout = job["steps"][0]
    assert checkout["with"]["ref"] == "${{ github.sha }}"
    assert checkout["with"]["persist-credentials"] is False
    gate = job["steps"][1]
    assert gate["run"] == "python3 tools/release_preflight.py"
    assert gate["timeout-minutes"] == 3
    assert gate["env"]["GITHUB_TOKEN"] == "${{ secrets.GITHUB_TOKEN }}"
    builds = [step for step in job["steps"] if "build-push-action@" in step.get("uses", "")]
    assert len(builds) == 1
    build = builds[0]["with"]
    assert build["context"] == "."
    assert build["file"] == "deploy/gateway/Dockerfile"
    assert build["push"] is True
    assert build["tags"] == (
        "ghcr.io/${{ steps.image.outputs.owner }}/amx-gateway:"
        "${{ github.ref_name }}-${{ github.sha }}"
    )
    owner = next(step for step in job["steps"] if step.get("id") == "image")
    assert owner["env"]["OWNER"] == "${{ github.repository_owner }}"
    assert "${OWNER,,}" in owner["run"]
    assert (
        "org.opencontainers.image.source=${{ github.server_url }}/${{ github.repository }}"
        in build["labels"]
    )
    dockerfile = (ROOT / build["file"]).read_text().lower()
    assert "stalwart" not in dockerfile
    assert "license notice license.gateway" in dockerfile
    # Guard against a second publishing path for local-only Stalwart helpers.
    for path in (ROOT / ".github/workflows").glob("*.y*ml"):
        if path.name != "release.yml":
            assert "build-push-action" not in path.read_text()
            assert "docker push" not in path.read_text()


def test_stalwart_remains_upstream_digest_pinned_and_local_only():
    compose = (ROOT / "deploy/compose.stalwart.yaml").read_text()
    assert "stalwartlabs/stalwart:v0.16.25@sha256:" in compose
    dockerfile = (ROOT / "deploy/stalwart/Dockerfile").read_text()
    assert "FROM stalwartlabs/stalwart:v0.16.25@sha256:" in dockerfile
    assert "LOCAL BUILD ONLY" in dockerfile
    assert "GNU GENERAL PUBLIC LICENSE" in (ROOT / "LICENSE.gateway").read_text()
    assert "Apache License" in (ROOT / "LICENSE").read_text()
    assert "GPLv3 combined work" in (ROOT / "NOTICE").read_text()


def test_python_publisher_is_manual_only_oidc_and_uses_the_same_gate():
    text = (ROOT / ".github/workflows/publish.yml").read_text()
    workflow = yaml.safe_load(text)
    assert workflow[True] == {
        "workflow_dispatch": {
            "inputs": {
                "tag": {
                    "description": "Existing release tag to publish (for example v0.3.0)",
                    "required": True,
                    "type": "string",
                }
            }
        }
    }
    assert workflow["env"] == {"AMX_RELEASE_TAG": "${{ inputs.tag }}"}
    assert "project agent-mail-exchange, owner vsletten, repository amx," in text
    assert "workflow publish.yml, environment pypi" in text
    assert "pending trusted publisher" in text
    assert "allow ONLY branch main, no tags" in text
    assert set(workflow["jobs"]) == {"build", "publish"}
    assert workflow["permissions"] == {"contents": "read"}
    build_job = workflow["jobs"]["build"]
    assert build_job["if"] == "github.ref == 'refs/heads/main'"
    assert build_job["permissions"] == {
        "contents": "read",
        "checks": "read",
        "pull-requests": "read",
    }
    assert "environment" not in build_job
    build_steps = build_job["steps"]
    assert build_steps[0]["with"] == {"ref": "${{ github.sha }}", "persist-credentials": False}
    assert build_steps[1]["run"] == "python3 tools/release_preflight.py"
    assert next(i for i, step in enumerate(build_steps) if step.get("run") == "uv build") > 1
    upload = build_steps[-1]
    assert upload["uses"].startswith("actions/upload-artifact@")
    assert upload["with"] == {
        "name": "distributions-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt }}",
        "path": "dist/",
        "if-no-files-found": "error",
    }
    assert build_job["outputs"]["artifact-id"] == "${{ steps.distributions.outputs.artifact-id }}"
    assert upload["id"] == "distributions"
    assert all(
        re.fullmatch(r"[\w/-]+@[0-9a-f]{40}", step["uses"])
        for job in workflow["jobs"].values()
        for step in job["steps"]
        if "uses" in step
    )
    job = workflow["jobs"]["publish"]
    assert job["if"] == "github.ref == 'refs/heads/main'"
    assert job["needs"] == "build"
    assert job["environment"] == "pypi"
    assert job["permissions"] == {
        "contents": "read",
        "checks": "read",
        "pull-requests": "read",
        "id-token": "write",
    }
    steps = job["steps"]
    assert steps[0]["with"] == {"ref": "${{ github.sha }}", "persist-credentials": False}
    assert len(steps) == 4
    assert steps[1]["uses"].startswith("actions/download-artifact@")
    assert steps[1]["with"] == {
        "artifact-ids": "${{ needs.build.outputs.artifact-id }}",
        "path": "dist/",
        "merge-multiple": True,
    }
    assert steps[-2]["run"] == "python3 tools/release_preflight.py"
    assert steps[-2]["env"] == {"GITHUB_TOKEN": "${{ secrets.GITHUB_TOKEN }}"}
    assert steps[-2]["timeout-minutes"] == 3
    publisher = steps[-1]
    assert re.fullmatch(r"pypa/gh-action-pypi-publish@[0-9a-f]{40}", publisher["uses"])
    assert "with" not in publisher  # OIDC only, no password or token.


def test_gateway_wheel_diagnostic_precedes_config_loading(monkeypatch, capsys):
    from amx import gateway

    def missing(name):
        assert name == "Milter"
        raise ModuleNotFoundError(name)

    monkeypatch.setattr(gateway.importlib, "import_module", missing)
    monkeypatch.setattr(gateway, "run", lambda *_: pytest.fail("must not load config or start"))
    monkeypatch.setattr(gateway, "load_config", lambda *_: pytest.fail("must not read config"))
    monkeypatch.setattr(sys, "argv", ["amx-gateway", "--config", "nonexistent.toml"])
    with pytest.raises(SystemExit) as error:
        gateway.main()
    assert error.value.code == 2
    output = capsys.readouterr().err
    assert "container" in output and "source checkout" in output
    assert "--group gateway" in output
    assert "Traceback" not in output


def test_gateway_wheel_help_precedes_native_import_and_config(monkeypatch, capsys):
    from amx import gateway

    def forbidden(*args):
        pytest.fail("help must not import Milter, read config or start the gateway")

    monkeypatch.setattr(gateway.importlib, "import_module", forbidden)
    monkeypatch.setattr(gateway, "load_config", forbidden)
    monkeypatch.setattr(gateway, "run", forbidden)
    monkeypatch.setattr(sys, "argv", ["amx-gateway", "--help"])
    with pytest.raises(SystemExit) as error:
        gateway.main()
    assert error.value.code == 0
    output = capsys.readouterr()
    assert "usage:" in output.out and "--config" in output.out
    assert output.err == ""
