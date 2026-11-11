"""Release authority is synthetic, exact-head and fail-closed; never call GitHub."""

import copy
import importlib.util
import itertools
import json
import re
import tomllib
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "release_preflight", ROOT / "tools/release_preflight.py"
)
assert SPEC and SPEC.loader
preflight = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preflight)

REPO = "contributor/mail-project"
SOURCE = "a" * 40
HEAD = "b" * 40
TAG_OBJECT = "c" * 40
REF = "refs/tags/v0.2.0"


@pytest.fixture
def replies():
    pr = {
        "number": 8,
        "state": "closed",
        "merged": True,
        "merge_commit_sha": SOURCE,
        "base": {"ref": "main", "repo": {"full_name": REPO}},
        "head": {"sha": HEAD},
    }
    return {
        "git/ref/heads/main": {"object": {"type": "commit", "sha": SOURCE}},
        "git/ref/tags/v0.2.0": {"object": {"type": "tag", "sha": TAG_OBJECT}},
        f"git/tags/{TAG_OBJECT}": {"object": {"type": "commit", "sha": SOURCE}},
        f"commits/{SOURCE}/pulls?per_page=100": [pr],
        "pulls/8": pr,
        f"commits/{HEAD}/check-runs?per_page=100&filter=latest": {
            "total_count": len(preflight.EXPECTED_CHECKS),
            "check_runs": [
                {"name": name, "head_sha": HEAD, "status": "completed", "conclusion": "success"}
                for name in preflight.EXPECTED_CHECKS
            ],
        },
    }


def verify(replies, mutate=None):
    calls = []

    def api(path):
        calls.append(path)
        if mutate:
            mutate(path, calls)
        return copy.deepcopy(replies[path])

    event = {"ref": REF, "after": TAG_OBJECT, "deleted": False}
    return preflight.verify(api, SOURCE, REF, event, REPO), calls


def test_merged_main_exact_head_passes_and_rechecks_refs(replies):
    (_, calls) = verify(replies)
    assert calls.count("git/ref/heads/main") == 2
    assert calls.count("git/ref/tags/v0.2.0") == 2
    assert calls.count("pulls/8") == 2
    assert f"commits/{HEAD}/check-runs?per_page=100&filter=latest" in calls


def test_lightweight_tag_passes(replies):
    replies["git/ref/tags/v0.2.0"]["object"] = {"type": "commit", "sha": SOURCE}
    preflight.verify(lambda path: replies[path], SOURCE, REF, {"ref": REF, "after": SOURCE}, REPO)


@pytest.mark.parametrize("change", ["unreviewed", "nonmain", "unmerged", "wrong_merge"])
def test_refuses_unreviewed_or_nonmain_commit(replies, change):
    if change == "unreviewed":
        replies[f"commits/{SOURCE}/pulls?per_page=100"] = []
    elif change == "nonmain":
        replies["pulls/8"]["base"]["ref"] = "feature"
    elif change == "unmerged":
        replies["pulls/8"]["merged"] = False
    else:
        replies["pulls/8"]["merge_commit_sha"] = HEAD
    with pytest.raises(preflight.Refused):
        verify(replies)


@pytest.mark.parametrize(
    "change", ["missing", "failure", "pending", "skipped", "wrong_head", "duplicate"]
)
def test_requires_every_check_success_on_exact_pr_head(replies, change):
    checks = replies[f"commits/{HEAD}/check-runs?per_page=100&filter=latest"]
    if change == "missing":
        checks["check_runs"].pop()
        checks["total_count"] -= 1
    elif change == "duplicate":
        checks["check_runs"].append(copy.deepcopy(checks["check_runs"][0]))
        checks["total_count"] += 1
    elif change == "wrong_head":
        checks["check_runs"][0]["head_sha"] = SOURCE
    elif change == "pending":
        checks["check_runs"][0].update(status="in_progress", conclusion=None)
    else:
        checks["check_runs"][0]["conclusion"] = change
    with pytest.raises(preflight.Refused):
        verify(replies)


@pytest.mark.parametrize("change", ["main", "tag_target", "moved_same_target"])
def test_rejects_stale_event_or_current_nonmain(replies, change):
    if change == "main":
        replies["git/ref/heads/main"]["object"]["sha"] = HEAD
    elif change == "tag_target":
        replies[f"git/tags/{TAG_OBJECT}"]["object"]["sha"] = HEAD
    else:
        replies["git/ref/tags/v0.2.0"]["object"]["sha"] = "d" * 40
    with pytest.raises(preflight.Refused):
        verify(replies)


@pytest.mark.parametrize("drift", ["main", "tag", "pr"])
def test_rejects_drift_during_proof(replies, drift):
    target = {"main": "git/ref/heads/main", "tag": "git/ref/tags/v0.2.0", "pr": "pulls/8"}[drift]

    def mutate(path, calls):
        if path == target and calls.count(path) == 2:
            if drift == "pr":
                replies[path]["head"]["sha"] = "d" * 40
            else:
                replies[path]["object"]["sha"] = "d" * 40

    with pytest.raises(preflight.Refused):
        verify(replies, mutate)


@pytest.mark.parametrize(
    "field,value", [("deleted", True), ("ref", "refs/heads/main"), ("after", "0" * 40)]
)
def test_refuses_wrong_event(replies, field, value):
    event = {"ref": REF, "after": TAG_OBJECT, field: value}
    with pytest.raises(preflight.Refused):
        preflight.verify(lambda path: replies[path], SOURCE, REF, event, REPO)


def test_incomplete_check_page_refuses(replies):
    replies[f"commits/{HEAD}/check-runs?per_page=100&filter=latest"]["total_count"] = 101
    with pytest.raises(preflight.Refused):
        verify(replies)


def test_api_failure_propagates_without_success(replies):
    def unavailable(path):
        raise preflight.Refused("API unavailable")

    with pytest.raises(preflight.Refused):
        preflight.verify(unavailable, SOURCE, REF, {"ref": REF, "after": TAG_OBJECT}, REPO)


def test_sourcery_is_not_a_release_gate_but_every_ci_job_is(replies):
    assert "Sourcery review" not in preflight.EXPECTED_CHECKS
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    names = []
    for job in workflow["jobs"].values():
        matrix = job.get("strategy", {}).get("matrix", {})
        # Fail closed if CI adds matrix features not expanded here.
        assert not {"include", "exclude"} & matrix.keys()
        for values in itertools.product(*matrix.values()):
            name = job["name"]
            for axis, value in zip(matrix, values, strict=True):
                name = re.sub(r"\$\{\{\s*matrix\." + re.escape(axis) + r"\s*\}\}", str(value), name)
            assert "${{" not in name
            names.append(name)
    assert len(names) == len(set(names))
    assert sorted(preflight.EXPECTED_CHECKS) == sorted(names)
    verify(replies)


def test_repository_is_bound_to_runtime_context(replies):
    replies["pulls/8"]["base"]["repo"]["full_name"] = "another/project"
    with pytest.raises(preflight.Refused, match="Wrong PR repository"):
        verify(replies)


def test_release_version_matches_static_metadata():
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text())
    preflight.verify_version("refs/tags/v" + metadata["project"]["version"], metadata)


@pytest.mark.parametrize(
    "ref,project",
    [
        ("refs/tags/v0.3.0", {"version": "0.2.0"}),
        ("refs/tags/v0.2.0", {"dynamic": ["version"]}),
        ("refs/tags/v0.2.0", {"version": "0.2.0", "dynamic": ["version"]}),
        ("refs/tags/v0.2.0", {"version": 2}),
        ("refs/heads/v0.2.0", {"version": "0.2.0"}),
    ],
)
def test_release_version_mismatch_or_dynamic_version_refuses(ref, project):
    with pytest.raises(preflight.Refused, match="version"):
        preflight.verify_version(ref, {"project": project})


def test_main_refuses_version_mismatch_before_api_or_event_reads(monkeypatch, capsys):
    monkeypatch.setenv("GITHUB_REPOSITORY", REPO)
    monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
    monkeypatch.setenv("GITHUB_SHA", SOURCE)
    monkeypatch.setenv("GITHUB_REF", "refs/tags/v999.0.0")
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setattr(preflight.subprocess, "check_output", lambda *a, **kw: SOURCE)
    monkeypatch.setattr(
        preflight, "github_api", lambda *a: pytest.fail("must refuse before contacting GitHub")
    )
    assert preflight.main() == 1
    assert "version mismatch" in capsys.readouterr().err


def test_manual_dispatch_preserves_tag_main_pr_and_ci_proof(replies):
    calls = []

    def api(path):
        calls.append(path)
        return copy.deepcopy(replies[path])

    result = preflight.verify(
        api, SOURCE, REF, {"inputs": {"tag": "v0.2.0"}}, REPO, "workflow_dispatch"
    )
    assert result == (8, HEAD)
    assert calls.count("git/ref/tags/v0.2.0") == 2
    assert calls.count("git/ref/heads/main") == 2
    assert calls.count("pulls/8") == 2
    assert f"commits/{HEAD}/check-runs?per_page=100&filter=latest" in calls


@pytest.mark.parametrize("tag", [None, "", "v0.3.0", "refs/tags/v0.2.0", "v0.2.0/other"])
def test_manual_dispatch_requires_matching_explicit_tag_before_api(replies, tag):
    def forbidden(path):
        pytest.fail("must reject mismatched dispatch before API reads")

    with pytest.raises(preflight.Refused):
        preflight.verify(
            forbidden, SOURCE, REF, {"inputs": {"tag": tag}}, REPO, "workflow_dispatch"
        )


@pytest.mark.parametrize("change", ["main", "tag", "ci", "unmerged"])
def test_manual_dispatch_does_not_bypass_existing_safety_gates(replies, change):
    if change == "main":
        replies["git/ref/heads/main"]["object"]["sha"] = HEAD
    elif change == "tag":
        replies[f"git/tags/{TAG_OBJECT}"]["object"]["sha"] = HEAD
    elif change == "ci":
        replies[f"commits/{HEAD}/check-runs?per_page=100&filter=latest"]["check_runs"][0][
            "conclusion"
        ] = "failure"
    else:
        replies["pulls/8"]["merged"] = False
    with pytest.raises(preflight.Refused):
        preflight.verify(
            lambda path: replies[path],
            SOURCE,
            REF,
            {"inputs": {"tag": "v0.2.0"}},
            REPO,
            "workflow_dispatch",
        )


def test_manual_dispatch_rejects_tag_object_drift_even_when_target_is_unchanged(replies):
    calls = []

    def api(path):
        calls.append(path)
        if path == "git/ref/tags/v0.2.0" and calls.count(path) == 2:
            return {"object": {"type": "commit", "sha": SOURCE}}
        return copy.deepcopy(replies[path])

    with pytest.raises(preflight.Refused, match="drifted"):
        preflight.verify(api, SOURCE, REF, {"inputs": {"tag": "v0.2.0"}}, REPO, "workflow_dispatch")


def test_main_manual_dispatch_binds_input_to_frozen_checkout_and_static_version(
    tmp_path, monkeypatch, capsys
):
    tag = "v" + tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"inputs": {"tag": tag}}))
    for key, value in {
        "GITHUB_REPOSITORY": REPO,
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_SHA": SOURCE,
        "GITHUB_REF": "refs/heads/main",
        "AMX_RELEASE_TAG": tag,
        "GITHUB_EVENT_PATH": str(event),
        "GITHUB_TOKEN": "synthetic-ephemeral-token",
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(preflight.subprocess, "check_output", lambda *a, **kw: SOURCE)
    marker = object()
    monkeypatch.setattr(preflight, "github_api", lambda *a: marker)
    calls = []

    def verify(*args):
        calls.append(args)
        return 8, HEAD

    monkeypatch.setattr(preflight, "verify", verify)
    assert preflight.main() == 0
    assert calls == [
        (marker, SOURCE, "refs/tags/" + tag, {"inputs": {"tag": tag}}, REPO, "workflow_dispatch")
    ]
    assert "Release authorized" in capsys.readouterr().out


@pytest.mark.parametrize("ref", ["refs/heads/feature", "refs/tags/v0.3.0"])
def test_main_manual_dispatch_refuses_nonmain_workflow_before_checkout_or_api(
    monkeypatch, capsys, ref
):
    monkeypatch.setenv("GITHUB_REPOSITORY", REPO)
    monkeypatch.setenv("GITHUB_EVENT_NAME", "workflow_dispatch")
    monkeypatch.setenv("GITHUB_REF", ref)
    monkeypatch.setattr(
        preflight.subprocess, "check_output", lambda *a, **kw: pytest.fail("no checkout read")
    )
    monkeypatch.setattr(preflight, "github_api", lambda *a: pytest.fail("no API read"))
    assert preflight.main() == 1
    assert "Dispatch must run from main" in capsys.readouterr().err
