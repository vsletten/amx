"""Fail closed before release auth/build: current tag/main + merged PR exact-head CI.

Uses only read-only GitHub REST endpoints and the ephemeral Actions token. Bounded
responses (no pagination/retries), 10s request timeout, 120s process deadline.
"""

import json
import os
import re
import signal
import subprocess
import sys
import tomllib
from pathlib import Path
from urllib.error import URLError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, Request, build_opener

EXPECTED_CHECKS = (
    "ruff and unit tests",
    "compose scenario suite",
    "compose scenario suite, contoso on Stalwart (M6)",
    "public hygiene",
    "private selfhost, two agent hosts (SH-26)",
    "live bundle, postfix",
    "live bundle, stalwart",
)


class Refused(Exception):
    """Missing, ambiguous, stale or unsuccessful release authority."""


def require(condition, message):
    if not condition:
        raise Refused(message)


def sha(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value), "Invalid SHA")
    return value


def snapshot(api, commit, ref, pushed_object=None):
    main = api("git/ref/heads/main")["object"]
    require(
        main.get("type") == "commit" and main.get("sha") == commit,
        "Source is not current main",
    )
    tag = api("git/ref/tags/" + quote(ref.removeprefix("refs/tags/"), safe=""))["object"]
    # Compare the raw tag object to the original push, not just its peeled commit:
    # a replay after moving/recreating an annotated tag must also refuse.
    if pushed_object is not None:
        require(tag["sha"] == pushed_object, "Tag moved since the triggering push")
    target = tag
    for _ in range(4):
        sha(target["sha"])
        if target["type"] == "commit":
            break
        require(target["type"] == "tag", "Tag does not resolve to a commit")
        target = api("git/tags/" + target["sha"])["object"]
    require(target["type"] == "commit" and target["sha"] == commit, "Tag/source mismatch")
    return main, tag


def pr_identity(pr, commit, repository):
    require(pr["state"] == "closed" and pr["merged"] is True, "PR is not merged")
    require(pr["base"]["ref"] == "main", "PR base is not main")
    require(pr["base"]["repo"]["full_name"] == repository, "Wrong PR repository")
    require(pr["merge_commit_sha"] == commit, "PR merge/source mismatch")
    return sha(pr["head"]["sha"])


def verify(api, commit, ref, event, repository, event_name="push"):
    sha(commit)
    require(re.fullmatch(r"refs/tags/v[A-Za-z0-9_.-]{0,86}", ref), "Invalid release tag")
    pushed_object = None
    if event_name == "push":
        require(event["ref"] == ref and not event.get("deleted", False), "Not a tag push")
        pushed_object = sha(event["after"])
    else:
        require(event_name == "workflow_dispatch", "Unsupported release event")
        require(
            event.get("inputs", {}).get("tag") == ref.removeprefix("refs/tags/"),
            "Dispatch tag/input mismatch",
        )
    # Manual dispatch has no pushed tag-object ID. Bind its requested tag to the
    # immutable workflow SHA/current main, and recheck the raw object for drift.
    before = snapshot(api, commit, ref, pushed_object)
    prs = api(f"commits/{commit}/pulls?per_page=100")
    require(isinstance(prs, list) and len(prs) < 100, "Incomplete PR association response")
    candidates = [
        pr
        for pr in prs
        if pr.get("merge_commit_sha") == commit and pr.get("base", {}).get("ref") == "main"
    ]
    require(len(candidates) == 1, "No unique merged-main PR for source")
    number = candidates[0]["number"]
    require(isinstance(number, int) and number > 0, "Invalid PR number")
    head = pr_identity(api(f"pulls/{number}"), commit, repository)
    checks = api(f"commits/{head}/check-runs?per_page=100&filter=latest")
    runs = checks["check_runs"]
    require(checks["total_count"] == len(runs) < 100, "Incomplete check response")
    for name in EXPECTED_CHECKS:
        matches = [run for run in runs if run["name"] == name]
        require(len(matches) == 1, "Missing or ambiguous required check: " + name)
        run = matches[0]
        require(
            run["head_sha"] == head
            and run["status"] == "completed"
            and run["conclusion"] == "success",
            "Required check not successful on exact PR head: " + name,
        )
    require(pr_identity(api(f"pulls/{number}"), commit, repository) == head, "PR head drifted")
    require(snapshot(api, commit, ref, pushed_object) == before, "Release refs drifted")
    return number, head


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Refused("API redirect refused")


def github_api(token, repository):
    opener = build_opener(NoRedirect())

    def get(path):
        request = Request(
            f"https://api.github.com/repos/{repository}/{path}",
            headers={
                "Authorization": "Bearer " + token,
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        with opener.open(request, timeout=10) as response:
            content = response.read(2_000_001)
        require(len(content) <= 2_000_000, "API response too large")
        return json.loads(content)

    return get


def deadline(signum, frame):
    raise Refused("Preflight deadline exceeded")


def verify_version(ref, metadata):
    """Read static project metadata only; never import or resolve the backend."""
    project = metadata["project"]
    version = project.get("version")
    require(
        isinstance(version, str)
        and bool(version)
        and "version" not in project.get("dynamic", [])
        and ref == "refs/tags/v" + version,
        "Release tag/package version mismatch or non-static version",
    )


def main():
    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(120)
    try:
        repository = os.environ["GITHUB_REPOSITORY"]
        require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository), "Invalid repository")
        event_name = os.environ["GITHUB_EVENT_NAME"]
        require(event_name in {"push", "workflow_dispatch"}, "Unsupported release event")
        if event_name == "workflow_dispatch":
            require(os.environ["GITHUB_REF"] == "refs/heads/main", "Dispatch must run from main")
        ref = (
            "refs/tags/" + os.environ["AMX_RELEASE_TAG"]
            if event_name == "workflow_dispatch"
            else os.environ["GITHUB_REF"]
        )
        commit = sha(os.environ["GITHUB_SHA"])
        checkout = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True, timeout=10
        ).strip()
        require(checkout == commit, "Checkout/source mismatch")
        verify_version(
            ref,
            tomllib.loads((Path(__file__).resolve().parents[1] / "pyproject.toml").read_text()),
        )
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        token = os.environ["GITHUB_TOKEN"]
        require(bool(token), "Missing ephemeral token")
        number, head = verify(
            github_api(token, repository), commit, ref, event, repository, event_name
        )
        print(f"Release authorized: source={commit} merged PR={number} checked head={head}")
        return 0
    except Refused as error:
        print(f"Release refused: {error}", file=sys.stderr)
        return 1
    except (KeyError, TypeError, ValueError, OSError, URLError, subprocess.SubprocessError):
        # Never print request headers, tokens, API bodies or arbitrary provider errors.
        print("Release refused: unavailable or malformed release evidence", file=sys.stderr)
        return 1
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    sys.exit(main())
