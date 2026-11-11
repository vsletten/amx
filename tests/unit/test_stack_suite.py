"""Real subprocess/flock tests; Docker/uv are private credential-free fixture executables."""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
FAKE = r"""#!/usr/bin/env python3
import json
import os
import sys
import time
from pathlib import Path

engine = Path(os.environ["FAKE_ENGINE"])
args = sys.argv[1:]
name = Path(sys.argv[0]).name
root = Path.cwd()

def event(action):
    journal = Path(os.environ["AMX_SUITE_LOCK"] + ".json")
    owner = json.loads(journal.read_text())["owner"] if journal.exists() else None
    with (engine / "events").open("a") as stream:
        stream.write(json.dumps({"action": action, "root": str(root), "args": args,
                                 "pid": os.getpid(), "pgid": os.getpgrp(),
                                 "profiles": os.environ.get("COMPOSE_PROFILES"),
                                 "owner": owner,
                                 "resources": resources if name == "docker" else {}}) + "\n")

def stage(action):
    event(action)
    if os.environ.get("FAIL_STAGE") == action:
        sys.exit(19)
    gate = os.environ.get("HOLD_" + action.upper())
    if gate:
        Path(gate + ".ready").touch()
        while not Path(gate).exists():
            time.sleep(.01)

if name == "uv":
    if args[:3] == ["run", "--group", "gateway"]:
        args = ["run", *args[3:]]
    if args[:2] == ["run", "python"]:
        os.execv(sys.executable, [sys.executable, *args[2:]])
    if os.environ.get("SPAWN_STUBBORN"):
        import subprocess
        child = subprocess.Popen([sys.executable, os.environ["SPAWN_STUBBORN"]], close_fds=True)
        while not Path(os.environ["CHILD_READY"]).exists():
            time.sleep(.01)
    stage("scenarios")
    if os.environ.get("SCENARIO_RECREATE"):
        import runpy
        support = runpy.run_path(str(root / "scenarios/support.py"))
        support["compose"]("up", "-d", "--no-deps", "runner-ct")
    sys.exit(0)

state = engine / "resources.json"
resources = json.loads(state.read_text()) if state.exists() else {}
if args[0] == "info":
    print("private-fixture-engine")
elif args[0] in ("ps", "volume", "network") and "inspect" not in args and "rm" not in args:
    kind = "container" if args[0] == "ps" else args[0]
    print("\n".join(key for key, value in resources.items() if value["kind"] == kind))
elif "inspect" in args:
    print(json.dumps(resources[args[-1]]["labels"]))
elif "rm" in args:
    if "container-mailhost" in resources:
        if os.environ.get("CHILD_READY"):
            child_pid = Path(os.environ["CHILD_READY"]).read_text()
            stat = Path("/proc") / child_pid / "stat"
            if stat.exists() and stat.read_text().rpartition(")")[2].split()[0] not in ("Z", "X"):
                event("unsafe-down-with-active-child")
        stage("down")
    if (engine / "fail-down").exists():
        sys.exit(23)
    if os.environ.get("FOREIGN_AFTER_SCAN"):
        for kind in ("container", "volume", "network"):
            resources["foreign-" + kind] = {"kind": kind, "labels": {"foreign": "yes"}}
    with (engine / "removals").open("a") as stream:
        stream.write(json.dumps(args) + "\n")
    if not (engine / "leave-resources").exists():
        resources.pop(args[-1], None)
    state.write_text(json.dumps(resources))
elif args[0] == "compose":
    files = [Path(args[i+1]) for i, arg in enumerate(args) if arg == "-f"]
    action = next(a for a in args if a in ("up", "down", "run", "logs", "config"))
    if action == "config":
        volumes = {"mail": {}}
        if any("stalwart" in str(f) for f in files):
            volumes["stalwart-ct"] = {}
        services = {"mailhost": {}, "runner-ct": {}}
        if "--profile" in args and args[args.index("--profile") + 1] == "*":
            services["smoke"] = {"profiles": ["test"]}
        print(json.dumps({"services": services,
                          "volumes": volumes, "networks": {"amx": {}}}))
    elif action == "up":
        override = json.loads(files[-1].read_text())
        for section, kind in (("services", "container"), ("volumes", "volume"),
                              ("networks", "network")):
            for key, value in override[section].items():
                if section == "services" and key == "smoke":
                    continue  # merging labels does not remove the base service's profile
                labels = dict(value["labels"])
                labels["com.docker.compose.project.working_dir"] = str(root / "deploy")
                resources[kind + "-" + key] = {"kind": kind, "labels": labels}
        state.write_text(json.dumps(resources))
        stage("up")
    elif action == "run":
        override = json.loads(files[-1].read_text())
        labels = dict(override["services"].get("smoke", {}).get("labels", {}))
        labels["com.docker.compose.project.working_dir"] = str(root / "deploy")
        resources["container-smoke-run"] = {"kind": "container", "labels": labels}
        state.write_text(json.dumps(resources))
        stage("smoke")
        del resources["container-smoke-run"]
        state.write_text(json.dumps(resources))
    elif action == "down":
        if os.environ.get("CHILD_READY"):
            child_pid = Path(os.environ["CHILD_READY"]).read_text()
            stat = Path("/proc") / child_pid / "stat"
            if stat.exists() and stat.read_text().rpartition(")")[2].split()[0] not in ("Z", "X"):
                event("unsafe-down-with-active-child")
        stage("down")
        if (engine / "fail-down").exists():
            sys.exit(23)
        if not (engine / "leave-resources").exists():
            all_profiles = "--profile" in args and args[args.index("--profile") + 1] == "*"
            # Real Compose leaves an interrupted profiled one-off (and its
            # attached network) unless down includes that service's profile.
            remaining = {
                key: value for key, value in resources.items()
                if "container-smoke-run" in resources and not all_profiles
                and (key == "container-smoke-run" or value["kind"] == "network")
            }
            state.write_text(json.dumps(remaining))
    elif action == "logs":
        event("logs")
else:
    raise AssertionError(args)
"""


def wait_for(probe, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if probe():
            return
        time.sleep(0.01)
    raise AssertionError("timed out waiting for fixture subprocess")


@pytest.fixture
def stack(tmp_path):
    engine = tmp_path / "engine"
    engine.mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for command in ("docker", "uv"):
        executable = bin_dir / command
        executable.write_text(FAKE.replace("#!/usr/bin/env python3", f"#!{sys.executable}"))
        executable.chmod(0o755)
    home = tmp_path / "home"
    home.mkdir()
    env = {
        "PATH": f"{bin_dir}:/usr/bin:/bin",
        "HOME": str(home),
        "TMPDIR": str(tmp_path),
        "FAKE_ENGINE": str(engine),
        "AMX_SUITE_LOCK": str(tmp_path / "host.lock"),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_AUTHOR_NAME": "Fixture",
        "GIT_AUTHOR_EMAIL": "fixture@example.test",
        "GIT_COMMITTER_NAME": "Fixture",
        "GIT_COMMITTER_EMAIL": "fixture@example.test",
    }
    first = tmp_path / "first"
    first.mkdir()
    for relative in ("Makefile", "tools/stack_suite.py", "scenarios/support.py"):
        target = first / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    deploy = first / "deploy"
    deploy.mkdir()
    for name in ("compose.yaml", "compose.stalwart.yaml"):
        (deploy / name).write_text("name: amx\n")
    generator = deploy / "generate-dev.sh"
    generator.write_text("#!/bin/sh\nmkdir -p deploy/generated/state\n")
    generator.chmod(0o755)
    for command in (
        ["git", "init", "-q"],
        ["git", "add", "."],
        ["git", "commit", "-qm", "fixture"],
    ):
        subprocess.run(command, cwd=first, env=env, check=True, capture_output=True)
    second = tmp_path / "second"
    subprocess.run(
        ["git", "worktree", "add", "-qb", "second", str(second)],
        cwd=first,
        env=env,
        check=True,
        capture_output=True,
    )
    processes = []
    gates = []

    class Stack:
        trees = (first, second)

        def start(self, tree=first, *, mta="postfix", direct=False, command=None, **extra):
            gates.extend(Path(value) for key, value in extra.items() if key.startswith("HOLD_"))
            log = tmp_path / f"output-{len(processes)}"
            args = command or (
                [sys.executable, "tools/stack_suite.py", "suite", "--mta", mta]
                if direct
                else ["make", "suite", f"MTA_CT={mta}"]
            )
            with log.open("w") as output:
                process = subprocess.Popen(
                    args,
                    cwd=tree,
                    env={**env, **extra},
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
            processes.append(process)
            process.log = log
            return process

        def finish(self, process, success=True):
            code = process.wait(timeout=15)
            assert (code == 0) == success, process.log.read_text()
            return process.log.read_text()

        def events(self):
            path = engine / "events"
            return (
                [json.loads(line) for line in path.read_text().splitlines()]
                if path.exists()
                else []
            )

        def clean(self):
            assert json.loads((engine / "resources.json").read_text()) == {}
            assert not Path(env["AMX_SUITE_LOCK"] + ".json").exists()
            for tree in self.trees:
                assert not (tree / "deploy/generated/state").exists()
                assert not (tree / "deploy/generated/mta_ct").exists()

    fixture = Stack()
    fixture.env, fixture.engine, fixture.tmp = env, engine, tmp_path
    yield fixture
    # Release fixture gates on assertion failures as well; never signal historical
    # event PIDs, which the OS may already have reused for unrelated processes.
    for gate in gates:
        gate.touch()
    for process in processes:
        if process.poll() is None:
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()


@pytest.mark.parametrize("mta", ["postfix", "stalwart"])
def test_suite_lifecycle(stack, mta):
    stack.finish(stack.start(mta=mta))
    assert [e["action"] for e in stack.events()] == ["up", "smoke", "scenarios", "down"]
    down = stack.events()[-1]
    assert down["args"] == ["container", "rm", "-f", "container-mailhost"]
    removals = [json.loads(line) for line in (stack.engine / "removals").read_text().splitlines()]
    assert (["volume", "rm", "volume-stalwart-ct"] in removals) == (mta == "stalwart")
    stack.clean()


@pytest.mark.parametrize("mta", ["postfix", "stalwart"])
def test_scenario_recreation_preserves_ownership_and_mta(stack, mta):
    stack.finish(stack.start(mta=mta, SCENARIO_RECREATE="1"))
    ups = [e for e in stack.events() if e["action"] == "up"]
    assert len(ups) == 2
    assert any("compose.stalwart.yaml" in a for a in ups[1]["args"]) == (mta == "stalwart")
    assert any(a.endswith(".compose.json") for a in ups[1]["args"])
    runner = ups[1]["resources"]["container-runner-ct"]["labels"]
    assert (
        runner["ai.amx.suite-owner"]
        == ups[0]["resources"]["container-runner-ct"]["labels"]["ai.amx.suite-owner"]
    )
    assert runner["com.docker.compose.project.working_dir"] == str(stack.trees[0] / "deploy")
    assert runner["ai.amx.suite-owner"] == ups[1]["owner"]
    stack.clean()


def test_distinct_worktrees_serialize_and_report_waiter(stack):
    gate = stack.tmp / "release"
    first = stack.start(HOLD_SCENARIOS=str(gate), mta="stalwart")
    wait_for(lambda: gate.with_suffix(".ready").exists())
    second = stack.start(tree=stack.trees[1])
    wait_for(lambda: "waiting for host validation lock" in second.log.read_text())
    assert [e["action"] for e in stack.events()] == ["up", "smoke", "scenarios"]
    gate.touch()
    stack.finish(first)
    stack.finish(second)
    assert [e["action"] for e in stack.events()] == [
        "up",
        "smoke",
        "scenarios",
        "down",
        "up",
        "smoke",
        "scenarios",
        "down",
    ]
    stack.clean()


@pytest.mark.parametrize("stage", ["up", "smoke", "scenarios"])
def test_failures_clean_before_unlock(stack, stage):
    stack.finish(stack.start(FAIL_STAGE=stage), success=False)
    assert stack.events()[-1]["action"] == "down"
    stack.clean()
    stack.finish(stack.start(tree=stack.trees[1]))
    stack.clean()


@pytest.mark.parametrize("sig", [signal.SIGINT, signal.SIGTERM, signal.SIGHUP])
@pytest.mark.parametrize("stage", ["up", "smoke", "scenarios"])
def test_signal_cleans_while_waiter_is_excluded(stack, sig, stage):
    gate, down = stack.tmp / "release", stack.tmp / "down"
    first = stack.start(direct=True, **{f"HOLD_{stage.upper()}": str(gate)}, HOLD_DOWN=str(down))
    wait_for(lambda: Path(str(gate) + ".ready").exists())
    first.send_signal(sig)
    wait_for(lambda: Path(str(down) + ".ready").exists())
    second = stack.start(tree=stack.trees[1])
    wait_for(lambda: "waiting for host validation lock" in second.log.read_text())
    assert len([e for e in stack.events() if e["action"] == "up"]) == 1
    first.send_signal(signal.SIGTERM)  # repeated signal cannot break teardown
    down.touch()
    stack.finish(first, success=False)
    stack.finish(second)
    stack.clean()


def test_sigkill_descendant_retains_lock_then_other_tree_recovers_previous_variant(stack):
    gate = stack.tmp / "release"
    first = stack.start(direct=True, mta="stalwart", HOLD_SCENARIOS=str(gate))
    wait_for(lambda: Path(str(gate) + ".ready").exists())
    first.kill()
    stack.finish(first, success=False)
    second = stack.start(tree=stack.trees[1])
    wait_for(lambda: "waiting for host validation lock" in second.log.read_text())
    gate.touch()  # old descendant exits; inherited flock is released
    output = stack.finish(second)
    assert "recovering previous suite" in output
    events = stack.events()
    assert [e["action"] for e in events] == [
        "up",
        "smoke",
        "scenarios",
        "down",
        "up",
        "smoke",
        "scenarios",
        "down",
    ]
    assert events[3]["root"] == str(stack.trees[0])
    removals = (stack.engine / "removals").read_text()
    assert '"volume-stalwart-ct"' in removals
    stack.clean()


@pytest.mark.parametrize("failure", ["fail-down", "leave-resources"])
def test_cleanup_failure_retains_journal_and_prevents_new_start(stack, failure):
    (stack.engine / failure).touch()
    stack.finish(stack.start(), success=False)
    journal = Path(stack.env["AMX_SUITE_LOCK"] + ".json")
    assert journal.exists()
    assert (stack.trees[0] / "deploy/generated/state").exists()
    stack.finish(stack.start(tree=stack.trees[1]), success=False)
    assert len([e for e in stack.events() if e["action"] == "up"]) == 1
    (stack.engine / failure).unlink()
    stack.finish(stack.start(tree=stack.trees[1]))
    stack.clean()


@pytest.mark.parametrize("kind", ["container", "volume", "network"])
def test_foreign_resources_without_journal_are_untouched(stack, kind):
    foreign = {"foreign": {"kind": kind, "labels": {}}}
    path = stack.engine / "resources.json"
    path.write_text(json.dumps(foreign))
    output = stack.finish(stack.start(), success=False)
    assert "no suite ownership journal" in output
    assert json.loads(path.read_text()) == foreign
    assert stack.events() == []


@pytest.mark.parametrize("tamper", ["owner", "working_dir", "repository", "engine"])
def test_recovery_refuses_foreign_provenance(stack, tamper):
    (stack.engine / "fail-down").touch()
    stack.finish(stack.start(), success=False)
    path = stack.engine / "resources.json"
    before = json.loads(path.read_text())
    if tamper in ("repository", "engine"):
        journal = Path(stack.env["AMX_SUITE_LOCK"] + ".json")
        record = json.loads(journal.read_text())
        record[tamper] = "not-this-repository-or-engine"
        journal.write_text(json.dumps(record))
    else:
        label = (
            "ai.amx.suite-owner" if tamper == "owner" else "com.docker.compose.project.working_dir"
        )
        before["container-mailhost"]["labels"][label] = "foreign"
        path.write_text(json.dumps(before))
    event_count = len(stack.events())
    output = stack.finish(stack.start(tree=stack.trees[1]), success=False)
    assert "refusing cleanup" in output
    assert len(stack.events()) == event_count
    assert json.loads(path.read_text()) == before


def test_live_validate_make_target_shares_suite_lock(stack):
    gate = stack.tmp / "release"
    first = stack.start(HOLD_SCENARIOS=str(gate))
    wait_for(lambda: Path(str(gate) + ".ready").exists())
    # No live validator is executed: the fixture's harmless program only logs.
    script = stack.trees[1] / "tools/live_validate.py"
    script.write_text("from pathlib import Path\nPath('live-ran').touch()\n")
    second = stack.start(tree=stack.trees[1], command=["make", "live-validate"])
    wait_for(lambda: "waiting for host validation lock" in second.log.read_text())
    assert not (stack.trees[1] / "live-ran").exists()
    gate.touch()
    stack.finish(first)
    stack.finish(second)
    assert (stack.trees[1] / "live-ran").exists()
    stack.clean()


def active(pid):
    try:
        return Path(f"/proc/{pid}/stat").read_text().rpartition(")")[2].split()[0] not in ("Z", "X")
    except FileNotFoundError:
        return False


@pytest.fixture
def wrapper(tmp_path, monkeypatch):
    import importlib.util

    spec = importlib.util.spec_from_file_location("suite_test", ROOT / "tools/stack_suite.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "LOCK", tmp_path / "host.lock")
    return module


def test_unquiescent_timeout_quarantines_without_cleanup_or_orphan(wrapper, monkeypatch):
    import itertools
    from unittest.mock import Mock

    monkeypatch.setattr(wrapper, "group_active", lambda _pgid: True)
    monkeypatch.setattr(wrapper.time, "monotonic", itertools.count(0, 20).__next__)
    monkeypatch.setattr(wrapper.time, "sleep", Mock(side_effect=AssertionError("unbounded wait")))
    fork = Mock(side_effect=AssertionError("must not create an orphan"))
    killpg = Mock()
    process = Mock(pid=424242)
    monkeypatch.setattr(wrapper.os, "fork", fork)
    monkeypatch.setattr(wrapper.os, "killpg", killpg)
    monkeypatch.setattr(wrapper.os, "waitid", Mock())
    monkeypatch.setattr(wrapper.subprocess, "Popen", Mock(return_value=process))
    # Late .unsafe creation is deliberately impossible. Admission must survive
    # without even trying that write, because the active marker predates spawn.
    original_open = Path.open

    def deny_unsafe(path, *args, **kwargs):
        if path.name.endswith(".unsafe"):
            raise PermissionError("late quarantine publication forbidden")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", deny_unsafe)
    with wrapper.locked() as lease:
        with pytest.raises(RuntimeError, match="admission quarantined"):
            lease.run(["trusted-fixture-command"])
        assert not lease.quiescent
    marker = wrapper.LOCK.with_name(wrapper.LOCK.name + ".active")
    assert json.loads(marker.read_text()) == {"pgid": 424242}
    process.wait.assert_not_called()
    fork.assert_not_called()
    assert [call.args for call in killpg.call_args_list] == [
        (424242, signal.SIGTERM),
        (424242, signal.SIGKILL),
    ]
    for _ in range(2):
        with (
            pytest.raises(RuntimeError, match="active group marker requires investigation"),
            wrapper.locked(),
        ):
            pytest.fail("quarantined lease admitted work")
    assert marker.exists()
    # Proven quiescence admits a new lease; no PID signaling after leader reap.
    monkeypatch.setattr(wrapper, "group_active", lambda _pgid: False)
    with wrapper.locked():
        assert not marker.exists()


def test_marker_holder_still_exiting_settles_then_admits(wrapper, monkeypatch):
    # The kernel releases an exiting holder's flock before /proc shows it as a
    # zombie. A waiter woken inside that window must not quarantine admission.
    import itertools
    from unittest.mock import Mock

    marker = wrapper.LOCK.with_name(wrapper.LOCK.name + ".active")
    marker.write_text('{"pgid": 424242}')
    exiting = iter([True, True, True])
    monkeypatch.setattr(wrapper, "group_active", lambda _pgid: next(exiting, False))
    # A scripted clock, so a stalled test process cannot reach the real deadline.
    monkeypatch.setattr(wrapper.time, "monotonic", itertools.count(0, 0.01).__next__)
    sleep = Mock()
    monkeypatch.setattr(wrapper.time, "sleep", sleep)
    with wrapper.locked():
        assert not marker.exists()
    assert sleep.call_count == 3


def test_marker_group_that_never_settles_is_refused_after_bounded_wait(wrapper, monkeypatch):
    import itertools
    from unittest.mock import Mock

    marker = wrapper.LOCK.with_name(wrapper.LOCK.name + ".active")
    marker.write_text('{"pgid": 424242}')
    monkeypatch.setattr(wrapper, "group_active", lambda _pgid: True)
    monkeypatch.setattr(wrapper.time, "monotonic", itertools.count(0, 0.5).__next__)
    sleep = Mock()
    monkeypatch.setattr(wrapper.time, "sleep", sleep)
    with (
        pytest.raises(RuntimeError, match="active group marker requires investigation"),
        wrapper.locked(),
    ):
        pytest.fail("unsettled group admitted work")
    assert marker.exists()
    assert 0 < sleep.call_count <= 10


@pytest.mark.parametrize("failure", ["open", "fsync", "directory"])
def test_admission_publication_failure_refuses_before_spawn(wrapper, monkeypatch, failure):
    from unittest.mock import Mock

    spawn = Mock(side_effect=AssertionError("must not spawn without durable admission barrier"))
    monkeypatch.setattr(wrapper.subprocess, "Popen", spawn)
    denied = Mock(side_effect=PermissionError("publication denied"))
    if failure == "open":
        original_open = Path.open

        def open_marker(path, *args, **kwargs):
            if path.name.endswith(".active"):
                raise PermissionError("publication denied")
            return original_open(path, *args, **kwargs)

        monkeypatch.setattr(Path, "open", open_marker)
    elif failure == "fsync":
        monkeypatch.setattr(wrapper.os, "fsync", denied)
    else:
        monkeypatch.setattr(wrapper, "sync_directory", denied)
    with wrapper.locked() as lease, pytest.raises(PermissionError, match="publication denied"):
        lease.run(["trusted-fixture-command"])
    spawn.assert_not_called()


def test_identity_publication_failure_keeps_barrier_for_survivors(wrapper, monkeypatch):
    import itertools
    from unittest.mock import Mock

    process = Mock(pid=424242)
    monkeypatch.setattr(wrapper.subprocess, "Popen", Mock(return_value=process))
    monkeypatch.setattr(Path, "replace", Mock(side_effect=PermissionError("rename denied")))
    monkeypatch.setattr(wrapper.os, "killpg", Mock())
    monkeypatch.setattr(wrapper, "group_active", lambda _pgid: True)
    monkeypatch.setattr(wrapper.time, "monotonic", itertools.count(0, 20).__next__)
    monkeypatch.setattr(wrapper.time, "sleep", Mock(side_effect=AssertionError("unbounded wait")))
    with wrapper.locked() as lease, pytest.raises(RuntimeError, match="admission quarantined"):
        lease.run(["trusted-fixture-command"])
    marker = wrapper.LOCK.with_name(wrapper.LOCK.name + ".active")
    assert json.loads(marker.read_text()) == {"pgid": None}
    process.wait.assert_not_called()
    with (
        pytest.raises(RuntimeError, match="active group marker requires investigation"),
        wrapper.locked(),
    ):
        pytest.fail("ambiguous surviving group admitted work")


@pytest.mark.parametrize("mode", ["suite", "lock"])
@pytest.mark.parametrize("marker", ["unsafe", "active"])
def test_quarantine_refuses_subprocess_admission_for_every_mode(stack, mode, marker):
    Path(stack.env["AMX_SUITE_LOCK"] + "." + marker).write_text('{"pgid":null}')
    command = [sys.executable, "tools/stack_suite.py", mode]
    sentinel = stack.tmp / "must-not-run"
    if mode == "lock":
        command += ["--", "touch", str(sentinel)]
    output = stack.finish(stack.start(command=command), success=False)
    assert "marker requires investigation" in output
    assert stack.events() == []
    assert not sentinel.exists()


@pytest.mark.parametrize("mode", ["suite", "lock"])
def test_relative_lock_refused_in_both_worktrees_before_any_command(stack, mode):
    sentinel = stack.tmp / "must-not-run"
    command = [sys.executable, "tools/stack_suite.py", mode]
    if mode == "lock":
        command += ["--", "touch", str(sentinel)]
    for tree in stack.trees:
        output = stack.finish(
            stack.start(tree=tree, command=command, AMX_SUITE_LOCK="relative.lock"), success=False
        )
        assert "AMX_SUITE_LOCK must be absolute" in output
        assert not (tree / "relative.lock").exists()
    assert stack.events() == []
    assert not sentinel.exists()


def test_native_make_suite_with_whitespace_lock_parent(stack):
    parent = stack.tmp / "lock directory with spaces"
    parent.mkdir()
    stack.env["AMX_SUITE_LOCK"] = str(parent / "host.lock")
    stack.finish(stack.start(SCENARIO_RECREATE="1"))
    stack.clean()


def test_inherited_compose_profiles_cannot_activate_smoke_early(stack):
    stack.finish(stack.start(COMPOSE_PROFILES="test", SCENARIO_RECREATE="1"))
    assert all(event["profiles"] is None for event in stack.events())
    stack.clean()


def test_interruption_quiesces_stubborn_descendant_after_leader_exits(stack):
    child = stack.tmp / "child.py"
    ready, release = stack.tmp / "child-ready", stack.tmp / "child-release"
    child.write_text(
        "import os, signal, time\nfrom pathlib import Path\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "Path(os.environ['CHILD_READY']).write_text(str(os.getpid()))\n"
        "while not Path(os.environ['CHILD_RELEASE']).exists(): time.sleep(.01)\n"
    )
    gate = stack.tmp / "scenarios-release"
    first = stack.start(
        direct=True,
        HOLD_SCENARIOS=str(gate),
        SPAWN_STUBBORN=str(child),
        CHILD_READY=str(ready),
        CHILD_RELEASE=str(release),
    )
    try:
        wait_for(lambda: ready.exists() and Path(str(gate) + ".ready").exists())
        pid = int(ready.read_text())
        first.send_signal(signal.SIGTERM)
        second = stack.start(tree=stack.trees[1])
        wait_for(lambda: "waiting for host validation lock" in second.log.read_text())
        # A repeated cancellation must not skip group shutdown.
        first.send_signal(signal.SIGHUP)
        stack.finish(first, success=False)
        assert not active(pid), "cleanup/unlock proceeded with an active old descendant"
        assert not any(e["action"] == "unsafe-down-with-active-child" for e in stack.events())
        stack.finish(second)
        stack.clean()
    finally:
        release.touch()
        gate.touch()
        if ready.exists():
            wait_for(lambda: not active(int(ready.read_text())))


@pytest.mark.parametrize("sigkill", [False, True])
def test_profiled_smoke_is_owned_without_persistent_activation_and_recovers(stack, sigkill):
    gate = stack.tmp / "smoke-release"
    first = stack.start(direct=True, HOLD_SMOKE=str(gate))
    wait_for(lambda: Path(str(gate) + ".ready").exists())
    try:
        journal = json.loads(Path(stack.env["AMX_SUITE_LOCK"] + ".json").read_text())
        overlay = json.loads(Path(journal["overlay"]).read_text())
        assert overlay["services"]["smoke"] == {"labels": {"ai.amx.suite-owner": journal["owner"]}}
        resources = json.loads((stack.engine / "resources.json").read_text())
        assert "container-smoke" not in resources
        assert all("--profile" not in e["args"] for e in stack.events() if e["action"] == "up")
        assert resources["container-smoke-run"]["labels"]["ai.amx.suite-owner"] == journal["owner"]
        if sigkill:
            first.kill()
            stack.finish(first, success=False)
            smoke_group = next(e["pgid"] for e in stack.events() if e["action"] == "smoke")
            os.killpg(smoke_group, signal.SIGKILL)  # fixture make/Compose group only
        else:
            first.send_signal(signal.SIGTERM)
            stack.finish(first, success=False)
        stack.finish(stack.start(tree=stack.trees[1]))
        stack.clean()
    finally:
        gate.touch()


def test_foreign_resources_created_after_scan_are_not_removed(stack):
    output = stack.finish(stack.start(FOREIGN_AFTER_SCAN="1"), success=False)
    assert "cleanup incomplete" in output
    remaining = json.loads((stack.engine / "resources.json").read_text())
    assert remaining == {
        "foreign-" + kind: {"kind": kind, "labels": {"foreign": "yes"}}
        for kind in ("container", "volume", "network")
    }
    removals = (stack.engine / "removals").read_text()
    assert "foreign-" not in removals
    journal = Path(stack.env["AMX_SUITE_LOCK"] + ".json")
    assert journal.exists()
    assert (stack.trees[0] / "deploy/generated/state").exists()
    before = (stack.engine / "resources.json").read_text()
    stack.finish(stack.start(tree=stack.trees[1]), success=False)
    assert (stack.engine / "resources.json").read_text() == before


def test_unquiescent_suite_preserves_recovery_journal_and_skips_cleanup(wrapper, monkeypatch):
    from unittest.mock import Mock

    lease = Mock(quiescent=True)

    def run(command, **_kwargs):
        if command[0] == "make":
            lease.quiescent = False
            raise RuntimeError("admission quarantined")
        return "{}"

    lease.run.side_effect = run
    monkeypatch.setattr(wrapper, "repository", lambda *_: "fixture")
    monkeypatch.setattr(wrapper, "worktree_identity", lambda *_: {})
    monkeypatch.setattr(wrapper, "resources", lambda *_: {})
    monkeypatch.setattr(wrapper.signal, "signal", Mock())
    cleanup = Mock()
    monkeypatch.setattr(wrapper, "cleanup", cleanup)
    with pytest.raises(RuntimeError, match="admission quarantined"):
        wrapper.suite(lease, "postfix")
    cleanup.assert_not_called()
    assert wrapper.LOCK.with_name(wrapper.LOCK.name + ".json").exists()


def test_lock_command_arguments_are_literal_not_shell_input(stack):
    script = stack.tmp / "argv.py"
    output, sentinel = stack.tmp / "argv.json", stack.tmp / "must-not-run"
    script.write_text(
        "import json, sys\nfrom pathlib import Path\n"
        "Path(sys.argv[1]).write_text(json.dumps(sys.argv[2:]))\n"
    )
    arguments = ["with spaces", f"; touch {sentinel}", f"$(touch {sentinel})", "'quoted'"]
    command = [
        sys.executable,
        "tools/stack_suite.py",
        "lock",
        "--",
        sys.executable,
        str(script),
        str(output),
        *arguments,
    ]
    stack.finish(stack.start(command=command))
    assert json.loads(output.read_text()) == arguments
    assert not sentinel.exists()


def test_recovery_does_not_need_deleted_overlay(stack):
    (stack.engine / "fail-down").touch()
    stack.finish(stack.start(), success=False)
    journal = Path(stack.env["AMX_SUITE_LOCK"] + ".json")
    record = json.loads(journal.read_text())
    Path(record["overlay"]).unlink()
    (stack.engine / "fail-down").unlink()
    output = stack.finish(stack.start(tree=stack.trees[1]))
    assert "recovering previous suite" in output
    stack.clean()


def test_sigkill_at_overlay_unlink_cannot_leave_dangling_journal(stack):
    # Inject SIGKILL at the precise unlink window, without production test hooks.
    shim = stack.trees[0] / "crash_cleanup.py"
    shim.write_text(
        "import os, runpy, signal\nfrom pathlib import Path\n"
        "original = Path.unlink\n"
        "def unlink(path, *args, **kwargs):\n"
        "    result = original(path, *args, **kwargs)\n"
        "    if path.name.endswith('.compose.json'):\n"
        "        os.kill(os.getpid(), signal.SIGKILL)\n"
        "    return result\n"
        "Path.unlink = unlink\n"
        "runpy.run_path('tools/stack_suite.py', run_name='__main__')\n"
    )
    stack.finish(stack.start(command=[sys.executable, str(shim), "suite"]), success=False)
    assert not Path(stack.env["AMX_SUITE_LOCK"] + ".json").exists()
    assert not Path(stack.env["AMX_SUITE_LOCK"] + ".compose.json").exists()
    stack.finish(stack.start(tree=stack.trees[1]))
    stack.clean()


@pytest.mark.parametrize("replacement", ["git-dir", "directory-inode"])
def test_recovery_refuses_replacement_worktree_from_same_repository(stack, replacement):
    (stack.engine / "fail-down").touch()
    recovery, owner = stack.trees
    stack.finish(stack.start(tree=owner), success=False)
    old_identity = json.loads(Path(stack.env["AMX_SUITE_LOCK"] + ".json").read_text())["worktree"]
    if replacement == "git-dir":
        # Another linked checkout shares the repository and directory identity,
        # but not the owning worktree's Git directory.
        third = stack.tmp / "replacement"
        subprocess.run(
            ["git", "worktree", "add", "-qb", "replacement", str(third)],
            cwd=recovery,
            env=stack.env,
            check=True,
            capture_output=True,
        )
        shutil.copyfile(third / ".git", owner / ".git")
    else:
        # Even an identical copy of the Git dir pointer must not authorize a new
        # directory at the old path. Keep the original allocated to prevent reuse.
        moved = owner.with_name("original-moved")
        owner.rename(moved)
        shutil.copytree(moved, owner)
        assert owner.stat().st_ino != old_identity["inode"]
    sentinel = owner / "deploy/generated/state/replacement-data"
    sentinel.write_text("new checkout must survive")
    before = (stack.engine / "resources.json").read_text()
    count = len(stack.events())
    output = stack.finish(stack.start(tree=recovery), success=False)
    assert "refusing cleanup" in output
    assert sentinel.read_text() == "new checkout must survive"
    assert (stack.engine / "resources.json").read_text() == before
    assert len(stack.events()) == count
