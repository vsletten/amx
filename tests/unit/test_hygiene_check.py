"""Generic release hygiene; examples are synthetic, not deployment identities."""

import importlib.util
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("hygiene_check", ROOT / "tools/hygiene_check.py")
assert SPEC and SPEC.loader
hygiene = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hygiene)

PUBLIC = "8.8." + "8.8"


@pytest.mark.parametrize(
    "text,rule",
    [
        ("TASK" + "-123", "queue-id"),
        ("nameserver: " + PUBLIC, "public-ipv4"),
        ("https://" + PUBLIC + "/", "public-ipv4"),
        ("user@" + "mail.org", "email"),
        ("host.tail." + "ts.net", "tailnet"),
        ("/home/" + "alice/config", "home-path"),
        ("/Users/" + "alice/config", "home-path"),
        ("/home/" + "alice", "home-path"),
        ("/Users/" + "alice", "home-path"),
        ('home="/home/' + 'alice"', "home-path"),
        ("/Users/" + "<user>/config", "home-path"),
    ],
)
def test_each_rule_hits(text, rule):
    assert rule in hygiene.rules(text)


@pytest.mark.parametrize(
    "text",
    [
        "TASKS-123",
        "./home/" + "alice/config",
        "~/config",
        "placeholder.ts.net",
        "image: alpine/socat:1.8.0.3",
        "image: socat:1.8." + "0.3",
        '  image: "socat:1.8.' + '0.3"',
        "FROM socat:1.8." + "0.3",
        "FROM --platform=linux/amd64 socat:1.8." + "0.3 AS build",
        "COPY --from=socat:1.8." + "0.3 /bin/tool /bin/tool",
        "version 1.8.0.3",
        "package==1.8.0.3",
        "invalid 999.999.999.999",
        "192.0.2.1",
        "198.51.100.10",
        "203.0.113.5",
        "10.1.2.3",
        "172.16.1.1",
        "192.168.1.1",
        "100.64.0.1",
        "100.127.255.254",
        "127.0.0.1",
        "0.0.0.0",
        "255.255.255.0",
        "255.255.255.255",
        "169.254.1.1",
        "user@example.com",
        "user@sub.example.com",
        "user@example.org",
        "user@example.net",
        "user@domain.example",
        "user@domain.test",
        "user@domain.invalid",
        "user@domain.localhost",
        "123+contributor@users.noreply.github.com",
        "noreply@github.com",
        "user@home.arpa",
        "RFC 5321 §4.5.4.1",
    ],
)
def test_safe_examples(text):
    assert hygiene.rules(text) == []


@pytest.mark.parametrize(
    "prefix",
    ["http://", "dns=", "ip: ", "listen: ", "version: http://", "image: http://", "ip: socat:"],
)
def test_version_looking_address_is_still_detected(prefix):
    assert "public-ipv4" in hygiene.rules(prefix + "1.8." + "0.3")


def test_netmask_exception_is_not_arbitrary_quad():
    assert "public-ipv4" in hygiene.rules("255.0." + "255.0")


def test_private_regex_is_case_insensitive_and_diagnostic_does_not_leak(
    tmp_path, capsys, monkeypatch
):
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    (root / "tracked.txt").write_text("SyntheticToken\n")
    subprocess.run(["git", "add", "."], cwd=root, check=True)
    deny = tmp_path / "deny"
    deny.write_text("# comment\nsynthetictoken\n")
    monkeypatch.chdir(root)
    monkeypatch.setattr("sys.argv", ["hygiene", "--deny-file", str(deny)])
    assert hygiene.main() == 1
    assert capsys.readouterr().out == "tracked.txt:1: private-deny\n"


def test_only_tracked_text_scanned_including_newly_staged_files(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "third_party").mkdir()
    bad = "TASK" + "-456"
    (tmp_path / "third_party/vendor.txt").write_text(bad)
    (tmp_path / "binary").write_bytes(b"\0" + bad.encode())
    (tmp_path / "untracked.txt").write_text(bad)
    subprocess.run(["git", "add", "third_party", "binary"], cwd=tmp_path, check=True)
    assert hygiene.scan(tmp_path) == []
    subprocess.run(["git", "add", "untracked.txt"], cwd=tmp_path, check=True)
    assert hygiene.scan(tmp_path) == ["untracked.txt:1: queue-id"]


def test_private_regex_supplements_generic_rules():
    assert hygiene.rules("MiXeD", (re.compile("mixed", re.I),)) == ["private-deny"]
    assert hygiene.rules("safe", (re.compile("mixed", re.I),)) == []


@pytest.mark.parametrize(
    "target,exists", [("TASK" + "-789", False), ("TASK" + "-789", True), ("/dev/zero", False)]
)
def test_symlink_target_is_scanned_without_opening_referent(tmp_path, monkeypatch, target, exists):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    if exists:
        (tmp_path / target).write_text("safe referent")
    link = tmp_path / "link"
    link.symlink_to(target)
    subprocess.run(["git", "add", "link"], cwd=tmp_path, check=True)

    def no_file_reads(*args, **kwargs):
        pytest.fail("symlink scanning must never open the referent")

    monkeypatch.setattr(Path, "read_bytes", no_file_reads)
    expected = ["link:1: queue-id"] if target.startswith("TASK") else []
    assert hygiene.scan(tmp_path) == expected


def test_home_pattern_does_not_flag_its_own_source_or_synthetic_fixtures():
    for path in (ROOT / "tools/hygiene_check.py", Path(__file__)):
        assert all(not hygiene.rules(line) for line in path.read_text().splitlines())
