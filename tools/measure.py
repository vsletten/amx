"""Measure what PLAN §10 Q1 asks: gateway Python lines and MTA configuration lines.

    uv run python tools/measure.py [--json]

Python lines are logical source lines: non-blank, not comments, not docstrings. MTA lines are
non-blank, non-comment configuration lines; for master.cf only the lines that differ from the
Debian package's master.cf.dist count, read from the running mailhost container when there is one
(otherwise the whole file is counted and the output says so). Stalwart (M6) has no config file: its
count is the settings in the plan amx.adapters.stalwart renders for the dev stack, one per scalar
value, leaving out accounts (Dovecot's users file is not counted either) and free-text labels
(description, reason). Names count: routes, listeners, schedules, and folders are referred to by
name. docs/findings.md and docs/findings-stalwart.md quote this output.
"""

from __future__ import annotations

import argparse
import ast
import io
import json
import subprocess
import tokenize
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "amx"

GROUPS = {
    # The gateway proper: what runs beside Postfix and Dovecot.
    "gateway": [
        "adapters/milter.py",
        "adapters/lmtp.py",
        "adapters/submission.py",
        "adapters/holdwatch.py",
        "policy.py",
        "config.py",
        "holds.py",
        "identity.py",
        "journal.py",
        "store.py",
        "tasks.py",
        "runtime.py",
        "mailbox.py",
        "gateway.py",
    ],
    # The message profile (M1): shared by the gateway, the SDK, and the MCP server.
    "profile": ["profile.py"],
    # The optional content judge (M4b).
    "judge": ["judge.py"],
    # Surfaces for agents and people (M2, M5).
    "surfaces": ["sdk.py", "mcp_server.py", "cli.py", "narrate.py"],
    "examples": ["examples/echo.py", "examples/intake.py", "examples/llm_agent.py"],
    "test support": ["testkit.py"],
    # Stalwart provisioning (M6); it runs in a one-shot init container, not in the gateway.
    "stalwart init": ["adapters/stalwart.py"],
}
MTA_FILES = {
    "postfix main.cf": "deploy/mailhost/main.cf.template",
    "postfix master.cf (changed lines)": "deploy/mailhost/master.cf",
    "postfix allowed-recipients.pcre": "deploy/mailhost/allowed-recipients.pcre",
    "dovecot.conf": "deploy/mailhost/dovecot.conf",
    "dovecot-acl": "deploy/mailhost/dovecot-acl",
}


def python_lines(path: Path) -> int:
    source = path.read_text(encoding="utf-8")
    docstrings: set[int] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            body = node.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                docstrings.update(range(body[0].lineno, (body[0].end_lineno or 0) + 1))
    code: set[int] = set()
    skip = {tokenize.COMMENT, tokenize.NL, tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT}
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type in skip or token.type == tokenize.ENDMARKER:
            continue
        for line in range(token.start[0], token.end[0] + 1):
            if line not in docstrings:
                code.add(line)
    return len(code)


def _config_lines(text: str) -> list[str]:
    return [
        " ".join(line.split())
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _master_dist() -> str | None:
    try:
        result = subprocess.run(
            ["docker", "exec", "amx-mailhost-nw-1", "cat", "/usr/share/postfix/master.cf.dist"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout


_LABELS = frozenset({"description", "reason"})  # free text; names are identifiers


def _leaves(value: object) -> int:
    if isinstance(value, dict):
        return sum(_leaves(item) for key, item in value.items() if key not in _LABELS)
    if isinstance(value, list):
        return sum(_leaves(item) for item in value)
    return 1


def stalwart_settings() -> tuple[int, int]:
    """(operations, settings) in the dev stack's Stalwart plan for contoso, accounts left out."""
    import sys

    sys.path.insert(0, str(ROOT / "src"))
    from amx.adapters.stalwart import Site, read_dev_users, render_plan

    site = Site(
        domain="contoso.test",
        agent_domain="agents.contoso.test",
        hostname="mail.contoso.test",
        gateway_host="gateway-ct",
        gateway_ip="172.30.0.21",
    )
    users, masters = read_dev_users((ROOT / "deploy" / "dev-users").read_text(encoding="utf-8"))
    settings = [op for op in render_plan(site, users, masters) if op["object"] != "Account"]
    return len(settings), sum(_leaves(op["value"]) for op in settings)


def measure() -> dict[str, object]:
    python = {  # a file an older tree does not have yet is left out (measure a past commit)
        group: {name: python_lines(SRC / name) for name in names if (SRC / name).exists()}
        for group, names in GROUPS.items()
    }
    mta: dict[str, int] = {}
    notes: list[str] = []
    for label, relative in MTA_FILES.items():
        if not (ROOT / relative).exists():
            continue
        lines = _config_lines((ROOT / relative).read_text(encoding="utf-8"))
        if relative.endswith("master.cf"):
            dist = _master_dist()
            if dist is None:
                notes.append("master.cf counted whole: no running mailhost to diff against")
            else:
                stock = set(_config_lines(dist))
                lines = [line for line in lines if line not in stock]
        mta[label] = len(lines)
    stalwart: dict[str, int] = {}
    if (SRC / "adapters" / "stalwart.py").exists():
        operations, settings = stalwart_settings()
        stalwart = {"plan operations": operations, "plan settings": settings}
    return {
        "python": python,
        "python_totals": {group: sum(files.values()) for group, files in python.items()},
        "mta": mta,
        "mta_total": sum(mta.values()),
        "postfix_total": sum(value for key, value in mta.items() if key.startswith("postfix")),
        "stalwart": stalwart,
        "notes": notes,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--json", action="store_true", help="print the full breakdown as JSON")
    result = measure()
    if parser.parse_args().json:
        print(json.dumps(result, indent=2))
        return
    for group, total in result["python_totals"].items():  # type: ignore[union-attr]
        print(f"python {group:<13} {total:>5}")
    for label, total in result["mta"].items():  # type: ignore[union-attr]
        print(f"mta    {label:<34} {total:>3}")
    print(f"mta    total {result['mta_total']} (postfix {result['postfix_total']})")
    for label, total in result["stalwart"].items():  # type: ignore[union-attr]
        print(f"mta    stalwart {label:<25} {total:>3}")
    for note in result["notes"]:  # type: ignore[union-attr]
        print(f"note: {note}")


if __name__ == "__main__":
    main()
