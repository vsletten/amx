"""Reproduce SH-42 rule mutation checks in isolated Python processes, without editing Git files.

Run: uv run --group gateway python tools/check_attachment_mutations.py
Only fixture-backed attachment unit tests run; no mail stack or live credentials are used.
"""

from __future__ import annotations
import __future__

import argparse
import importlib
import inspect
import json
import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TESTS = [
    "tests/unit/test_attachments.py",
    "tests/unit/test_attachment_edges.py",
    "tests/unit/test_attachment_gateway.py",
    "tests/unit/test_attachment_surfaces.py",
    "tests/unit/test_attachment_remediation.py",
    "tests/unit/test_attachment_hosted_review.py",
]


def change(module_name: str, symbol: str, old: str, new: str) -> None:
    """Compile one deliberately broken function in its real module globals, in memory only."""
    module = importlib.import_module(module_name)
    owner = module
    *parents, name = symbol.split(".")
    for parent in parents:
        owner = getattr(owner, parent)
    source = textwrap.dedent(inspect.getsource(getattr(owner, name)))
    if old not in source:
        raise RuntimeError(f"stale mutation: {module_name}.{symbol}: {old}")
    source = source.replace(old, new)
    exec(
        compile(source, "<sh42-mutant>", "exec", __future__.annotations.compiler_flag),
        module.__dict__,
    )
    setattr(owner, name, module.__dict__[name])


# Each case runs in a fresh interpreter. A pytest failure (1), not an import/usage error, kills it.
CASES = [
    (
        "all 25 sniffer vectors",
        "test_sniffer",
        'import amx.attachments as a; a.sniff_type=lambda *args: "mutant/unknown"',
    ),
    (
        "portable and bounded filenames",
        "test_safe_names or test_bounded_filename",
        "import amx.attachments as a; a.safe_filename=lambda name: name",
    ),
    (
        "RFC2231 non-ASCII names",
        "test_mime_roundtrip",
        "import amx.profile as p; "
        'p.safe_filename=lambda name: name.encode("ascii", "ignore").decode()',
    ),
    (
        "base64 MIME",
        "test_mime_roundtrip",
        'change("amx.profile", "build", \'cte="base64"\', \'cte="quoted-printable"\')',
    ),
    (
        "attachment disposition",
        "test_mime_roundtrip",
        'change("amx.profile", "build", \'disposition="attachment"\', \'disposition="inline"\')',
    ),
    (
        "machine payload excluded",
        "test_mime_roundtrip",
        """import amx.profile as p
from amx.attachments import ReceivedAttachment
p.received_attachments=lambda message: tuple(
    ReceivedAttachment(i, part.get_filename(), part.get_content_type(), part)
    for i,part in enumerate(part for part in message.walk() if part.get_filename()))""",
    ),
    (
        "SDK encoded size limit",
        "test_sdk_send_reply_and_encoded_size_boundary",
        "import amx.sdk as s; s.Agent._check_size=lambda *args: None",
    ),
    (
        "SDK executable refusal",
        "test_sdk_refuses or test_prepared_submission",
        "import amx.sdk as s; s.EXECUTABLE_TYPES=frozenset()",
    ),
    (
        "MCP send and reply files",
        "test_mcp_send_reply_list_read_save_roundtrip",
        "import amx.mcp_server as m; m.AgentTools._load_attachments=lambda *args: ()",
    ),
    (
        "MCP received metadata",
        "test_mcp_send_reply_list_read_save_roundtrip",
        """import amx.mcp_server as m
original=m.summarize
def damaged(*args, **kwargs):
    result=original(*args, **kwargs)
    result.pop("attachments", None)
    return result
m.summarize=damaged""",
    ),
    (
        "MCP reply file propagation",
        "test_mcp_send_reply_list_read_save_roundtrip",
        'change("amx.mcp_server", "AgentTools.reply", "attachments=files", "attachments=()")',
    ),
    (
        "SDK Received.reply file propagation",
        "test_sdk_send_reply_and_encoded_size_boundary",
        'change("amx.sdk", "Received.reply", "attachments=attachments", "attachments=()")',
    ),
    (
        "SDK prepared executable recheck",
        "test_prepared_submission_also_refuses_executable",
        'change("amx.sdk", "Agent.submit_prepared", '
        '"if any(part.type in EXECUTABLE_TYPES for part in security_parts(message)):", '
        '"if False:")',
    ),
    (
        "MCP save tool registration",
        "test_save_registered",
        'change("amx.mcp_server", "build_server", '
        '"@server.tool()\\n    async def save_attachment", "async def save_attachment")',
    ),
    (
        "missing/directory/state/link/credential/size/executable path refusal",
        "test_host_path_refusals",
        """import amx.mcp_server as m
from amx.attachments import Attachment
m.AgentTools._load_attachments=lambda self, paths: tuple(
    Attachment("dummy.pdf", b"%PDF-fixture") for _ in paths)""",
    ),
    (
        "default private roots and symlinks",
        "test_default_private_directories",
        "import amx.attachment_files as f; f.private_directories=lambda *args: ()",
    ),
    (
        "stat before reading",
        "test_file_size_is_checked_before_read",
        'change("amx.attachment_files", "load_files", '
        '"if info.st_size + total > max_bytes:", "if False:")',
    ),
    (
        "bounded read on file growth",
        "test_file_growth_read_is_bounded",
        'change("amx.attachment_files", "load_files", '
        '"stream.read(max_bytes - total + 1)", "stream.read()")',
    ),
    (
        "save path confinement",
        "test_save_helper_alone",
        "import amx.attachment_files as f; f.safe_filename=lambda name: name",
    ),
    (
        "exclusive save, no overwrite",
        "test_save_is_observational",
        """import amx.attachment_files as f
original=f.os.link
def overwrite(source, destination, **kwargs):
    try:
        f.os.unlink(destination, dir_fd=kwargs['dst_dir_fd'])
    except FileNotFoundError:
        pass
    return original(source, destination, **kwargs)
f.os.link=overwrite""",
    ),
    (
        "save leaves flags/custody unchanged",
        "test_save_is_observational",
        """import amx.mcp_server as m
original=m.AgentTools.save_attachment
def damaged(self, *args, **kwargs):
    self.mailbox.flag("INBOX", 1, "\\\\Seen")
    return original(self, *args, **kwargs)
m.AgentTools.save_attachment=damaged""",
    ),
    (
        "AX reply path grammar",
        "test_ax_rejects_malformed",
        'change("amx.adapters.ax", "parse_reply", '
        '"if not isinstance(paths, list) or any(not isinstance(path, str) for path in paths):", '
        '"if False:")',
    ),
    (
        "AX inbound saved files",
        "test_ax_inbound_files",
        'change("amx.ax_delivery", "AxDelivery.offer", '
        '"for part in inbound.attachments", "for part in ()")',
    ),
    (
        "AX outbound file propagation",
        "test_ax_inbound_files",
        "import amx.ax_delivery as a; a.load_files=lambda *args, **kwargs: ()",
    ),
    (
        "AX prepared retry persistence",
        "test_ax_inbound_files or test_ax_attachment_retry",
        'change("amx.ax_delivery", "AxDelivery._submit_reply", '
        '\'if "prepared" in reply:\', "if False:")',
    ),
    (
        "AX sender-only preserves attachments",
        "test_ax_sender_only_rebuild",
        'change("amx.ax_delivery", "AxDelivery._submit_reply", '
        '\'if "attachment_source" in reply:\', "if False:")',
    ),
    (
        "EOD true type, not declared PDF",
        "test_eod_refuses_disguised",
        """import amx.adapters.milter as m
m.security_parts=lambda message: ()""",
    ),
    (
        "submission true type before side effects",
        "test_submission_refuses_true_type",
        "import amx.adapters.submission as s; s.security_parts=lambda message: ()",
    ),
    (
        "submission encoded size",
        "test_submission_exact_limit",
        'change("amx.adapters.submission", "SubmissionService.submit", '
        '"if len(raw) > self.config.limits.max_bytes:", "if False:")',
    ),
    (
        "EOD encoded size",
        "test_eod_exact_size_boundary or test_sibling_milter",
        'change("amx.policy", "evaluate", '
        '"if message_size > size_limit or blocked_types:", "if blocked_types:")',
    ),
    (
        "sibling headroom",
        "test_sibling_milter",
        'change("amx.policy", "evaluate", "(3 if ctx.sibling else 1)", "1")',
    ),
    (
        "LMTP aligned with internal headroom",
        "test_live_hop_limits",
        'change("amx.adapters.lmtp", "controller", '
        '"data_size_limit=3 * config.limits.max_bytes", "data_size_limit=1")',
    ),
    (
        "submission listener aligned",
        "test_live_hop_limits",
        'change("amx.adapters.submission", "controller", '
        '"data_size_limit=service.config.limits.max_bytes", "data_size_limit=1")',
    ),
    (
        "default executable block list",
        "test_default_blocked_list or test_loaded_defaults",
        'import amx.config as c; c.DEFAULT_BLOCKED_TYPES=frozenset({"application/x-msdownload"})',
    ),
    (
        "in-process SDK lane limit",
        "test_in_process_sdk_uses_lane_size_limit",
        'change("amx.gateway", "outbound_agent", '
        '"max_bytes=config.limits.max_bytes", "max_bytes=1")',
    ),
    (
        "EOD declared/true disagreements in both directions",
        "test_true_type_wins_even_when_declared_type_is_blocked or test_eod_refuses_disguised",
        """import amx.adapters.milter as m
from types import SimpleNamespace
original=m.security_parts
m.security_parts=lambda message: tuple(
    SimpleNamespace(type=part.declared_type) for part in original(message))""",
    ),
    (
        "submission declared/true disagreements in both directions",
        "test_submission_true_type_wins or test_submission_refuses_true_type",
        'change("amx.adapters.submission", "SubmissionService.submit", '
        '"part.type in self.config.limits.blocked_attachment_types", '
        '"part.declared_type in self.config.limits.blocked_attachment_types")',
    ),
    (
        "AX missing/directory/state/link/executable/size path refusal",
        "test_ax_attachment_paths_use_same_refusals",
        "import amx.ax_delivery as a; a.load_files=lambda *args, **kwargs: ()",
    ),
    (
        "held release preserves attachment bytes",
        "test_held_release",
        """import amx.adapters.submission as s
from email.parser import BytesParser
from email import policy
original=s.sign
def damaged(raw, *args, **kwargs):
    message=BytesParser(policy=policy.SMTP).parsebytes(raw)
    message.set_payload([part for part in message.get_payload()
                         if part.get_content_disposition() != "attachment"])
    return original(message.as_bytes(policy=policy.SMTP), *args, **kwargs)
s.sign=damaged""",
    ),
    (
        "security traversal is not presentation enumeration",
        "test_review_mime_bypasses",
        """from amx.attachments import received_attachments
import amx.adapters.milter as m
import amx.adapters.submission as s
m.security_parts=s.security_parts=received_attachments""",
    ),
    (
        "all universal Mach-O headers are executable",
        "test_review_fat_macho",
        """import amx.attachments as a
original=a.sniff_type
def damaged(content, filename=""):
    if content[:4] in (bytes.fromhex("cafebabe"), bytes.fromhex("bebafeca"),
                      bytes.fromhex("cafebabf"), bytes.fromhex("bfbafeca")):
        return "application/octet-stream"
    return original(content, filename)
a.sniff_type=damaged""",
    ),
    (
        "old x-msdownload YAML alias remains effective",
        "test_review_old_yaml",
        "import amx.config as c; c.LimitsConfig.__post_init__=lambda self: None",
    ),
    (
        "descriptor-relative no-follow ancestor traversal",
        "test_review_descriptor_traversal",
        """import amx.attachment_files as f
from contextlib import contextmanager
@contextmanager
def damaged(path, *, create=False):
    if create:
        path.mkdir(parents=True, exist_ok=True)
    fd=f.os.open(path, f.os.O_RDONLY | f.os.O_DIRECTORY | f.os.O_NOFOLLOW)
    try:
        yield fd, lambda: None
    finally:
        f.os.close(fd)
f._directory=damaged""",
    ),
    (
        "descriptor I/O capability fail-closed",
        "test_review_descriptor_io_unavailable",
        'change("amx.attachment_files", "_directory", "if not _SAFE_DIR_FD:", "if False:")',
    ),
    (
        "structured forwarded MIME content is never empty",
        "test_review_structured_forward",
        """import amx.attachments as a
a.ReceivedAttachment.content=property(lambda self: self._part.get_payload(decode=True) or b"")""",
    ),
    (
        "builder message/rfc822 uses structured MIME",
        "test_review_builder_explicit_rfc822",
        'change("amx.profile", "build", '
        '\'if maintype.casefold() == "message" and subtype.casefold() == "rfc822":\', '
        '"if False:")',
    ),
    (
        "SDK scans structured files before prepare",
        "test_review_sdk_structured_file_scanned_before_prepare",
        'change("amx.sdk", "Agent.send", '
        '"if any(part.type in EXECUTABLE_TYPES for part in security_parts(message)):", '
        '"if False:")',
    ),
    (
        "AX parent lookup preflight precedes saving files",
        "test_review_ax_parent_failure",
        """import amx.ax_delivery as a
original=a.AxDelivery.offer
def damaged(self, client, uid, raw):
    inbound=a.bind(raw)
    directory=a.attachment_directory(self.runner.handled.path.parent, inbound.task)
    for part in inbound.attachments:
        a.save_file(part, directory)
    return original(self, client, uid, raw)
a.AxDelivery.offer=damaged""",
    ),
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", type=int)
    parser.add_argument("--output", type=Path, help="optional JSON evidence (no fixture contents)")
    args = parser.parse_args()
    if args.case is not None:
        import pytest

        _, selection, mutation = CASES[args.case]
        exec(mutation, globals())
        return pytest.main([*TESTS, "-q", "-k", selection, "-p", "no:cacheprovider"])
    # Audited: argv is built only from this interpreter, committed constants, and parser-typed
    # integer indexes; shell expansion is never used.
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
    baseline = subprocess.run([sys.executable, "-m", "pytest", *TESTS, "-q"], cwd=ROOT)
    if baseline.returncode:
        return baseline.returncode
    results = []
    for index, (label, _, _) in enumerate(CASES):
        # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
        result = subprocess.run(
            [sys.executable, __file__, "--case", str(index)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        summary = (
            result.stdout.strip().splitlines()[-1] if result.stdout.strip() else "no test output"
        )
        row = {
            "rule": label,
            "killed": result.returncode == 1,
            "exit_code": result.returncode,
            "pytest_summary": summary,
        }
        results.append(row)
        print(json.dumps(row), flush=True)
        if result.returncode != 1:
            print(result.stdout + result.stderr, flush=True)
    if args.output:
        args.output.write_text(json.dumps(results, indent=2) + "\n")
    return 0 if all(row["killed"] for row in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
