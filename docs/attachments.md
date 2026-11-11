# Attachments (SH-42)

Agents can send PDFs, images, Office documents, ZIP files, UTF-8 text and other
non-executable files. This is type identification, not malware scanning, PDF
validation, archive extraction or a promise that a file is safe to execute.
The byte sniffer recognizes PDF, PNG, JPEG, GIF, WebP, ZIP, Office ZIP entry
names (without decompression), PE, ELF, Mach-O and shebang scripts. UTF-8 text
uses its filename suffix for plain text, CSV, Markdown or JSON; empty/unknown
bytes are `application/octet-stream`.

## Send and receive

The SDK's `Agent.send`, `Received.reply` and profile `build` accept
`attachments=[Attachment("report.pdf", pdf_bytes, "application/pdf")]`, with
`Attachment` imported from `amx.attachments`. The declared type is optional.
Files become base64 MIME attachments. Names become portable basenames without
controls, bounded to 180 UTF-8 bytes; non-ASCII names use RFC 2231 encoding.
`payload.json` remains the inline machine-readable part, not a file attachment.
Parsed messages expose attachment `index` (zero-based), `filename`, true `type`,
`declared_type`, `size` and decoded `content` bytes on demand. `metadata()` omits
bytes. Human mail uses the same parser.

For MCP, write a file on the MCP server's host, then call `send` or `reply` with
`attachments=["/absolute/path/report.pdf"]`. Results list filename, true type
and decoded size. Inputs must resolve to readable regular files; bounded reads
are stat-checked. State, config and credential directories, including symlink
targets, are forbidden. Defaults cover `~/.amx`, `runner-state`, and `amx` under
XDG data/state/config roots. With custom paths use `amx-mcp --state` and repeat
`--credential-directory` for additional private directories. To reattach a
previously saved file under private runner state, first copy it to a non-private
working directory; input refusal applies to saved files too.

MCP `list_inbox` and `read_thread` include attachment metadata. Call
`save_attachment(message_id, index, directory=None)` for a host-local saved path.
Saving does not take, flag or handle the message, even when AX/the runner owns it.
The default directory is `<agent-runner-state>/attachments/<task>/`; without
`--state` it is `$XDG_DATA_HOME/amx/host/ai.amx.runner.<address-digest>/attachments/<task>/`
(`~/.local/share` is the XDG default). An explicit directory selects another
host-local folder. Names cannot escape it; exclusive 0600 writes and numeric
prefixes avoid overwrites and symlinks. Saved files have no automatic retention:
the host operator removes them under their own retention policy.

AX relay replies accept `data.attachments`, a list of host-local paths with the
same file/private-state/type/size checks. The relay persists complete prepared
MIME bytes before SMTP, so retries after temporary or uncertain submission do
not reread changed files or require the original path. Inbound files are saved
under the runner's explicit `--state/attachments/<task>/` and listed by name,
true type, size and path in AX text and v1 `data.attachments`. The target must
share the runner's filesystem host and OS user to open them.

## Limits and blocked types

`limits.max_bytes` defaults to 10,485,760 bytes (10 MiB) for the complete encoded
input message, including body, headers, payload and base64 overhead, not 10 MiB
of decoded files. The SDK refuses over-limit mail before preparation/submission
and refuses executable true types even if declared as PDF. For non-default lanes
set `Agent(..., max_bytes=<lane limit>)`; MCP/runner accept `--max-bytes` or
`AMX_MAX_BYTES`. Keep client settings aligned with gateway YAML; the gateway is
authoritative.

`limits.blocked_attachment_types` matches true types at milter end-of-data and
submission. Defaults are:

- `application/x-msdownload` (compatibility)
- `application/vnd.microsoft.portable-executable` (PE)
- `application/x-executable` (ELF)
- `application/x-mach-binary` (Mach-O)
- `text/x-script` (shebang)

Oversized/blocked input receives `552 5.3.4` (`size-or-attachment`). Submission
checks precede signing, journaling, holds and reinjection; bypassing the SDK
cannot bypass enforcement. ZIP contents are not scanned for nested executables.

The Postfix live topology's default configured limits are:

| Hop | Bytes | Scope |
|---|---:|---|
| SDK / authenticated submission | 10,485,760 | complete encoded input |
| Public port 25 / public milter | 10,485,760 | encoded received mail |
| Postfix cleanup, reinjection, queue | 31,457,280 | `GLOBAL_MAX_BYTES = 3 * max_bytes` |
| Trusted sibling milter / gateway LMTP | 31,457,280 | internal signing/rendering headroom |
| Postfix outbound SMTP/relay | no smaller local cap | queue headroom; remote MX SIZE applies |

The trusted sibling path is gateway-only, never a public size bypass. Identity,
attachment and policy checks remain. Extra headroom accommodates DKIM, Received
headers and rendered text. Remote recipients enforce their limits on the final
signed mail. This is configuration evidence, not a claim of live boundary
measurement: verify actual deployed hop values before relying on them.

## Holds and validation

The content judge reads text parts and machine payload, not attachments. An
attached document may carry instructions the judge never sees. Treat files as
untrusted data. The held copy is the complete MIME message; approvers can inspect
or download attachments before moving it to Approved. Release signs and sends
the journaled copy without dropping or rewriting attachment bytes. Unit tests
are not a claim of a real mail-client walkthrough.

The attachment scenario registers disposable agents, exercises a byte-identical
PDF and tests a disguised executable refusal. Run scenarios only through the
supported isolated suites in [dev-suite.md](dev-suite.md), never against
established agents or foreign Compose projects. Native unit coverage is
`uv run --group gateway pytest tests/unit/test_attachment*.py -q`.

See [public self-hosting](selfhost-public.md#attachments-sh-42) for operator
consent and approval, and [the private guide](selfhost-people.md) for Stalwart.
