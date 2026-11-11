# Findings: contoso on Stalwart (M6)

PLAN §10 question 5 asks how much of the design depends on the MTA. M6 answers it by swapping
contoso's Postfix + Dovecot mailhost for Stalwart Community and rerunning the scenario suite.
northwind and plainmail stay on Postfix, so every contoso scenario crosses the two MTAs.

- **Historical M6 Stalwart:** `stalwartlabs/stalwart:v0.16.23` pinned by digest (`sha256:be2156…2592`). This
  is the Community edition (AGPL-3.0): the image is unmodified and no Enterprise license key is
  set.
- **Provisioning:** `stalwart-cli` v1.0.12, checksum-verified.
- **Run it:** `make suite MTA_CT=stalwart` (host lock, smoke/scenarios and cleanup included).
- **Pieces:**
  - `deploy/compose.stalwart.yaml`
  - `deploy/stalwart/` (`config.json`, and the Dockerfile of the one-shot init image)
  - `amx.adapters.stalwart` (renders the Stalwart plan and runs the provisioning)
- **Design and debt:** PLAN §5.8 and §8.
- **CVE-2026-81036** (OAuth `redirect_uri`, open upstream at v0.16.24): the plan closes it with
  two `OidcProvider` settings, measured below. It gates any Stalwart live lane.

## Self-host spike (SH-00)

Native measurements below support the SH-00 decision; independent review,
exact-head CI and publication remain the parent worker's gates. All measurements
elsewhere on this page describe their historical releases/runs, not the new pin.

The dev mailhost and local-only provisioner now both pin
`stalwartlabs/stalwart:v0.16.25@sha256:74e5a7d55303ba525d939c6bf97ed4e010df7521f52d80afc22a815b66bd53f3`.
The OCI index was retrieved with read-only
`docker buildx imagetools inspect stalwartlabs/stalwart:v0.16.25` on 2026-10-15.
Its linux/amd64 manifest is
`sha256:b5da09f43a0e407073353162810e756030bd5258aef0f7edbf82e73e85dc8359`.
This is image provenance, not a native execution measurement or a security verdict.
The existing OIDC mitigations remain in place.

Repeatable native instrumentation: `tools/stalwart_probe.py`, invoked only by
`make suite MTA_CT=stalwart SH00_PROBE=1`. See [dev-suite.md](dev-suite.md#sh-00-native-probe-support)
for custody, isolation and output format. Its experimental settings are separate
from the normal Stalwart adapter: no SH-01, SH-02, SH-12 or SH-13 gateway behavior
is implemented by this checkpoint, and no scenario ID is added.

| Check | Current measurement status | Probe support / remaining acceptance |
|---|---|---|
| (a) Sibling loop | native pass, review pending | At `78f907f`, `sibling-in` 10027 self-relayed to `sibling` 10028 and then the LMTP observer. One accepted delivery per probe; a deliberate LMTP refusal produced a local `multipart/report` DSN. No loop rejection prevented delivery. SH-13 should build this mechanism; this probe adds no gateway sibling authorization. |
| (b) SASL identity | native pass, review pending | TLS submission on 465 and STARTTLS on 587 each produced three milter connections (MAIL, RCPT, DATA). All three carried `{auth_authen}: ops@contoso.test` at MAIL replay, including the DATA connection with EOM. |
| (c) Milter coverage | native pass, review pending | Ingress/sibling endpoint connection counts were 3/0 on 25, 465 and 587; 0/0 on 10025; 0/3 for the 10027 self-relay and for direct 10028. The second milter is gated on `listener == 'sibling'`, not on the constant `Stalwart v0.16.25` daemon macro. |
| (d) Signing split | native pass, review pending | At `e949577`, `dkimSignDomain` signed people mail with the verified `sh00`/`contoso.test` key. An actual gateway submission's exact outbound journal bytes were reinjected on 10025: the one original agent signature remained identical and cryptographically verified before/after; Stalwart added no signature. The raw body was **not unchanged**: 53 → 55 bytes, exactly one appended CRLF (details below). |
| (e) Client protocol | native pass within fixture limits | At `e949577`, HTTPS autoconfig XML 200 (1661 bytes) supplied IMAPS 993 and TLS submission 465; those parsed settings were used for INBOX read, authenticated send, ordinary-approver shared `UID MOVE`, and Approved readback. HTTP variants and the well-known path also returned the native XML. Autodiscover GET was 404; POST was 200 with a structurally parsed settings response (1557 bytes), not merely a successful status. Real DNS/SNI hostname certificates and devices are unmeasured. |
| (f) NOHDRS stall | native gateway suite pass, review pending | At `78f907f`, the ordinary real amx gateway path completed smoke and all scenarios. The unit test invokes the actual vendored pymilter negotiate callback and confirms NOHDRS stays off. The recorder is not equivalent to pymilter and supplies no evidence for this row. |
| (g) Private domains | native pass, review pending | Management apply plus query readback accepted `home.arpa`, `amx.internal`, a placeholder tailnet name and each `agents.` subdomain. Decided: SH-10 defaults to `home.arpa` (reversible); real MagicDNS/tailnet DNS and TLS have not been measured. |

The `78f907f` exact tree (`6fe5b16d409b6307fdd73dc7aeaae49766d89c37`)
ran `make suite MTA_CT=stalwart SH00_PROBE=1` on 2026-10-15 in a task-owned
isolated Docker engine: smoke 1 passed; scenarios 48 passed, 3 skipped, 1 existing
xfail in 479.20 seconds; supervisor exit 0 including cleanup. The parent's baseline
at `005880a` had the same scenario outcomes on 0.16.23. Evidence artifacts are
the probe's native log and extracted result. These artifacts are not distributed with
this repository; the measurements below record the relevant macro names and delivery
counts. A prior candidate failed on the probe's invalid `Certificate`
`path` property; using the pinned schema's `filePath` repaired that instrumentation,
not Stalwart or gateway behavior.

### Final native probe and the signing criterion

The final code measurement is `e9495771961baf44be4f6e11faa39138305bfb68`,
tree `b2e47782817687acfa98b33f2a061e411ad25224`, exported identically into
`/work/native-round6`. On 2026-10-15 it ran
`make suite MTA_CT=stalwart SH00_PROBE=1` in the task-owned isolated engine
`195e60b1-0034-4a91-8244-c5d306dcf22f`, through X0's host lock, ownership and
cleanup, with a minimal environment, nice 10 and eight-thread caps. Smoke passed
(1 test, 3.80 seconds). The native probe emitted all implemented checks passing;
its overall `partial` status means (f) comes from the real gateway suite, not the
recorders. `native-round6.log` and `native-round6.result.json` retain the actual
counts, macros, XML structures and body observations. The full round6 scenario
run subsequently completed: **48 passed, 3 skipped, 1 existing xfail in 488.32
seconds**, supervisor exit 0. Readback found zero `amx` containers, volumes and
networks, no ownership journal/active marker, and no generated state left behind.
This supplies the separate actual gateway-path evidence for (f), alongside the
earlier complete .25 suite above and the parent's ordinary .25 run (48 passed,
3 skipped, 1 existing xfail in 485.34 seconds). Local units on the final code
passed 1111 tests with 3 optional AX-binary skips in 275.06 seconds. The findings
publication changes after `e949577` are documentation-only, not unmeasured code.

**What changed in (d)'s test, not in the gateway.** The original SH-00 criterion
is people-domain signing and no additional signature on gateway-signed agent
reinjection. The probe had added a stronger raw-body byte-equality requirement.
The retained `parent-round5-stalwart.log` demonstrates that proxy failing even
with the exact gateway journal bytes, valid DKIM before/after, and one identical
signature. This was not merely a possible IMAP normalization artifact.

Decided (reversible): keep signature identity/count and cryptographic checks as
gates; report the body delta separately, allowing only identical bytes or the
exact observed single appended CRLF. Every other delta still fails, including
other canonical-equivalent edits. The corruption, fake-signature and extra-signature
refusal tests remain intact. No production gateway behavior was changed.

The new native observation is `equal: false`, 53 bytes before and 55 after:

- Before SHA-256: `fb703622a0c627704d2088de78f2c9fc9b24ee4342aec66854a70cf9f4f2a7eb`.
- After SHA-256: `7018d21c3420faf29cc2bd5fe2b0f229f8c015fd8ca14c4389c3db92171b0676`.
- Delta: one appended `CRLF`, creating a trailing empty line; the relaxed canonical
  bodies are equal, and both cryptographic DKIM verifications succeed.

`amx.identity.sign` explicitly uses `relaxed/relaxed`; dkimpy's
`Relaxed.canonicalize_body` strips trailing empty lines, as specified by
[RFC 6376 §3.4.4](https://www.rfc-editor.org/rfc/rfc6376#section-3.4.4).
Neither raw-body nor whole-message byte identity is claimed.

### Discovery measurements and limits

The client script follows the ISP-hosted Thunderbird URL priority: HTTPS
`autoconfig.<domain>/mail/config-v1.1.xml`, HTTPS well-known, then their HTTP
variants. From the fixture's `mail.contoso.test` hostname it derives the people
domain; the native XML advertises `mail.contoso.test`, IMAP 993/SSL, SMTP 465/SSL,
`password-cleartext` over TLS and `%EMAILADDRESS%` usernames. The script parses
that real XML rather than generating substitute settings. It uses the advertised
ports to read/send/approve a fixture hold. Real gateway release remains S06c's
separate full-suite check.

The autodiscover POST response has root `Autodiscover`, action `settings`, and
the Microsoft `autodiscover/responseschema/2006` and
`autodiscover/outlook/responseschema/2006a` namespaces. Parsed protocol records
advertise IMAP 993, SMTP 465 and POP3 995, with server `mail.contoso.test`, SSL on,
authentication required and login `ops@contoso.test`. POP3 was advertised, not
exercised. These observations establish a native configuration response, not
validation of Outlook or any other actual client. SH-11 need not invent static
XML for these measured native endpoints, but still owns real deployment/account
setup and its other deliverables.

This sealed fixture maps candidate hostnames to localhost and validates only the
development certificate's localhost SAN. Real discovery DNS, SNI/hostname
certificate validation, tailnet connectivity and every real client/device remain
unmeasured. External ISPDB/MX fallback was deliberately not fetched. The existing
workstation Docker project is foreign and was never used.

SH-13 should build the measured self-relay mechanism, and SH-10 should default to
`home.arpa` (reversible). The Stalwart default is supported at the measured spike
level; this is not public-profile hardening or a release claim. Independent review,
final-source tests/CI and publication remain pending.

Verdict: Stalwart

## SH-13 implementation and acceptance boundary

The normal dev/live adapter now renders the SH-00 self-relay: gateway-only
10027 admission, a `received_via_port` route to loopback 10028, and a second
fail-closed milter selected only for `listener == 'sibling'`. The gateway uses
the actually reached milter endpoint for sibling provenance, not Stalwart's
constant daemon macro. Configuration and compatibility details are in
[task-transitions.md](task-transitions.md).

S22 no longer has a Stalwart `xfail`: both compose suites must prove delivery
and refusal of the identical signed port-25 replay. Unit tests cover native
libmilter through the TCP frontends with three-stage Stalwart replay, local
signature verification, authorization failures, retry receipts and refusal DSNs.
These are not a substitute for a native Stalwart S22 result. During implementation
the canonical local suites refused the foreign shared Docker stack with
`amx resources have no suite ownership journal`; no stack was adopted or changed.
Exact-head hosted compose CI remains required before publication/merge.

## Historical M6 verdict

**Proposal §4's claim holds: the same gateway works on either MTA, with the hold queue kept
where each mailhost can protect it.** Proposal §4 and §5.9 say the same gateway works with
Stalwart or with Postfix plus Dovecot. With contoso on Stalwart:
- the gateway image, its policy core, and its configuration file are the same;
- the whole scenario suite passes, 29 of 29 tests;
- two changes made that possible in M6, 57 lines of gateway Python in all;
- two more came after M6. One makes Stalwart's per-stage milter connections count as one SMTP
  session, so its decisions and backpressure match Postfix's ("After M6", below). The other
  makes the hold queue's location configuration (100 lines).

M6 itself shipped with one failure, S06d, which checks that an agent cannot approve its own held
mail. That rule never lived in the gateway: on Dovecot it is an IMAP ACL on the agent's own
Outbox. Stalwart cannot express it there, because an owner has every right on its own folders.
The fix expresses the rule Stalwart's way, by ownership. Each agent's queue lives in an account
the agents do not own, shared read-only to the agent (see "The approver"). The gateway only had
to learn where the queue is.

Three qualifications on "the same gateway":
- **Stalwart was driven through its milter client, not the MTA hooks the proposal planned for
  it** (§5.3: "registers as an MTA hook (Stalwart)"). The milter was enough, so the HTTP-hooks
  adapter was never built.
- **Stalwart's milter is a different dialect of the same protocol.**
  - It opens a new connection at each stage and replays the session so far.
  - It sends the whole message as the body.
  - It resolves the milter's host only once, and a failed lookup silently fails open.
  - Its connect timeout lives in a different setting.

  The gateway handles all of these. The body needed code in M6, and the per-stage connections
  needed code after it; the rest is configuration.
- **"Customize the MTA a bit" is about the same size on both MTAs.** It is 126 Stalwart settings
  against 142 lines of Postfix and Dovecot, which are not quite the same unit. Stalwart has more
  defaults to turn off, and its configuration has to be written into its database by a client,
  not dropped in as files.

## Scenario results

Both runs are on this branch's final code, from `make down` then `make up`, with
`uv run pytest scenarios -m integration`. Contoso on Stalwart gave 28 passed and 1 xfailed in
2 min 31 s. The default Postfix run gave 29 passed in 3 min 0 s. Smoke passes on both. Timings
below are from those two runs. Earlier runs on this branch gave the same results with slightly
different timings, except one Postfix run in which S10 lost a race that predates M6 (PLAN §8).
S11's LLM runs used the host's Ollama (`deepseek-v4.1-flash:cloud`) and passed on both MTAs.

**Rerun after the hold-queue fix (PLAN §5.8).** These runs are on the final code, after the cold
review's fixes and on top of the stage correlation (PR #23). Each ran from `make down`, `make up`,
and `make smoke`, then `make scenarios`:
- **Contoso on Stalwart:** 29 passed in 2 min 45 s, S06d included.
- **Default Postfix:** 29 passed in 2 min 19 s.

Smoke passed on both, S11's LLM runs ran on both, and neither gateway restarted. Before the
review fixes, the same runs gave 29 passed on each MTA as well.

One earlier Stalwart run on the same code failed S06d before its probes. gateway-ct aborted in
native code: glibc logged `malloc_consolidate(): unaligned fastbin chunk detected`, with no
Python traceback. It happened 0.6 s after S06c's release, as Stalwart opened a milter connection
for S06d's first message. That message got `451 4.3.5` in the second the gateway took to
restart. The crash did not recur in four more runs of both contoso S06 tests (on a gateway with
`PYTHONFAULTHANDLER=1`), or in four later full runs on this branch. It also did not appear in
the stage-correlation branch's full runs on both MTAs. It was a heap write after free in
pymilter's handling of Python thread states under libmilter's worker pool. Stalwart's connection
per stage makes about four times as many milter connections per message as Postfix, so it hit
the rare case first. The gateway now builds a patched pymilter; PLAN §8 has the cause and the
fix.

"Crosses Stalwart" says what the scenario does on contoso's mailhost:
- **in:** contoso's inbound SMTP and the milter;
- **LMTP:** delivery to the gateway;
- **out:** reinjection and outbound delivery;
- **IMAP:** mailbox reads, appends, and moves.

| Scenario | Crosses Stalwart | Postfix | Stalwart | Notes on Stalwart |
|---|---|---|---|---|
| S01 round trip, Victor CC'd | in, LMTP, IMAP, out | pass | pass | The trace shows `mailhost-ct stalwart` queue and delivery lines. |
| S02 human reply | (northwind and plainmail only) | pass | pass | |
| S03a unknown agent at RCPT | in | pass | pass | `550 5.1.1` from the RCPT-stage milter. Stalwart logs a milter-refused RCPT without the recipient, so only the gateway's row ties it to the task (see "Other things"). |
| S03b bad machine part, bounce | in | pass | pass | `550 5.6.0` at end of DATA; northwind bounces. |
| S03c dead MX | (northwind only) | pass | pass | |
| S04a watermark backpressure | in, LMTP, out | pass | pass | All six were handled 11.5 s after submission (Postfix: 11.6 s), and none was lost. Of the six deferrals, 3 were at RCPT and 3 at the end of DATA. After M6 the stage correlation put all six at RCPT, as on Postfix (below). |
| S04b gateway outage | in, LMTP | pass | pass | `451 4.3.5` after 5.6 s; delivered 4.5 s after the restart (Postfix: `451 4.7.1` after 0.4 s; delivered 4.5 s after the restart). The first run failed (see "Other things"). |
| S05a unsigned or wrong selector | in | pass | pass | `550 5.7.1` from the gateway's DKIM check; Stalwart verifies nothing itself. |
| S05b DKIM revocation | in | pass | pass | |
| S05c response-only grant | (submission only) | pass | pass | |
| S06 hold queue, approve and reject | (northwind only) | pass | pass | |
| S06c contoso hold, approver releases | in, LMTP, IMAP, out | pass | pass | At pat 0.3 s after the approver's move (Postfix: 0.8 s). After M6 the approver is `approver@contoso.test`, an ordinary account moving the message in `holds@`'s shared folders: at pat 0.3 s after the move. |
| S06d agent cannot approve its own hold | IMAP | pass | pass (was a strict `xfail` in M6) | M6: the agent's own login could do every step S06 forbids, and its own move released the hold. After M6, every probe is refused on Stalwart: `NOPERM`, or `CANNOT` for the rename out to another account. A copy in the agent's own `Outbox/Approved` is ignored. See "The approver". |
| S07 loop guard | in, LMTP, out | pass | pass | |
| S08 journal verify | (gateways) | pass | pass | |
| S09 closed task | in | pass | pass | `550 5.1.6` at RCPT. |
| S10 replay | in, LMTP | pass | pass | |
| S11a LLM negotiation, person steps in | in, LMTP, IMAP, out | pass | pass | inspections is contoso's LLM agent. |
| S11 injection, agent lane | in, out | pass | pass | |
| S11 injection, human lane | in, LMTP, out | pass | pass | |
| S11 MCP server | out | pass | pass | |
| S12 human lane (two tests) | in, LMTP, IMAP | pass | pass | The milter's transport-header strip (`chgheader`) works on Stalwart's header rewrite. |
| S13a injection, agent lane | in | pass | pass | |
| S13b injection, human lane | in, LMTP, IMAP | pass | pass | The tainted reply lands in Stalwart's `Outbox/Held`. |
| S14 parts disagree | in | pass | pass | |
| S15 intent smuggling | in | pass | pass | |
| S16 judge down | in, LMTP, IMAP | pass | pass | `451 4.7.0` passes through verbatim. |
| S17 off / observe / enforce | in, LMTP, IMAP | pass | pass | |

## What the gateway had to change: 57 lines in M6, more after

`tools/measure.py` counted the gateway at 3,278 logical lines on `main` before M6 and 3,335 on
M6's branch. In M6, policy, LMTP delivery, submission, holdwatch, the journal, and the content
judge did not change. Two things did, and a third came after M6:

1. **Stalwart sends the whole message as the milter body.** Its milter client sends each header
   with `SMFIC_HEADER` and then the entire raw message, headers included, in the `SMFIC_BODY`
   chunks. That is by design ([discussion #2369](https://github.com/stalwartlabs/stalwart/discussions/2369)).
   Postfix sends only the body. The adapter rebuilt the message as headers + body, so on
   Stalwart the header block appeared twice, and the DKIM body hash failed on every signed
   message. Measured with the pre-M6 gateway image behind Stalwart, a correctly signed agent
   request got `550 5.7.1 dkim fail: bad signature`.
   - The fix: the milter recognizes Stalwart by the `{daemon_name}` macro it sends at CONNECT
     (`Stalwart v0.16.23`; Postfix sends `$myhostname`), and drops the repeated header block.
   - It drops the block only when the block holds exactly the headers the MTA sent, in order,
     and accepts CRLF or bare-LF line ends. The cold review asked for that: a cut at the first
     CRLFCRLF alone could land inside a bare-LF body and hide text from the content judge while
     the agent still received it.
   - If the block cannot be found exactly, the milter answers `451 4.3.0` and the message is not
     judged or delivered. It fails closed.
   - `amx.adapters.milter.message_body` has unit tests: both body shapes, bare LF, folded
     headers, a message with no body, and each kind of mismatch.
2. **The master login is spelled differently.** Dovecot's is `user*gateway`. Stalwart's is
   `user%gateway@contoso.test`: an account that holds the `impersonate` permission logs in as
   the target. `mailbox.master_login` in the gateway YAML is now a template, and the default is
   Dovecot's. `compose.stalwart.yaml` sets `AMX_MAILBOX_MASTER_LOGIN` for gateway-ct, so one
   `contoso.yaml` serves both mailhosts.
3. **After M6: the hold queue's location is configuration.** `mailbox.hold_owner` and
   `mailbox.hold_prefix` (the `AMX_MAILBOX_HOLD_OWNER` and `AMX_MAILBOX_HOLD_PREFIX` overrides)
   say whose mailbox holds each agent's queue, and under which folders. The defaults are the
   agent's own mailbox and `Outbox/`, which is Dovecot's layout, so the Postfix path is
   unchanged.
   - Submission, holdwatch, and `amx-mcp --held-folder` use the location.
   - When the queue is not the agent's own, holdwatch files the released message's signed copy
     in the agent's Sent.
   - Mailbox names are quoted where they contain a space (`Shared Folders/…`), because imaplib
     sends them as they are.

   The gateway went from 3,541 to 3,641 logical lines (on `main` after the stage correlation
   below).

Everything else Stalwart needed lives in its own configuration (next section), in the scenario
harness, and in `amx trace`, which now reads Stalwart's log lines beside Postfix's.

### After M6: one SMTP session across Stalwart's stage connections

Stalwart opens a milter connection for every stage and every RCPT command, and each one replays
the session so far ("How Stalwart drives a milter", below). The gateway kept its state per
connection. It therefore decided and recorded the replays again, and it released an RCPT
admission when the RCPT stage's connection closed. `StageReplays` in `amx.adapters.milter` now
ties each connection to its SMTP session. It is 199 logical lines (`tools/measure.py`: 3,342 on
`main` before, 3,541 after), and only connections whose `{daemon_name}` is Stalwart's use it.

**How a connection is placed.** Stalwart sends no queue id (`{i}`) and no session id. What it
does send identifies the session:
- **At CONNECT:** its `{daemon_name}` and `j`, and the SMTP client's address and port (also
  `{client_addr}` and `{client_port}`). No two SMTP sessions open on one Stalwart share these.
- **At MAIL:** the sender. A transaction is matched on it.
- **At RCPT:** every RCPT Stalwart accepted so far, in order, then the new one at the RCPT
  stage. Each is matched on its position and address.

A replay that matches is answered with the decision the first connection made: no evaluation,
no row, no second admission. The admission is carried by the session, bound to the Message-ID
at end of DATA, and settled by LMTP as on Postfix.

**Why it fails closed.** Whatever does not match is decided afresh, which is what the gateway
did for every replay before. That covers:
- a gateway restart between stages;
- a session idle past 60 s;
- a recipient Stalwart rewrote or expanded after the milter saw it;
- a recipient Stalwart refused after the milter accepted it. Stalwart runs the milter before its
  own RCPT checks (`crates/smtp/src/inbound/rcpt.rs`), so its next replay omits it. The replay's
  first difference also releases the admissions of every RCPT from there on.

Nothing depends on when a connection's close() is handled. Stalwart opens a session's next
connection only after the last one's replies, but its QUIT does not wait for the milter to
close, so the next connection can arrive first. The latest connection holds the session, and
one that loses it to a newer one is decided afresh from then on.

**Transactions that end without DATA.** Stalwart never sends ABORT. Any stage after MAIL
replays at least one RCPT, so a connection that replays MAIL and no RCPT was a new
transaction's MAIL stage, from the same sender (after RSET, say). The old transaction's
admissions are released, and the MAIL row is recorded, when the next connection takes the
session over (or at close() if none does). So even when the close() comes late, the next
stage never reuses the old transaction's decisions. A new sender at MAIL, or end of DATA, ends
the transaction too, and so does a DATA stage that is dropped before end of DATA. An admission
abandoned any other way counts until the session's next connection, its next MAIL, or 60 s
idle. Stalwart's greylisting, off here, would be the common case (PLAN §8).

**Measured.** The counts are rows in contoso's `policy_events`. Each Stalwart column is
`make down`, `make up MTA_CT=stalwart`, then S04a and S01 alone. The Postfix column is the same
two scenarios' rows, taken from a full Postfix run on this branch.

| | Stalwart, `main` (6ecab3a) | Stalwart, correlated | Postfix |
|---|---|---|---|
| S04a deferrals at RCPT / at end of DATA | 3 / 3 | 6 / 0 | 6 / 0 |
| `recipient-ok` rows for S04a's six messages | 15 | 6 | 6 |
| `recipient-ok` rows for S01's task | 2 | 1 | 1 |
| CONNECT rows / MAIL rows | 36 / 36 | 13 / 13 | (not isolated; healthchecks add CONNECT rows) |
| End-of-DATA rows | 7 | 7 | 7 |

Before, three messages that won their RCPT were deferred after their body was sent. Each of
the six S04a messages left one `recipient-ok` row per connection that decided it. Now each
decision leaves one row, as on Postfix, and the 13 CONNECT and 13 MAIL rows are one per SMTP
session and transaction. S04a asserts both on both MTAs: no deferral at end of DATA, and one
`recipient-ok` row per message. In six S04a runs on Stalwart, every deferral was at RCPT.
Handling all six took 11.2 to 21.6 s. That spread comes from northwind's retry timing (PLAN §8
gives 13 to 23 s on Postfix), not from where the deferral happened.

**The whole suite, rule by rule.** The final runs were `make down`, `make up`, `make smoke`,
and `make scenarios`, on each MTA.
- **Results:** Stalwart gave 28 passed and 1 xfailed (S06d, as before); Postfix gave 29 passed.
- **Matching rows:** every other MAIL, RCPT, and end-of-DATA count in contoso's `policy_events`
  is equal by rule: 58 `mail-ok`, 46 `recipient-ok`, 6 `agent-watermark`, 2 `closed-task`,
  1 `agent-unknown`, and 33 `eod-ok`, as well as every end-of-DATA refusal and taint.
- **The one difference:** a third `non-agent-recipient` row on Stalwart. It is smoke's
  relay-denied recipient. Stalwart runs the milter before its own relay check, so the milter
  accepts the recipient and Stalwart then refuses it with `550 5.1.2`. Postfix refuses it
  before the milter.
- **CONNECT rows:** 58 on Stalwart against 128 on Postfix. The difference is Postfix's
  healthchecks.
- **Restarts:** neither gateway restarted in either run.

**Configuring it away was not possible.** The pinned version's `MtaMilter` object (source, and
the [reference](https://stalw.art/docs/ref/object/mta-milter/)) has a `stages` set and no
setting that keeps one connection across stages. Each configured stage is a separate
connection.
- **Dropping `mail`** still leaves the RCPT-to-DATA replay that carried the admission bug.
- **`data` alone** would move the RCPT rules to end of DATA: unknown agent, closed task, and the
  watermark. PLAN §5.4 rejects that.
- **Protocol flags** (Stalwart's `flagsProtocol` offer, or the milter's own negotiation) can make
  Stalwart skip CONNECT, MAIL, or RCPT on every connection, but not per stage.
- **MTA hooks** are one request per stage as well.

## The configuration Stalwart needed, beside Postfix and Dovecot

Stalwart 0.16 has no configuration file beyond `config.json`, which only names the datastore.
Every setting is a JMAP object in the datastore, written by `stalwart-cli apply` from a
declarative plan. `amx.adapters.stalwart` renders that plan from `deploy/dev-users`, the same
file the Postfix mailhost's entrypoint reads. It is 24 operations and 126 settings;
`uv run python -m amx.adapters.stalwart plan …` prints it. The count leaves out accounts and
free-text descriptions. Names count, because routes, listeners, schedules, and folders are
referred to by name.

| What it does | Postfix + Dovecot (`deploy/mailhost/`) | Stalwart plan (`amx.adapters.stalwart`) |
|---|---|---|
| Call the gateway's policy during the SMTP transaction | `smtpd_milters = inet:gateway-ct:8890`, `milter_protocol = 6` | `MtaMilter`: `hostname: 172.30.0.21` (an IP, see below), `port: 8890`, `protocolVersion: v6`, `stages: {mail, rcpt, data}` |
| Fail closed when the gateway is down | `milter_default_action = tempfail` | `MtaMilter.tempFailOnError: true` |
| Milter timeouts | `milter_connect_timeout`, `milter_command_timeout`, `milter_content_timeout` | `timeoutCommand`, `timeoutData`; `timeoutConnect` is read but unused (per the source), so the plan leaves it at its default |
| Reinjection listener with no milter | master.cf `10025 inet … -o smtpd_milters=` | `NetworkListener reinject [::]:10025`; `MtaMilter.enable: local_port == 25` |
| Trust the compose network; relay only to the five domains | `mynetworks = 172.30.0.0/24`, `permit_mynetworks`, `allowed-recipients.pcre` (five domains) | `MtaStageRcpt.allowRelaying: is_ip_in_cidr(remote_ip, '172.30.0.0/24') && (rcpt_domain == 'northwind.test' \|\| …)`, with the same five domains |
| No SASL on reinjection | (Postfix smtpd asks for none) | `MtaStageAuth.require: local_port != 25 && !(local_port == 10025)`; the default demands AUTH on every port but 25 |
| Agent mail goes to the gateway over LMTP | `transport_maps`: `agents.contoso.test lmtp:inet:gateway-ct:2424` | `MtaRoute gateway` (Relay, `gateway-ct:2424`, `lmtp`); `MtaOutboundStrategy.route`: `rcpt_domain == 'agents.contoso.test'` → `'gateway'`, *before* the local rule |
| Keep the task token in the recipient | `recipient_delimiter = +` | `Domain agents.contoso.test`: `subAddressing: Disabled` and `allowRelaying: true` |
| Mail domains | `virtual_mailbox_domains = $mydomain, $agent_domain`, `vmailbox` | `Domain contoso.test`, `Domain agents.contoso.test` (`dkimManagement: Manual`) |
| Hostname | `myhostname` | `MtaStageConnect.hostname`, `SystemSettings.defaultHostname`, `STALWART_HOSTNAME` |
| Retry in seconds, bounce in 30 s | `queue_run_delay`, `minimal_backoff_time 5s`, `maximal_backoff_time 30s`, `maximal_queue_lifetime 30s`, `bounce_queue_lifetime 30s` | `MtaDeliverySchedule local/remote/dsn`: retry 5, 10, 20, 30 s; expiry 30 s |
| Users | Dovecot `passwd-file` built from dev-users | `Account` per user; `Authentication` relaxed to accept the dev passwords |
| Master logins | `passdb … master = yes` for gateway and approver, `auth_master_user_separator = *` | `Account gateway@contoso.test` with the `impersonate` permission; login `user%gateway@contoso.test`. The approver is an ordinary account (next rows). |
| Plain IMAP on 143 | `protocols = imap`, `disable_plaintext_auth = no`, `ssl = no` | `NetworkListener imap [::]:143`, `useTls: false`; `Imap.allowPlainTextAuth: true` |
| Folder names | `mailbox Sent/Drafts/Trash { auto = subscribe }` | `Email.defaultFolders`: Stalwart's defaults are "Sent Items" and "Deleted Items", and the gateway files mail in `Sent` |
| Hold-queue folders | each user's `Outbox/*`: the entrypoint runs `doveadm mailbox create`, and `auto = subscribe` | `Holds/<agent>/*` in the mailbox of `holds@contoso.test`, an account with no password; the init container runs IMAP `CREATE`, `SETACL`, and `SUBSCRIBE` as the gateway's master login. The gateway reads the location from `AMX_MAILBOX_HOLD_OWNER` and `AMX_MAILBOX_HOLD_PREFIX` |
| The agent cannot approve its own hold | `dovecot-acl`: negative owner rights on `Outbox/*`, plus an ACL-limited approver login | ownership: IMAP ACLs give the agent `lr` on its queue and `approver@contoso.test`, an ordinary account, Dovecot's approver rights: `lrswte` on Held, `lrswi` on Approved and Rejected (see "The approver"; M6 had no equivalent) |
| Log to stdout, where `amx trace` reads it | `maillog_file = /dev/stdout` | a `Tracer` of type `Stdout`, with the image's file tracer disabled (it writes to a missing `/var/log/stalwart`) |

**Stalwart defaults that Postfix doesn't have, switched off to match:**
- **Checks and signing.** The spam filter, and SPF, DKIM, DMARC, ARC, and reverse-IP checks
  (`SenderAuth`). Postfix runs none of them here; the gateway verifies DKIM and DMARC itself.
  DKIM signing of mail and of bounces is also off, because the gateway signs per agent.
- **Rate limits.** Two inbound throttles: 5 per second per IP, and 25 per hour per sender domain
  and recipient. S04 alone sends six messages in a second from one IP.
- **Session limits.**
  - A cap of 10 messages per SMTP session, which northwind's connection reuse would hit.
  - A 5 s sleep after a refused RCPT, now 1 s with a hard limit of 20, as Postfix's
    `smtpd_error_sleep_time` and `smtpd_hard_error_limit` do.
  - IP auto-bans; the compose network is an `AllowedIp`.
- **EHLO.** It was required and had to be a fully qualified name on port 25. The scenario
  harness's raw sends skip EHLO, which Postfix allows.
- **Outbound fetches at startup.** Pyzor lookups, the ASN/geo database, and the web UI bundle
  from GitHub. The stack's DNS answers only `.test`, so these would fail anyway; they are off so
  nothing even tries.
- **OAuth clients.** After a valid login, any client id with any `redirect_uri` got an
  authorization code, and anyone could register a public client. Both are off (`OidcProvider.requireClientRegistration`,
  `anonymousClientRegistration`); see "CVE-2026-81036" at the end. Postfix and Dovecot have no
  OAuth server.

**How the plan gets in.** Stalwart binds listeners and loads its password policy only at startup,
and it resolves the milter's host only when it builds its configuration. The one-shot
`stalwart-init-ct` container therefore does this, all with no network, on the mailhost's volume:
1. Boot the pinned binary (copied unmodified from the image) and apply the settings.
2. Boot it again and apply the accounts.
3. Create the hold-queue folders over IMAP.

It takes about 3 s. It records a hash of the plan, so another `make up` on a running stack does
nothing. Then the mailhost starts from the unmodified image.

Re-provisioning, measured with the init image on a scratch volume with no network:

| Run | Settings phase | Accounts phase | Result |
|---|---|---|---|
| Fresh volume | 0 destroyed, 23 updated, 8 created | 0 destroyed, 2 updated, 7 created | provisioned; folders created for 5 users |
| Same plan again | (not run) | (not run) | "already provisioned with this plan" |
| Gateway IP changed, same volume | 1 destroyed, 30 updated, 1 created | 0 destroyed, 9 updated, 0 created | the old milter is replaced; both domains and all 7 accounts are matched and updated, not duplicated |
| Changed plan while a Stalwart runs on the volume | (fails) | (fails) | "datastore is locked (make down first)" in 0.66 s |

The plan reconciles the milter and allowed-IP lists, so it deletes entries it does not declare.
On the fresh volume that deleted nothing: Stalwart 0.16.23 ships no default milter or allowed
IP.

**Counts (PLAN §10 Q1's yardstick):**
- Postfix + Dovecot: 142 configuration lines (Postfix 63, Dovecot 79).
- Stalwart: 126 settings in 24 plan operations, 16 of them `@type` choices of a variant (for
  example `Relay` for the route, or `Disabled` for sub-addressing). Free-text descriptions are
  left out; names count.
  - Also counted on this side: `compose.stalwart.yaml` (41 lines) and the init image's
    `Dockerfile` (34 lines, most of it the checksum-verified CLI download). The Postfix side's
    Dockerfile and entrypoint are not counted in its 142.
  - The plan is written as data in `amx.adapters.stalwart`: 557 logical lines of Python, most of
    them the plan itself.
  - Since then, §5.11's `DsnReportSettings` and the CVE-2026-81036 `OidcProvider` operation
    (two settings) were added; the counts above are M6's.

The sizes are about equal. The difference is where the settings live and how they get in:
Postfix reads text files at startup, while Stalwart's settings are records in its database that
a client writes over its API.

## How Stalwart drives a milter, next to Postfix

These are protocol-level differences. The gateway's milter handles all of them. Only the first
one needed code (above), and the fixed IP was a compose setting.

- **A new milter connection per stage, and per RCPT command.** Postfix opens one milter
  session per SMTP connection. Stalwart opens a fresh connection at every enabled stage (here
  MAIL, RCPT, DATA), and one for each RCPT command. Each connection replays CONNECT, MAIL, and
  every RCPT accepted so far (`crates/smtp/src/inbound/milter/message.rs`). HELO would be
  replayed too, but the gateway's milter does not ask for it. The M6 gateway kept its state per
  connection, so:
  - It evaluated MAIL-stage rules up to three times per message and RCPT-stage rules twice. A
    delivered message left two `recipient-ok` rows in `policy_events`, and `amx trace` showed
    the RCPT decision twice.
  - It released an RCPT admission when the RCPT-stage connection closed, and took it again
    during the DATA-stage replay. Backpressure still happened at the sender, but a message that
    won its RCPT could be deferred at the end of DATA instead, after its body was sent. In M6's
    S04a run, three of northwind's six deferrals were `450 4.2.1` "in reply to RCPT TO command"
    and three were "in reply to end of DATA command". Nothing was lost, and LMTP never had to
    refuse.

  The gateway now ties the connections to their SMTP session ("After M6", above). Each decision
  is made and recorded once, and every S04a deferral is at RCPT, as on Postfix.
  - Healthcheck connections never reach the milter, because they send no MAIL. On Postfix every
    connection runs the milter's connect callback, which is about 86,000 CONNECT rows a day per
    mailhost (PLAN §8).
- **The milter's host is resolved once, at configuration time. A failure is fail-open.**
  - Stalwart resolves `hostname:port` when it builds its configuration.
  - If that fails, it logs `Unable to resolve milter hostname` and runs with no milter at all.
  - Measured in a sandbox: with `gateway-ct` not resolvable at boot, an RCPT to
    `intake+t_abc@agents.contoso.test` got `250 2.1.5 OK`, unfiltered.
  - The mailhost boots before the gateway (the gateway waits for its mailhost to be healthy), so
    the milter is addressed by a fixed IP (`172.30.0.21`), and the unreachable case becomes the
    intended `451`.
  - Postfix resolves the milter per connection and applies `milter_default_action = tempfail`
    when it cannot.
- **The tempfail reply differs.**
  - When the gateway is down, Stalwart answers `451 4.3.5 Unable to accept message at this
    time.` and Postfix answers `451 4.7.1 Service unavailable - try again later`. S04b expects
    whichever is right for contoso's MTA.
  - The gateway's own replies (`550 5.1.1`, `450 4.2.1`, `451 4.7.0 content check
    unavailable`, and so on) pass through verbatim on both.
- **Headers the milter adds are prepended, not appended.** Nothing reads header order.
- **Milter `quarantine` only adds an `X-Quarantine` header on Stalwart.** It does not hold the
  message. amx's shipped verdict ladder never quarantines, but the configurable `quarantine`
  action would degrade to "delivered with a header" on Stalwart (PLAN §8).
- **The `{i}` (queue id) macro is never sent, and no session id is either.** amx doesn't use
  the queue id. The stage correlation uses the client's address and port instead.

**MTA hooks were not needed.** The proposal planned for the gateway to register as a Stalwart MTA
hook (proposal §5.3), and PLAN §5.1 reserved `adapters/stalwart.py` for an HTTP-hooks adapter.
The milter path covered every stage the policy uses, with reply codes intact, so the HTTP adapter
was not built. Hooks would not avoid the per-stage replay either: they are also one request per
stage. [Discussion #3171](https://github.com/stalwartlabs/stalwart/discussions/3171) confirms
that hooks and milters are inbound-only, and that matches the design: outbound policy lives in
the gateway's submission path on both MTAs.

## The approver (S06)

On Dovecot, M5 made the approval rule a mailbox rule. A global ACL takes every write right on
`Outbox/*` from the agent's own login, and a separate `approver` master login may only move
messages there (PLAN §8). With the hold queue in the agent's own mailbox, Stalwart's IMAP cannot
express that, for two reasons, both confirmed in its source and measured in M6:

- **An owner always has every right on its own folders.** `MYRIGHTS` on `Outbox/Held` returns
  `rliteswkxpa` for the agent. `SETACL` on its own rights returns OK and changes nothing. There
  are no negative rights and no `anyone` identifier. Per-account permissions (`imapMove`,
  `imapAppend`, …) apply to all of an account's folders, so they would also stop the agent's
  ordinary work.
- **The master login becomes the owner.** Impersonation (`user%approver@contoso.test`) opens a
  session with the target's own access token, so an "approver" login has exactly the agent's
  rights. It cannot be limited to moves in `Outbox/*`, and it can read and mark anything.

**Measured in M6's S06d.** With the agent's own login (`intake@agents.contoso.test`, password
`dev-intake`), Stalwart allowed each of these:
- APPEND to `Outbox/Approved` and to `Outbox/Rejected`;
- CREATE `Outbox/Approved2`, and RENAME a folder into `Outbox/`;
- STORE `$AmxDone` on its held copy (holdwatch would then skip it);
- MOVE `Outbox/Held` → `Outbox/Approved`. The gateway released the message: hold state
  `released`, signed and sent.

On Dovecot the same run refused all of them.

**As built after M6: ownership decides, not negative rights.** Each agent's hold queue lives in
a mailbox the agent does not own (PLAN §5.8 has the design):
- **The owner.** `holds@contoso.test` owns `Holds/<agent>/Held`, `Approved`, and `Rejected`. It
  has no password, so only the gateway's master login opens it. The gateway files holds there,
  watches Approved and Rejected there, and moves a refused release back to Held there.
- **The agent.** It has `lr` on its three folders, and `l` on its tree root `Holds/<agent>`. It
  sees them as `Shared Folders/holds@contoso.test/Holds/<agent>/…`. It gets no `s`, because
  Stalwart maps `s` and `w` to one right, and `w` would let it set `$AmxDone`. `MYRIGHTS`
  returns `rl`.
- **The approver.** `approver@contoso.test` is an ordinary account now, with Dovecot's approver
  rights on every agent's queue: `lrswte` on Held, and `lrswi` on Approved and Rejected. It can
  move a message out of Held and into a decision, and nothing else. It is not a master: logging in as `intake@…%approver@contoso.test` is
  refused (Stalwart closes the connection and logs `security.unauthorized`), and it cannot open
  anyone's INBOX. Dovecot's approver, by contrast, is still one master login that can read every
  mailbox on its host.
- **Sent.** The gateway cannot move a released message from `holds@`'s mailbox into the agent's
  Sent, so it files the signed copy there, as it does for ordinary sends. The approved copy
  stays in Approved, flagged `$AmxDone`.

The init container creates the folders and sets each ACL to exactly these grants, removing any
other. It then reads the ACLs back and subscribes the agents and the approver, so Roundcube lists
the folders. Before building it, the layout was measured against a scratch Stalwart (the pinned
init image, no network, a fresh datastore). The agent's own login got `[NOPERM]`, or `[CANNOT]`
for a rename across accounts, for each of these:
- APPEND of the held copy's exact bytes to Approved and to Rejected;
- MOVE and COPY to Approved;
- CREATE in the queue, and RENAME into it or out of it;
- DELETE of Approved;
- SETACL on itself;
- STORE `$AmxDone` and `\Seen`.

In the same run:
- another agent could not see intake's folders;
- the approver's MOVE worked;
- the gateway, acting as `holds@`, could move a message back to Held and flag it done.

A second provisioning of the same volume created nothing. A third, after a stray grant was
added and the agent's rights widened, removed the grant and narrowed the rights back to `lr`.

**Measured in S06d after M6.** S06d now probes intake's queue where its login sees it,
`Shared Folders/holds@contoso.test/Holds/intake/`:
- It first proves it can EXAMINE Approved and Rejected, so no probe can pass against a missing
  folder.
- It appends the held copy's own bytes, which holdwatch would accept, instead of a forged
  message.
- It adds RENAMEs of Approved and Held within the queue, a RENAME out, GETACL, and SETACL.
- It requires every refusal to be `NOPERM`. Only a RENAME between two accounts may instead get
  Stalwart's `CANNOT`, because Stalwart refuses that whatever the ACL says.

Stalwart refused every probe, and so did Dovecot, where the same test probes `Outbox/*`. On
Stalwart, S06d also plants a byte-identical copy in an `Outbox/Approved` of intake's own. The
hold stayed `held` through the 21 s the test waits (holdwatch's IDLE, then its 20 s rescan), and
nothing reached pat. The wait makes S06d take about 25 s on Stalwart.

**Dovecot keeps its own layout.** The shared layout would also end Dovecot's one-approver
residual, but it is not better there in every respect. It would need a shared namespace and
per-mailbox ACLs in place of the global ACL file, and it would move the agent's view of its
queue and change the approver's login. Today's Dovecot layout already refuses every attack S06
checks. So the location is configuration (`mailbox.hold_owner`, `mailbox.hold_prefix`), and each
mailhost uses the layout it can enforce.

## Other things M6 found

- **Sub-addressing rewrites the envelope in Stalwart.** With sub-addressing on, Stalwart resolves
  `intake+<task>@agents.contoso.test` to the `intake` account and rewrites the recipient to
  `intake@…` before routing. The LMTP delivery would lose the task token that correlation
  depends on. Postfix's `recipient_delimiter` only affects lookups and keeps the full address in
  the envelope. Turning sub-addressing off for the agent domain, and marking the domain
  `allowRelaying`, keeps the address unchanged all the way to the gateway.
- **The accounts cannot be created in the same boot as the password policy.** Stalwart checks a
  new password with zxcvbn against the policy it loaded at startup. The default policy rejects
  `dev-gateway` as "similar to a commonly used password", even after the policy object is
  updated. So the init container applies the settings, restarts, then creates the accounts.
- **A 30 s milter timeout cost the first S04b run.** Stalwart bounds the milter's TCP connect with
  `timeoutCommand`; `timeoutConnect` is read but never used. The first run had copied Postfix's
  30 s `milter_command_timeout` into `timeoutCommand`. With gateway-ct stopped, connects to its
  fixed IP hung for the full 30 s: the bridge still had the stopped container's neighbor entry,
  so the SYNs were dropped, not refused.
  - Northwind's dev queue lifetime is also 30 s, so the message expired and bounced instead of
    draining.
  - S05a and S05b then failed as fallout: they ran before the restarted gateway was listening.
  - `timeoutCommand` is now 5 s, as `milter_connect_timeout` is on Postfix. `timeoutData` stays
    at 60 s, to cover the judge at end of data.
  - Postfix fails faster here because it names the milter host, and Docker's DNS stops resolving
    a stopped container.
- **Stalwart does not log a milter-refused RCPT with its recipient.** It logs `smtp.rcpt-to`
  only for accepted recipients. A milter refusal leaves a `milter.action-reply-code` event with
  no address, so `amx trace` cannot show an MTA line for S03a on Stalwart. Postfix's `NOQUEUE:
  milter-reject` line names the recipient.
- **IMAP `SEARCH HEADER Message-ID` finds nothing on Stalwart.** It matched no message for any
  form of the id: with and without angle brackets, or a prefix. Dovecot matches a substring.
  - The gateway doesn't use it; holdwatch searches by keyword, which works.
  - The new contoso scenarios match on the fetched Message-ID instead, as `testkit.move_message`
    does.
  - In M6's first run this sank S06d before it measured anything, because a strict `xfail`
    accepts any exception. The `xfail` then required `SelfApprovalAllowed`, which only S06d's
    final check raises. After M6, S06d needs no `xfail` on either MTA.
- **The configuration surface changed completely in 0.16** (April 2026). There is no TOML: the
  datastore holds everything as JMAP objects, and `stalwart-cli apply` is the declarative path.
  PLAN §3.2 deferred Stalwart for exactly this risk. The 0.13–0.15 key names in most blog posts
  and answers do not apply. The research notes behind this page read the 0.16.23 source and the
  registry schema rather than the docs, where the two disagree.

## CVE-2026-81036: an authorization code for any redirect URI (checked 2026-09-27)

**The advisory.** VulnCheck published it on 2026-08-26
(https://www.vulncheck.com/advisories/stalwart-mail-server-through-0.16.19-authorization-code-disclosure-via-unvalidated-oauth-redirect-uri):
in its default configuration, Stalwart through 0.16.19 does not compare an OAuth `redirect_uri`
with a registered one, so an authorization code can be sent to an attacker's URL.

**Upstream, on 2026-09-27.** The latest release is v0.16.24, published that day
(`gh api repos/stalwartlabs/stalwart/releases/latest`). Its CHANGELOG has no entry for the
issue, the repository's five published advisories do not include it (the last is
CVE-2026-26312, 2026-02-14), and issue #3205, which names GHSA-6xx8-3vx5-5rv3, was closed
"not planned" on 2026-07-01 by the bot that sends bug reports to support.stalw.art. So: not fixed,
in no version.

**What the source does** (v0.16.24, `crates/http/src/auth/oauth/auth.rs` and
`registration.rs`, `crates/common/src/auth/oauth/registration.rs`):
- The login endpoint (`POST /api/auth` with `type: authCode`, which the `/login` page calls)
  requires a `redirect_uri`. An `http://` one needs PKCE unless the server is in recovery mode.
- A **self-describing public-client id** (RFC 7591 registration at `/auth/register`, the
  `draft-ietf-mailmaint-oauth-public` profile, encoded with the server's OAuth key) carries its
  redirect URIs, and the login checks the presented one against them.
- **Any other client id** goes to `validate_client_registration`, whose first branch returns
  "valid" when `requireClientRegistration` is off, which is the default. The token endpoint then
  only checks that the exchange's `redirect_uri` equals the one the code was issued with. So a
  password accepted at login yields a code for any client id string and any `redirect_uri`.
- With `requireClientRegistration` on, a client id with no `OAuthClient` registration is
  `invalid_request`; a registered one with a `redirect_uri` its list does not hold is
  `invalid_client` (exact match, or the same loopback address with any port). The check is
  skipped for an account holding `oAuthClientOverride`, which the default permission sets give
  only to the superuser role: not to users, groups, or tenants.
- `anonymousClientRegistration` is on by default (`crates/registry/src/schema/structs_impl.rs`),
  so anyone reaching the listener may register a public client naming their own redirect URI,
  rate-limited as an anonymous request. That is the public-clients profile working as designed,
  and the login page names the client, but nothing here needs it. Off, registration needs an
  account with `oAuthClientRegistration`, which the default permission sets give only to the
  superuser role.

**The dev stack's exposure.** It pins v0.16.23. The plan declares three listeners (25, 10025,
143), and Stalwart's defaults add the rest: on the running mailhost, 8080 (HTTP), 443, 465, 993,
and 4190 accept connections. From gateway-ct, `http://mailhost-ct:8080/.well-known/oauth-authorization-server`
answers with `authorization_endpoint: https://mail.contoso.test/login`, the token, device, and
registration endpoints, and `response_types_supported: ["code"]`. Only 25 and 143 are published
to the host, on 127.0.0.1, so the endpoints are reachable from the compose network alone: the
gateways, the runner, Roundcube, the other mailhosts, and CoreDNS. Nothing on the stack uses
OAuth; the gateway, the runner, Roundcube, and the scenarios all log in with passwords over IMAP
and SMTP. Severity here is low. The settings cost nothing, so the plan sets them anyway.

**The mitigation.** One `update` of the `OidcProvider` singleton in the settings phase:
`requireClientRegistration: true`, `anonymousClientRegistration: false`. Stalwart reads both at
startup, and the init container restarts once after the settings, so the mailhost boots with
them.

**Measured in a sandbox** (the init image, then the pinned mailhost image on a throwaway volume
in its own network, host port 127.0.0.1:18580; `ops@contoso.test`'s dev password, client id
`evil`, `redirectUri: https://attacker.example/cb`):

| Probe | Plan before | Plan after |
|---|---|---|
| `POST /api/auth` (`type: authCode`) | HTTP 200, `{"type":"authenticated","client_code":"…","iss":"https://mail.contoso.test"}` | HTTP 401, `You have to authenticate first.`; the log shows `auth.success` for ops, then `auth.error … "Invalid client registration."` |
| `POST /auth/register`, no credentials, a public client named `evil` for `https://attacker.example/cb` | a registration response with a client id for it | HTTP 401, `You have to authenticate first.` |
| `POST /api/auth` with a wrong password (control) | `{"type":"failure"}` | `{"type":"failure"}` |

**Measured on the stack** (`make down && make up MTA_CT=stalwart`): the same login from
gateway-ct against `mailhost-ct:8080` returns 401. Smoke passes, and the scenario suite passes
with S18e as its strict `xfail`, as before.

**What it gates.** Any Stalwart live lane. PLAN §11 bundles Postfix + Dovecot only. A Stalwart
host would serve `/login` on 443 to the internet; the settings close the reported path, but the
OAuth surface has not been reviewed further, upstream has not acknowledged the report, and
Stalwart is 0.x with five published advisories. A release that fixes it, with the pin bumped the
way `deploy/compose.stalwart.yaml` and `deploy/stalwart/Dockerfile` pin by digest, would be the
real fix; the settings stay.
