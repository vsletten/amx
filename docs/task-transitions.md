# Task transitions and duplicate delivery

Change this contract first, then make the code match. It fixes a state-ordering bug:
a handler's closing reply was
overwritten by the message it answered, and a closed task refused a retry of mail it had
already delivered.

Scope: one gateway's `tasks` row per `(agent, token)` and the gateway's own decisions about
mail for that recipient agent. Each participant keeps its own row, even when both agents
share a gateway; the two sides agree only through the states their messages carry.

## 1. States

| Class | States |
|---|---|
| open | `submitted`, `working`, `input-required` |
| closed (terminal) | `completed`, `failed`, `canceled` |

## 2. Who writes a task's state, and when

| Writer | When | State written |
|---|---|---|
| LMTP, for a delivered message | after its handler returns (sync and queued), or just before filing (remote, whose handler runs later on the agent's host); only if no other write reached the task while the handler ran | the message's `Agent-Task-State`; a DSN's is `failed` |
| Submission, a sent message | after reinjection | its `Agent-Task-State` (default `submitted`) |
| Submission, a held message | when it is filed in the hold queue | its `Agent-Task-State` |
| Submission, a rejected hold | when a person rejects it | `canceled` |

A delivery that does not succeed writes nothing: a handler's `Refuse`, a `TryLater` or crash
(until a retry succeeds), an LMTP preflight refusal, a replay answered as a duplicate, and a
local event (`deliver_local`). What the handler submitted before failing still counts, because
submission wrote it.

A remote agent's refusal writes nothing either (PLAN §5.11). Its runner refuses after the
gateway filed the message, and it sends the gateway a `refuse` command. The gateway records that
in `refusals`, not in `tasks`: the state LMTP recorded at filing stands, and the delivery stays
`completed`, because the message was filed. The sender learns through the DSN, which its own
gateway's LMTP records as `failed`, as for any bounce (T3 when its task is closed).

### Person-first correlation (SH-01)

For uncorrelated human mail to a bare agent address, LMTP assigns a random token
only when the milter's `Agent-Grant-Can-Open-Tasks` result is `true`. It stamps
`Agent-Task-Assigned` on that recipient's copy before journaling and dispatch.
The stamp is transport-owned: ingress strips sender assertions, and submission
strips agent assertions. Trust, judgment and taint are unchanged.

`task_assignments` persists the first token per envelope recipient and Message-ID,
so retries, concurrent deliveries and queued restart recovery keep the same
correlation. This additive table is deliberately separate from `tasks`: assignment
does not create a state or pretend a person sent `Agent-Task-State`. The agent's
authenticated reply opens the task through ordinary submission (including its
local grant, outbound allowlist, rate, taint and hold checks). `ctx.reply` and SDK
parsing use the stamp and retain the original Message-ID/References thread.

Replies-only human mail, already-correlated mail and delivery reports receive no
new assignment. Authenticating people as owners is separate work (SH-12). S21 temporarily
enables the dev human-lane capability and restores it in `finally`; no shipped
human-lane grant is broadened.

### Sibling correlation and task keys (SH-02)

An agent-lane message to a bare recipient takes its signed `Agent-Task`; an explicit
sub-address must still match. Ingress checks known/closed state per recipient agent,
including mixed bare and tokenized recipients. Submission and LMTP's revision guard
also scope every read/write to that agent. Legacy token-primary-key stores migrate
transactionally, retaining state, timestamps and revision; unscoped `Store.task`
reads remain available only when the token identifies exactly one row.

Breaking Python API (State API version 2, `amx.policy.STATE_API_VERSION`):
`State.known_tasks` and `State.closed_tasks` are sets/frozensets of `(agent, token)`
string pairs, not sets of token strings. For example use
`frozenset({("intake", "t_example")})`. The constructor raises `TypeError` for
legacy token-only entries or malformed pairs; it never applies a token to every
agent. `Store.closed_tasks()` likewise returns `frozenset[tuple[str, str]]`;
test `("intake", token) in store.closed_tasks()`, not `token in ...`.
`Store.task_keys()` and `Store.task_keys(closed=True)` remain the production
ingress snapshot APIs. External callers must migrate both fields and membership
tests together. This versions the Python State contract separately from package
metadata (`pyproject.toml`, currently 0.3.0) and the unchanged `amx/0.1` wire
profile; no release tag is created by this change.

The task primary-key migration requires a stopped-writer upgrade, not a rolling
upgrade. Stop every gateway and every other SQLite writer before a fresh backup
and before any new binary opens `Store`; old `ON CONFLICT(token)` writers cannot
use the migrated table. Never mix old and new writers. See
[the public runbook's stopped-writer upgrade](selfhost-public.md#stopped-writer-upgrade-and-task-key-migration) for the supported one-gateway-container lifecycle
and rollback by restoring the original backup after stopping the new binary.

Submissions on both MTAs split envelopes, not signed bytes: sibling recipients go to
`sibling_port: 10027`, ordinary/role recipients to `postfix_port: 10025`.
Only the gateway IP can queue on 10027. An after-queue SMTP transport feeds the
loopback-only filtered 10028 listener, whose MTA-owned `amx-sibling` daemon macro
sets the policy's sibling fact. Own-agent grants still require valid local DKIM,
an enabled local agent, and the configured intent/schema/open-task capabilities;
port 25 never gains that grant, even for an identical signed replay. YAML agents
verify using their explicitly enabled configured selector; registry agents retain
the registry's revocation/rotation authority. Other domains still use DNS.

The port defaults to 0 (disabled); dev and live configurations enable it for both MTAs.
Existing YAML `postfix_sibling_port` and `AMX_POSTFIX_SIBLING_PORT` remain supported
aliases. Environment overrides YAML; `AMX_SIBLING_PORT` wins over the old environment
name, and `sibling_port` wins over the old YAML key, including an explicit 0.
Python callers use the renamed `GatewayConfig.sibling_port` field.

Stalwart's gateway-only `sibling-in` listener on 10027 routes by
`received_via_port` to its own loopback-only `sibling` listener on 10028, before
agent-domain LMTP routing. A connect-stage system script denies non-gateway
clients on 10027. Neither listener requires AUTH or adds signatures/spam filtering.
Only `listener == 'sibling'` enables the second fail-closed milter at 8891.
Set `listeners.sibling_milter_port: 8891` (or `AMX_SIBLING_MILTER_PORT`) in the
gateway; 0 retains the Postfix single-milter path. These milter ports must stay
private, like LMTP. Changing them requires a gateway restart.

libmilter has one socket per process. With the second endpoint enabled, two TCP
frontends share one private Unix-socket native backend and one registry/store/replay
cache. Each CONNECT's unused hostname carries a random, one-use internal handle
bound to the actual reached TCP port; the adapter consumes it before policy runs.
It is never a message header or an MTA-supplied trust macro. All other frames and
signed message bytes pass unchanged. Stalwart's constant daemon macro remains
available for stage replay/body handling, but cannot confer sibling trust.
S22 requires delivery and refusal of the identical signed port-25 replay on both
MTAs, with no expected-failure exception.

Gateway-generated refusal DSNs use ordinary trusted reinjection even for a sibling
sender: they must reach LMTP as system events and can fail an already closed task
(T3). Only the gateway's report-generation call site selects that route; submitted
agent mail and held releases still take sibling ingress, regardless of their headers.

### Outbound retry progress

Normal authenticated submission and approved held release persist the first
signed, journaled bytes plus their SMTP recipient groups in `outbound_progress`,
keyed by sender agent, Message-ID and operation. Each positive DATA queue receipt
is committed before the next group is attempted. A retry after temporary failure
or process restart sends only the remaining groups, using those exact signed bytes;
new `Received` traces and LF/CRLF normalization do not replace the canonical copy.
All other submitted content, including task, state and To/Cc/Bcc recipients, must
match or the Message-ID replay is refused. Current authentication, grants,
allowlist, rate, taint and hold gates still apply before any remaining send.
Send accounting and task/hold completion commit atomically after all groups succeed.
A completed retry does not send or write task state again. Concurrent attempts
are serialized by a five-minute reclaimable lease.

An approval with any accepted group stays `releasing` after failure; it cannot be
rejected with a false "not sent" event. Remaining groups still require current
authorization and the original approval. The Approved watcher retries it rather
than silently marking it done when authorization is temporarily unavailable.
System refusal DSNs retain their separate trusted ordinary route.

This is not exactly-once SMTP: a connection lost before the positive DATA reply,
or a process/storage failure between acceptance and the durable checkpoint, is
ambiguous. That group is retried at least once and may be duplicated remotely.
A submission without a Message-ID receives a fresh identity on each attempt;
the gateway cannot infer that identical content is a duplicate. Clients requiring
retry correlation must retain a Message-ID. A queue receipt proves MTA custody,
not final recipient delivery.

## 3. Transition rules

- **T1. The handler's reply wins over the message it answered.** LMTP reads the task before the
  handler runs and records the delivered message's state only if the task is unchanged
  afterwards (a revision counter, not a timestamp). A reply, a held reply, or any other write
  during the handler stands. With no reply, the delivered message's state is recorded, as
  before. Handler completion and the pre-handler revision are checkpointed together before
  attempting the task write. A task-write failure returns a temporary failure (or stays pending
  in queued mode); retry and restart recovery resume the task write without rerunning the
  handler. The original revision is used on every attempt, so a reply written while waiting
  also wins. An absent task is recorded as revision `-1`; `NULL` in an older handled row means
  its pre-handler state is unknown, so its current task state is preserved.
- **T2. A closed task never reopens.** Any writer's open state for a task in a closed state is
  ignored, whether the writer is LMTP, submission, or a held reply. This covers a message
  accepted before its task closed and delivered after it, and a remote agent's mail filed after
  its runner closed the task.
- **T3. A closed state replaces a closed state.** The later outcome is recorded: a rejected
  hold cancels a task its held reply completed, and a bounce fails a task its reply completed.
- **T4. Nothing else moves a task.** The milter reads task state; it never writes it.

| Mode | Handler outcome | Final row (task open before) |
|---|---|---|
| sync | replies `completed` | `completed` (was reopened to the inbound `submitted`) |
| sync | replies `working` | `working` (was overwritten with `submitted`) |
| sync | no reply | the delivered message's state |
| sync | replies X, then `Refuse` | X |
| sync | `Refuse` with no reply | unchanged; no row for a new task |
| sync | `TryLater`, then succeeds on a retry | as the successful attempt |
| queued | any | as sync, when the worker runs it |
| remote | none here | the delivered message's state at filing; the runner's reply is a later write |
| remote | the runner refuses (`refuse` command, PLAN §5.11) | unchanged: the state at filing. At the sender's gateway, the DSN writes `failed`; `test_a_refusal_bounces_to_the_verified_sender_once`, S18k |
| any | reply held | the held reply's state; a rejection then makes it `canceled` (T3) |
| any | delivered message in a task that is already closed | unchanged (T2) |
| any | DSN for a message in a closed task | `failed` (T3) |
| sync/queued | handler succeeds, task write fails | handler remains `handled`; retry/recovery resumes the write with its saved revision; `test_task_write_failure_resumes_without_rerunning_the_handler`, `test_recovery_resumes_a_failed_task_write_without_rerunning_the_handler` |
| sync/queued | task changes while that write waits | newer state stands; same tests |

## 4. Duplicate delivery into a closed task

An **accepted delivery** of a Message-ID to a recipient is a completed `deliveries` marker
(including stores predating `delivery_progress`), or a `delivery_progress` row that LMTP
has taken responsibility for: `handled` or `completed` (the handler ran), or `journaled` with
`accepted = 1` (a queued agent's `250 queued`). The completed marker is authoritative, matching
LMTP's first deduplication check; a missing progress row cannot revoke it. LMTP answers a replay
of one without running the
handler again: `duplicate already delivered` or `duplicate already queued`, or it resumes at the
mailbox append (§5.4). A `refused` delivery, or one LMTP deferred, is not accepted. A remote
agent's refusal (PLAN §5.11) does not change that: its delivery was filed, so it stays accepted,
and a retry is answered `duplicate already delivered` with no second DSN.

The recipient is the envelope address with its task token (`intake+t_x@agents.contoso.test`), as
LMTP keys it, so a recipient's accepted deliveries are exactly the messages a retry to it could
be repeating.

- **D1. RCPT refuses what cannot be a retry.** A closed task's recipient with no accepted
  delivery gets `550 5.1.6 task is closed` at RCPT, as before (S09).
- **D2. RCPT defers what could be one.** A closed task's recipient with an accepted delivery is
  accepted at RCPT (rule `closed-task-at-eod`; the watermark still applies), and end of DATA
  decides with the Message-ID.
- **D3. End of DATA refuses new mail.** A message for a closed task gets `550 5.1.6 task is
  closed` unless every agent recipient in the transaction has an accepted delivery of its
  Message-ID. This also refuses a message whose task closed between RCPT and end of DATA.
- **D4. A retry is acknowledged.** A retry passes D3, then every other end-of-DATA rule again, and
  reaches LMTP, which answers it as a duplicate: the handler does not run and no reply is
  submitted.
- **D5. LMTP applies no closed-task rule.** A message the milter accepted before its task
  closed is delivered to its handler, and T2 keeps the task closed.

| Path | Task | Recipient has accepted mail | This Message-ID accepted | Result | Evidence |
|---|---|---|---|---|---|
| MX, new message | closed | no | no | RCPT `550 5.1.6` | `test_s09_closed_task_rejected_at_rcpt`; `test_policy` |
| MX, new message | closed | yes | no | RCPT 250, then end of DATA `550 5.1.6` | `test_s09_a_closed_task_refuses_new_mail_and_acknowledges_a_retry`; `test_milter` |
| MX, retry of delivered mail | closed | yes | yes | 250; LMTP `duplicate already delivered`; no handler run, no reply | same S09 test; `test_milter`, `test_lmtp` |
| MX, retry with a legacy completed marker but no progress row | closed | yes | yes | same duplicate acknowledgment | `test_a_closed_task_acknowledges_a_retry_and_refuses_new_mail[legacy]`; `test_legacy_completed_markers_are_accepted_without_progress_rows` |
| MX, retry of refused mail | closed | any | no (`refused`) | `550 5.1.6` (at RCPT or end of DATA) | `test_journal_store` |
| MX, any message | open | any | any | unchanged: the S10 matrix | `docs/s10-replay-matrix.md` |
| direct LMTP | any | any | any | no task rule; Message-ID dedupe only | S10 |

Postfix and Stalwart give the same results. On Stalwart the RCPT decision is carried to the DATA
stage's connection (§5.8), and end of DATA reads the replayed recipients.

**Structural invariant / refuted review lead:** an accepted transaction cannot mix open and
closed agent task tokens. Before D3, task-token matching requires every agent recipient's token
to equal the parsed task; `test_agent_task_must_match_recipient_subaddress_token` proves that a
mixed-token transaction is refused. People copied on the transaction are excluded from that
comparison (`test_a_person_copied_on_an_agent_thread_needs_no_task_token`).

## 5. What this leaves (also in PLAN §8)

- End of DATA refuses the whole message. New mail to a closed task (one that has accepted mail)
  and to other recipients in the same transaction, a person at `contoso.test` for example, is
  refused for all of them. At RCPT only the agent was refused.
- A retry that arrives while the first copy is still in the MX's own queue, not yet at LMTP,
  has no delivery row. If its task closed in the meantime, the retry is refused, and the first
  copy is delivered anyway (D5).
- An agent's open-state reply in a closed task is sent, but it does not reopen the task (T2), so
  the counterparty's answer is refused.
- A retry is judged again by every other rule, so a rule that changed since the first delivery
  (a revoked grant, a different judgment) can still refuse mail that was delivered.
