# S10 replay contract

Change this matrix first, then make the code match.

S10 tests Message-ID deduplication for one recipient through both contoso MTAs
(Postfix and Stalwart), in an open task. Task transitions and retries into a closed task
have their own contract, `docs/task-transitions.md` (#21). The journaled outbound reply is
authoritative for what intake emitted; S10 still checks it rather than the task row.

## Intake marker and precedence

These rows partition the full input space. `*` means any value, including any combination
of the other subject markers. Subject matching is case insensitive. `[slow]` only delays
the handler; it does not change the selected reply.

| Reply callback | Intent | Lane | Subject condition | Reply |
|---|---|---|---|---|
| absent | * | * | * | none |
| present | error | * | * | none |
| present | non-error | human | `[reply]`, with or without other markers | default human reply |
| present | non-error | human | no `[reply]` | none |
| present | non-error | system | * | none |
| present | non-error | agent | `[loop]`, with or without `[keep-open]` | working loop reply |
| present | request | agent | no `[loop]`, `[keep-open]` | working request reply |
| present | request | agent | neither marker | completed request reply |
| present | other non-error | agent | no `[loop]`, with or without `[keep-open]` | none |

Every row is covered by `test_intake_reply_precedence`. Callback availability and error
handling take precedence to prevent unavailable sends and error loops. Human replies
are selected before agent-only markers; `[loop]` keeps its pre-existing priority. Only
agent requests without `[loop]` gain the new marker behavior.

## Transport and evidence

For each row below, Postfix and Stalwart must produce the same gateway result. S10
constructs a unique task, one recipient, one Message-ID, and identical signed SMTP
bytes; these invariants exclude unrelated receipts and multi-recipient outcomes.

| Path | Prior delivery | Task at RCPT | Expected result | Evidence / named test |
|---|---|---|---|---|
| MX first copy | none | new/open | SMTP 250, LMTP queued, eventually completed | `test_s10_same_message_id_invokes_handler_once` |
| MX replay | in flight | open | SMTP 250; LMTP `duplicate already queued` | S10; `test_wait_for_lmtp_duplicate_waits_for_the_matching_success` |
| MX replay | completed | open | SMTP 250; LMTP `duplicate already delivered` | same tests |
| MX replay | accepted | terminal | 250 at end of DATA; LMTP duplicate; outside S10 | `docs/task-transitions.md` D2–D4; S09 |
| MX replay | none/refused | terminal | `550 5.1.6`; outside S10 | `docs/task-transitions.md` D1, D3; S09 |
| direct LMTP retry | completed | any; no RCPT policy | `250 2.0.0 duplicate already delivered` | S10; `test_lmtp_client_greets_and_prints_the_recipients_reply` |
| direct LMTP retry | none/in flight | any | not constructed by S10: wait for completed delivery first | S10 completion barrier |

An SMTP 250 acknowledges MTA queuing, not LMTP delivery. Before final counts, S10 must
observe the MX's successful duplicate receipt for its exact recipient, then receive
the synchronous direct LMTP duplicate response. A queue event, temporary failure,
different recipient, or ordinary non-duplicate success must not satisfy the receipt
barrier (`test_wait_for_lmtp_duplicate_times_out_without_a_duplicate_receipt`). Missing
evidence fails the scenario; it is never treated as success.

Postfix logs the full `250 2.0.0 duplicate already ...` reply. Stalwart logs `code = 250`
and `details = "duplicate already ..."`, with the enhanced status stripped. The receipt
barrier must match each MTA's actual log representation; the first revised CI run caught
an incorrect assumption that Stalwart retained `2.0.0` in `details`.

Finally S10 reads intake's actual journaled reply and requires `working`, then checks
one handler invocation, inbound journal row, completed delivery, and submitted reply.
`test_s10_rejects_a_closing_reply_even_when_the_task_row_is_open` proves that a final
`submitted` row cannot hide an incorrect `completed` reply.
