# Parts agreement contract

Change this matrix first, then make the code match.

This contract covers the production milter, the calibration split, and the wording/state
A/B tool. It describes the intended meaning of the question, not a guarantee that a
probabilistic judge will answer correctly. PLAN §5.7 records observed scores and the
known identifier-versus-label miss; the gateway does not validate receiver slot tables.

## Inputs and surfaces

The milter parses an SDK message and calls `judge.machine_part_text`. The live split's
`_input` calls that same serializer for payload cases. Both retain all payload fields
except the top-level `@context`, emit sorted UTF-8 JSON, and pass a string to
`judge.request_body`. No-machine messages skip `parts_agree`. The A/B `string` shape
uses this exact state; `object` parses the string; `content` deliberately drops fields
and is an unsafe diagnostic, never a gateway input.

`test_the_judge_sees_the_payload_without_context_and_with_sorted_keys` and
`test_machine_part_text_drops_the_context_and_keeps_the_rest_as_written` cover the
wire conversion. `test_parts_agree_is_only_asked_when_there_is_a_machine_part_and_parts_are_capped`
covers omission and truncation.

For a present machine part, B means all bookkeeping fits the text, V means all shared
semantic values and commitments match, and E means the machine part adds semantic
content or an action. Absent bookkeeping makes B true; absent shared values makes V
true. These eight combinations exhaust the question's semantic input space:

| B | V | E | Milter / live split / A/B string or object: intended answer | Split coverage |
|---|---|---|---|---|
| yes | yes | no | agree | proposals, bookings, quotes, acknowledgments |
| yes | yes | yes | disagree | extra slot, cancellation, spend, reorder |
| yes | no | no | disagree | changed time, changed amount, declined booking |
| yes | no | yes | disagree | Seattle visit added to a different reply |
| no | yes | no | disagree; known model miss | slot id `thu-1600`, label Monday 08:00 |
| no | yes | yes | disagree | composite of id mismatch and extra action |
| no | no | no | disagree | composite of id mismatch and changed value |
| no | no | yes | disagree | composite of all three defects |

`test_parts_agree_matrix_preserves_semantic_fields` anchors every row to a real SDK
writer/milter reader round trip without claiming that unit tests validate Jev accuracy.
The lossy `content` surface cannot preserve B,
so its answers must not be used to justify production acceptance.

The SDK's text MIME part includes a terminal newline. Machine-part serialization parity
does not imply the synthetic split reproduces that text byte-for-byte.

## Precedence and policy

1. Identity must already allow the message: a content score cannot grant authority.
2. No payload or disabled check means no agreement question, rather than disagreement.
3. A mismatch or extra content outweighs matching fields; bookkeeping is tolerated only
   when consistent. Keys such as `done` are not permission to hide a commitment.
4. The unchanged default enforce policy uses the raw score: below 0.2 rejects on the
   agent lane and taints on the human lane; at or above 0.2 adds no agreement action.
5. Judge failure uses the existing lane error policy; truncation taints unseen content.
   Off makes no call; observe records the result without enforcement.

Other signals still apply independently and the most severe action wins. See the
existing content-policy tests for mode, error, truncation, and monotonicity coverage.

## Calibration authority

The production question and serializer are authoritative. `m4b` is a frozen historical
baseline, independent of future edits to the production question. A/B reports must
classify unrounded per-case means against 0.2, then round only display values. Scores
must pass the production response validator; redirects must never receive credentials.
Invalid experiment arguments must fail before any paid request.

The split is tuning data, including S14 when supplied to A/B; S14 is therefore a
scenario regression check rather than a held-out evaluation of wording selection.
The separately collected S11 messages were reported as held out in the original round.
