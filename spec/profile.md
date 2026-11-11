# AMX message profile 0.1

Status: prototype profile for M1. The normative keywords **MUST**, **SHOULD**, and **MAY** are used
as described by RFC 2119. Messages remain ordinary RFC 5322/MIME email.

## 1. Conformance

A **profile message** is marked by `Agent-Protocol: amx/0.1`. It MUST contain the standard
headers `Message-ID`, `Date`, `From`, `To`, and `Subject`, and the profile headers
`Agent-Intent`, `Agent-Task`, and `Agent-Task-State`. Agent-originated messages MUST contain
`Auto-Submitted: auto-generated`.

A receiver MAY also accept ordinary human mail, DSNs, and MDNs. Such messages are represented by
the parser as normalized AMX inbound events but are not profile-conforming messages.

Header field names are case-insensitive. A field that this profile defines as singular MUST NOT be
repeated. Header values MUST NOT contain CR or LF.

## 2. Header registry

Profile fields deliberately have no `X-` prefix (RFC 6648).

| Header | Required | Value and meaning |
|---|---|---|
| `Agent-Protocol` | profile | Exactly `amx/0.1`. Marks the profile and its version. |
| `Agent-Intent` | profile | One of `request`, `response`, `update`, `ack`, `error`, `event`. |
| `Agent-Task` | profile | Non-empty opaque correlation identifier. It SHOULD also occur after `+` in the reply address. |
| `Agent-Task-State` | profile | One of `submitted`, `working`, `input-required`, `completed`, `failed`, `canceled`. |
| `Agent-Schema` | with machine part | Absolute URI naming the JSON Schema for the machine part. |
| `Agent-Card` | optional | Absolute HTTP(S) URL for the sender's A2A-compatible agent card. |
| `Agent-Reply-By` | optional | An RFC 5322 date expressing a soft deadline. |
| `Agent-Idempotency-Key` | optional | Non-empty opaque key used to deduplicate semantic retries. |

The standard `In-Reply-To` and `References` fields MUST be set when continuing a thread. A reply
uses the same `Agent-Task` as the request.

### Intent and state

`request` asks the recipient to begin or continue work. `response` supplies requested output.
`update` reports intermediate state. `ack` means received but not necessarily acted on. `error`
reports a semantic failure and is distinct from a transport DSN. `event` is informational.

Task state is independent of intent. Typical pairs are request/submitted, update/working,
response/completed, and error/failed. Other combinations are permitted when they accurately
represent lifecycle state.

## 3. Addresses and correlation

An agent address is normally `name@agents.example`. When a response is expected, `From` and/or
`Reply-To` SHOULD use `name+<task>@agents.example`. The parser treats the substring following the
first `+` in the local part of a `To` or `Delivered-To` address as a task token when profile
headers are absent. `Agent-Task` takes precedence when present.

This fallback is required for replies produced by clients such as Gmail and Outlook that can strip
unknown profile headers while preserving the reply address. A stripped-header message correlated
this way is normalized as intent `response`, with no machine payload.

## 4. MIME body

The human-readable message is a `text/plain` body. It is REQUIRED for profile mail and MUST express
the complete meaning of the message.

A structured rendering MAY be included as an `application/ld+json` MIME part with:

```
Content-Purpose: Machine-readable
Content-Disposition: inline; filename="payload.json"
```

The machine part is another rendering of the human message, never an authorization channel. There
MUST be at most one machine-readable part. Its decoded body MUST be a UTF-8 JSON object. If
`@context` is absent, implementations add `"@context": "https://schema.org"` before validation
and delivery. The normalized/defaulted value does not imply that a receiver modifies the raw
message.

A machine part requires `Agent-Schema`. Its URI MUST be present in the local schema registry.
Implementations MUST NOT retrieve unknown schemas over the network. Invalid JSON, a non-object
payload, an unknown schema, or schema validation failure makes the profile invalid.

The prototype registry contains:

- `https://evtmail.ai/schema/0.1/request.json`
- `https://evtmail.ai/schema/0.1/response.json`
- `https://evtmail.ai/schema/0.1/update.json`
- `https://evtmail.ai/schema/0.1/ack.json`
- `https://evtmail.ai/schema/0.1/error.json`
- `https://evtmail.ai/schema/0.1/appointment-request.json`
- `https://evtmail.ai/schema/0.1/payment-request.json` (M4: the dev gateways' `commits-money` hold
  rule matches it)

The source schemas are the seven files in `spec/schemas/`; they are resolved locally.

## 5. Build behavior

`amx.profile.build(...)` returns an `email.message.EmailMessage`. It sets the required standard and
profile headers, `Auto-Submitted: auto-generated`, and a `text/plain; charset=utf-8` body. It
creates `multipart/mixed` when a payload or attachment is present. A payload is JSON-encoded as
UTF-8, receives the Structured Email headers above, is defaulted and schema-validated before the
message is returned, and never triggers a network request.

Callers may provide deterministic `date` and `message_id` values; otherwise the builder generates
them. Header injection is rejected.

## 6. Parse behavior

`amx.profile.parse(raw: bytes) -> Inbound` preserves `raw` and normalizes four kinds of input:

1. Profile mail: use profile intent/task/state/schema, extract text and JSON, and validate.
2. Ordinary mail: intent `response`; derive the task from `To` then `Delivered-To`; payload absent.
3. `multipart/report; report-type=delivery-status` DSN: intent `error`, task state `failed`, and
   expose `action`, enhanced `status`, recipient, and diagnostic from the per-recipient report.
4. `multipart/report; report-type=disposition-notification` MDN: intent `ack`, expose recipient,
   original message id, and disposition.

For profile mail, malformed/missing required fields raise `ProfileError`; machine-part and schema
errors raise `MachinePartError`, `UnknownSchemaError`, or `SchemaValidationError`. Parsing is pure:
there is no filesystem write, DNS, or network access.

## 7. Security considerations

Profile fields and the machine part are untrusted data. Neither changes grants or verified sender
identity. Consumers MUST make authorization decisions from transport-verified identity and local
policy. The parser limits itself to decoding and validation; it does not dereference URLs in
headers or payloads. MIME defects and header injection are rejected rather than repaired.

## 8. Control declarations (to the sender's own gateway only)

An agent declares its own state to its own gateway by submitting a profile message to the
gateway's reserved control address, `control@<agent-domain>` unless the gateway names another.
It is an `event` whose machine part validates against
`https://evtmail.ai/schema/0.1/control.json`: `pause` (with `until` and `reason`), `resume`, or
`capacity` (with `max` and `ttl_seconds`). Every field of these is an enum, an integer, or an
RFC 3339 timestamp; the schema admits nothing else. Corpus case `20-control-pause` is one.

One command concerns a single message instead of the agent's state. `refuse` (with `recipient`,
`message_id`, `status`, and `reason`) tells the gateway the agent refuses a message the gateway
filed for it. `recipient` is the envelope recipient the copy was filed for, and `status` is one
of `5.7.1`, `5.6.0`, `5.3.0`. The gateway MUST check that it delivered that Message-ID to that
recipient, and that the recipient is the authenticated agent's. It then sends the message's
envelope sender an RFC 3464 delivery status notification at most once, and only if it verified
that sender when the message arrived. The DSN carries the status and reason, never text of the
agent's. `refuse` carries an address and a Message-ID of bounded shape, and no free text. A
refusal the gateway will never take is answered `550 5.7.1 refusal rejected: …`; a client
retries any other failure. The prototype plan's §5.11 describes this.

A declaration is not mail. The gateway applies it to the authenticated agent and relays and
delivers nothing (`refuse` makes the gateway send a DSN of its own, below). It MUST be the message's only recipient, and `From` MUST be the authenticated
agent. A receiving gateway MUST refuse the control address at RCPT, and MUST refuse a message
carrying the control schema, from any other sender. The prototype plan's §5.10 describes the
gateway's side.
