# Agent Mail Exchange: SMTP as the transport for agent-to-agent and agent-to-human work

Status: PROPOSAL (2026-09-21; revised 2026-09-23 to match the prototype; §5.4 notes remote
agents, 2026-09-26). Working name `amx`; the
name is a placeholder. A functionality prototype is being built in this repository; its plan is
[`PLAN.md`](PLAN.md), and M0 (mail plumbing) and M1 (message profile and corpus) are done.
Scope: a standalone open-source project for agent-to-agent and agent-to-human email.
Owner: Victor (direction). Authored with Claude.
The prototype plan is [PLAN.md](PLAN.md); current capabilities and release goals are in
[ROADMAP.md](ROADMAP.md).

## TL;DR

Email is already a domain-specific transport for autonomous agents. It has store-and-forward
delivery, retry, backpressure, durable records, federated addressing over DNS, authoritative
sender identity, threading, receipts, attachments, a text-only wire format, and a client on
every device on earth. None of that has to be built. The gap is that every current "email for
agents" product treats the mailbox as the primitive and wraps it in a REST API. The MTA, the
part of the stack that actually implements delivery, policy, identity, and queueing, is left
untouched.

The proposal is a small open-source system in three parts:

1. **A message profile.** A constrained way to write an RFC 5322 message so that it carries a
   machine-readable part alongside a human-readable part, with headers for intent, task
   correlation, and schema. Every message stays a valid email that Gmail or Thunderbird can
   display.
2. **A gateway that customizes the MTA "just a bit."** Ingress policy at the SMTP transaction
   (identity checks, schema validation, backpressure via reply codes), delivery by LMTP straight
   into agent runtimes instead of mailboxes, per-agent signing keys, an outbound hold queue for
   human approval, and a journal.
3. **A thin SDK and an MCP server** so an agent can participate without knowing anything about
   SMTP.

The thesis, in one line: give agents an address, not an API, and put the interesting behavior in
the mail transfer agent where the protocol already has the vocabulary for it.

## 1. Value proposition

### 1.1 What you get

For someone building agents:

- **Asynchronous by default.** Agents on different clocks, in different organizations, behind
  different firewalls, exchange work without both being online. The sending MTA queues and
  retries for days. Nobody writes a retry loop.
- **Backpressure without code.** An agent that is busy answers the SMTP transaction with a
  temporary failure. The sender's MTA backs off on its own schedule. An agent that refuses work
  answers with a permanent failure and the sender gets a bounce explaining why.
- **Federation for free.** Addressing is DNS MX. Any two parties with domains can exchange
  messages with no shared platform, no account on each other's system, no API keys to exchange.
  Four billion existing endpoints are reachable on day one.
- **Authoritative identity.** SPF, DKIM, and DMARC give a receiver a cryptographically verified
  sending domain. The signature covers `From`, so the domain vouches for the agent address it
  signed: a verified agent identity, with one DNS record for the whole agent domain.
- **Threads and correlation.** Message-ID, In-Reply-To, and References form a conversation DAG.
  Sub-addressing (`agent+token@domain`) puts a correlation token in the envelope itself, so
  replies from any client, including a human hitting reply in Outlook, come back correlated.
- **Receipts and failures.** Delivery status notifications and message disposition
  notifications are standardized. So are enhanced status codes that say *why* something failed.
- **A durable record.** Every message is a text file. Archiving, search, legal hold, and audit
  are solved problems with decades of tooling.
- **Attachments and structured payloads.** MIME carries JSON, PDFs, images, and calendar
  invites in one message, with content-hash deduplication trivially layered on top.

For humans working with agents:

- **The same channel.** A person can be on the To or CC line of any agent conversation and read
  it in their normal mail client. An agent's inbox is a real mailbox a person can open. Human
  oversight is not a feature to build; it is a consequence of the medium.
- **Approval in the tool you already have.** Outbound agent mail that needs a sign-off sits in a
  folder. The person moves it to Approved, or replies "approve," and the MTA releases it.
- **A record you can hand to a lawyer.** The transcript of what your agents agreed to with
  someone else's agents is an mbox file, signed at every hop.

For operators:

- **Run it on your own domain.** One compose file. No vendor holds your agents' identities or
  their mail.
- **Policy where policy belongs.** Rate limits, allowlists, schema gates, quarantine, and hold
  queues are enforced at the SMTP transaction, before any agent code runs on an untrusted
  message.

### 1.2 What the "just give it an inbox" approach leaves on the table

Handing an agent a hosted mailbox and a REST API works, and several companies now sell exactly
that (section 6). It also discards most of what makes SMTP interesting as a transport:

| Property | Hosted inbox + REST | MTA-level integration |
|---|---|---|
| Backpressure | Poll or webhook; sender retries are your problem | 4xx at RCPT or DATA; sender's MTA retries |
| Reject before ingest | Message lands, then you filter | 5xx at the transaction; no storage, bounce carries reason |
| Agent identity | An API key per tenant | Domain DKIM over the agent's From address; revoke one agent at the gateway |
| Delivery = invocation | Webhook fan-out from a store | LMTP hands the message to the runtime; the reply code is the ack |
| Human approval of outbound | Application feature | Hold queue in the MTA; the mail client is the approval UI |
| Policy language | Vendor-specific | Sieve, standardized and sandboxed |
| Audit journal | Vendor export | Journaling at the MTA, hash-chained locally |
| Lock-in | Inboxes live with the vendor | Inboxes live on your domain; move the MX |

The product is the delta in the right-hand column, packaged so a single developer can get it in
an afternoon.

### 1.3 What this is not

- Not a new wire protocol. The wire is SMTP and the message is RFC 5322. Anything that needs
  changing is expressed in headers, MIME parts, DNS records, and MTA policy.
- Not a low-latency channel. Delivery is seconds to minutes. Tool calls inside one agent's loop
  belong in MCP or a function call, not here.
- Not a replacement for A2A or MCP. It is the transport those protocols lack for
  cross-organization, offline-tolerant, human-inspectable work. Section 5.7 covers bridging.
- Not a spam cannon. Machine-speed sending across the public internet is the fastest way to
  get a domain blacklisted. The design assumes low volume, high value, and strict outbound
  policy.

## 2. Why now

- Agents are being handed email addresses at scale. AgentMail reported hundreds of thousands
  of agent inboxes and 500+ business customers when it raised its seed in March 2026, with user
  counts tripling and then quadrupling after OpenClaw's January launch.
- Agent-to-agent protocols have matured but stopped at the transport question. A2A reached
  v1.0 in January 2026 and defines JSON-RPC, gRPC, and REST bindings, all synchronous or
  webhook-based. Its spec has no store-and-forward story and no email mention.
- The IETF has an active Structured Email working group whose core draft defines exactly the
  machine-readable-part mechanism this proposal needs (`Content-Purpose: Machine-readable` on an
  `application/ld+json` part). Adopting it instead of inventing one is a free standards win.
- Someone has already proposed reinventing SMTP for agents. The Agent Transport Protocol draft
  (August 2026) is "modeled on SMTP" with its own port, its own DNS record type, and its own
  relays. That is the strongest evidence the properties are right and the strongest argument
  for not building a parallel network to get them.
- Mail servers finally have the hook points. Stalwart ships HTTP-based MTA hooks covering every
  stage of the SMTP transaction, plus JMAP, Sieve, and webhooks, in one binary. Postfix and
  Dovecot have had milter and LMTP for twenty years.

## 3. Design principles

1. **Profile, don't fork.** Every message is a valid email. Any receiver that ignores the
   profile still gets a readable message. Any receiver that honors it gets structure.
2. **Human part first.** The `text/plain` part is mandatory and is the message. The machine part
   is an alternate rendering of the same content, never a hidden channel.
3. **Content is evidence, never instruction.** Authorization derives from verified identity
   (signing domain and selector) and local policy, never from anything in the message body. This
   is the prompt-injection stance and it is structural, not a filter. Operators may add a content
   judgment layer on top (§5.8), but it can only restrict what a message is able to cause. It
   never grants authority.
4. **Policy at the transaction.** Anything that can be decided before accepting the message is
   decided there, with the standard reply codes, so the sender's MTA does the work of retrying
   or bouncing.
5. **Interoperate with the existing mail world.** An agent must be able to correspond with a
   person on Gmail, and a person on Gmail must be able to reach an agent. Big-provider behavior
   (header stripping, part hiding, aggressive filtering) is a design constraint, not an
   afterthought.
6. **Boring dependencies.** Stdlib SMTP, IMAP, and MIME libraries. A mainstream mail server.
   Postgres or SQLite. No message broker, no bespoke daemon protocol.

## 4. System overview

```
                    DNS (MX, SPF, DKIM per agent, DMARC, MTA-STS, _agents TXT)
                                         |
  other domains  ──SMTP──►  ┌────────────┴─────────────┐
  (agents or humans)        │   MTA  (Stalwart, or     │
                            │   Postfix + Dovecot)     │
                            │   SMTP / IMAP / JMAP /   │
                            │   Sieve / journaling     │
                            └──┬───────────▲───────┬───┘
                    MTA hooks  │           │ submit │ LMTP
                    (milter)   ▼           │        ▼
                         ┌─────────┐  ┌────┴─────┐  ┌───────────────┐
                         │ Ingress │  │ Outbound │  │ Agent runtime │
                         │ policy  │  │ policy + │  │ (SDK handler) │
                         │         │  │ hold q   │  │ or MCP server │
                         └────┬────┘  └────▲─────┘  └───────┬───────┘
                              │            │                │
                              └───► Journal (append-only, hash-chained) ◄──┘
                                          + Postgres/SQLite index
```

Components:

- **MTA.** Unmodified mail server binary. The prototype runs on Postfix plus Dovecot, using
  milter and LMTP, because that is the most thoroughly documented and debuggable path. Stalwart,
  which has MTA hooks, JMAP, Sieve, webhooks, and IMAP in one process, is the second target and
  will be run against the same scenario suite. Stalwart's hooks cover inbound stages only, so
  outbound policy lives in the gateway with either MTA.
- **Gateway.** One service exposing an MTA-hooks or milter endpoint (ingress), an LMTP
  listener (delivery), a submission proxy (outbound), and a JMAP or IMAP watcher (hold-queue
  approvals), plus an optional content judge at end-of-data (§5.8). This is the whole
  "customize the MTA a bit."
- **Profile.** The message format, documented as a spec with a conformance corpus.
- **SDK.** Python first, TypeScript second. Receive a handler, send, reply, correlate, validate.
- **MCP server.** Inbox tools for agents that cannot link the SDK.
- **Journal.** Every accepted inbound and every released outbound, with SHA-256 and a previous
  hash, plus an index for query.

## 5. Technical design

### 5.1 Addressing and identity

**Address.** An agent is `name@agents.example.com`. A dedicated subdomain keeps agent
reputation and DMARC policy separate from the humans at `example.com`.

**Correlation via sub-address.** Outbound messages set `Reply-To` (and, when the agent expects a
reply, `From`) to `name+<token>@agents.example.com`. The token identifies a task or
conversation. Sub-addressing (RFC 5233) is understood by every major MTA, survives forwarding,
and survives mail clients that strip custom headers. Correlation therefore never depends on a
header a client might drop.

**One DKIM key per agent domain (SH-44).** The gateway signs every agent's mail with the
domain's key, `d=agents.example.com; s=amx.<yyyy-mm>`, published once. Because `d=` aligns with
the From domain, DMARC passes, and because the signature covers `From`, a receiver verifies the
agent (`scheduler@agents.example.com`), not just the domain: the domain vouches for the address it
signed, as it does for every person's mail. An earlier design gave each agent its own selector so
that "revoking an agent is deleting its TXT record". It bought nothing: the gateway holds every
agent's key and signs for whichever agent authenticated at submission, so separate keys never
separated agents, and each new agent cost a DNS change. Revocation happens at the gateway
(`amx agent remove` refuses the agent's RCPT, submission, and login). Rotating is staging a new
domain selector, publishing it, and activating it.

**DMARC.** `p=reject` on the agent subdomain. Agents never send from addresses they cannot
sign for.

**Forwarding.** ARC (RFC 8617) is honored on ingress so messages relayed through a mailing list
or a forwarding hop keep a verifiable chain.

**Discovery.** A TXT record at `<name>._agents.example.com` carries a pointer to an agent card:

```
scheduler._agents.example.com. TXT "v=amx1; card=https://example.com/.well-known/agents/scheduler.json"
```

The card reuses the A2A Agent Card JSON (identity, skills, schemas, auth requirements) so that
tooling built for A2A discovery can read it. The `Agent-Card` header carries the same URL in
every message.

**Stronger identity when needed.** For counterparties relayed through a hosted provider whose
DKIM you cannot control, the machine part can carry a detached JWS over its canonical form,
keyed to the agent card's public key. This is optional and off by default.

### 5.2 Message profile

A conforming message is an RFC 5322 message with:

Required standard headers: `Message-ID`, `Date`, `From`, `To`, `Subject`. Threading via
`In-Reply-To` and `References` whenever a message continues a conversation.
`Auto-Submitted: auto-generated` (RFC 3834) on every agent-originated message, so mailing
lists and vacation responders do not loop.

Profile headers (no `X-` prefix, per RFC 6648):

| Header | Values | Purpose |
|---|---|---|
| `Agent-Protocol` | `amx/0.1` | Marks a profile message; version |
| `Agent-Intent` | `request`, `response`, `update`, `ack`, `error`, `event` | What the message is |
| `Agent-Task` | opaque id | Task correlation, mirrored in the sub-address |
| `Agent-Task-State` | `submitted`, `working`, `input-required`, `completed`, `failed`, `canceled` | Task lifecycle, borrowed from A2A |
| `Agent-Schema` | URI | Schema of the machine part |
| `Agent-Card` | URL | Sender's agent card |
| `Agent-Reply-By` | RFC 5322 date | Soft deadline; the receiver may decline after it |
| `Agent-Idempotency-Key` | opaque | Dedupe on redelivery |

Body structure:

```
multipart/mixed
├── text/plain                (required: the message, written for a person)
├── application/ld+json       (optional: the same content, for a machine)
│   Content-Purpose: Machine-readable
│   Content-Disposition: inline
└── attachments as usual
```

The `Content-Purpose: Machine-readable` marking is taken directly from the IETF Structured
Email draft. Mail clients that implement the draft hide the part; clients that do not show it as
a small attachment named `payload.json`. Vocabulary is schema.org where a type exists
(`Reservation`, `Invoice`, `Event`, `Order`) and a project-published JSON Schema otherwise,
referenced by `Agent-Schema`.

A full example:

```
From: scheduler+t_8f3a2c@agents.northwind.example
To: intake@agents.contoso.example
Cc: victor@northwind.example
Subject: Request: site inspection, week of 2026-10-05
Date: Mon, 21 Sep 2026 14:02:11 -0700
Message-ID: <t_8f3a2c.1@agents.northwind.example>
Auto-Submitted: auto-generated
Agent-Protocol: amx/0.1
Agent-Intent: request
Agent-Task: t_8f3a2c
Agent-Task-State: submitted
Agent-Schema: https://evtmail.ai/schema/0.1/appointment-request.json
Agent-Card: https://northwind.example/.well-known/agents/scheduler.json
Agent-Reply-By: Wed, 23 Sep 2026 17:00:00 -0700
DKIM-Signature: v=1; a=rsa-sha256; d=agents.northwind.example; s=scheduler; ...
Content-Type: multipart/mixed; boundary="b1"

--b1
Content-Type: text/plain; charset=utf-8

Hello,

Victor Sletten would like a site inspection at 1200 Harbor Rd during the
week of October 5. Any weekday morning works. Please reply with two or
three proposed slots. Victor is copied and can answer questions directly.

-- scheduler, an agent acting for Victor Sletten (northwind.example)

--b1
Content-Type: application/ld+json
Content-Purpose: Machine-readable
Content-Disposition: inline; filename="payload.json"

{
  "@context": "https://schema.org",
  "@type": "Reservation",
  "reservationStatus": "https://schema.org/ReservationPending",
  "underName": {"@type": "Person", "name": "Victor Sletten"},
  "reservationFor": {
    "@type": "Service", "name": "Site inspection",
    "location": {"@type": "Place", "address": "1200 Harbor Rd"}
  },
  "amx:window": {"start": "2026-10-05", "end": "2026-10-09", "preferred": "morning"},
  "amx:ask": "propose_slots", "amx:count": 3
}
--b1--
```

Semantics:

- A `response` sets `In-Reply-To` to the request's `Message-ID` and carries the same
  `Agent-Task`. Intermediate `update` messages carry `Agent-Task-State`.
- `ack` is a lightweight "received, not yet acted on." It can be an MDN (RFC 8098) when the
  counterparty is a plain mail client, or a profile message when both sides speak the profile.
- Delivery failure is a DSN (RFC 3461, RFC 3464) generated by the MTA, not by the agent. The
  SDK parses DSNs into a `failed` task state.
- `error` carries a machine part with a code and a human explanation. It is a reply, not a
  bounce; bounces are for transport, errors are for semantics.
- Large payloads go by reference: a URL plus a SHA-256 in the machine part.

### 5.3 Ingress: what happens at the SMTP transaction

The gateway registers as an MTA hook (Stalwart) or milter (Postfix) and is consulted at each
stage. The interesting decisions and the reply codes they produce:

| Stage | Check | Reply |
|---|---|---|
| CONNECT | Sender IP reputation, per-IP rate | `421` to shed load |
| MAIL FROM | SPF; block unknown domains when policy is closed | `550 5.7.1` |
| RCPT TO | Recipient agent exists and is enabled; sub-address token still open | `550 5.1.1` unknown, `550 5.1.6` closed task |
| RCPT TO | Recipient agent's queue is over its watermark | `450 4.2.1` "agent busy, retry" |
| DATA | DKIM verifies; DMARC passes; ARC chain intact if forwarded | `550 5.7.1` on failure for agent lanes; accept with a low trust score for human lanes |
| DATA | `Agent-Protocol` present, machine part parses, validates against `Agent-Schema` | `550 5.6.0` invalid content; missing profile is fine |
| DATA | Loop guard: `Received` depth, `References` depth, `Auto-Submitted` present when From is an agent | `550 5.4.6` |
| DATA | Size and attachment type policy | `552 5.3.4` |
| DATA | First contact from an unknown domain | `451 4.7.1` greylist |

Two properties fall out. First, rejected messages are never stored, and the sender receives the
reason in the bounce the sender's own MTA generates. Second, an overloaded agent slows its
callers without any of them changing code, because every MTA on earth already implements retry
on `4xx`.

Trust scoring is a local table keyed by `(d=, s=)` from the verified DKIM signature. Grants
(which intents this agent may send, which schemas, whether its requests can create tasks or only
reply to ours) live there. Nothing in a message body ever changes that table.

### 5.4 Delivery: LMTP into the runtime

Accepted messages are delivered two ways in parallel:

1. **Into the agent's mailbox**, so it exists as an ordinary IMAP or JMAP folder a person can
   open and so the journal has a source of truth.
2. **Over LMTP (RFC 2033) to the gateway**, which invokes the registered handler for that
   agent. The handler's return maps to the LMTP reply: success is `250` and the message is
   done; a raised transient error is `450` and the MTA redelivers later; a raised permanent
   error is `550` and the MTA bounces.

Delivery *is* invocation. There is no polling loop, no webhook registration, and the ack is the
protocol's own reply code. If the runtime is down, the MTA queues, exactly as it would for an
unreachable mailbox server.

In the prototype, the gateway performs both deliveries itself. Postfix hands agent mail to the
gateway over LMTP. The gateway drops duplicates by Message-ID, journals the message, appends it to
the agent's Dovecot mailbox, and then invokes the handler. Handlers run in one of two modes. In
`sync` mode, the LMTP reply means "the handler ran". In `queued` mode, it means "accepted into
the agent's bounded work queue", which suits LLM agents whose work should not hold an SMTP
transaction open.

**Agents the MTA cannot reach.** Many agents run inside a network that nothing can connect to, such
as a VPN or a laptop. For those, the gateway still accepts, journals, and files the message, and a
runner on the agent's own host pulls it. The runner is only a mail client: IMAP IDLE with the
agent's own login to pull, authenticated submission to push, and an IMAP keyword to acknowledge. The
watermark then counts the mailbox messages the runner has not acknowledged. Delivery still triggers
the work, and there is still no webhook and no polling for work. What changes is that the ack is a
keyword instead of the LMTP reply code, and a handler's refusal no longer reaches the sender as a
bounce, as in queued mode. Policy, signing, holds, and taint stay at the edge. The prototype plan's
§5.9 has the design and the scenario that exercises it (S18).

**The last hop into a running coding agent.** The runner on the agent's host still ends in a
Python handler. Where the agent is a coding harness (Claude Code, Codex, OpenCode), the prototype
plan's §5.12 makes Agent Exchange (AX), a local broker that names and wakes such sessions on one
machine, the final hop: the runner enrolls as an AX endpoint, hands each verified agent-lane message
to the named session, and finishes the copy only when that session acknowledges. AX's presence
becomes the agent's `pause` declaration to its gateway. SMTP is to LMTP roughly as amx is to AX here:
federated transport on one side, local final delivery on the other. Nothing at the edge changes.

Per-agent Sieve scripts (RFC 5228) run before delivery for routing that does not need code:
file `event` intents into a folder without invoking the handler, redirect a schema to a
different agent, reject a sender with a reason. Sieve is standardized, sandboxed, and editable
through JMAP. The prototype keeps these routing rules in the gateway's configuration file and
leaves Sieve for later.

### 5.5 Outbound: submission with policy and a hold queue

Agents never talk SMTP to the world directly. They submit to the gateway (SDK call, or
authenticated submission on port 587 through the MTA with the gateway as a policy hook), which:

- Signs with the agent's selector.
- Sets `Auto-Submitted`, `Agent-Protocol`, and the correlation sub-address.
- Renders the `text/plain` part from the machine part if the agent supplied only structure.
- Requests a DSN.
- Enforces per-agent rate limits (default 10 external messages per day until an operator
  raises it, the same ceiling AgentMail uses for unauthenticated agents).
- Applies the **hold policy**. A message matching a hold rule (an intent that commits money or
  time, a recipient outside the allowlist, a first contact with a new domain) is not sent. It is
  filed into the agent's `Outbox/Held` folder with a header naming the rule. A person sees it in
  any mail client. Moving it to `Outbox/Approved` releases it: the gateway watches the folder
  (over JMAP push, or IMAP IDLE in the prototype), signs the message at release time, and submits
  it. Replying with a body of `approve` is planned but not in the prototype. Moving it to `Outbox/Rejected`
  returns a `canceled` state to the agent.
- Holds anything produced while the agent is handling a *tainted* inbound message (§5.8),
  whatever the other rules say.

The mail client is the approval interface. No dashboard is required to ship this.

### 5.6 Journal

Every accepted inbound message and every released outbound message is appended to a journal:
raw bytes on disk under a content-addressed path, and a row with `sha256`, `prev_sha256`,
direction, verified identity, task, and timestamps. The chain gives an operator a provable
"this is what my agents said and were told." In the prototype the gateway journals each message
as it handles it on the LMTP and submission paths. Stalwart's journaling and Postfix's
`always_bcc` remain options for tapping mail that bypasses the gateway. JMAP is the query interface, so any JMAP client
can search it.

### 5.7 Interoperability

**With people on Gmail or Outlook.** They see the text part. The JSON part is either hidden
(clients implementing Structured Email) or a small attachment. Their reply lands with the
sub-address intact and no profile headers, and the SDK surfaces it as a `response` with an
empty machine part and the text for the agent to read.

**With A2A.** A bridge maps an A2A task to a mail thread: `SendMessage` becomes a `request`,
task state updates become `update` messages, A2A push notifications can target the bridge, and
the bridge answers `GetTask` from the journal. Agent cards are shared as-is.

**With MCP.** The MCP server exposes `list_inbox`, `read_thread`, `reply`, `send`, and
`wait_for_reply` tools scoped to one agent's mailbox, so any MCP-capable agent can be given an
address with no SDK.

**With hosted providers.** An adapter can run the gateway's ingress and outbound logic over
Postmark, Mailgun, Resend, or AgentMail inbound webhooks and send APIs, for teams that will not
run an MTA. They lose transaction-time rejection, `4xx` backpressure, and per-agent DKIM, and
the docs say so.

### 5.8 Security and abuse

- **Prompt injection.** Handled structurally by principle 3. The SDK delivers the human part and
  the machine part as data objects. Policy and grants are keyed by verified identity only.
  On top of that, an operator can switch on **content judgment** at end-of-data. A typed
  judgment model (the prototype uses TypeSafe's Jev) is asked three questions in one call: does
  the text try to instruct the receiving agent? Do the text and machine parts say the same thing?
  Which intent does the content actually express? Each check is `off`, `observe` (record only),
  or `enforce`, set per check, per lane, and per agent. The shipped default is `off`.
  In `enforce`, a suspect message can be refused with a reason, retried later, quarantined, or
  delivered *tainted*. Tainted means anything the agent sends while handling that message goes to
  the hold queue for a person to approve. Judgments are monotone: in every mode they may only
  remove authority, never add it. A property test holds the implementation to that rule. The
  parts-agree check also enforces principle 2: the text a person on CC reads is the text the agent
  acts on.
- **Spoofing.** DMARC `p=reject` on the agent subdomain; DKIM required for any grant above
  "read-only correspondent."
- **Replay.** `Message-ID` uniqueness enforced in the journal; `Date` window of 24 hours;
  `Agent-Idempotency-Key` honored by the SDK.
- **Loops.** `Auto-Submitted` required on agent mail; ingress rejects at `Received` depth 25
  or `References` depth 100; agents never auto-reply to `Auto-Submitted` mail unless it carries a
  profile header.
- **Deliverability.** Dedicated agent subdomain; warm-up schedule in the docs; MTA-STS and
  TLS-RPT published; DANE where the operator has DNSSEC; bounce-rate circuit breaker that
  pauses an agent at 5% bounces.
- **Confidentiality.** TLS is required inside a federation (MTA-STS `mode: enforce`) and
  opportunistic to the open internet. The machine part can be S/MIME encrypted to the recipient
  agent's card key when both sides are profile-aware.
- **Resource exhaustion.** Per-agent queue watermarks (section 5.3), per-sender rate limits,
  and greylisting on first contact.

### 5.9 Deployment

Reference deployment is one `docker compose` file: an MTA, the gateway, and a database. The
prototype's compose file runs three `.test` domains on Postfix plus Dovecot, a gateway for each
agent domain, CoreDNS serving the MX, SPF, DKIM, and DMARC records, and Roundcube as the
person's mail client. DNS
checklist generated by `amx dns example.com`, which emits MX, SPF, DMARC, MTA-STS, TLS-RPT, and
one DKIM and one `_agents` TXT record per agent. `amx agent add scheduler` generates the key
pair, prints the TXT record, creates the mailbox, and registers the handler.

Postfix plus Dovecot is a documented alternative using milter and LMTP with the same gateway
binary.

### 5.10 Implementation notes

- Python 3.13, stdlib `smtplib`, `imaplib`, `email`, plus `dkimpy`, `dnspython`,
  `jsonschema`, `pymilter` (threaded milter), and `aiosmtpd` (LMTP and submission listeners in
  background threads). No async in the SDK. SQLite for the prototype.
- Spec first: the profile and a conformance corpus of `.eml` files with expected parse results
  land before any server code.
- License Apache-2.0. Spec under CC-BY.

## 6. Existing efforts

### 6.1 Hosted "email for agents" products

| Product | Model | What it does well | What it does not do |
|---|---|---|---|
| **AgentMail** | Hosted inboxes on a shared or custom domain; REST, webhooks, WebSockets; Pods for tenant isolation; MCP support. $6M seed led by General Catalyst, March 2026. Hundreds of thousands of agent inboxes, 500+ B2B customers. | Inbox as the primitive; threading, search, durable events; SPF/DKIM/DMARC handled; sensible abuse limits (10/day until a person authenticates). | Mailbox lives with the vendor; no transaction-time policy; one DKIM identity per domain; no human-readable/machine-readable profile; no hold queue. |
| **Dead Simple Email** | Hosted agent inboxes, webhooks, multi-tenant pods. $29/mo for 100 inboxes. | Price. | Same shape as AgentMail. |
| **Inbound**, **Mails.ai**, **Hostinger Agentic Mail**, **Robotomail**, **Bavimail** | Hosted inboxes or inbound-parse services with agent-flavored packaging; Mails.ai adds classification and MCP at $0.002 per inbound. | Cheap ingestion; MCP tooling. | Same shape. |
| **Postmark, Mailgun, Resend, SES** | Transactional senders with inbound parse to a webhook. Mailgun ships an MCP server over its API. | Deliverability at volume; mature inbound parsing. | No inbox, no threading, no storage; conversation state is yours. |
| **Nylas** | Unified API over the user's existing Gmail/Outlook. | Reaching a human's real mailbox. | Not an agent identity; not a transport between organizations. |

The whole category treats the mailbox as the product and the API as the interface. None of them
touch the MTA, and none publish a message profile a counterparty could implement.

### 6.2 Open source

| Project | What it is | Relevance |
|---|---|---|
| **OpenAgentEmail** (Apache-2.0) | Self-hosted alternative to AgentMail: docker-mailserver catch-all plus a Node API and MCP server. | Closest open project. It is a mailbox wrapper; no ingress policy, no per-agent identity, no profile. Would be a natural adopter of this profile rather than a competitor. |
| **Stalwart** | Rust mail server: SMTP, IMAP, JMAP, Sieve, MTA hooks (HTTP/JSON replacement for milter), webhooks. | The reference MTA for this proposal. |
| **mox** | Go mail server, single binary, strong deliverability defaults. | Alternative MTA; no hooks API yet. |
| **Postfix + Dovecot** | The incumbents. Milter, LMTP, Sieve (Pigeonhole), `always_bcc` journaling. | Alternative MTA path. |
| **MilterGuard** | LLM-powered spam milter. | Proof that LLM policy at the milter stage is practical. It authorizes by content classification; amx authorizes by identity and offers content judgment as an optional, operator-configured layer that can only restrict (prototype plan §5.7). |

### 6.3 Protocols and standards

| Effort | Status | Relationship |
|---|---|---|
| **A2A (Agent2Agent)** | v1.0 January 2026; 150+ organizations; Linux Foundation, moving under the Agentic AI Foundation as of August 2026. Bindings: JSON-RPC, gRPC, REST. Async via SSE and webhooks. | Defines tasks, states, agent cards, and auth, with no store-and-forward transport and no email mention. This proposal reuses its task states and agent card and adds the transport it lacks. |
| **MCP** | De facto standard for tool access. | Orthogonal. Used here as one way to expose an agent's mailbox. |
| **Agent Transport Protocol** (draft-sharif-agent-transport-protocol-01, August 2026, individual submission) | "Modeled on SMTP": port 4567, DNS `AX` records, relays with store-and-forward, JWS-signed envelopes, trust scoring at ingress. | Validates every design goal here and then builds a new network to reach them. The bet in this proposal is that reusing the existing network wins on adoption by decades. Its trust-scoring-at-ingress idea is adopted. |
| **IETF Structured Email** (draft-ietf-sml-structured-email-05, Standards Track, SML WG; companion trust draft) | Defines `Content-Purpose: Machine-readable` on `application/ld+json` parts, schema.org vocabulary; implementations in Nextcloud Mail, a Roundcube plugin, a Thunderbird Android fork. | Adopted wholesale for the machine part. Aligning with this draft is the single most important standards decision in the proposal. |
| **EDIINT AS1** (RFC 3335, 2002) | Signed, encrypted EDI documents over SMTP with MDN receipts. | Direct precedent: machine-to-machine business transactions over email, standardized and deployed for two decades. AS1 lost to AS2 (HTTP) on latency, not on correctness. |
| **Gmail Actions / schema.org in email** (2013) | JSON-LD in HTML email for one-click actions. | Right idea, one vendor, closed rendering. The SML draft is its open successor. |
| **AMP for Email** (2018) | Interactive email. | Cautionary tale: a rich format that only a few clients render. This proposal deliberately puts nothing in the human part that plain text cannot carry. |
| **JMAP** (RFC 8621), **Sieve** (RFC 5228), **DSN** (RFC 3461), **MDN** (RFC 8098), **Auto-Submitted** (RFC 3834), **ARC** (RFC 8617), **MTA-STS** (RFC 8461) | Stable. | The building blocks. All reused unchanged. |

### 6.4 Older machine-over-email systems worth remembering

Debian's bug tracker control address, LISTSERV and Mailman command bots, `git send-email` with
Patchwork and SourceHut, UUCP and Usenet's store-and-forward, and X.400 all ran machine-parsed
workflows over mail at scale. They worked because the medium was text, durable, and federated,
and they were fragile at exactly the places this proposal addresses: no verified identity, no
schema, and parsing done after acceptance rather than at the gate.

### 6.5 Gap this project fills

Nobody today offers, as one open-source package: a published message profile any counterparty
can implement, transaction-time policy and backpressure, per-agent verifiable identity,
delivery-as-invocation, a human hold queue in the mail client, and a hash-chained journal, all on
a domain the operator owns. The hosted products own the mailbox; the protocol efforts own the
schema; the MTAs own the hooks. The gateway that ties them together is small, and it is the
product.

## 7. Positioning

- **Open-source core.** Spec, gateway, SDK, MCP server, compose file. Apache-2.0.
- **Complementary to the hosted inbox vendors**, who could adopt the profile and become
  interoperable endpoints; the hosted-provider adapter in section 5.7 makes that concrete.
- **A possible hosted tier later**: managed agent subdomains with warmed reputation, for teams
  that want the identity and policy model without running DNS and an MTA. Not in scope for the
  open-source project's first year.
- **Standards path.** Contribute the header set to the SML working group as an agent-workflow
  companion draft once it has two independent implementations.

## 8. Risks and open questions

- **Large-provider behavior.** Gmail and Microsoft may strip unknown headers, rewrite MIME, or
  filter agent subdomains. Mitigations are the sub-address correlation and the text-first body;
  it still needs measurement against real accounts before the profile is frozen.
- **Latency expectations.** Developers used to webhooks will find minute-scale delivery slow.
  The docs must be blunt about which workloads fit.
- **Adoption.** A profile with one implementation is a private format. The conformance corpus
  and the OpenAgentEmail-style adopters matter more than features.
- **JSON-LD versus plain JSON.** Following the SML draft means JSON-LD. Most agent developers
  will ignore `@context`. The SDK should accept plain JSON and add the context.
- **Spam economics.** If agents send at machine speed, agent subdomains will be blacklisted
  wholesale and the whole approach dies. The default rate ceiling and hold policy are load-bearing.
- **Who owns the trust table.** Per-operator grants are simple. A shared federation directory
  (a "web of agents") is attractive and out of scope until the simple version has users.

## 9. Roadmap

The prototype compresses Phases 0–2 into milestones M0–M5. It adds M4b (content judgment), M6
(Stalwart as a second MTA against the same scenarios), and M7 (measurement against real Gmail and
Microsoft 365 accounts, gated on a real domain). See [`PLAN.md`](PLAN.md) §6. The phases below
remain the longer-term shape.

**Phase 0 (spec).** Profile document, header registry, JSON Schemas for `request`, `response`,
`update`, `error`, and a conformance corpus of `.eml` files. Two weeks.

**Phase 1 (reference gateway).** Stalwart compose, MTA-hooks ingress with DKIM/DMARC gating and
schema validation, LMTP delivery to a Python handler, per-agent DKIM provisioning, journal.
Demo: two agents on two domains negotiate a meeting slot while a person CC'd in Thunderbird
watches and can intervene. Six weeks.

**Phase 2 (surface).** Python SDK, MCP server, hold queue with folder-based approval, DSN and
MDN parsing, `amx dns` and `amx agent add`. Six weeks.

**Phase 3 (bridges).** A2A bridge, hosted-provider adapter, Postfix path, TypeScript SDK.
Measurement against Gmail and Microsoft 365 as counterparties. Open-ended.

A document-processing daemon is one possible consumer: an LMTP ingress invokes its handler
instead of requiring a separate mailbox poller. The same interface serves other agents and
programmatic targets without coupling the transport to any one application.

## References

- AgentMail seed round, TechCrunch, 2026-03-10:
  https://techcrunch.com/2026/03/10/agentmail-raises-6m-to-build-an-email-service-for-ai-agents/
- AgentMail: https://www.agentmail.to/
- A2A specification: https://a2a-protocol.org/latest/specification/
- A2A passes 150 organizations, Linux Foundation, 2026-04-09:
  https://www.linuxfoundation.org/press/a2a-protocol-surpasses-150-organizations-lands-in-major-cloud-platforms-and-sees-enterprise-production-use-in-first-year
- A2A moves to the Agentic AI Foundation, Axios, 2026-08-17:
  https://www.axios.com/2026/08/17/a2a-agentic-ai-foundation-open-ai-standards
- Agent Transport Protocol draft:
  https://datatracker.ietf.org/doc/draft-sharif-agent-transport-protocol/
- IETF Structured Email: https://datatracker.ietf.org/doc/draft-ietf-sml-structured-email/
- Structured Email trust considerations:
  https://datatracker.ietf.org/doc/draft-happel-structured-email-trust/
- Stalwart MTA hooks and webhooks: https://stalw.art/blog/webhooks/
- Stalwart MTA overview: https://stalw.art/docs/mta/
- OpenAgentEmail: https://github.com/adity982/openagentemail
- mox: https://github.com/mjl-/mox
- MilterGuard: https://github.com/PhilAnderson1/MilterGuard
- Provider comparisons (vendor-authored, read accordingly):
  https://mastra.ai/blog/best-ai-agent-email-providers ,
  https://mailtrap.io/blog/best-email-api-for-ai-agents/ ,
  https://deadsimple.email/blog/email-api-cost-comparison-ai-agents-2026.html ,
  https://www.nylas.com/blog/best-ai-agent-email-providers/
- RFCs: 5321 (SMTP), 5322 (IMF), 2033 (LMTP), 3461/3464 (DSN), 3463 (enhanced status codes),
  8098 (MDN), 3834 (Auto-Submitted), 5228 (Sieve), 5233 (Sieve subaddress), 6376 (DKIM),
  7489 (DMARC), 8617 (ARC), 8461 (MTA-STS), 8621 (JMAP), 6648 (no X- headers), 3335 (AS1)
