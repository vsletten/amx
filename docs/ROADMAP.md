# Roadmap

amx adds transaction-time policy, verified identity, task correlation, human approval and
an auditable journal to ordinary email. It works with unmodified Postfix + Dovecot or
Stalwart, and delivers to Python handlers, remote mail clients, MCP clients and Agent
Exchange (AX) sessions. Operators bring their own domain and infrastructure.

This is a functionality prototype, not a claim of production hardening. The SH identifiers
below are stable feature identifiers. “Shipped” means implemented in this source tree;
validation coverage is not a claim that every device or deployment has been tested.
[PLAN.md](PLAN.md) explains the design; [findings.md](findings.md) and
[findings-stalwart.md](findings-stalwart.md) record measurements and limitations.

## Available today

| ID | Shipped capability |
|---|---|
| SH-00 | Stalwart 0.16.25 self-host prerequisites measured: sibling routing, SASL identity, milter coverage, signing split, client discovery and private domain handling. |
| SH-01 | Eligible person-first mail gets a correlated task so an agent can reply to a bare-address request. |
| SH-02 | Agents on one Postfix gateway mail each other through a trusted sibling path with agent-scoped task state. |
| SH-03 | Apache-2.0 source licensing, separately installable clients without libmilter, and a GPLv3 combined gateway-image distribution boundary. |
| SH-10 | Parameter-driven Stalwart live bundle alongside the existing Postfix bundle. |
| SH-10b | Stalwart household hardening defaults, protected management surfaces and TLS for gateway mailbox access. |
| SH-11 | Operator-managed people accounts, app passwords, shared hold approval, native client discovery and Apple configuration profiles. |
| SH-12 | Signed-in local people whose sender matches their login receive owner-task authority; internet mail cannot claim that grant. |
| SH-13 | Trusted sibling agent mail on Stalwart, with separate milter endpoints and replay checks. |
| SH-20 | Private local-only routing rejects external recipients for both people and agents. |
| SH-21 | Own-domain agent signatures verify against registered local keys without public DNS. |
| SH-22 | Operator-provided TLS files and renewal hooks reload certificates without restarting the bundle. |
| SH-23 | Native per-agent host runners supervised by Linux systemd user services or macOS launchd. |
| SH-24a | MCP mailbox custody uses its own keyword, with explicit completion and refusal. |
| SH-24b | Runner custody hands mail to an available AX target or leaves it for an active MCP client. |
| SH-25 | AX v0.8.1 relay compatibility pinned to an exact upstream release commit, with agent-host upgrade guidance. |
| SH-26 | Integrated private-profile validation covers a server, two agent hosts, AX/MCP delivery, people, holds and isolation from external recipients. |
| SH-40 | Verified, aligned human senders and per-agent sender lists restrict who can address an agent as its owner. |
| SH-42 | Typed, size-limited MIME attachments with true-type checks, safe filenames, SDK/MCP/AX support and preserved bytes through holds and retries. |
| SH-44 | One DKIM key per agent domain, staged rotation and agent identity derived from the signed From address. |
| SH-45 | Host-installed runners store mail while AX sessions are offline; explicit owner hold/refuse policy still applies. |
| SH-46 | An owner's signed From/To/Cc authorize task-scoped reply recipients, with reply-all and all remaining policy ceilings preserved. |
| SH-47 | Household-scoped agents and sender/outbound lists prevent cross-household agent authority on a shared lane. |

Attachment support does not include antivirus, archive extraction, document extraction or
an attachment-content judge. Household separation is an agent-authority boundary, not
mailbox privacy from the operator or delegated approval. Real mail apps remain unmeasured;
see the [client status table](../README.md#self-host-mail-client-measurement-status-sh-00).

## v0.3: bring your own domain

The public quickstart uses **Postfix + Dovecot in `deploy/live`**. It already provides a
single-domain internet-facing bundle, ACME, DNS rendering and preflight checks. Public
Stalwart support is not a prerequisite for this release.

The private quickstart uses **Stalwart on a tailnet or LAN**, with SH-26's integrated
validation. It includes native agent-host setup and AX/MCP custody. A tailnet-only server
may be unreachable from clients that synchronize through a vendor's cloud; protocol
validation does not establish device compatibility or prove the optional SH-22T sidecar.

| ID | Release work still open |
|---|---|
| SH-34 | [Public self-host guide](selfhost-public.md) is available: operator-owned domains, DNS/PTR, TLS, backups and provider port-25 restrictions. |
| SH-50 | [README](../README.md) quickstarts and agent-host/AX setup are available; package/image publication and the release tag remain release work. |

SH-03, SH-25 and SH-26 are implemented foundations for v0.3. Package metadata is
0.3.0, with schema IDs under `https://evtmail.ai/schema/0.1/`. These are identifiers;
schema validation uses the bundled registry, not HTTP retrieval. Packaging and image
publication must still be verified; this roadmap does not assert a published artifact.
v0.3.0 ships without PyPI publication. The Python publisher is manual-only: after
registering the pending trusted publisher documented in `publish.yml`, dispatch it
from current main with the existing release tag as its required `tag` input. It
refuses stale tags, tag/version mismatches and unsuccessful exact-head CI.
Before registering that publisher, configure required PR/check protection on main
and an external `pypi` environment deployment branch policy allowing **only branch
main, no tags**. A workflow's own guards are not protection against a writer who
changes that workflow on another branch. This repository does not provision those
account settings or register a publisher.
Use the [generic public Postfix runbook](selfhost-public.md) or the
[private Stalwart guide](selfhost-people.md).

## v0.4 and later

These items are open unless the status explicitly says otherwise. Ordering expresses
technical dependencies, not promised dates.

| ID | Planned outcome and completion boundary |
|---|---|
| SH-04 | Replace pymilter with a permissively licensed pure-Python milter behind the same adapter interface; both MTA suites must pass without the native extension, removing that GPL boundary from the gateway image. |
| SH-14 | Adopt a stable Stalwart 1.0 release when suitable, documenting upgrades that preserve accounts, mail and holds and validating both scenarios and the private bundle. |
| SH-15 | Bring the shared `holds@` layout to Dovecot with ordinary owner-account ACLs, replacing the approver master login while retaining legacy configuration compatibility. |
| SH-16 | Allow approval to be disabled explicitly for private profiles only, recording skipped holds and retaining taint; refuse this setting for public profiles. |
| SH-22T | Add an optional tailnet sidecar and automatic certificate renewal after SH-22; verify TLS and management sign-in from another tailnet device. Host-managed certificate files remain the available alternative. |
| SH-30 | Add the public Stalwart profile: ACME, people-domain DNS/signing and inbound authentication/spam checks, with public preflight and bidirectional DMARC-passing validation. |
| SH-31 | Add an authenticated smarthost relay for providers that block outbound port 25; prove the relay preserves gateway DKIM signatures for people and agent outbound mail. |
| SH-32 | Bind client/submission ports to an optional private network address while keeping only SMTP and required ACME ports public; verify exposure externally and document cloud-client tradeoffs. |
| SH-33 | Harden internet-facing Stalwart: isolate admin/OAuth endpoints, enable ingress protections and check pinned versions and security advisories before upgrades. |
| SH-35 | Demonstrate a reproducible public-profile deployment from documented configuration, with backup/rollback preparation, preflight and bidirectional authenticated mail; site-specific configuration stays outside this repository. |
| SH-36 | Add public-profile approval by reply: a one-use notice token plus a verified, aligned owner reply releases or rejects a hold; forged and replayed replies fail, and folder-based approval remains available. Depends on SH-30 and SH-40. |
| SH-41 | Ship configurable exec, webhook and Maildir handlers, mapping temporary/permanent failures to runtime outcomes and testing each through the runner. |
| SH-43 | Provide a paper-ingestion example using verified owner senders and stock handlers to save/process PDFs and reply; strangers must be refused. Depends on SH-40 and SH-41. |

**DNS automation** is also planned: publish and rotate the records currently rendered by
the CLI through provider integrations, with explicit operator authorization and checks
that the served keys match. No provider is required by the core design.

Future work must preserve transaction-time policy, explicit approval authority, verified
identity and journal evidence. Features do not grant authority merely because a message
body asks for it, and a release is not permission to send to outside recipients.
