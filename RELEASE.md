# Agent Mail Exchange v0.3.0

Agent Mail Exchange gives agents an email address on an operator-owned domain,
using ordinary SMTP, DNS, DKIM and IMAP rather than a proprietary inbox API.
This release is a functionality prototype, not a production-hardening claim.

## Release scope

- **Public self-hosting:** the Postfix + Dovecot quickstart includes a single-domain
  deployment bundle, DNS rendering, ACME certificates and preflight checks.
- **Private self-hosting:** the Stalwart quickstart includes people accounts,
  restricted local routing and integrated two-agent-host validation.
- **Agent delivery:** Python handlers, remote runners, MCP mailbox custody and
  pinned Agent Exchange compatibility support agents on separate hosts.
- **Policy and evidence:** verified sender identity, task-scoped recipient grants,
  human approval holds, backpressure, typed attachments and a hash-chained journal
  remain part of the gateway boundary. A release grants no permission to send mail
  to recipients who have not consented.

Start with the [README quickstarts](README.md) and follow the appropriate
[public Postfix runbook](docs/selfhost-public.md) or
[private Stalwart guide](docs/selfhost-people.md). The
[roadmap](docs/ROADMAP.md) distinguishes implemented features from planned work;
protocol validation is not a claim of real-device mail-client compatibility.

## Distribution

The source tag is `v0.3.0`. To install the client tools from that source, with
Python 3.13 or newer and uv installed:

```sh
git clone --branch v0.3.0 --depth 1 https://github.com/vsletten/amx.git
cd amx
uv tool install .
amx --help
amx-runner --help
amx-mcp --help
```

Server deployment uses the checkout and its Compose files as documented in the
quickstarts. Gateway container releases use the immutable image reference
`ghcr.io/vsletten/amx-gateway:v0.3.0-<full-commit-sha>`; use the exact reference and
digest in the GitHub release rather than assuming a floating image tag exists.

**PyPI publication will follow in a later release.** No Python package-index
upload is part of v0.3.0; the Python publisher is manual-only and requires its
separate trusted-publisher and deployment protections.

The project's own source and client tools are Apache-2.0. The combined gateway
image imports pymilter and is GPLv3; third-party licenses and corresponding-source
obligations apply. Stalwart-derived validation images remain local builds and are
not release artifacts. See [licensing](docs/licensing.md),
[contributing](CONTRIBUTING.md) and [private security reporting](SECURITY.md).
