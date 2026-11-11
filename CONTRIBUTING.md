# Contributing

Please follow the [Code of Conduct](CODE_OF_CONDUCT.md). For security issues, use
the private reporting process in [SECURITY.md](SECURITY.md), not a public issue.

## Development setup

Use Linux for native gateway development, Python 3.13, [uv](https://docs.astral.sh/uv/),
a C compiler, and libmilter development headers (`libmilter-dev` on Debian/Ubuntu).
The Compose suites also require Docker with the Compose plugin, version 2.24.4 or
newer for the Stalwart override. From a source checkout:

```sh
uv sync --locked
uv run ruff check .
uv run pytest tests/unit -q
```

The default install is client-only and skips native-milter modules. To cover the
native gateway, install the headers first and explicitly select the gateway dependency group,
as CI does:

```sh
uv sync --locked --group gateway
uv run --group gateway ruff check .
uv run --group gateway ruff format --check .
uv run --group gateway pytest tests/unit -q
```

Plain `uv run` syncs back to client-only dependencies; keep `--group gateway` on
commands that need pymilter. See [licensing and installation](docs/licensing.md).

## Two-MTA validation

On a disposable, task-owned Docker engine with no unrelated project resources:

```sh
make suite
make suite MTA_CT=postfix
make suite MTA_CT=stalwart
```

`make suite` defaults to Postfix on a fresh checkout (otherwise it uses the recorded
MTA). The explicit commands match the two Compose scenario jobs in
[CI](.github/workflows/ci.yml):

- Postfix runs the baseline two-domain mail stack, smoke checks, and integration
  scenarios covering mail transport and gateway policy, including replies, holds,
  backpressure, and attachments.
- Stalwart replaces one domain's Postfix/Dovecot mailhost with Stalwart Community,
  running the shared scenarios plus native-adapter behavior against the other
  domain's unchanged Postfix stack.

The suites serialize access using a host-wide lease and clean up their owned test
resources. They are destructive test infrastructure, not an interactive stack.
Do not bypass the lease with separate `up`/`down` commands or run them on a shared
engine hosting unrelated mail. Read [the validation guide](docs/dev-suite.md) before
running a suite; do not override ownership refusals. LLM-dependent scenarios may
skip when Ollama is absent. CI also checks both fresh live-bundle fixtures and the
private two-agent-host fixture on disposable engines.

## Pull requests

Describe the problem, the change, and how you verified it. Add regression tests for
behavior changes. Run ruff checks and formatting, the relevant unit tests, and the
appropriate isolated suites; report exact results and any skips. Pull requests need
passing tests, ruff, and green CI before merge. Keep changes focused and never
include credentials, private mail, generated state, or deployment secrets.

## Licensing and sign-off

This project's own source is Apache-2.0. Third-party code retains its own licenses;
the gateway image that imports pymilter in-process is a GPLv3 combined work, not an
Apache-only distribution. See [docs/licensing.md](docs/licensing.md) for the boundary
and corresponding-source obligations.

SEL-licensed Stalwart binaries and images derived from them must never be committed
or published. Local-only suite builds do not grant redistribution rights.

Contributions use the [Developer Certificate of Origin 1.1](https://developercertificate.org/)
(DCO), not a CLA. By adding a sign-off, you certify the contribution under DCO 1.1.
Sign off each contribution commit using your own Git identity:

```sh
git commit -s
```

Git adds a `Signed-off-by` trailer from that identity. A sign-off is a certification,
not a cryptographic signature. Use an identity you are comfortable retaining in the
public history; a GitHub noreply address can avoid publishing a personal email.
