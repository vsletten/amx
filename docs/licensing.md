# Licensing and distribution (SH-03)

## Own source and clients

amx's own source is Apache-2.0; see the root `LICENSE` and `NOTICE`.
Third-party notices and licenses are not replaced by that grant. The wheel
includes the Apache license and notice. The distribution is `agent-mail-exchange`;
the import package and console commands remain `amx`. Python 3.13 or newer is required.

The `deploy/roundcube/plugins/amx_folder_drawer/` plugin is Apache-2.0, consistent
with Roundcube 1.6.11's [source-header plugin exception](https://github.com/roundcube/roundcubemail/blob/1.6.11/program/include/iniset.php#L9-L11),
whose [full terms](https://github.com/roundcube/roundcubemail/blob/1.6.11/README.md#L59-L63)
exclude plugins that merely call Roundcube functions and include it by reference
from being considered modifications of Roundcube.

From a source checkout on macOS or Linux, one command installs `amx`, `amx-runner` and `amx-mcp`:

```sh
uv tool install .
```

For a reproducible install, check out an exact commit before installing. An exact
source archive can instead be extracted and installed with
`uv tool install /absolute/path/to/source`.
The default install includes MCP, needs no C compiler or libmilter, and never
installs pymilter. The old `mcp` extra remains a compatibility alias.
`amx --help`, `amx-runner --help`, `amx-mcp --help` and `amx-gateway --help` need no mail service or
credentials. Installing client tools does not enroll an agent or activate services.

## Gateway's pymilter boundary

Only `amx.adapters.milter` imports `Milter`. The vendored pymilter is GPL v2 or
later (`third_party/pymilter/miltermodule.c` and `COPYING`); its AMX modifications
are documented in `third_party/pymilter/AMX.md`. The gateway imports it in-process,
so the gateway image is distributed as a GPLv3 combined work, selecting pymilter's
GPLv3 option. Apache-2.0 code may be combined under GPLv3; amx's own source stays
Apache-2.0. `LICENSE.gateway` supplies the GPLv3 text. This is not a claim that
pymilter is Apache-licensed. SH-04, an optional pure-Python replacement, is the
planned way to remove this boundary.

A Linux gateway build or native gateway test needs libmilter headers and must
explicitly select `uv sync --locked --group gateway` and
`uv run --group gateway ...`. Plain `uv run` syncs back to client-only dependencies.
The gateway Dockerfile, CI and Makefile select this PEP 735 dependency group;
it is not a published extra and no wheel metadata requests unpatched pymilter.
The client wheel's `amx-gateway --help` works without native dependencies. An invocation
with `--config PATH` diagnoses absent native dependencies before reading configuration or
starting services, and directs users to the container or a source checkout with this group.
The AX runner is a client
and does not need it. The default unit run skips the native-milter modules; CI's
explicit gateway run executes them.

The gateway image includes `/app/LICENSE`, `/app/NOTICE`, `/app/LICENSE.gateway`,
amx source, schemas, the patched pymilter source and its original notices.
Corresponding build instructions are `deploy/gateway/Dockerfile`, `pyproject.toml`
and `uv.lock` at the exact tag/revision identified by the OCI labels. Distributors
must provide equivalent access to corresponding source (including the vendored
patch and build scripts) to every image recipient, preserve third-party licenses,
and satisfy GPLv3's source obligations. In particular, do not distribute a public
image with only a private, inaccessible source link. Other installed dependencies
and the base distribution retain their own licenses and source obligations.

## Release allowlist and Stalwart exclusion

Pushing a `v*` tag runs `.github/workflows/release.yml`. Before registry auth,
build or push, `tools/release_preflight.py` fails closed unless the fresh tag
binding matches the triggering push (including on replay), its commit is current
`origin/main`, and it corresponds to a merged PR into this repository's `main`.
That PR's exact head must have successful, completed `ruff and unit tests`,
`compose scenario suite`, `compose scenario suite, contoso on Stalwart (M6)`,
`public hygiene`, `private selfhost, two agent hosts (SH-26)`, `live bundle, postfix`
and `live bundle, stalwart` checks. Sourcery is not a tag-release gate; this does
not remove the PR merge review requirement. Absent, pending, skipped, failed or ambiguous checks
refuse release. The PR head and refs are read again after the proof to reject
drift. API failures, oversized/incomplete replies and deadlines also refuse;
there are no retries or human approval gates. This is release authority based on
merged-PR evidence, not a claim about branch-protection settings.

The workflow checks out the exact event commit, builds only
`deploy/gateway/Dockerfile`, and publishes only
the gateway image with tag `<git-tag>-<full-git-sha>` (Linux amd64 on the hosted
runner). There is no version-only or `latest` alias. The commit-specific name
prevents a moved tag or old event from overwriting a different source revision;
it is immutable by naming convention, not registry-enforced write protection.
A same-source rebuild can still differ, so consumers must pin the resulting
image digest (`<registry>/<namespace>/amx-gateway@sha256:<digest>`), not just its tag.
Use the image namespace reported by the release workflow; the notation here is a placeholder.
The OCI revision identifies the exact source. It does not publish AX, mailhost,
Stalwart, init, sync or probe images. All four third-party release actions are
pinned to full commit SHAs; only the ephemeral Actions token is used.

Compose pulls the official `stalwartlabs/stalwart` image by digest. The official
binary includes SEL-only code even when used in Community mode. SELv2 §2.3 bars
redistributing that binary. `deploy/stalwart/Dockerfile` copies it for local init,
sync and probe builds: those derived images MUST remain local and MUST NOT be
pushed to any registry. Running an upstream image through Compose does not
republish it. The gateway Dockerfile has no Stalwart stage or binary copy.
