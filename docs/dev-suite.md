# Fleet-safe validation suites (X0)

On a Linux development host, use:

```sh
uv sync --locked --group gateway
make suite MTA_CT=postfix
make suite MTA_CT=stalwart
make live-validate
make live-validate LIVE_MTA=stalwart
```

The dev stack deliberately keeps project `amx`, its fixed networks/subnet and host
ports. Different worktrees cannot run it concurrently. `tools/stack_suite.py`
holds one exclusive `flock` across prepare/up, smoke, scenarios, failure logs and
down. A waiter prints the lock path before blocking. Failure or INT/TERM/HUP stops
and waits for the active subprocess group, then cleans up before releasing the
lock. Repeated signals during final teardown are ignored. CI captures the suite's
output, including container logs emitted before teardown on failure.

## Lock and ownership

The default is `/tmp/amx-validation.lock`, independent of checkout, HOME and TMPDIR.
It is never unlinked: replacing the inode would split existing waiters from new
arrivals. All cooperating workers must use the same path. `AMX_SUITE_LOCK` permits
a private fixture root or an explicitly coordinated host-wide location. Relative
paths are rejected before opening the lease or running any command; do not
set it per worktree, per worker or per MTA. The invoking users need write access
to the same lock and its adjacent journal/override files (normally all fleet
workers run as one OS user). Permission errors fail closed. This is a cooperative
host-local lock, not distributed locking for different hosts sharing a daemon.

Before startup, the supervisor records the owning worktree, Git common directory,
worktree-specific Git directory and directory device/inode, Docker engine ID,
MTA and a random run token in `<lock>.json`. A replacement checkout at the old
path is not the owner, even if it shares the same Git repository. An ownership-only
Compose override at `<lock>.compose.json` labels every service, named volume and
network with that token. Neither file contains credentials. The journal is
atomically replaced before prepare/up. The normal Compose project name, network
names, addresses and ports are unchanged.

The ownership render uses `--profile '*' config`, so even transient profiled
services such as `smoke` receive labels. The override contains labels only: it does
not replace the base service's `profiles`. `up` does not enable all profiles;
smoke still starts only via explicit `run --rm smoke`. Inherited `COMPOSE_PROFILES`
is removed from suite and scenario subprocess environments. Teardown inventories
all project containers, including interrupted profiled one-offs.

Cleanup validates the journal's repository and engine, the token on every `amx`
resource, and Compose's working-directory label on every container. It removes
only that validated snapshot: full immutable container/network IDs and exact named
volumes, never project-wide Compose down. Volumes and networks are removed without
force, so concurrent attachments cause a refusal rather than collateral teardown.
New foreign resources created after the scan are not targeted; the post-removal
inventory detects them and retains the recovery journal/state. This includes any
paused/interrupted smoke one-off and its attached network. All ownership checks
precede mutation.
Only after confirming no `amx` containers, volumes
or networks remain does it remove the owning worktree's `deploy/generated/state`
and `mta_ct` record and retire the journal before its override (with a directory
fsync between them). Recovery teardown does not require the override, so an
interrupted current-format journal with a missing override remains recoverable.
Journals from before worktree identity was recorded fail closed rather than
adopting an unverifiable checkout. Dev DKIM keys and TLS files
are deliberately kept, as with the existing `down` target.

An existing `amx` stack without the journal, a different run token, a different
Compose working directory/repository, or an engine mismatch is not ours: startup
or cleanup fails without deleting foreign resources. There is no automatic
adoption, force-clean option, or project-name-only fallback. Do not use this
validator on a machine whose `amx` resources belong to an unrelated install.

## Killed runs and cleanup errors

INT/TERM/HUP first quiesces the active process group, then performs cleanup. The
supervisor keeps its session leader unreaped while checking Linux group/session
membership (not command strings), allowing 10 seconds after TERM and 5 after KILL
for dev-suite commands. Generic `lock` commands receive 120 seconds after TERM
to finish validator cleanup, then 5 seconds after KILL.
This includes TERM-ignoring descendants that closed inherited FDs. Repeated signals
cannot skip cancellation. Zombies are quiescent; the leader is reaped only after
active work is gone. If kernel-stuck work survives the bounded TERM/KILL waits,
cleanup is skipped and the caller returns nonzero. An adjacent `<lock>.active`
admission marker is durably published BEFORE every spawn and updated with its PGID
before waiting. Publication failure refuses spawn; surviving work needs no late,
fallible quarantine write. Every locked entry checks this marker, even when a
descendant closed the inherited lock FD. The marker is cleared only after proven
group quiescence, either by its supervisor or the next lease holder. No orphan,
timer or indefinite polling process is created. An ambiguous marker (including
SIGKILL between spawn and PGID publication) fails closed for explicit investigation;
there is no force-clear option. Legacy `<lock>.unsafe` markers also still refuse
admission. Ordinary signal and SIGKILL recovery follow the normal paths below.

SIGKILL cannot run a finally block. Immediate subprocesses inherit the lock FD,
so killing only the supervisor does not admit a waiter while the surviving
make/Compose/pytest chain still retains it. Once those children
exit (or the entire run is killed), the next suite takes the lease, reports
recovery, and cleans the journal's worktree and previous MTA before its own up.
This also cleans a partial/failed startup, including generated bind-mount state.

If targeted Docker removal fails, resources remain, or filesystem cleanup fails, the suite
returns nonzero and retains the journal. The next suite retries recovery and
cannot start a new stack until it succeeds. Keep the recorded worktree and its
Git identity until recovery completes. A removed/replaced checkout or damaged journal
fails closed and needs operator investigation; never delete the
journal to bypass a refusal. A host reboot that clears `/tmp` also loses recovery
metadata; use a coordinated persistent lock path if recovery across reboot is
needed. This card promises process-kill recovery, not reboot recovery.

Low-level `up`, `smoke`, `scenarios`, `integration` and `down` remain available for
the supervisor and dedicated non-fleet interactive engines. Calling them directly
on a shared host bypasses the lease and is unsafe. In particular, do not run an
extra `make down` after a suite: a waiting worktree may already own the stack.
The suite is destructive test infrastructure, not a persistent interactive stack.

## Sharing the lease with other validators

`make live-validate` invokes:

```sh
uv run python tools/stack_suite.py lock -- uv run python tools/live_validate.py
```

The generic `lock -- COMMAND ...` mode holds the same lease until the command
and its signal handling finish; it does not adopt or purge the command's resources.
The live validator retains its existing separate `amx-live` project and refusal
to overwrite existing live resources. It handles INT/TERM/HUP through its finally,
ignores repeated signals during cleanup, bounds runner shutdown at 30s TERM/5s KILL,
and bounds its final down command at 60s, inside the supervisor's 120s TERM grace.
Success/failure still clean up; explicit `--keep` still opts out. Optional arguments such as `--state` must
also be passed through this wrapper, never by calling the live validator directly.

`make selfhost-validate` wraps `tools/selfhost_validate.py` with this same `lock`
mode, keeping its up/checks/finally-cleanup entirely inside the lease.
Do not nest `make suite` or `make live-validate` under `lock`: a second flock of
the same inode would deadlock. Reuse the underlying validator functions instead.
X0 supplies the primitive; SH-26 supplies the integrated private acceptance below.

### SH-26 integrated private profile

`make selfhost-validate` creates one fresh native Stalwart private bundle and two
separate agent-host containers on its internal bridge. Each runs the production
`amx-runner` from its own unchanged `amx agent add --live` credentials bundle.
The pinned AX image is built anonymously/read-only from the existing shared pin.
One host attaches a real AX session driven by a deterministic protocol client (no
LLM); the other has no attached target and polls genuine `amx-mcp` over stdio.
Runner and MCP share only that host's custody state, never the other host's.

The integrated run proves a native-discovered person account using SASL and IMAPS,
person-to-agent and same-thread replies on both hosts, signed sibling round trips
without an agent DNS zone, MCP read/reply/done keywords, and a genuine policy hold
approved by the ordinary owner's IMAP MOVE (the agent's MOVE is denied). Endpoint
host-file mappings are only for TLS connectivity; no DKIM TXT zone is installed.
The established stopped-sink, accepted-DATA and temporary native-route controls
prove the sink canary detects escape before probes are removed and the zero-mail
baseline is taken. Positive local paths and foreign-submission refusals are then
checked with a live sink throughout a quiet window.

The validator refuses existing `amx-live` resources and nonfresh state; it never
adopts them. Its callable host-side mutation helpers require the real X0 active
session/kernel lease and exact fresh fixture state before changing files,
containers or mail. INT/TERM/HUP cleanup stays within the same lease; repeated
signals cannot skip bounded down. No `--keep` or unlocked fallback is supplied.
The private report contains only fixed check names and exception types. Do not
upload the state directory (credentials and private mail); CI uploads only the
sanitized validator output. Both ordinary MTA scenario/live-bundle jobs remain.

CI runs this exact command on every PR and main on a disposable engine, using
the same `AMX_CI_RUNS_ON` selector as the other jobs (default `ubuntu-24.04`).
The provisioned disposable DinD runners are selected through that variable.
Unit/fake-engine tests verify orchestration and refusal, not native acceptance.
Do not run it on a shared engine or retry a native engine's ownership refusal.

### SH-10 fresh Stalwart live bundle

`make live-validate LIVE_MTA=stalwart` runs the same generic lock wrapper, then
`tools/live_validate.py --mta stalwart`. Omitting `LIVE_MTA` retains the original
Postfix validator. Stalwart uses fresh private `home.arpa` parameters, the actual
`amx live install/up/preflight` CLI, and registration while the server runs. It
requires verified STARTTLS/IMAPS, a refused incorrect submission token, an
agent-denied hold approval, an ordinary approver's MOVE, a DKIM-verified delivery
to the local postmaster, inbound milter/LMTP delivery, and login revocation through sync. It does not stand in
for SH-11/12/13 or SH-26 acceptance.

The fixture's Compose network is `internal: true`, its DNS points to container
loopback, and only loopback host ports are published. Docker does not publish
ports directly from an internal bridge: a fixture-only socat edge (the dev
stack's pinned image) forwards only the three fixed mail endpoints. Mail
containers stay on the internal bridge, with no external route. There is no external mail
recipient or resolver. It refuses preexisting `amx-live` containers, volumes or
networks and nonfresh supplied state; startup/check failures and handled signals
still run bounded cleanup inside the lease. Optional explicit arguments use
`uv run python tools/stack_suite.py lock -- uv run python tools/live_validate.py
--mta stalwart --state <fresh-dir>`; never run the validator directly on a shared
host. `validation.json` and failure `compose.log` are in that printed state
directory (which also holds generated secrets; never upload the whole directory).
The CI live-bundle matrix runs both validators on disposable CI engines;
use that path rather than bypassing a local engine's ownership refusal.

## SH-00 native probe support

On a task-owned engine with no foreign `amx` resources, run:

```sh
make suite MTA_CT=stalwart SH00_PROBE=1
```

Never select the default engine on a host whose `amx` project belongs to another
installation. An isolated engine must be supplied explicitly by its owner (for
example via `DOCKER_HOST`); this command does not provision or adopt an engine.
Keep the coordinated host lock even on the isolated engine. Do not nest `suite`
inside `stack_suite.py lock`.

The fixture entrypoint first verifies the native X0 active session and ancestry,
the supervisor's actual named exclusive Linux FLOCK (read-only `/proc` fdinfo;
it never acquires or releases the owner's lock), canonical journal/Git worktree,
engine and ownership-token-labelled containers publishing both loopback endpoints.
Spoofed environment variables, a stale journal or an unrelated lockholder do not
admit a send. Missing/inaccessible custody evidence fails closed before SDK,
mailbox, journal-data or fixture access. This local stale-state/accident guard is
not a security boundary against a hostile UID able to modify the source or Docker.
X0's supervisor and recovery protocol are unchanged.

The ordinary suite performs up and smoke, then its scenarios recipe obtains an
actual signed fixture through the gateway's SDK submission and Sent mailbox,
cryptographically verifies it, and runs the profiled `stalwart-probe` one-off
before the existing scenarios. Generated fixture bytes/public DKIM records live
under `deploy/generated/state/sh00` and are removed by normal suite cleanup.
The one-off gets
the same ownership labels from X0's all-profile render. It has `network_mode:
none`, no published ports, no shared datastore, and only read-only development TLS
and signed-fixture mounts. The `probe` Docker target adds dkimpy/dnspython at the
versions in uv.lock; ordinary init/sync target the standard-library `provisioner`.
It boots the pinned binary on a temporary RocksDB store, applies a separate
experimental plan, observes two milter endpoints and an LMTP sink on loopback,
and removes the store on normal exit. Suite teardown handles interrupted one-offs
under the unchanged X0 journal/ownership checks. The image remains local-only;
never publish it, since it contains the Stalwart binary.

The probe emits one `AMX_SH00_RESULT=<JSON>` line, also on failure; capture the suite
output as the artifact. A zero exit status means the implemented probes completed,
not that SH-00 acceptance is complete. The overall result deliberately says
`partial`: amx's actual native negotiation is measured by the ordinary scenario
suite, not this tool. The signing probe verifies a real native people signature
and the real gateway fixture's DKIM before/after 10025, with exactly one identical
original signature. It reports raw body equality, lengths and hashes separately:
the measured 53 → 55 byte body is not equal, differing by one appended CRLF.
Only identical bytes or that exact single trailing-empty-line delta are allowed;
other changes still fail. amx signs relaxed/relaxed (RFC 6376 §3.4.4 ignores trailing
empty lines). Neither raw-body nor whole-message byte identity is claimed.

Discovery follows the ISP-hosted Thunderbird URL priority (HTTPS autoconfig,
HTTPS well-known, then their HTTP variants), as in Mozilla's
`mail/components/accountcreation/modules/FetchConfig.sys.mjs`. External ISPDB/MX
fallback is intentionally not fetched in the sealed fixture. The fixture aliases
candidate hosts to localhost and verifies its development certificate for
localhost; real discovery-host DNS/certificates are unmeasured. Real native XML,
when present, is parsed and its advertised IMAP/submission ports are exercised;
when absent, directly configured protocol checks are explicitly separate and
cannot pass as discovered settings. Autodiscover includes a real POST request;
the response is parsed for namespaces, settings action and protocol records,
rather than treating HTTP 200 alone as support. Advertised POP3 is not exercised.

Its recorders are
test instrumentation, not amx policy or SH-13 implementation. It never emits a
final `Verdict:`. Run the ordinary Postfix suite separately as required by the card.

Unit tests use only loopback fixture servers, without Docker or external APIs:

```sh
uv run pytest tests/unit/test_stalwart_probe.py tests/unit/test_stalwart.py -q
```

## X0 regression tests without Docker

```sh
uv run pytest tests/unit/test_stack_suite.py -q
```

These use real processes, GNU make, real Git worktrees and real `flock`, but only
private fake Docker/uv executables. Each subprocess gets an explicit minimal
environment and fixture HOME/PATH/lock/engine; provider credentials and the host
Docker socket/context are not inherited. File gates, rather than assumed timing,
control concurrency, signals and SIGKILL recovery tests.
