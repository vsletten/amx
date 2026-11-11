# Native agent hosts (SH-23)

Install the client package on each agent's Mac or Linux host (Python 3.13+;
no gateway dependency group or libmilter needed). Run as the same login user as AX,
never with sudo. `amx host` does not install or restart AX or any agent gateway.

## Install AX before the host service

For an AX-backed host, install AX **v0.8.1 or later** from AX's upstream release
before `amx host install`. The reproducible v0.8.1 install uses the installer from
the same release commit as `deploy/ax/AX_COMMIT`:

```sh
curl -fsSL https://raw.githubusercontent.com/summationai/agent-exchange/66b1d34a4bbe222eb31c6fc31ffd8c2ae72c6ec6/install.sh -o install-ax.sh
# Inspect install-ax.sh before running it. It verifies the release archive checksum.
AX_VERSION=v0.8.1 sh install-ax.sh
ax version  # 0.8.1
```

The installer defaults to `~/.local/bin/ax`; ensure that directory is on PATH
(or select the installed path with `--ax-binary`). For a later release, follow
that release's upstream install and upgrade guidance, selecting its explicit tag.
The runner image and CI keep building the exact shared commit rather than
installing a moving latest release.

Every session of the same OS user shares one local broker by default (`~/.ax`);
an explicit `AX_HOME` selects another. **Upgrade AX between sessions, never
under a running one.** Replacing the executable does not update the running
broker or existing MCP children. Following the
[v0.8.1 update guide](https://github.com/summationai/agent-exchange/blob/66b1d34a4bbe222eb31c6fc31ffd8c2ae72c6ec6/AGENTS.md#updating-running-sessions):

1. Finish active work, close AX sessions normally, and retain their saved names.
   Stop any AX-backed amx runner service through its recorded service manager
   (below) so it cannot reconnect and restart the broker during the upgrade.
2. Identify this user's `ax serve` PID owning the relevant `broker.sock`. Stop
   only that verified broker with TERM and wait for exit. Never kill a launcher,
   harness, bridge or process group. If identity is uncertain, leave it running;
   the broker upgrade remains pending.
3. Before starting the new broker, privately back up the stopped AX home's
   mailbox and saved sessions, preserving owner-only access. An upgrade from
   0.7.x migrates the mailbox to schema 4; reinstalling 0.7.x is not a rollback.
4. Install the selected release, run `ax agents` to start its broker, then
   relaunch the saved session names and restart the recorded amx runner services.
   Keep the runner and target on the same OS user and AX home.

The runner uses upstream's `ax attach --relay -n NAME` contract, which supplies
relay permissions without `AX_ALLOW_BYPASS`. The receiving session still needs
its real native permissions and the owner's explicit external policy (for
example `--external verified`); amx does not open or bypass those gates.

## Install and manage the host service

After securely handing over the 0600 bundle produced by `amx agent add --live`
(or `amx live agent add`):

```sh
amx host install ./agent.json --ax my-session --offline hold
# Or use a Python handler installed in the same Python environment:
amx host install ./first.json ./second.json --handler my_package:handle
# A self-signed server also needs its public CA certificate:
amx host install ./agent.json --ca ./ca.pem --ax my-session
```

`--ax-home` defaults to `~/.ax`, as it does in `amx-runner`; use an explicit
path if the target uses a different AX home. `--ax-binary` can select an
installed executable. It is resolved at install time, not through a login
shell. No API-key credentials are configured. Native same-user supervision
preserves AX's existing 0600 Unix-socket boundary.

`amx host install` defaults to `--offline hold`: when the named AX target has no
attached session, the runner leaves intake open and mail waits visibly in the
agent's INBOX until the target attaches. Select `--offline pause` when the
operator instead wants inbound SMTP clients to receive a temporary failure and
retry later. AX owner policy remains authoritative in either mode: an attached
target whose owner policy is `hold` or `refuse` still declares an `operator`
pause to the gateway.

The standalone `amx-runner` keeps `--offline pause` as its compatibility
default. Pass `--offline hold` explicitly to give a standalone AX runner the
same store-and-forward behavior as a host-installed runner. `--presence-timeout`
still controls how long `pause` waits before declaring the target offline; it
does not turn `hold` into a pause.

Host-installed and standalone AX runners use `amx-<digest>` as their default endpoint name, derived
from the full agent address. Equal local parts on different domains therefore
have distinct names in the shared AX home; reinstalling preserves the name.
Standalone `--ax-name` still overrides it. When upgrading a standalone runner that used
the old `<state>/ax` default, add `--ax-home <old-state>/ax` to preserve that broker and
its state; add `--ax-name <previous-endpoint-name>` if its old endpoint identity must also
remain unchanged. No existing AX home is moved, deleted, or adopted automatically.

One service is identified by a digest of the full agent address. Linux uses
`~/.config/systemd/user/ai.amx.runner.<digest>.service` (or XDG_CONFIG_HOME),
`WantedBy=default.target`, and `Restart=always`. macOS uses
`~/Library/LaunchAgents/ai.amx.runner.<digest>.plist`, `RunAtLoad`, and
`KeepAlive` in `gui/<uid>`. A logged-in GUI user domain must exist on macOS.
No root daemon, linger configuration, reboot or cross-user service is required.

The service runs the installing Python environment's actual `amx.runner`
module. Keep that environment installed at its original path. Handler modules
must be importable there. Working directory, credentials and handling database
live under `~/.local/share/amx/host/<service-id>` (or XDG_DATA_HOME);
`--state-home` overrides that root. The directory is 0700 and the managed
credentials copy is 0600. The source bundle is left unchanged: after successful
installation, delete the handover copy yourself. Never put secrets in unit
files, environment variables or process arguments. Linux logs go to the user
journal; Mac logs are `runner.log` and `runner.err.log` in the state directory.

Use the path printed by install to inspect the service:

```sh
systemctl --user is-enabled ai.amx.runner.<digest>.service
systemctl --user show ai.amx.runner.<digest>.service -p MainPID -p ActiveState
launchctl print gui/$(id -u)/ai.amx.runner.<digest>
```

Existing service files or loaded jobs are never adopted or overwritten. To
change options or rotate credentials, uninstall then install the new bundle.
A failed manager activation retains an installation receipt for cleanup;
inspect the reported manager error and uninstall before retrying.

Batch installs are per-agent, not atomic. Each successful agent is printed immediately;
on failure the error identifies the current address/service ID and the completed addresses.
Earlier agents remain installed, later agents are not attempted, and a possibly activated
current agent retains its receipt. Explicitly uninstall each recorded completed/current
installation (using the same `--state-home`) before retrying the batch, or keep completed
agents and retry only unfinished bundles after uninstalling the failed current agent.
Do not delete receipts or service files by hand to bypass this safety check.

### Replacing the temporary long-presence drop-in

Hosts that used
`~/.config/systemd/user/ai.amx.runner.<id>.service.d/store-and-forward.conf`
to add a very long `--presence-timeout` should move the installation to the
native policy. Preserve the source credentials bundle and the AX target name,
then remove only the known workaround before uninstalling. This order is
required because uninstall refuses to stop a loaded unit with any drop-in:

```sh
rm -rf ~/.config/systemd/user/ai.amx.runner.<id>.service.d
systemctl --user daemon-reload
amx host uninstall agent@agents.example.test
amx host install ./agent.json --ax my-session --offline hold
```

Do not remove the managed service file or its installation receipt by hand.
`amx host uninstall` otherwise remains unchanged and preserves the runner's
handling state by default. Existing installations without that workaround also
need this uninstall/reinstall cycle to gain the new managed `hold` default;
upgrading the package alone preserves their old standalone `pause` behavior.

```sh
amx host uninstall agent@agents.example.test
# Use the same --state-home if install used it. Explicitly discard local state:
amx host uninstall agent@agents.example.test --purge-state
```

Uninstall stops/disables only the recorded service and removes its managed
credentials. It refuses a modified service file rather than stopping an
unrelated job. Handling state is retained by default to prevent duplicate
handling on reinstall. `--purge-state` removes that agent's installation
state directory, not the source bundle or AX home. SH-24b also retains shared
mailbox custody under `${XDG_STATE_HOME:-~/.local/state}/amx/custody`. Runner and
amx-mcp must run as the same OS user with the same state-home setting. Do not
remove those custody files while messages are unfinished, even when `Seen` is
clear: an uncertain AX send may already have reached its target. MCP polling
keeps intake open without AX (`--mcp-grace`, default 60 s); both consumers absent
for `--presence-timeout` (default 30 s after grace expires) pauses intake. With
`--ax`, an absent target no longer invokes the optional Python handler. A
standalone explicit `--handler` still processes mail as before, excluding MCP
claims.

Manager errors, stop timeouts and failed post-stop readback retain ownership and credentials.
A missing service file is recoverable only with a private owned receipt and manager proof
that no active/foreign job remains. A Linux reload failure retains the receipt for another
uninstall attempt; changed files and foreign loaded configurations are never adopted.

## Handler retry contract

Delivery to a Python handler is at least once, not exactly once. SIGTERM normally lets
an in-flight handler finish, but SIGKILL, a crash or a manager stop deadline can interrupt
it after an external effect and before the runner's durable outcome log is committed.
Restart can then invoke the handler again and repeat that effect. Retaining the handling
database suppresses already-recorded outcomes; it cannot close this pre-commit window.

Handlers should use the existing stable `(context.agent, message.thread.message_id)` pair
as their application idempotency key and atomically associate it with their own durable
effect (or pass it to an effect provider that supports idempotency). The RFC Message-ID is
stable across retry. `context.agent` is the agent's local name; if an effect store is shared
across domains, namespace this pair by the installation's full agent address as well.
The fields
`message.thread.in_reply_to` and `message.thread.references` provide
thread correlation, not a replacement per-message key. If Message-ID is absent, do not
assume exactly-once effects: require an application-specific stable key or refuse/defer
the effect. No general external-effect ledger or exactly-once guarantee is provided.

## Automated native acceptance

The opt-in `tools/native_host_acceptance.py` installs the real runner against
a task-private loopback IMAP fixture, proves login enablement and a new PID
after SIGKILL, then proves two fixture deliveries (before/after restart).
It removes only its random-address service in a finally block. It does not
use Compose, production mail, live credentials or an existing AX broker.
Unit tests never invoke this native check or an actual service manager.

See the tool's `--help` for the explicit execution gate and receipt directory.
This native fixture tests supervision and mail intake, not MTA integration;
`make suite MTA_CT=postfix` and `make suite MTA_CT=stalwart` remain separate gates.
