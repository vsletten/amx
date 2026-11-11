# Private self-hosting and people on Stalwart

This is the private Stalwart profile on a LAN or private network, not an
internet-facing Stalwart runbook. For public agent mail use
[Postfix self-hosting](selfhost-public.md). The private profile provides people
accounts, agent hosts, shared approvals and local-only routing. No public DNS
or public SMTP listener is needed. It does not grant permission to contact
outside recipients; both people and agents are refused foreign recipients.

## Private server setup

Use a dedicated Linux Docker host with Compose 2.24.4+, Python 3.13+, OpenSSL
and uv. From a source checkout (see [installation](../README.md#install-from-source)):

```sh
uv sync --locked
cp deploy/live/stalwart.example.yaml deploy/live/live.yaml
${EDITOR:-vi} deploy/live/live.yaml
uv run amx live install
uv run amx live up
uv run amx live preflight
uv run amx live agent add outpost
```

Keep `mta: stalwart`, `profile: private` and a state directory outside the
checkout. Defaults are `home.arpa`, `agents.home.arpa`, `mail.home.arpa`, loopback
binding and self-signed TLS. For remote clients set `network.bind_address` to
the server's LAN/private IPv4, then resolve the mail hostname on each client or
your private DNS. IP literals are not mail domains. Default ports are agent
submission 587, IMAPS 993, people submission 465 and HTTPS discovery 443. No
port 25 is published in private mode, even if remapped. Do not expose this
profile to the internet. Docker publications can bypass host-firewall rules;
check your actual exposure separately.

HTTP (admin, account portal and discovery) binds independently using
`stalwart.admin_bind_address`: only loopback or a tailnet IPv4 in 100.64.0.0/10
is accepted. For a tailnet deployment set that address for remote discovery;
a LAN-only deployment may keep management on loopback and use local operator
access plus manually configured mail clients. The app-password workflow below
requires HTTPS reachability from the operator. Do not broaden the management
bind to a public/LAN address to work around a refusal. Internal management port
8080 stays unpublished. HTTPS uses the mail hostname and matching certificate.

For self-signed TLS, trust only the public `secrets/tls/ca.pem` on intended
clients. Never transfer the CA private key. Resolve `autoconfig.home.arpa`,
`autodiscover.home.arpa` and the people domain to the appropriate private HTTPS
address when using discovery. Certificates must cover these names. The host kit
accepts `--ca ./ca.pem` for scoped runner trust without disabling verification.

First `up` stages the genuine pinned Stalwart WebUI release via HTTPS, verifies
its digest and ZIP integrity, then starts services. A no-egress runtime instead
sets `stalwart.webui_bundle` before install to an out-of-band copy of exactly:
https://github.com/stalwartlabs/webui/releases/download/v1.0.11/webui.zip
with SHA-256 `d67e68caba02024301c79da9f15fe465de9bf5382cee54bdf9c309a97b4179a5`.
Keep that file for reinstalls. Corrupt/missing inputs are refused before state
changes; do not replace the pin with a moving latest URL. Stalwart-derived
init/sync images are local-only builds; never publish them.

Private preflight makes no public-DNS or outbound-MX probe. It checks actual
TLS listeners, runtime management settings/publications and the served WebUI;
stopped/unreadable services fail rather than passing on configuration alone.
The gateway verifies IMAPS with hostname/SNI and the scoped CA; plaintext IMAP
authentication is disabled. OIDC requires registered clients and denies
anonymous registration. Household SMTP starting limits are 30 requests/second/IP
and 200 messages/hour per sender/recipient pair; only the gateway's exact
internal IPv4 is trusted against auto-ban. These are not public capacity claims.

Securely transfer each agent's one-time 0600 bundle to its host, then follow
[the host kit](agent-host.md) for client/AX installation, native supervision,
CA trust and explicit session permissions. Delete transfer copies after setup.
Add a person with the commands below; a signed-in local person's sender must
match the SASL login. An owner can inspect an actual held message in the shared
hold folders and move it to Approved or Rejected. Agents cannot approve their
own mail. Private routing never selects an external MX; allowlists can narrow
eligible recipients but cannot lift local-only. Holds, taint and release-time
recipient checks remain authoritative.

The following examples assume source-checkout `uv sync --locked` and an activated
checkout environment (`. .venv/bin/activate`), or the separately installed source
client tools. Pass `--params deploy/live/live.yaml` when using the parameter
file created above; `--params live.yaml` below denotes a file at your current
directory, not a different default.

## Operator-managed TLS and renewal

Stalwart also accepts files renewed by an operator-managed certificate tool:

```yaml
tls:
  mode: files
  certificate: /operator/certs/fullchain.pem
  private_key: /operator/certs/privkey.pem
  # ca_file: /operator/certs/private-ca.pem
```

Paths resolve relative to the parameters file unless absolute; `~` works. Supply
an unexpired PEM leaf plus intermediates and matching unencrypted private key,
covering `mx_host` and the discovery names. Omit `ca_file` for system trust;
otherwise keep that private trust root stable across renewal. Install validates
the pair and stages it under `secrets/tls` with a 0600 key. Containers mount
the staged directory read-only, never the external issuer's private directory.

Use the renewal tool's successful deploy hook, as the same operator:

```sh
uv run amx live certs --params deploy/live/live.yaml
```

In files mode, this validates/copies the pair, reloads Stalwart via its private
management CLI and reloads gateway submission TLS through the 0600 control
socket. No new management publication, SIGHUP or container restart is needed.
Existing sessions remain usable; new handshakes select the new certificate.
`amx live reload-tls` reloads already-staged files without copying or renewal.
Self-signed Stalwart `certs` also hot-reloads. Errors return nonzero with no
restart fallback. A partial failure can leave Stalwart renewed before the
gateway: fix the cause and rerun `certs`, which retries both halves even when
files are unchanged. Successful copying alone is not proof of a served renewal.

## Maintenance and backup

Stalwart state lives under `state_dir/stalwart/`, with private recovery/settings
under `secrets/stalwart/`. Ordinary `down` preserves it. Canonical `up` stops the
owned bundle without deleting data, then recreates init/runtime and reapplies
settings to repair drift. Never run another init directly against live RocksDB.
Before changing settings or upgrading, suspend mutating admin, renewal,
registration and account-sync jobs. Serialize backup with all other maintenance,
stop the entire bundle (gateway, Stalwart and its sync/init services) and all
other state/mailbox writers, and verify they remain stopped. IMAP and submission
will be unavailable. Only then take a consistent snapshot of the entire state
directory including secrets and the datastore with an operator backup tool,
using a fresh unique output location on every attempt. Never reuse a successful
or failed backup path; preserve failed evidence separately and choose a new
location on retry. Verify the snapshot and copy it off-host before upgrading.
Retain matching parameters, source revision and images. Rollback requires those
matching stopped-state copies, not just an older executable; stop and verify all
writers and mutating jobs again before restoring. If aborting before an upgrade,
resume only unchanged state with its matching old binary/configuration, then
compatible writers and jobs. Reconcile writes after the checkpoint before
retrying an upgrade.

The inherited Postfix host-login `rotate`, `backup` and `down --purge` commands
deliberately refuse Stalwart; even forced purge is unsupported. Do not bypass
those refusals or use Postfix's mail-volume tarball as a Stalwart backup.
Registered agent credential rotation remains supported; replace host bundles
through the host kit. See [attachments](attachments.md) for file and judge limits.

## People accounts (SH-11)

People are ordinary accounts in `org_domain`, not agents or master logins. These
commands require an installed `mta: stalwart` live parameters file. Account changes
are queued in a private, hash-only `secrets/stalwart/people.json`; the existing
`stalwart-sync` applies them through the native management API without restart.
`list` shows desired managed state, not a claim that the server has applied it.
Install initializes an explicit empty people state. A missing configured state file
refuses sync; that refusal does not revoke accounts already present on the server.
Unmanaged principals are never adopted. Reserved/system identities and addresses
outside the people domain are refused.

## Account lifecycle

```sh
amx user add alice --owner --params live.yaml --password-out alice-account.secret \
  --app-password-out alice-mail.secret
amx user list --params live.yaml
amx user passwd alice --params live.yaml --password-out alice-new-account.secret \
  --app-password-out alice-new-mail.secret
amx user profile alice --params live.yaml --output alice.mobileconfig
amx user remove alice --params live.yaml
```

Without `--password-out`, supply a private `--password-file` or use the hidden
terminal prompt (minimum 16 characters). No password belongs in argv or a URL.
Generated secret files are exclusive 0600 outputs and never printed. The account
password is administrative; give the native app password to the mail client.
`--app-password-out` waits for account sync, then authenticates over verified HTTPS
and uses Stalwart's own `x:AppPassword/set`. It does not manufacture a secondary
credential or attempt the unsupported Account/set secondary-credential path.
The HTTPS hostname must resolve from the operator host. Self-signed installs use
the bundle's scoped `ca.pem`; other installs use system trust.

Rotation invalidates all previous app passwords. Ordinary agent registrations
preserve native app passwords. Removal disables authentication and removes owner
ACLs, but retains mail and a tombstone to prevent accidental identity reuse; it is
not mailbox destruction. A failed optional app-password creation does not undo an
already queued account change: retry via `passwd` with a new private output path.
Use `passwd --owner` or `passwd --no-owner` to promote or demote an existing
account while rotating its password; omitting both retains its current owner role.
The stable random ownership token and locally recorded generations survive rotations;
an arbitrary managed-looking server description does not establish ownership.

`--owner` grants approver-only rights on every existing and future agent hold tree,
including disabled agents: `lrswte` on Held, `lrswi` on Approved/Rejected and `l` on
the agent tree root. It confers no impersonation or ACL-administration right. Other
people get no hold access. The agent retains only `lr`, never approval rights.

## Native discovery and Apple Mail

The live Stalwart listener serves its native HTTPS autoconfig and autodiscover
on 443. People submit with implicit TLS on 465 (not the agent-only gateway's
submission listener). IMAPS remains 993. The parameters' optional
`network.ports.discovery` and `network.ports.people_submission` change published
ports for local fixtures; standard mail-client discovery advertises standard ports,
so deployments using hostname-only setup must retain 443/465/993.

On your LAN/tailnet DNS, resolve the mail hostname and `autoconfig.<org_domain>`
(and, for Outlook discovery, `autodiscover.<org_domain>`) to the server. The people
domain's well-known path is another lookup candidate if it resolves there.
Self-signed certificates include these aliases and the people domain. Other TLS
issuers must cover the same names. The native discovery endpoint also works directly
on the mail hostname. No static XML is served by amx.

The protocol client tries HTTPS `autoconfig.<domain>/mail/config-v1.1.xml`, then
HTTPS `<domain>/.well-known/autoconfig/mail/config-v1.1.xml`, then the supplied
mail hostname's native endpoint. It deliberately refuses HTTP downgrade, external
ISPDB/MX fallback, cross-origin redirects, a different advertised mailhost, or non-TLS settings.
Bounded same-origin HTTPS GET redirects support Stalwart's native JMAP session discovery.
Only the actual parsed XML's ports are used for IMAP and submission.

`profile` writes an XML property list with a Configuration payload containing
`com.apple.mail.managed`, TLS server names/ports, and the person's full address as
both usernames. It contains no password or CA private key; the device prompts for
its app password. Trust the deployment CA separately for self-signed installations.
A Mac can lint it without installing any profile:

```sh
plutil -lint alice.mobileconfig
```

No real mail application/device has been measured; the README status table remains
unmeasured. The HTTPS listener is bound to the configured private bind address;
public-profile HTTP surface hardening remains SH-33, not a reason to expose it to
the internet here.

## Acceptance in the existing sealed live validator

On a disposable engine, with ownership inventory clear, run only:

```sh
make live-validate LIVE_MTA=stalwart
make suite MTA_CT=postfix
make suite MTA_CT=stalwart
```

The first command keeps the existing native lease/refusal/cleanup entrypoint. It
adds a person through `amx user add --owner`, creates a real native app password,
fetches real native autoconfig, and uses the parsed settings for IMAPS login/read,
authenticated TLS submission to another fixture person, and owner UID MOVE of an
actual gateway hold. It verifies signed delivery, agent denial, future-agent ACLs,
app-password survival across registration, rotation/revocation, and emits an actual
`alice.mobileconfig` in the printed validation state directory for Mac linting.
The fixture maps only approved fake names/ports to its sealed edge and validates
the real hostname/SNI against the scoped CA. It never uses system DNS or disables
certificate verification. No synthetic XML or mock IMAP/SMTP peer is used by that
live path. Local unit tests alone are not proof that native acceptance passed.
