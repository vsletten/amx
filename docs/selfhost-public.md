# Public self-hosting: one agent domain on one VPS

This runbook uses the Postfix + Dovecot `deploy/live` bundle: one gateway, one
agent domain, one IPv4 host. The worked names are `example.com`,
`agents.example.com` and `mail.example.com`. They are reserved examples, not a
service: replace them with names you control, and replace `203.0.113.10` with
your VPS's static public IPv4. People keep their existing mail accounts; this
bundle does not host people's mailboxes or the parent domain's mail.

This is a functionality prototype, not a hardened or highly available mail
service. Read [the design](PLAN.md#11-the-live-lane-one-agent-domain-on-one-internet-facing-host-after-m6) and
[the roadmap](ROADMAP.md) for limitations. Public Stalwart is not this runbook;
use [the private Stalwart guide](selfhost-people.md) on a LAN or private network.

All deployment commands below are for an operator deliberately provisioning a
dedicated host. They are not instructions to activate services during a code
review. No installation authorizes external mail: record explicit recipient
consent in a private operations record outside the repository before any send.
Do not run validation suites against a live server or a shared Docker engine.

## 1. Prerequisites and exposure

- A domain whose DNS you control, including permission to publish an agent
  subdomain. Preserve existing website and mail records; do not replace a working
  parent zone with this example.
- A Linux VPS with a static public IPv4, outbound TCP 25 permitted, and a PTR
  record you can set. Many clouds block outbound 25 by default; some VPS providers
  open it only on request or after account verification. Check current provider
  policy before renting a host. This bundle has no documented smarthost fallback.
- Inbound TCP 25 (SMTP), 587 (agent submission), 993 (IMAPS), and 80 during ACME
  HTTP-01 issuance/renewal. Restrict administration separately. No gateway milter,
  LMTP, cleartext IMAP or reinjection port belongs on the internet.
- Docker Engine and its Compose plugin (2.24.4+), Git, OpenSSL with
  `openssl passwd -6`, `nc`, Python 3.13+, and [uv](https://docs.astral.sh/uv/).
  The default client install needs no libmilter headers; containers build their
  own native gateway dependencies. Linux native gateway development additionally
  needs a compiler and `libmilter-dev`.
- A non-root deployment user allowed to use Docker. Docker access is effectively
  root access; restrict that group. Keep host time synchronized.

Publish an A record for `mail.example.com`, and set the IP's PTR to that same
name at the VPS provider, not at your DNS host. Some providers require the
forward A record before accepting a PTR. Check the IP's reputation before use.
The lane is IPv4-only; do not publish an AAAA record for its mail hostname.
Docker publications may bypass host-firewall rules such as ufw; verify exposure
with the provider firewall and an authorized external probe.

## 2. Install the CLI from source and configure

Obtain a source checkout and work from its root on the VPS. There is no assumed
public repository URL, package-index release, deploy key or repository name.
Use the checkout environment for deployment: the live CLI locates Compose files
relative to the source tree. Keep the checkout at that path.

```sh
uv sync --locked
uv run amx live --help
cp deploy/live/live.example.yaml deploy/live/live.yaml
${EDITOR:-vi} deploy/live/live.yaml
```

The ignored `deploy/live/live.yaml` is the parameter file, not a place for
passwords or API keys. Set at least these fields, replacing every example value:

```yaml
mta: postfix
profile: public
agent_domain: agents.example.com
mx_host: mail.example.com
public_ip: 203.0.113.10
admin_contact: ops@example.com
state_dir: ~/amx-live/amx-live
accept_from: [owner@example.com]
outbound_allowlist: [owner@example.com]
limits:
  external_per_day: 10
dns:
  manage_apex: false
  dmarc_policy: none
```

Use a real reachable address for `admin_contact` (the ACME account contact) and
a real, consenting owner's DKIM-aligned address for both lists. Do not put real
addresses in tracked examples. Exact addresses are safer than domain-wide grants.
An empty outbound list means unrestricted recipients, not deny-all; an empty
sender list accepts anyone's human-lane mail at low trust. The settings above
intentionally restrict both. Section 7 explains the task-scoped To/Cc exception.

`dns.manage_apex: false` avoids requesting changes to parent-zone SPF/DMARC/CAA.
If you control an otherwise unused parent zone and deliberately want those
records, enable it only after reviewing section 4. Every optional parameter is
shown in [the example](../deploy/live/live.example.yaml).

All live subcommands accept `--params /absolute/path/to/live.yaml`, or read
`AMX_LIVE_PARAMS`; otherwise they use `deploy/live/live.yaml` in this checkout.
Examples use that default. Run subsequent commands from the same checkout and
as the same operator, with the same parameters.

```sh
uv run amx live install
uv run amx live dns
```

Install writes configuration, random credentials and keys into `state_dir`,
outside the checkout. It is idempotent: it preserves existing secrets and agents,
and refuses damaged credentials rather than silently replacing them. Do not
move a damaged file aside to bypass that refusal; restore a verified backup.

## 3. State and secrets

The default state directory is `~/amx-live/amx-live`:

```text
compose.env                 Compose names, ports and paths
dns-records.txt             generated DNS request
data/                       journal.sqlite, raw store and task state
secrets/                    owner-only directory
  credentials.yaml          host logins and gateway master credential
  gateway/gateway.yaml      rendered gateway configuration
  gateway/registry/         agent hashes, policy and domain DKIM state
  gateway/keys/             private signing keys
  mailhost/accounts/        hashed agent logins and adoption markers
  agents/                   one-time plaintext credentials bundles
  logins.txt                approver and postmaster mail-client logins
  tls/                      mounted certificate and private key
  acme/                     ACME account and lineage
backups/                    local backup output (copy off-host)
```

Secret directories are 0700 and secret files 0600; public certificates may be
0644. Registration stores hashes and writes each agent's plaintext credentials
once into a private bundle. Transfer that bundle securely to its host, retain
0600 permissions, and delete the server's transfer copy after successful setup.
Backups with secrets are equally sensitive. Never commit or upload state or mail.

Optional judge/model API keys come from the environment of `up`, never YAML.
Without `TYPESAFE_API_KEY`, the content judge is a deterministic stub, even with
`content_judge.mode: enforce`; this is not live content protection. A securely
supplied key selects Jev; `AMX_LLM_API_KEY` is for configured LLM handlers.
Docker administrators can inspect container environments. Do not print resolved
Compose configuration while keys are present. A later `up` without the keys can
replace a keyed container with the stub. Plan secret injection privately rather
than placing keys in shell history, command arguments or logs.

## 4. Publish DNS

The `dns` command renders Type, Name relative to zone, and Data from the actual
keys. Copy its values, not the placeholders below. New installs use one domain
DKIM key (`amx.<yyyy-mm>`); adding an agent requires no DNS change. Rotation
briefly publishes more than one selector.

For the zone `example.com`, the configured example with `manage_apex: false`
requires these records (TTL 600 is a reasonable starting point):

| Type | Name relative to zone | Data |
|---|---|---|
| A | mail | `203.0.113.10` |
| MX | agents | priority `10`, target `mail.example.com.` |
| TXT | agents | `v=spf1 ip4:203.0.113.10 -all` |
| TXT | mail | `v=spf1 ip4:203.0.113.10 -all` |
| TXT | amx.<yyyy-mm>._domainkey.agents | actual `v=DKIM1; k=rsa; p=...` from the CLI |
| TXT | _dmarc.agents | `v=DMARC1; p=none; rua=mailto:postmaster@agents.example.com; adkim=s; aspf=r` |
| TXT | _smtp._tls.agents | `v=TLSRPTv1; rua=mailto:postmaster@agents.example.com` |
| CAA | mail | flag `0`, tag `issue`, value `letsencrypt.org` |

Equivalent BIND record syntax, relative to the parent zone (replace the selector
and public key; this is illustrative, not a complete authoritative zone):

```dns
$ORIGIN example.com.
$TTL 600
mail IN A 203.0.113.10
agents IN MX 10 mail.example.com.
agents IN TXT "v=spf1 ip4:203.0.113.10 -all"
mail IN TXT "v=spf1 ip4:203.0.113.10 -all"
amx.<yyyy-mm>._domainkey.agents IN TXT "v=DKIM1; k=rsa; p=<public-key>"
_dmarc.agents IN TXT "v=DMARC1; p=none; rua=mailto:postmaster@agents.example.com; adkim=s; aspf=r"
_smtp._tls.agents IN TXT "v=TLSRPTv1; rua=mailto:postmaster@agents.example.com"
mail IN CAA 0 issue "letsencrypt.org"
```

PTR is a separate reverse-zone record configured at the VPS provider:
`203.0.113.10 -> mail.example.com`. It is not added to the forward zone above.
Names in many DNS forms are relative: entering a full name may accidentally
append the zone twice. MX targets, by contrast, must identify the full mail host.
Do not use a proxied/CDN A record for SMTP.

With `manage_apex: true`, the renderer instead puts CAA at `@`, adds an apex
`v=spf1 -all` when the apex is neither agent domain nor MX host, and adds apex
DMARC. Do not apply that no-mail SPF to a parent domain already sending mail.
Preserve its existing mail service and unrelated records. Ensure one SPF record
per name, one DMARC record per name, the intended MX, and no conflicting CNAME;
never blindly delete the provider's defaults or existing zone contents.

`p=none` is the default measurement policy, not spoof protection. Review reports
and authentication before intentionally moving the agent record to quarantine
or reject. Strict DKIM alignment covers agent mail; relaxed SPF alignment also
allows null-envelope DSNs using the related HELO name. The parent DMARC policy
can govern subdomains lacking their own record. Keep `rua` inside the configured
zone; external report destinations require that destination's DNS authorization.
Read reports with the postmaster login in `secrets/logins.txt`. Role forwarding
to `admin_contact` is optional and off by default: without SRS it can fail SPF
and produce backscatter, so prefer reading the mailbox directly.

### Long DKIM TXT values and delegation

Many DNS forms split or truncate long TXT values. A TXT record can contain
several quoted strings of at most 255 characters, concatenated into one value;
do not create multiple independent TXT records for the chunks. The renderer
prints both the whole value and a quoted-string form. Prefer retaining the
2048-bit key and correcting the DNS editor rather than reducing key strength.
Preflight compares the served key with the private key and catches truncation.

If someone else controls the parent zone, arrange individual records or an NS
delegation. For a delegated `agents.example.com` zone, set `dns_zone` to
`agents.example.com`, keep `manage_apex: false`, and preferably place `mx_host`
inside it (for example `mail.agents.example.com`). Then render a zone using your
actual authoritative nameservers:

```sh
uv run amx live dns --zone-file agents.zone --ns ns1.example.com --ns ns2.example.com
```

The zone-file option emits only records under the agent domain, plus SOA/NS.
It does not configure your DNS service or parent delegation. If the MX hostname
remains outside that domain, publish its A/SPF/CAA records in its own zone too.
Do not publish `_agents` discovery pointing to a page you do not serve.
MTA-STS is not bundled; it would also need a separate HTTPS policy service.

## 5. ACME, startup and preflight

After the mail-host A record resolves to your VPS, CAA allows the issuer and
port 80 is reachable, issue the certificate:

```sh
uv run amx live certs
uv run amx live up
uv run amx live status
uv run amx live preflight
uv run amx live preflight --probe probe-user@probe.example.com
```

The last command is optional: replace its SSH target with an authorized outside
host that has `nc`. A local probe cannot prove internet reachability. Preflight
checks DNS, PTR, the outbound IPv4 TCP-25 connection, certificate names/expiry,
and actual STARTTLS on 25/587 and TLS on 993. It sends no mail, but its network
connections appear in server logs. It prints PASS/WARN/FAIL/SKIP/INFO and exits
nonzero on FAIL; investigate warnings and skips rather than calling them a pass.
TLS listener checks require a running lane, so full preflight follows `up`, not
before it. Do not send until required checks pass.

ACME uses pinned certbot in a transient container. HTTP-01 publishes port 80
only while it runs. To test issuance, set `tls.acme_server: staging`, run `certs`,
then restore `letsencrypt` and run `certs` again before startup: staging
certificates are not publicly trusted. `tls.challenge: dns-01-manual` prompts
for a TXT record on every renewal and cannot renew unattended.

Schedule `certs` daily with your scheduler, using the absolute checkout path,
operator identity and uv executable; verify its exit status and retain private
logs. Certbot renews when due. On Postfix, changed certificates recreate the
mailhost and restart the gateway; failed restarts remain owed to later `certs`
runs. Monitor expiry and served certificates, not just scheduler success.

## 6. Add the first agent and receive mail

```sh
uv run amx live agent add outpost
uv run amx live agent list
uv run amx live preflight
```

The default mode is remote. Registration reloads agent state and mailhost logins
without restarting the lane, writes a one-time bundle under `secrets/agents`,
and prints its path. On a new domain-signed lane there is nothing else to publish.
Pending domain/data/registry changes must be restarted before registration;
obey the CLI's refusal rather than bypassing it.

On the agent's Linux or Mac host, install the client from source as explained in
[the README](../README.md#install-from-source), privately transfer the printed
bundle as `outpost.json`, and run a foreground example handler:

```sh
umask 077
AMX_HANDLER_LOG="$PWD/outpost-deliveries.jsonl" amx-runner --credentials ./outpost.json --handler amx.examples.intake:handle
```

The host needs only outbound IMAPS 993 and STARTTLS submission 587 to the server.
For a supervised Python handler or an AX-backed session, follow
[the agent-host kit](agent-host.md), including its pinned AX release installation
and owner permissions. Host-installed AX runners default to store-and-forward
while a session is absent; the standalone AX runner needs explicit
`--offline hold` for that behavior. Neither mode bypasses owner hold/refuse.

From the consenting address configured in `accept_from`, send an ordinary email
to `outpost@agents.example.com`, substituting your real domain. Its sender must
have passing DKIM aligned exactly with From and a DMARC record. A corporate
provider signing under another domain may not qualify. The log override above
avoids the example handler's container-only `/data` default. Verify delivery in
the private `outpost-deliveries.jsonl` file and the agent's mailbox using its
private bundle; protect that log as mail and do not print credentials into shared
logs. This is the first receive, not proof of external
reply delivery. Any reply remains subject to section 7 and requires consent.

An alternative in-process agent is:

```sh
uv run amx live agent add intake --mode queued --handler amx.examples.intake:handle
```

Custom handlers must be installed in the runtime that imports them; registration
does not install arbitrary packages. For agent-to-agent mail across domains,
configure explicit trust grants as described in [the design](PLAN.md), not an
owner sender-list entry.

## 7. Sender authority, outbound consent, limits and holds

- `accept_from` matches verified human addresses or domains, not unverified From
  text. Listed senders arrive as owners (`Agent-Trust: high`). A domain entry
  authorizes every verified sender there; prefer exact addresses.
- `outbound_allowlist` narrows external recipients, with refusal `550 5.7.1`
  before a hold. Record recipient authorization privately and set the list before
  any send. Empty means unrestricted, not blocked. Approval is not a substitute
  for permission to contact a recipient.
- A verified owner's signed From/To/Cc can authorize named people within that
  task without a list entry or first-contact hold. Text mentions do not count;
  closing the task ends that authority, and other agents are not copied. Review
  To/Cc before sending owner mail: the lane list is not an absolute ceiling on
  those task-scoped recipients. Local-only, household, taint and daily limits
  still apply.
- `limits.external_per_day` defaults to 10 per agent; external recipients count,
  including people on the parent domain. The gateway's own domain is local.
  Rate limits do not grant permission and cannot be bypassed by approving a hold.
- First contact with a new domain, risky schemas and tainted tasks can hold mail.
  Rules, current recipient policy and daily ceilings are checked at release too.
  An allowed address is not guaranteed an immediate send.

For Postfix approval, add a desktop IMAP account with server `mail.example.com`,
port 993, TLS, username `outpost@agents.example.com*approver`, and the approver
password read privately from `secrets/logins.txt`. Subscribe to the Outbox
folders. Inspect the complete message, attachments and recipients; move it from
`Outbox/Held` to `Outbox/Approved` to release, or `Outbox/Rejected` to cancel its
task. The approver can read every agent mailbox; this is privileged operator
access, not an ordinary people's account. The agent's own login cannot approve.
An arbitrary APPEND into Approved does not send: release requires the
byte-identical journaled held message. Reply-based approval is not implemented.
No webmail or management UI is required or published by this Postfix bundle.

After editing lane-wide policy, run `install`, then rebuild/apply pending
configuration with `up` and any explicit service restart the installer reports:

```sh
uv run amx live install
uv run amx live up
uv run amx live compose restart gateway
```

### Another person's agents on the same lane (SH-47)

Use a household label and an explicit non-empty per-agent sender list:

```sh
uv run amx live agent add helper --household household-b --accept-from member@example.com
uv run amx live agent set helper --accept-from member@example.com --outbound-allowlist member@example.com
uv run amx live agent set helper --inherit-outbound-allowlist
uv run amx live agent list
```

The repeated list options replace their old list; omitted fields remain unchanged.
These operations do not reissue credentials. A labeled agent never inherits the
lane-wide sender/outbound lists: its own outbound list wins, otherwise its own
`accept_from` supplies recipients. `--inherit-outbound-allowlist` removes the
override. An explicit empty outbound list is unrestricted; use only intentionally.
Own-domain agents may mail only within their household, even when another
household's agent is named in owner To/Cc. This is an agent-authority boundary,
not tenant privacy: the operator reads and approves mail for every household.
Unlabeled agents belong to the default household.

## 8. Rotation and removal

```sh
uv run amx live agent rotate outpost --no-dkim
uv run amx live dkim status
uv run amx live dkim stage
uv run amx live dns
uv run amx live preflight
uv run amx live dkim activate
uv run amx live dkim retire
uv run amx live rotate --what approver
uv run amx live agent remove outpost
uv run amx live agent enable outpost
```

These are separate maintenance operations, not one script to run blindly.
Credential rotation writes a new private bundle; hand it over and replace the
host installation as documented in [the host kit](agent-host.md). Old submission
tokens/logins cease working and open IMAP sessions end. On a domain-signed lane,
agent rotation is credentials-only; domain DKIM rotation is separate.

For DKIM, stage, publish the new record alongside the old one, preflight until
it is served, then activate. Activation checks DNS and retains the previous
selector for the overlap (default seven days). Only after overlap should you
retire and delete the records the CLI identifies. Do not overwrite a selector's
record with a different key while signed mail can remain queued or cached.

Host login rotation (`approver`, `postmaster`, `gateway-master`) restarts the
services that use it. Update affected clients privately. Removal disables RCPT,
submission and IMAP, including approver access, while retaining mail and state;
`enable` restores it. Purge is destructive and requires a disabled agent and a
grace period: inspect `agent remove --help`, back up first and do not bypass
its refusal or skip its grace merely for convenience.

## 9. Backup, upgrades and rollback

For a consistent rollback or whole-host backup, first suspend mutating admin,
certificate-renewal and registration jobs, and serialize the backup with all
other maintenance operations. Stop BOTH gateway and mailhost, plus every other
process that can write state or Maildir (including delivery and IMAP writers).
Verify that they have stopped and cannot be automatically restarted before
continuing. Stopping only the gateway is insufficient: Dovecot/IMAP and delivery
can still modify Maildir. The backup command does not coordinate or stop writers.
SMTP and IMAP will be unavailable; outside MTAs normally queue and retry while
the mailhost is stopped. This stopped mailhost does not accept new mail.

```sh
uv run amx live compose stop gateway mailhost
uv run amx live compose ps --all gateway mailhost
# Verify both are stopped, and all other writers/jobs above are quiescent.
BACKUP_DIR=$(mktemp -d "$HOME/amx-backup.XXXXXXXX") || exit 1
uv run amx live backup --out "$BACKUP_DIR" --with-secrets
```

In `compose ps --all`, require both containers to be exited/stopped, not running
or restarting. Check other writer processes and suspended jobs separately;
Compose's service listing alone cannot prove they are quiescent.

Use an independently created unique empty output directory for EVERY attempt.
`--out` can create a directory and also accepts an existing empty one, as created
by `mktemp -d` above. Do not rely on the default second-resolution timestamp:
the CLI reuses existing directories rather than refusing them. Never reuse an
output path after success OR failure. Preserve failed output separately for
diagnosis and create a new directory on retry; do not retry into or merge it with
a previous backup.

Backups contain a verified SQLite journal snapshot, raw store/other data,
`mail.tar.gz`, `journal-verify.txt`, and a SHA-256 `manifest.json`. With
`--with-secrets` they also include keys, registry and credentials: guard the
entire directory as a secret. Mail export uses a separate transient tar container
with the mail volume mounted read-only; it does not need a running mailhost.
Keep all writers stopped through verification and any separate queue backup.
Verify the manifest's hashes and journal result, retain the parameters and exact
source revision separately, and copy an untouched backup off-host. Rehearse restore on
an isolated host, never over the running lane. For ordinary backup maintenance,
resume only the unchanged state with its matching binary/configuration after
the verified off-host checkpoint; then resume compatible writers and jobs.

The built-in Postfix backup exports the mail volume but not Postfix's queue
volume. Preserve that queue separately with an operator backup tool or ensure it
is drained under authorized recipient policy before a whole-host move. Do not
assume the mail tarball includes queued mail.

### Schema-identifier cutover for 0.3.0

The 0.3.0 schema identifiers are a breaking change from the pre-0.3 namespace.
The new registry deliberately has no legacy aliases. Do not update a running
deployment with old-identifier messages still waiting for validation or processing.

1. Arrange a coordinated maintenance window with every participating producer and
   consumer. Quiesce new task creation and new inbound submissions at the deployment
   boundary while leaving the OLD gateway, mailhost and consumers running to finish
   already-accepted work. Uncontrolled senders may retry old identifiers after the
   outage; if they cannot migrate, do not cut over this deployment yet.
2. Using the OLD binaries, drain accepted work under its existing recipient/approval
   policy. For Postfix, inspect `uv run amx live compose exec mailhost mailq` and
   require an empty queue. Also inspect each agent's pending mailbox/custody work,
   held outbound messages, delayed/retry work and unfinished tasks; an empty MTA
   queue alone is not proof. Stalwart operators must inspect their equivalent
   delivery queue as well. Do not force-release held mail merely to drain it.
3. If work cannot drain safely, postpone the cutover and keep the matched old
   source/state available. Never rewrite signed messages, stored raw bytes or
   journal evidence to change a schema identifier. Historical old-identifier mail
   is retained as evidence; any replay needs the matched old registry in isolation.
4. Once all participants are quiescent and accepted work is drained, follow the
   stopped-writer backup/upgrade procedure below. Upgrade all producers/consumers
   together, then verify a new-identifier request and reply with authorized agents
   before resuming normal intake. If that fails, use the matched-state rollback
   below rather than mixing old and new registries.

These are operator cutover prerequisites, not an automatic migration performed by
install or startup. Source preparation does not drain or upgrade a live deployment.

### Stopped-writer upgrade and task-key migration

Never roll mixed old/new writers across a database schema change. In particular,
SH-02 changes the task key from token-only to `(agent, token)`; old
`ON CONFLICT(token)` writers are incompatible. Even constructing `Store` may
migrate it. The supported topology has one gateway container containing
submission, LMTP, handlers and hold watchers; stop every additional CLI, portal
or other writer sharing its data directory as well, along with the mailhost and
all Maildir writers as described above.

1. Record the old revision, image identifiers and private parameters. Using the
   OLD checkout/environment, suspend mutating admin/renewal/registration jobs,
   stop BOTH gateway and mailhost and all other state/Maildir writers, and verify
   their stopped state. Keep them stopped; SMTP is unavailable and outside MTAs
   normally queue and retry, not deliver to this stopped mailhost.
2. Still with the OLD binary, create a unique empty output directory and take a
   fresh `--out` / `--with-secrets` backup as below, verify its manifest and
   journal, and preserve an untouched off-host copy. Never reuse its output path,
   even after failure; preserve failed evidence separately and retry with a new
   directory. The backup command constructs `Store` on its snapshot, so the new
   binary must not create
   the pre-migration rollback backup. Preserve the Postfix queue too.
3. Only after verifying that off-host checkpoint, update to an explicitly chosen
   source revision, sync its locked dependencies, run install and start its one new
   gateway. It migrates transactionally before serving. Apply installer-reported
   restarts. Never start an old writer against migrated state.
4. Check container health/logs, served certificates, preflight, journal integrity
   and each participant's task state before resuming compatible additional
   writers and jobs. Recheck consent before any mail-delivery verification.

If aborting before the source update, leave writers stopped while diagnosing a
failed backup; resume only the unchanged old state with its matching OLD
binary/configuration, then compatible writers and jobs. Do not start new source
without the verified off-host checkpoint. If new source has already touched the
state, use the matched-state rollback procedure below instead of just restarting
the old binary.

Commands for steps 1–3, separated by the deliberate source-update boundary:

```sh
# OLD source and environment: stop writers and secure the rollback backup first.
uv run amx live compose stop gateway mailhost
uv run amx live compose ps --all gateway mailhost
# Verify both are stopped; all other writers and mutating jobs must remain stopped.
BACKUP_DIR=$(mktemp -d "$HOME/amx-backup.XXXXXXXX") || exit 1
uv run amx live backup --out "$BACKUP_DIR" --with-secrets
# Stop here: verify and copy the backup; select the intended source revision.
# NEW source, only after the verified off-host checkpoint:
uv sync --locked
uv run amx live install
uv run amx live up
uv run amx live compose restart mailhost gateway
uv run amx live preflight
```

Rollback is not just downgrading code. Suspend mutating jobs, stop BOTH the NEW
gateway and mailhost and all other state/Maildir writers, and verify they remain
stopped. Preserve failed new state privately for diagnosis, and restore the
ORIGINAL backup's complete data directory (journal and raw store included),
without newer SQLite WAL/SHM files. Restore matching secrets/registry/accounts
and mail state from that same checkpoint as needed, preserving permissions and
mailbox generation markers. Do not merge composite participant rows into a
legacy token-only table. Restore the old source/environment/images only with
the old state. New writes after the checkpoint are absent from the restored
state; reconcile them explicitly before retrying, including queued delivery.

For full restoration onto an isolated replacement host, recreate the same
parameters and Compose volume names with the matching source, stop containers,
verify all state/Maildir writers and mutating jobs are stopped, restore secrets
and data, and unpack `mail.tar.gz` into the project's mail
volume (default `amx-live_mail`) using an operator restore tool. Restore any
separately preserved queue volume before startup. Start only the matching
binary, then verify state, journal, mailbox access and preflight. There is no
one-command restore; never run install over restored state without understanding
its migration effects.

For pre-registration installs, `install` migrates configured `agents:` into the
registry while preserving keys, credentials and mailboxes. Follow the same
stopped-writer backup procedure first. Obey migration refusals; after successful
migration and restart, remove the obsolete `agents:` parameters and securely
retire old plaintext transfer files. For legacy per-agent DKIM, install stages a
domain key; publish it, preflight, activate, retain old selectors through overlap,
then retire. Do not discard still-needed legacy keys during an upgrade.

## 10. Shutdown and retirement

```sh
uv run amx live compose exec mailhost mailq
uv run amx live down
```

Ordinary `down` preserves state, mail and Postfix queue volumes. `up` resumes
queued deliveries, so check recipient consent before restarting. Short outages
need no DNS change: other MTAs normally queue and retry a failed connection.

Permanent retirement needs a verified off-host backup and explicit destruction
authorization. `down --purge` deletes mail and queue volumes and refuses if the
queue is nonempty or unreadable; do not force around that protection. It does
not erase the external state directory or backup copies. Handle those through
your retention/secure-erasure procedure, not a speculative shell command.

When permanently retiring, remove the agent MX, clear PTR at the provider,
remove the mail-host A before releasing its IP, and remove every current/legacy
DKIM selector after the intended drain/retention interval. Set retired sender
SPF to `v=spf1 -all` and DMARC to reject where you own that policy; preserve
unrelated parent-domain mail. Remove unused TLS-RPT/report destinations and
retain only intentional CAA. Record remaining resources privately outside the
repository.

## 11. Validate locally

Use only a disposable development engine with no live or unrelated mail stack:

```sh
make live-validate
```

This fixture uses fake DNS, a sealed SMTP sink and local ports; it does not
establish public deliverability or exercise real ACME issuance. It refuses
existing lane resources, seeds/purges its owned test volumes, and uses the same
host-wide lease as the developer suites. Never bypass an ownership refusal or
run a raw validator/up/down against a shared engine. See
[the validation guide](dev-suite.md) for lease, cleanup and the separate Stalwart
and integrated private-profile checks.

## Attachments (SH-42)

Agents support typed MIME attachments through the SDK, MCP and AX. See
[the attachment guide](attachments.md) for file custody, limits and security
boundaries. Attachments remain untrusted: the content judge reads message text
and machine payload, not attachment contents. Review the complete held message
before approving it. No malware scanner or archive/document extraction is
included.
