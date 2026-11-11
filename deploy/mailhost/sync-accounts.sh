#!/bin/sh
# Merge registered agents' mail accounts into Dovecot without a restart (PLAN §5.2).
#
#   amx-sync-accounts once    rebuild /etc/dovecot/users and /etc/dovecot/dovecot-acl now
#   amx-sync-accounts watch   do that at start, whenever the accounts file changes (checked every
#                             second), and once a minute regardless, retrying a pass that failed
#
# Passes take a lock, so a `once` run by hand while watch is mid-pass waits for it: two passes
# share the files they build, and at once they would lose each other's lines. Each pass that
# completes touches /run/amx-sync-accounts.ok, which a healthcheck can require to be recent.
#
# `amx agent add --live` and its siblings write the accounts file ($AMX_ACCOUNTS_FILE, default
# /opt/amx/accounts/agents.passwd), one line per registered agent:
# address:{SHA512-CRYPT}hash:enabled|disabled|purge:generation (amx.accounts). The entrypoint
# builds its own users once, into the base files; each pass writes the base plus the registered
# agents to /etc/dovecot/users, which Dovecot's passwd-file re-reads once its mtime changes (at
# most once a second per auth process). The same script serves both mailhosts:
#
#   AMX_SYNC_BASE_USERS     the entrypoint's users (default /etc/dovecot/users.dev)
#   AMX_SYNC_BASE_ACL       the entrypoint's ACL (default /etc/dovecot/dovecot-acl.dev)
#   AMX_SYNC_BASE_VMAILBOX  unset on the dev stack, whose Postfix lets the milter judge agent
#                           recipients. The live mailhost sets it: its Postfix refuses unlisted
#                           recipients itself (PLAN §11.2), so each pass also writes
#                           /etc/postfix/vmailbox, this base plus every enabled agent.
#   AMX_SYNC_ADOPT          unset on the dev stack. The live mailhost names the file where
#                           `amx live install` lists the agents it migrated from the parameters
#                           file (address:generation): their homes predate registration and carry
#                           no generation, so they are adopted, not deleted (PLAN §11.5).
#
# For each registered agent:
# - enabled: a login, and the INBOX ACL line every agent gets (no insert into its own INBOX);
# - disabled: the same, with nologin=y, which refuses the agent's own login and master logins;
# - purge: no login, and its home (maildir included) is deleted.
# A new agent's hold-queue folders are created (with the ACL plugin off, as the entrypoint does
# for the dev users) while its login still says nologin, so it can never create one itself.
# The home records the generation it was made for, and whether it is provisioned; both live on
# the mail volume, so a recreated container does not provision again. A home made for another
# generation is an earlier agent's under the same name: it is deleted first.
# A changed password, a disable, or a purge also ends the agent's open IMAP sessions (doveadm
# kick): Dovecot checks a password only at login, so a runner logged in with the old one would
# otherwise keep its IDLE session.
# Only addresses in $AGENT_DOMAIN, with a hash in the crypt alphabet, are accepted: a
# registration never touches a person's login or another home.
set -eu

: "${AGENT_DOMAIN:?AGENT_DOMAIN is required}"
accounts=${AMX_ACCOUNTS_FILE:-/opt/amx/accounts/agents.passwd}
base_users=${AMX_SYNC_BASE_USERS:-/etc/dovecot/users.dev}
base_acl=${AMX_SYNC_BASE_ACL:-/etc/dovecot/dovecot-acl.dev}
base_vmailbox=${AMX_SYNC_BASE_VMAILBOX:-}
adopt=${AMX_SYNC_ADOPT:-}
state=/var/lib/amx-accounts
# Root only: the accepted lines it keeps hold every agent's hash, which /etc/dovecot/users hides
# from the mail processes too (root:dovecot 0640).
mkdir -p "$state"
chmod 0700 "$state"

log() { echo "amx-sync-accounts: $*" >&2; }

# One pass: print the addresses that are not provisioned yet on stdout.
build() {
    cp "$base_users" /etc/dovecot/users.new
    cp "$base_acl" /etc/dovecot/dovecot-acl.new
    if [ -n "$base_vmailbox" ]; then
        cp "$base_vmailbox" /etc/postfix/vmailbox.new
    fi
    : >"$state/accepted.new"
    [ -f "$accounts" ] || { install_files; kick_changed; return 0; }
    while IFS= read -r line; do
        case "$line" in ""|'#'*) continue ;; esac
        # address:hash:state:generation, and nothing else: exactly three colons.
        case "$line" in *:*:*:*:*|*[[:space:]]*) log "skipping a malformed line"; continue ;; esac
        address=${line%%:*}
        rest=${line#*:}
        generation=${rest##*:}
        rest=${rest%:*}
        line_state=${rest##*:}
        hash=${rest%:*}
        local_part=${address%@*}
        domain=${address#*@}
        if [ "$domain" != "$AGENT_DOMAIN" ] || [ "$local_part" = "$address" ]; then
            log "skipping $address: not an address in $AGENT_DOMAIN"
            continue
        fi
        case "$local_part" in ''|-*|*[!a-z0-9-]*) log "skipping $address: bad name"; continue ;; esac
        case "$generation" in
            ????????????????) ;;
            *) log "skipping $address: bad generation"; continue ;;
        esac
        case "$generation" in *[!0-9a-f]*) log "skipping $address: bad generation"; continue ;; esac
        if cut -d: -f1 "$base_users" | grep -qxF "$address"; then
            log "skipping $address: the entrypoint's own user of that name exists"
            continue
        fi
        home="/var/mail/vhosts/$domain/$local_part"
        case "$line_state" in
            purge)
                if [ -e "$home" ]; then
                    rm -rf -- "$home"
                    log "purged $address"
                fi
                continue
                ;;
            enabled|disabled) ;;
            *) log "skipping $address: unknown state $line_state"; continue ;;
        esac
        case "$hash" in
            '{SHA512-CRYPT}$6$'*) ;;
            *) log "skipping $address: not a {SHA512-CRYPT} hash"; continue ;;
        esac
        case "$hash" in
            *[!A-Za-z0-9./\$\{\}-]*) log "skipping $address: bad characters in its hash"; continue ;;
        esac
        if [ -d "$home" ] && [ ! -e "$home/.amx-generation" ] && adopted "$address:$generation"
        then
            # A mailbox made before registration, for this very registration (the migration).
            printf '%s\n' "$generation" >"$home/.amx-generation"
            log "adopted $address's existing mailbox"
        fi
        if [ -e "$home" ] && [ "$(cat "$home/.amx-generation" 2>/dev/null)" != "$generation" ]; then
            rm -rf -- "$home"
            log "deleted an earlier agent's mailbox at $address"
        fi
        if [ ! -e "$home" ]; then
            install -d -o vmail -g vmail "$home"
            printf '%s\n' "$generation" >"$home/.amx-generation"
        fi
        extra=""
        if [ "$line_state" = disabled ]; then
            extra=" nologin=y reason=agent-disabled"
        elif [ "$(cat "$home/.amx-ready" 2>/dev/null)" != "$generation" ]; then
            extra=" nologin=y reason=provisioning"
            echo "$address"
        fi
        printf '%s:%s:5000:5000::%s::userdb_mail=maildir:~/Maildir%s\n' \
            "$address" "$hash" "$home" "$extra" >>/etc/dovecot/users.new
        printf 'INBOX -user=%s ip\n' "$address" >>/etc/dovecot/dovecot-acl.new
        if [ -n "$base_vmailbox" ] && [ "$line_state" = enabled ]; then
            # Postfix accepts RCPT for an enabled agent (the gateway still judges it); a disabled
            # one is refused 550 5.1.1 even while the milter is down.
            printf '%s OK\n' "$address" >>/etc/postfix/vmailbox.new
        fi
        printf '%s\n' "$line" >>"$state/accepted.new"
    done <"$accounts"
    install_files
    kick_changed
}

install_files() {
    chown root:dovecot /etc/dovecot/users.new
    chmod 0640 /etc/dovecot/users.new
    chmod 0644 /etc/dovecot/dovecot-acl.new
    # The ACL first: a login the new users file allows must already be confined. A file that did
    # not change is left alone, so a pass with nothing to do changes nothing.
    replace_if_changed /etc/dovecot/dovecot-acl.new /etc/dovecot/dovecot-acl
    replace_if_changed /etc/dovecot/users.new /etc/dovecot/users
    [ -n "$base_vmailbox" ] || return 0
    # Unchanged only if the new list matches the live list, the copy kept once a table was
    # installed in full (a pass that died between the two renames below leaves it stale), and a
    # table no older than its list. Anything else is built again: the entrypoint, for one,
    # resets the table to the base at every start, while this state survives a restart.
    if cmp -s /etc/postfix/vmailbox.new /etc/postfix/vmailbox \
        && cmp -s /etc/postfix/vmailbox.new "$state/vmailbox.installed" \
        && ! [ /etc/postfix/vmailbox -nt /etc/postfix/vmailbox.db ]; then
        rm -f /etc/postfix/vmailbox.new
        return 0
    fi
    # A new table under a temporary name, then renamed over the old one: smtpd never reads a
    # half-written table, and each Postfix process that sees the change finishes its session
    # and exits, so the next one reads the new list (no reload).
    # The list goes in before the table, and the copy last: a pass that dies between them leaves
    # a table older than its list, or a stale copy, and either makes the next pass rebuild.
    chmod 0644 /etc/postfix/vmailbox.new
    postmap /etc/postfix/vmailbox.new
    chmod 0644 /etc/postfix/vmailbox.new.db
    mv /etc/postfix/vmailbox.new /etc/postfix/vmailbox
    mv /etc/postfix/vmailbox.new.db /etc/postfix/vmailbox.db
    cp /etc/postfix/vmailbox "$state/vmailbox.installed"
}

replace_if_changed() {
    if cmp -s "$1" "$2"; then
        rm -f "$1"
    else
        mv "$1" "$2"
    fi
}

# Whether the migration listed this exact registration (address:generation) for adoption.
adopted() {
    [ -n "$adopt" ] && [ -f "$adopt" ] && grep -qxF "$1" "$adopt"
}

# End the IMAP sessions of every agent whose accepted line changed or went (new hash, disabled,
# purged): its password was checked only when it logged in. Twice, two seconds apart: Dovecot
# re-reads the users file at most once a second per auth process, so a client that reconnected
# at once may have logged in against the old file; after the second kick, every login has read
# the new one.
kick_changed() {
    kicked=""
    if [ -f "$state/accepted" ]; then
        while IFS= read -r previous; do
            grep -qxF "$previous" "$state/accepted.new" && continue
            address=${previous%%:*}
            timeout 30 doveadm kick "$address" >/dev/null 2>&1 || true
            kicked="$kicked $address"
            log "ended $address's IMAP sessions"
        done <"$state/accepted"
    fi
    mv "$state/accepted.new" "$state/accepted"
    [ -n "$kicked" ] || return 0
    sleep 2
    for address in $kicked; do
        timeout 30 doveadm kick "$address" >/dev/null 2>&1 || true
    done
}

# Create each new agent's hold-queue folders; fail if any is missing (its login stays off).
provision() {
    failed=0
    for address in "$@"; do
        # The passwd-file is re-read at most once a second: wait until the user is visible.
        attempts=0
        until timeout 30 doveadm user "$address" >/dev/null 2>&1 || [ "$attempts" -ge 30 ]; do
            attempts=$((attempts + 1))
            sleep 0.1
        done
        for folder in Outbox Outbox/Held Outbox/Approved Outbox/Rejected; do
            timeout 30 doveadm -o mail_plugins= mailbox create -u "$address" "$folder" \
                2>/dev/null || true
        done
        existing=$(timeout 30 doveadm mailbox list -u "$address" 'Outbox*' | sort | tr '\n' ' ')
        if [ "$existing" != "Outbox Outbox/Approved Outbox/Held Outbox/Rejected " ]; then
            log "hold-queue folders missing for $address: $existing; its login stays off"
            failed=1
            continue
        fi
        local_part=${address%@*}
        home="/var/mail/vhosts/${address#*@}/$local_part"
        cp "$home/.amx-generation" "$home/.amx-ready"
        log "provisioned $address"
    done
    return "$failed"
}

# One pass. It runs with set -e in force (the `once` command, or watch's child process), so a
# step that fails anywhere fails the pass, and watch tries it again a second later.
sync_once() {
    new=$(build) || return 1
    if [ -z "$new" ]; then
        touch /run/amx-sync-accounts.ok
        return 0
    fi
    sync_status=0
    # shellcheck disable=SC2086 # addresses have no spaces (checked above)
    provision $new || sync_status=1
    # Enable the provisioned logins. In a command substitution, as above: dash applies set -e
    # there, where a plain call on the left of || would ignore a failing step.
    pending=$(build) || return 1
    [ -z "$pending" ] || log "still provisioning: $pending"
    # The pass itself completed: every file is consistent. An agent whose folders could not be
    # made stays off, is logged, and is retried every second, but it does not make the mailhost
    # unhealthy (which would hold every other agent's gateway back).
    touch /run/amx-sync-accounts.ok
    return "$sync_status"
}

checksum() {
    if [ -f "$accounts" ]; then sha256sum "$accounts" | cut -d' ' -f1; else echo none; fi
}

case "${1:-once}" in
    once)
        # One pass at a time (watch's, or one run by hand): they build the same files. A pass
        # that cannot get the lock in two minutes fails, and watch tries again.
        exec 9>"$state/lock"
        flock -w 120 9
        sync_once
        ;;
    watch)
        applied=""
        last=0
        while :; do
            current=$(checksum)
            now=$(date +%s)
            # Also once a minute with no change: a pass that went wrong in a way this loop could
            # not see (a file changed under it, say) is put right without waiting for the next
            # registration.
            if [ "$current" != "$applied" ] || [ $((now - last)) -ge 60 ]; then
                # A child process: inside `if`, set -e would not stop a failing step here.
                if sh "$0" once; then
                    applied=$current
                    last=$now
                else
                    log "sync failed; retrying"
                fi
            fi
            sleep 1
        done
        ;;
    *)
        echo "usage: amx-sync-accounts once|watch" >&2
        exit 2
        ;;
esac
