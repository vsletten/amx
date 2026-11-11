#!/bin/sh
# The live mailhost's start (docs/selfhost-public.md): users, maps, and configuration from
# /secrets/mail-users (password hashes, written 0600 by `amx live install`, so no password is
# ever on a command line here), then Postfix in the foreground. mail-users holds the host's own
# logins (postmaster and the two master users); the agents are registered (PLAN §5.2, §11.5),
# and amx-sync-accounts merges them from /secrets/accounts/agents.passwd while this runs.
set -eu

: "${MX_HOST:?}" "${AGENT_DOMAIN:?}" "${MAILHOST_IP:?}" "${GATEWAY_IP:?}" "${ROLE_ADDRESSES:?}"
: "${MAX_BYTES:?}" "${GLOBAL_MAX_BYTES:?}"
: "${ROLE_FORWARD:=}"
users_file=/secrets/mail-users
postmaster="postmaster@${AGENT_DOMAIN}"

for file in "$users_file" /tls/server.pem /tls/server-key.pem; do
    if [ ! -s "$file" ]; then
        echo "missing $file: run amx live install (and amx live certs)" >&2
        exit 1
    fi
done

is_role() {
    for role in $ROLE_ADDRESSES; do
        [ "$1" = "$role" ] && return 0
    done
    return 1
}

install -d -o vmail -g vmail /var/mail/vhosts
# The base files amx-sync-accounts starts each pass from (the Dockerfile's AMX_SYNC_BASE_*).
: >/etc/dovecot/users.base
: >/etc/postfix/vmailbox.base
: >/etc/dovecot/master-users.143
: >/etc/dovecot/master-users.993
cp /opt/amx/dovecot-acl /etc/dovecot/dovecot-acl.base
while IFS='|' read -r user_email user_hash <&3; do
    case "$user_email" in
        ""|'#'*) continue ;;
        gateway) master_file=/etc/dovecot/master-users.143 ;;   # the private network only
        approver) master_file=/etc/dovecot/master-users.993 ;;  # the internet's one master
        *) master_file="" ;;
    esac
    case "$user_hash" in
        '{SHA512-CRYPT}$6$'*) ;;
        *) echo "not a SHA512-CRYPT hash for $user_email: run amx live install" >&2; exit 1 ;;
    esac
    if [ -n "$master_file" ]; then
        printf '%s:%s\n' "$user_email" "$user_hash" >>"$master_file"
        continue
    fi
    if [ "${user_email#*@}" != "$AGENT_DOMAIN" ]; then
        echo "not in ${AGENT_DOMAIN}: $user_email" >&2
        exit 1
    fi
    local_part=${user_email%@*}
    user_home="/var/mail/vhosts/${AGENT_DOMAIN}/${local_part}"
    install -d -o vmail -g vmail "$user_home"
    printf '%s:%s:5000:5000::%s::userdb_mail=maildir:~/Maildir\n' \
        "$user_email" "$user_hash" "$user_home" >>/etc/dovecot/users.base
    printf '%s OK\n' "$user_email" >>/etc/postfix/vmailbox.base
    if ! is_role "$local_part"; then
        # An agent's own login may not insert into its INBOX (PLAN §5.9, dovecot-acl).
        printf 'INBOX -user=%s ip\n' "$user_email" >>/etc/dovecot/dovecot-acl.base
    fi
done 3<"$users_file"
for file in /etc/dovecot/master-users.143 /etc/dovecot/master-users.993; do
    if [ ! -s "$file" ]; then
        echo "no master user for $file in $users_file" >&2
        exit 1
    fi
done
if ! grep -q "^${postmaster}:" /etc/dovecot/users.base; then
    echo "no ${postmaster} mailbox in $users_file" >&2
    exit 1
fi
# Dovecot and Postfix start on the base alone; the sync adds the agents below, before Postfix
# accepts a connection.
cp /etc/dovecot/users.base /etc/dovecot/users
cp /etc/dovecot/dovecot-acl.base /etc/dovecot/dovecot-acl
cp /etc/postfix/vmailbox.base /etc/postfix/vmailbox
chown root:dovecot /etc/dovecot/users /etc/dovecot/users.base \
    /etc/dovecot/master-users.143 /etc/dovecot/master-users.993
chmod 0640 /etc/dovecot/users /etc/dovecot/users.base \
    /etc/dovecot/master-users.143 /etc/dovecot/master-users.993
chmod 0644 /etc/dovecot/dovecot-acl /etc/dovecot/dovecot-acl.base

vars='${MX_HOST} ${AGENT_DOMAIN} ${MAILHOST_IP} ${GATEWAY_IP} ${MAX_BYTES} ${GLOBAL_MAX_BYTES}'
envsubst "$vars" </opt/amx/main.cf.template >/etc/postfix/main.cf
envsubst "$vars" </opt/amx/master.cf.template >/etc/postfix/master.cf
envsubst "$vars" </opt/amx/dovecot.conf.template >/etc/dovecot/dovecot.conf

# Role mail (postmaster@, abuse@, and the MTA's own notices) goes to the postmaster mailbox, and
# to the admin contact too if the parameters ask for it (role_mail.forward_to_admin).
{
    for role in $ROLE_ADDRESSES; do
        if [ "$role" != postmaster ]; then
            printf '%s@%s %s\n' "$role" "$AGENT_DOMAIN" "$postmaster"
        fi
    done
    if [ -n "$ROLE_FORWARD" ]; then
        printf '%s %s, %s\n' "$postmaster" "$postmaster" "$ROLE_FORWARD"
    fi
    for local in postmaster root abuse MAILER-DAEMON; do
        printf '%s@%s %s\n' "$local" "$MX_HOST" "$postmaster"
        printf '%s@localhost %s\n' "$local" "$postmaster"
    done
} >/etc/postfix/virtual
printf '%s lmtp:unix:private/dovecot-lmtp\n%s lmtp:inet:[%s]:2424\n' \
    "$postmaster" "$AGENT_DOMAIN" "$GATEWAY_IP" >/etc/postfix/transport
postmap /etc/postfix/vmailbox /etc/postfix/virtual /etc/postfix/transport

# The queue is a volume (compose.yaml) that outlives this image: give its directories and queue
# files to this image's postfix user. (`postfix set-permissions` would do more, but it stops on
# the manual pages a slim image leaves out.)
spool=/var/spool/postfix
for dir in active bounce corrupt defer deferred flush hold incoming private saved trace; do
    install -d -o postfix -g root -m 0700 "$spool/$dir"
    find "$spool/$dir" -mindepth 1 ! -user postfix -exec chown postfix {} +
done
install -d -o postfix -g postdrop -m 1730 "$spool/maildrop"
install -d -o postfix -g postdrop -m 2710 "$spool/public"
postfix check
dovecot

# The base users' hold-queue folders, created with the ACL plugin off so no agent can create
# one itself (the dev mailhost's rule, PLAN §8). amx-sync-accounts does the same for each agent.
first_user=$(cut -d: -f1 /etc/dovecot/users.base | head -n 1)
for _ in $(seq 1 50); do
    doveadm user "$first_user" >/dev/null 2>&1 && break
    sleep 0.1
done
for mail_user in $(cut -d: -f1 /etc/dovecot/users.base); do
    for folder in Outbox Outbox/Held Outbox/Approved Outbox/Rejected; do
        doveadm -o mail_plugins= mailbox create -u "$mail_user" "$folder" 2>/dev/null || true
    done
    existing=$(doveadm mailbox list -u "$mail_user" 'Outbox*' | sort | tr '\n' ' ')
    if [ "$existing" != "Outbox Outbox/Approved Outbox/Held Outbox/Rejected " ]; then
        echo "hold-queue folders missing for $mail_user: $existing" >&2
        exit 1
    fi
done

# Registered agents (PLAN §5.2): merge them now, then whenever the accounts file changes. A
# failed first pass is not fatal: watch starts with a pass of its own and retries every second.
# If watch itself dies, it is started again: without it, registrations would silently stop
# reaching this mailhost. The healthcheck (compose.yaml) requires a pass to have succeeded in the
# last two minutes (watch runs one at least every minute).
rm -f /run/amx-sync-accounts.ok
amx-sync-accounts once || echo "amx-sync-accounts: first pass failed; watch retries" >&2
(
    while :; do
        amx-sync-accounts watch || true
        echo "amx-sync-accounts: watch exited; starting it again" >&2
        sleep 1
    done
) &

exec postfix start-fg
