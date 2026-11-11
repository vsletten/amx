#!/bin/sh
set -eu

: "${MAIL_DOMAIN:?MAIL_DOMAIN is required}"
: "${MAIL_HOSTNAME:?MAIL_HOSTNAME is required}"
: "${AGENT_DOMAIN:?AGENT_DOMAIN is required}"
: "${MILTER_ENDPOINT:=}"
: "${GATEWAY_HOST:=}"
: "${GATEWAY_IP:=127.0.0.1}"
export GATEWAY_IP

install -d -o vmail -g vmail /var/mail/vhosts
# The dev users go to users.dev and dovecot-acl.dev; amx-sync-accounts adds the agents registered
# with `amx agent add --live` and writes the files Dovecot reads (PLAN §5.2).
: >/etc/dovecot/users.dev
: >/etc/postfix/vmailbox
cp /opt/amx/dovecot-acl /etc/dovecot/dovecot-acl.dev
while IFS='|' read -r user_email user_password; do
    case "$user_email" in
        ""|'#'*|gateway|approver) continue ;;
    esac
    user_domain=${user_email#*@}
    if [ "$user_domain" != "$MAIL_DOMAIN" ] && [ "$user_domain" != "$AGENT_DOMAIN" ]; then
        continue
    fi
    local_part=${user_email%@*}
    user_home="/var/mail/vhosts/${user_domain}/${local_part}"
    install -d -o vmail -g vmail "$user_home"
    user_hash=$(doveadm pw -s SHA512-CRYPT -p "$user_password")
    printf '%s:%s:5000:5000::%s::userdb_mail=maildir:~/Maildir\n' \
        "$user_email" "$user_hash" "$user_home" >>/etc/dovecot/users.dev
    printf '%s OK\n' "$user_email" >>/etc/postfix/vmailbox
    if [ "$user_domain" = "$AGENT_DOMAIN" ]; then
        # An agent's own login may not insert into its INBOX (see /etc/dovecot/dovecot-acl).
        printf 'INBOX -user=%s ip\n' "$user_email" >>/etc/dovecot/dovecot-acl.dev
    fi
done </opt/amx/dev-users
chmod 0644 /etc/dovecot/dovecot-acl.dev
cp /etc/dovecot/users.dev /etc/dovecot/users
cp /etc/dovecot/dovecot-acl.dev /etc/dovecot/dovecot-acl
chmod 0644 /etc/dovecot/dovecot-acl

if [ ! -s /etc/dovecot/users ]; then
    echo "no development users found for ${MAIL_DOMAIN}" >&2
    exit 1
fi

# Master users: the gateway (full access) and the hold-queue approver (Outbox moves only; see
# /etc/dovecot/dovecot-acl). Neither is an agent login.
: >/etc/dovecot/master-users.143
for master in gateway approver; do
    master_password=$(awk -F '|' -v name="$master" '$1 == name { print $2; exit }' /opt/amx/dev-users)
    if [ -z "$master_password" ]; then
        echo "no development $master master user found" >&2
        exit 1
    fi
    master_hash=$(doveadm pw -s SHA512-CRYPT -p "$master_password")
    printf '%s:%s\n' "$master" "$master_hash" >>/etc/dovecot/master-users.143
done
chown root:dovecot /etc/dovecot/users /etc/dovecot/users.dev /etc/dovecot/master-users.143
chmod 0640 /etc/dovecot/users /etc/dovecot/users.dev /etc/dovecot/master-users.143

envsubst '${MAIL_DOMAIN} ${MAIL_HOSTNAME} ${AGENT_DOMAIN} ${MILTER_ENDPOINT}' \
    </opt/amx/main.cf.template >/etc/postfix/main.cf
envsubst '${GATEWAY_IP}' </opt/amx/master.cf.template >/etc/postfix/master.cf
postmap /etc/postfix/vmailbox
: >/etc/postfix/transport
if [ -n "$GATEWAY_HOST" ]; then
    printf '%s lmtp:inet:%s:2424\n' "$AGENT_DOMAIN" "$GATEWAY_HOST" \
        >>/etc/postfix/transport
fi
postmap /etc/postfix/transport

postfix check
dovecot

# Create every user's hold-queue folders now, with the ACL plugin off for this one command, so an
# agent can never create one itself (e.g. by renaming a folder onto a name that does not exist
# yet; see /etc/dovecot/dovecot-acl).
first_user=$(cut -d: -f1 /etc/dovecot/users | head -n 1)
for _ in $(seq 1 50); do
    doveadm user "$first_user" >/dev/null 2>&1 && break
    sleep 0.1
done
for mail_user in $(cut -d: -f1 /etc/dovecot/users); do
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
amx-sync-accounts once || echo "amx-sync-accounts: first pass failed; watch retries" >&2
amx-sync-accounts watch &

exec postfix start-fg
