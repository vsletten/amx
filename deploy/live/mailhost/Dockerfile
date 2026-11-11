# The live bundle's mailhost: the dev mailhost's packages (the same layer, so a machine that built
# the dev stack reuses it), with the live Postfix and Dovecot configuration: TLS, one agent
# domain, real retry timers, strict relay rules.
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && echo "postfix postfix/mailname string localhost" | debconf-set-selections \
    && echo "postfix postfix/main_mailer_type string 'Internet Site'" | debconf-set-selections \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        dovecot-core \
        dovecot-imapd \
        dovecot-lmtpd \
        gettext-base \
        netcat-openbsd \
        postfix \
        postfix-pcre \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 5000 vmail \
    && useradd --uid 5000 --gid vmail --home-dir /var/mail/vhosts --create-home vmail

COPY main.cf.template master.cf.template dovecot.conf.template /opt/amx/
# The same global ACL as the dev mailhost: an agent cannot approve its own holds (PLAN §8) or
# insert into its own INBOX (§5.9). amx-sync-accounts appends the per-agent INBOX rule.
COPY --from=shared dovecot-acl /opt/amx/dovecot-acl
COPY entrypoint.sh /usr/local/bin/amx-mailhost
# The dev mailhost's merge of registered agents (PLAN §5.2), unchanged: `amx agent add --live`
# and its siblings write the accounts file, and this picks it up without a restart.
COPY --from=shared sync-accounts.sh /usr/local/bin/amx-sync-accounts

RUN chmod 0755 /usr/local/bin/amx-mailhost /usr/local/bin/amx-sync-accounts \
    && chmod 0644 /opt/amx/*

# Where amx-sync-accounts finds its inputs here (also for `docker compose exec mailhost
# amx-sync-accounts once`): the accounts file and the migration's adoption list come from
# secrets/mailhost/accounts; the base files are the entrypoint's own users (postmaster). The live
# Postfix refuses unlisted recipients itself, so the sync keeps its recipient table too.
ENV AMX_ACCOUNTS_FILE=/secrets/accounts/agents.passwd \
    AMX_SYNC_ADOPT=/secrets/accounts/adopt \
    AMX_SYNC_BASE_USERS=/etc/dovecot/users.base \
    AMX_SYNC_BASE_ACL=/etc/dovecot/dovecot-acl.base \
    AMX_SYNC_BASE_VMAILBOX=/etc/postfix/vmailbox.base

EXPOSE 25 993
ENTRYPOINT ["/usr/local/bin/amx-mailhost"]
