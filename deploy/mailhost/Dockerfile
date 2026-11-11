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

COPY mailhost/main.cf.template /opt/amx/main.cf.template
COPY mailhost/master.cf /opt/amx/master.cf.template
COPY mailhost/allowed-recipients.pcre /etc/postfix/allowed-recipients.pcre
COPY mailhost/dovecot.conf /etc/dovecot/dovecot.conf
COPY mailhost/dovecot-acl /opt/amx/dovecot-acl
COPY mailhost/entrypoint.sh /usr/local/bin/amx-mailhost
COPY mailhost/sync-accounts.sh /usr/local/bin/amx-sync-accounts

RUN chmod 0755 /usr/local/bin/amx-mailhost /usr/local/bin/amx-sync-accounts \
    && chmod 0644 /opt/amx/master.cf.template /etc/postfix/allowed-recipients.pcre /opt/amx/dovecot-acl

EXPOSE 25 143 1143 10025
ENTRYPOINT ["/usr/local/bin/amx-mailhost"]
