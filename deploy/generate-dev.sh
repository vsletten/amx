#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
generated="$root/deploy/generated"
keys="$generated/keys"
zones="$generated/zones"
tls="$generated/tls"
# state/runner-ct is the remote agent runner's own directory (PLAN §5.9), not the gateway's.
# state/accounts/<gateway> holds the accounts file of agents registered with `amx agent add
# --live` (PLAN §5.2); each gateway's registry is state/<gateway>/registry, its /data/registry.
mkdir -p "$keys" "$zones" "$tls" "$generated/state/nw" "$generated/state/ct" \
    "$generated/state/runner-ct" "$generated/state/accounts/nw" "$generated/state/accounts/ct"

make_key() {
    name=$1
    key="$keys/$name.private.pem"
    if [ ! -f "$key" ]; then
        openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$key" >/dev/null 2>&1
        chmod 0600 "$key"
    fi
    openssl pkey -in "$key" -pubout -outform DER 2>/dev/null | base64 -w0
}

scheduler_key=$(make_key scheduler)
intake_key=$(make_key intake)
restricted_key=$(make_key restricted)
planner_key=$(make_key planner)
inspections_key=$(make_key inspections)
outpost_key=$(make_key outpost)

tls_version=3  # 3: edge-ct, where runner-ct reaches submission (PLAN §5.9)
current_tls_version=""
if [ -f "$tls/version" ]; then
    current_tls_version=$(tr -d '\n' <"$tls/version")
fi
if [ "$current_tls_version" != "$tls_version" ]; then
    rm -f "$tls/dev-ca-key.pem" "$tls/dev-ca.pem" "$tls/dev-ca.srl" \
        "$tls/server-key.pem" "$tls/server.pem"
fi
if [ ! -f "$tls/dev-ca-key.pem" ] || [ ! -f "$tls/dev-ca.pem" ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -subj "/CN=AMX development CA" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -addext "subjectKeyIdentifier=hash" \
        -keyout "$tls/dev-ca-key.pem" -out "$tls/dev-ca.pem" >/dev/null 2>&1
    chmod 0600 "$tls/dev-ca-key.pem"
fi
if [ ! -f "$tls/server-key.pem" ] || [ ! -f "$tls/server.pem" ]; then
    openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" \
        -keyout "$tls/server-key.pem" -out "$tls/server.csr" >/dev/null 2>&1
    printf '%s\n' \
        'subjectAltName=DNS:localhost,DNS:gateway-nw,DNS:gateway-ct,DNS:edge-ct,IP:127.0.0.1' \
        'basicConstraints=critical,CA:FALSE' \
        'keyUsage=critical,digitalSignature,keyEncipherment' \
        'extendedKeyUsage=serverAuth' >"$tls/server.ext"
    printf '%s\n' 'subjectKeyIdentifier=hash' 'authorityKeyIdentifier=keyid,issuer' \
        >>"$tls/server.ext"
    openssl x509 -req -days 825 -sha256 \
        -in "$tls/server.csr" -CA "$tls/dev-ca.pem" -CAkey "$tls/dev-ca-key.pem" \
        -CAcreateserial -extfile "$tls/server.ext" -out "$tls/server.pem" >/dev/null 2>&1
    rm -f "$tls/server.csr" "$tls/server.ext"
fi
chmod 0644 "$tls/dev-ca.pem" "$tls/server-key.pem" "$tls/server.pem"
printf '%s\n' "$tls_version" >"$tls/version"

serial=$(date -u +%s)
cp "$root/deploy/coredns/zones/northwind.test.zone" "$zones/northwind.test.zone"
cp "$root/deploy/coredns/zones/contoso.test.zone" "$zones/contoso.test.zone"
cp "$root/deploy/coredns/zones/plainmail.test.zone" "$zones/plainmail.test.zone"
cp "$root/deploy/coredns/zones/dead.test.zone" "$zones/dead.test.zone"

cat >"$zones/agents.northwind.test.zone" <<EOF
\$ORIGIN agents.northwind.test.
\$TTL 30
@ IN SOA mail.northwind.test. hostmaster.northwind.test. ($serial 30 30 300 30)
@ IN NS mail.northwind.test.
@ IN MX 10 mail.northwind.test.
@ IN TXT "v=spf1 mx -all"
_dmarc IN TXT "v=DMARC1; p=reject"
scheduler._domainkey IN TXT "v=DKIM1; k=rsa; p=$scheduler_key"
scheduler._agents IN TXT "v=amx1; card=https://northwind.test/.well-known/agents/scheduler.json"
restricted._domainkey IN TXT "v=DKIM1; k=rsa; p=$restricted_key"
restricted._agents IN TXT "v=amx1; card=https://northwind.test/.well-known/agents/restricted.json"
planner._domainkey IN TXT "v=DKIM1; k=rsa; p=$planner_key"
planner._agents IN TXT "v=amx1; card=https://northwind.test/.well-known/agents/planner.json"
EOF

cat >"$zones/agents.contoso.test.zone" <<EOF
\$ORIGIN agents.contoso.test.
\$TTL 30
@ IN SOA mail.contoso.test. hostmaster.contoso.test. ($serial 30 30 300 30)
@ IN NS mail.contoso.test.
@ IN MX 10 mail.contoso.test.
@ IN TXT "v=spf1 mx -all"
_dmarc IN TXT "v=DMARC1; p=reject"
intake._domainkey IN TXT "v=DKIM1; k=rsa; p=$intake_key"
intake._agents IN TXT "v=amx1; card=https://contoso.test/.well-known/agents/intake.json"
inspections._domainkey IN TXT "v=DKIM1; k=rsa; p=$inspections_key"
inspections._agents IN TXT "v=amx1; card=https://contoso.test/.well-known/agents/inspections.json"
outpost._domainkey IN TXT "v=DKIM1; k=rsa; p=$outpost_key"
outpost._agents IN TXT "v=amx1; card=https://contoso.test/.well-known/agents/outpost.json"
EOF
