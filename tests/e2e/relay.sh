#!/bin/sh
# relay.sh <ip>: тестовый CA + сертификат на IP, relay с TLS и QUIC address discovery.
# CA кладётся в /shared/ca.crt — ноды доверяют только ему (--relay-ca).
set -e
cd /tmp
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -keyout ca.key -out ca.crt -subj /CN=rift-test-ca \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout relay.key -out relay.csr -subj /CN=relay 2>/dev/null
printf 'subjectAltName=IP:%s\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' "$1" > ext
openssl x509 -req -in relay.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 1 \
  -extfile ext -out relay.crt 2>/dev/null
cat > relay.toml <<TOML
enable_quic_addr_discovery = true
[tls]
cert_mode = "Manual"
manual_cert_path = "/tmp/relay.crt"
manual_key_path = "/tmp/relay.key"
TOML
cp ca.crt /shared/ca.crt
exec iroh-relay --config-path relay.toml
