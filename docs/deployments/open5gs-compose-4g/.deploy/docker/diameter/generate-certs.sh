#!/bin/sh
# Generate a private test CA and separate certificates for this local deployment.
set -eu
cd "$(dirname "$0")"
umask 077
for peer in hss mme pcrf smf; do
  for suffix in key crt; do
    if [ -e "$peer/$peer.$suffix" ]; then
      echo "Existing certificates found; remove the local credentials before regenerating." >&2
      exit 1
    fi
  done
done
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT HUP INT TERM
openssl genrsa -traditional -out "$stage/ca.key" 2048
openssl req -new -x509 -key "$stage/ca.key" -out "$stage/ca.crt" -days 365 -subj /CN=local-diameter-test-ca
for peer in hss mme pcrf smf; do
  openssl genrsa -traditional -out "$stage/$peer.key" 2048
  openssl req -new -key "$stage/$peer.key" -out "$stage/$peer.csr" -subj "/CN=$peer.localdomain"
  printf 'subjectAltName=DNS:%s.localdomain\nextendedKeyUsage=serverAuth,clientAuth\n' "$peer" > "$stage/$peer.ext"
  openssl x509 -req -in "$stage/$peer.csr" -CA "$stage/ca.crt" -CAkey "$stage/ca.key" -set_serial "0x$(openssl rand -hex 16)" -out "$stage/$peer.crt" -days 365 -extfile "$stage/$peer.ext"
done
for peer in hss mme pcrf smf; do
  cp "$stage/$peer.key" "$peer/$peer.key"
  cp "$stage/$peer.crt" "$peer/$peer.crt"
  cp "$stage/ca.crt" "$peer/ca.crt"
done
