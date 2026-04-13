#!/bin/sh
set -e

while [ ! -f /shared-certs/mitmproxy-ca-cert.pem ]; do
  echo "Waiting for mitmproxy CA cert..."
  sleep 1
done

cp /shared-certs/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy.crt
update-ca-certificates

export NODE_EXTRA_CA_CERTS=/shared-certs/mitmproxy-ca-cert.pem

echo "mitmproxy CA cert installed"

# Ensure all volumes under home are owned by claude
chown -R claude:claude /home/claude

exec gosu claude "$@"
