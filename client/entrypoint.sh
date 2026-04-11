#!/bin/sh
set -e

while [ ! -f /shared-certs/mitmproxy-ca-cert.pem ]; do
  echo "Waiting for mitmproxy CA cert..."
  sleep 1
done

cp /shared-certs/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy.crt
update-ca-certificates
cat /shared-certs/mitmproxy-ca-cert.pem >> /etc/ssl/certs/ca-certificates.crt

echo "mitmproxy CA cert installed"

exec "$@"
