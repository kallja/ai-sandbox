#!/bin/sh
set -e

# Build a combined CA bundle: system CAs + Cloudflare cert (if present)
CA_BUNDLE="/tmp/combined-ca-bundle.pem"
cp /etc/ssl/certs/ca-certificates.crt "$CA_BUNDLE"

if [ -f /usr/local/share/ca-certificates/cloudflare.crt ]; then
  echo "Appending Cloudflare WARP certificate to CA bundle..."
  cat /usr/local/share/ca-certificates/cloudflare.crt >> "$CA_BUNDLE"
  echo "Cloudflare WARP certificate added"
else
  echo "No Cloudflare WARP certificate found, using system CAs only"
fi

exec mitmweb --web-host 0.0.0.0 --listen-port 8080 \
  --set confdir=/opt/mitmproxy \
  --set ssl_verify_upstream_trusted_ca="$CA_BUNDLE" \
  --no-web-open-browser \
  --set web_password='$argon2i$v=19$m=8,t=1,p=1$YWFhYWFhYWE$nXD9kg' \
  --set termlog_verbosity=info \
  -s /addon.py
