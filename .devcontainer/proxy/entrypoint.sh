#!/bin/sh
set -e

# ssl_verify_upstream_trusted_ca=... enables trust for Cloudflare WARP certificate.
exec mitmweb --web-host 0.0.0.0 --listen-port 8080 \
  --set ssl_verify_upstream_trusted_ca=/etc/ssl/certs/ca-certificates.crt \
  --set web_password="$PASSWORD_HASH" \
  --set termlog_verbosity=info \
  -s /addons/addon.py
