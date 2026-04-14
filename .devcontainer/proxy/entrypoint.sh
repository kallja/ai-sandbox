#!/bin/sh
set -e

exec mitmweb --web-host 0.0.0.0 --listen-port 8080 \
  --set confdir=/home/mitmproxy/.mitmproxy \
  # This enables trust for Cloudflare WARP certificate. Host certs are available in containers.
  --set ssl_verify_upstream_trusted_ca=/etc/ssl/certs/ca-certificates.crt \
  --no-web-open-browser \
  --set web_password='$argon2i$v=19$m=8,t=1,p=1$YWFhYWFhYWE$nXD9kg' \
  --set termlog_verbosity=info \
  -s /addon.py
