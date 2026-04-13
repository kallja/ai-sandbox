FROM mitmproxy/mitmproxy
USER root
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY certs/mitmproxy-ca.pem certs/mitmproxy-ca-cert.pem /opt/mitmproxy/
COPY --chmod=755 entrypoint.sh /entrypoint.sh
COPY addon.py claude_auth.py traffic_control.py rule.py /
ENTRYPOINT ["/entrypoint.sh"]
