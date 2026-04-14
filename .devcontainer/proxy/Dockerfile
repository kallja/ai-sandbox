FROM mitmproxy/mitmproxy

USER root
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

COPY certs/mitmproxy-ca.pem certs/mitmproxy-ca-cert.pem /home/mitmproxy/.mitmproxy/
COPY certs/extra/ /usr/local/share/ca-certificates/extra/
RUN update-ca-certificates

COPY --chmod=755 entrypoint.sh /entrypoint.sh
COPY addon.py claude_auth.py traffic_control.py rule.py /

USER mitmproxy

ENTRYPOINT ["/entrypoint.sh"]
