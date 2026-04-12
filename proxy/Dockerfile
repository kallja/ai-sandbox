FROM mitmproxy/mitmproxy
USER root
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --chmod=755 proxy/entrypoint.sh /entrypoint.sh
COPY proxy/addon.py proxy/claude_auth.py proxy/traffic_control.py proxy/rule.py /
ENTRYPOINT ["/entrypoint.sh"]
