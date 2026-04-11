FROM mitmproxy/mitmproxy
USER root
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --chmod=755 entrypoint.sh /entrypoint.sh
COPY addon.py /addon.py
ENTRYPOINT ["/entrypoint.sh"]
