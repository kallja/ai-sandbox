FROM debian:bookworm-slim

ENV PATH="/home/claude/.local/bin:$PATH"

RUN apt update -y \
    && apt install -y \
    bash \
    curl \
    && curl -fsSL https://claude.ai/install.sh | bash

RUN mkdir -p /home/claude \
    && mv /root/.local /home/claude/.local \
    && ln -sf /home/claude/.local/share/claude/versions/* /home/claude/.local/bin/claude

RUN apt install -y --no-install-recommends \
    ca-certificates \
    git \
    openssl \
    python3 python3-pip

COPY requirements-dev.txt /tmp/requirements-dev.txt
RUN \
    pip install --no-cache-dir --break-system-packages -r /tmp/requirements-dev.txt \
    && rm /tmp/requirements-dev.txt

COPY config/claude/ /home/claude/

COPY proxy/certs/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy-ca-cert.crt
RUN update-ca-certificates --fresh

RUN \
    addgroup --gid 1000 claude \
    && adduser --disabled-password --gecos "" --uid 1000 --ingroup claude claude \
    && mkdir -p /home/claude/.claude/projects \
    && chown -R claude:claude /home/claude/

USER claude
CMD ["sleep", "infinity"]
