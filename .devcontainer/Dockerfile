FROM debian:bookworm-slim

RUN apt update -y \
    && apt install -y --no-install-recommends \
    bash \
    ca-certificates \
    curl \
    git \
    openssl \
    python3 python3-pip


COPY --chmod=755 scripts/verified-download.sh scripts/install-go.sh /tmp/scripts/
ARG GO_VERSION=1.26.2
ARG GO_SHA256_AMD64=990e6b4bbba816dc3ee129eaeaf4b42f17c2800b88a2166c265ac1a200262282
ARG GO_SHA256_ARM64=c958a1fe1b361391db163a485e21f5f228142d6f8b584f6bef89b26f66dc5b23
RUN /tmp/scripts/install-go.sh "$GO_VERSION" "$GO_SHA256_AMD64" "$GO_SHA256_ARM64"

COPY requirements-dev.txt /tmp/requirements-dev.txt
RUN \
    pip install --no-cache-dir --break-system-packages -r /tmp/requirements-dev.txt \
    && rm /tmp/requirements-dev.txt

COPY --chmod=755 scripts/verified-download.sh scripts/install-claude.sh /tmp/scripts/
ARG CLAUDE_CODE_VERSION=2.1.119
ARG CLAUDE_CODE_SHA256_AMD64=cca43053f062949495596b11b6fd1b59cf79102adb13bacbe66997e6fae41e4a
ARG CLAUDE_CODE_SHA256_ARM64=382aa73ea4b07fd8d698e3159b5ef9e1b8739fae7505ba8ddd28b8a6a62819ce
RUN /tmp/scripts/install-claude.sh "$CLAUDE_CODE_VERSION" "$CLAUDE_CODE_SHA256_AMD64" "$CLAUDE_CODE_SHA256_ARM64"

COPY certs/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy-ca-cert.crt

COPY config/claude/ /home/claude/
COPY scripts/post-create.sh /devcontainer/scripts/post-create.sh

RUN \
    mkdir -p /home/claude \
    && addgroup --gid 1000 claude \
    && adduser --disabled-password --gecos "" --uid 1000 --ingroup claude claude \
    && mkdir -p /home/claude/.claude/projects \
    && chown -R claude:claude /home/claude/ \
    && update-ca-certificates --fresh

USER claude

WORKDIR /home/claude

ENV PATH="/usr/local/go/bin:$PATH"

CMD ["sleep", "infinity"]
