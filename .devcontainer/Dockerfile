FROM debian:bookworm-slim

RUN apt update -y \
    && apt install -y --no-install-recommends \
    bash \
    ca-certificates \
    curl \
    git \
    openssl \
    python3 python3-pip

COPY --chmod=755 scripts/verified-download.sh scripts/install-go.sh scripts/install-claude.sh /tmp/scripts/

ARG GO_VERSION=1.26.2
ARG GO_SHA256_AMD64=990e6b4bbba816dc3ee129eaeaf4b42f17c2800b88a2166c265ac1a200262282
ARG GO_SHA256_ARM64=c958a1fe1b361391db163a485e21f5f228142d6f8b584f6bef89b26f66dc5b23
RUN /tmp/scripts/install-go.sh "$GO_VERSION" "$GO_SHA256_AMD64" "$GO_SHA256_ARM64"

COPY certs/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy-ca-cert.crt
COPY config/claude/ /home/claude/

COPY requirements-dev.txt /tmp/requirements-dev.txt
RUN \
    pip install --no-cache-dir --break-system-packages -r /tmp/requirements-dev.txt \
    && rm /tmp/requirements-dev.txt

RUN \
    mkdir -p /home/claude \
    && addgroup --gid 1000 claude \
    && adduser --disabled-password --gecos "" --uid 1000 --ingroup claude claude \
    && mkdir -p /home/claude/.claude/projects \
    && chown -R claude:claude /home/claude/ \
    && update-ca-certificates --fresh

USER claude

WORKDIR /home/claude

ARG CLAUDE_CODE_VERSION=2.1.108
ARG CLAUDE_CODE_SHA256_AMD64=1f641676eb086ceafd76a5f51ffb260b948fa1f6d77991d8cd6e480267dfff37
ARG CLAUDE_CODE_SHA256_ARM64=7bef1f7dcf64a221fc66571a176ca6206088bec48613a46cb4fa6328169c0bd1
RUN /tmp/scripts/install-claude.sh "$CLAUDE_CODE_VERSION" "$CLAUDE_CODE_SHA256_AMD64" "$CLAUDE_CODE_SHA256_ARM64"

ENV PATH="/usr/local/go/bin:/home/claude/.local/bin:$PATH"

CMD ["sleep", "infinity"]
