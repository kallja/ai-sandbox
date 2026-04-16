FROM debian:bookworm-slim

ENV PATH="/home/claude/.local/bin:$PATH"

RUN apt update -y \
    && apt install -y \
    bash \
    curl

RUN mkdir -p /home/claude

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

COPY certs/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy-ca-cert.crt
RUN update-ca-certificates --fresh

RUN \
    addgroup --gid 1000 claude \
    && adduser --disabled-password --gecos "" --uid 1000 --ingroup claude claude \
    && mkdir -p /home/claude/.claude/projects \
    && chown -R claude:claude /home/claude/

USER claude

COPY --chown=claude:claude --chmod=700 scripts/install-claude.sh /home/claude/tmp/install-claude.sh
ARG CLAUDE_CODE_VERSION=2.1.108
ARG CLAUDE_CODE_SHA256_AMD64=1f641676eb086ceafd76a5f51ffb260b948fa1f6d77991d8cd6e480267dfff37
ARG CLAUDE_CODE_SHA256_ARM64=7bef1f7dcf64a221fc66571a176ca6206088bec48613a46cb4fa6328169c0bd1
RUN /home/claude/tmp/install-claude.sh "$CLAUDE_CODE_VERSION" "$CLAUDE_CODE_SHA256_AMD64" "$CLAUDE_CODE_SHA256_ARM64"
RUN rm -rf /home/claude/tmp

CMD ["sleep", "infinity"]
