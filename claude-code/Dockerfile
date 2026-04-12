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
    gosu \
    openssl \
    python3 python3-pip

COPY proxy/requirements.txt /tmp/requirements.txt
RUN \
    pip install --no-cache-dir --break-system-packages -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt

COPY claude-code/config/ /home/claude/

RUN \
    addgroup --gid 1000 claude \
    && adduser --disabled-password --gecos "" --uid 1000 --ingroup claude claude \
    && mkdir -p /home/claude/.claude/projects \
    && chown -R claude:claude /home/claude/

COPY claude-code/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["sleep", "infinity"]
