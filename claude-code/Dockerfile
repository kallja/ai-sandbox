FROM node:20-alpine

ENV PATH="/home/claude/.local/bin:$PATH"

RUN apk add --no-cache ca-certificates curl git bash openssl su-exec python3 py3-pip

RUN addgroup -g 1010 claude && adduser -D -u 1010 -G claude claude

USER claude
RUN curl -fsSL https://claude.ai/install.sh | bash
USER root

COPY claude-code/config/ /home/claude/
COPY proxy/requirements.txt /tmp/requirements.txt
RUN \
    mkdir -p /home/claude/.claude/projects \
    && chown -R claude:claude /home/claude/ \
    pip install --no-cache-dir --break-system-packages -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt

COPY claude-code/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["sleep", "infinity"]
