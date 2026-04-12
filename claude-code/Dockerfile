FROM node:20-alpine

RUN apk add --no-cache ca-certificates curl git bash openssl su-exec

RUN addgroup -g 1010 claude && adduser -D -u 1010 -G claude claude

USER claude
RUN curl -fsSL https://claude.ai/install.sh | bash
USER root

COPY config/ /home/claude/
RUN mkdir -p /home/claude/.claude/projects && chown -R claude:claude /home/claude/

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV PATH="/home/claude/.local/bin:$PATH"

ENTRYPOINT ["/entrypoint.sh"]
CMD ["sleep", "infinity"]
