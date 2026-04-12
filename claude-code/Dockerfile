FROM node:20-alpine

RUN apk add --no-cache ca-certificates curl git bash openssl

RUN curl -fsSL https://claude.ai/install.sh | bash

COPY config/ /root/

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV PATH="~/.local/bin:$PATH"

ENTRYPOINT ["/entrypoint.sh"]
CMD ["sleep", "infinity"]
