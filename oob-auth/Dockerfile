FROM golang:1.25-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /out/relay       ./cmd/relay/ && \
    CGO_ENABLED=0 go build -o /out/client-a     ./cmd/client-a/ && \
    CGO_ENABLED=0 go build -o /out/client-b     ./cmd/client-b/ && \
    CGO_ENABLED=0 go build -o /out/test-broker  ./cmd/test-broker/ && \
    CGO_ENABLED=0 go build -o /out/keygen       ./cmd/keygen/

# Generate test key pairs at build time.
FROM alpine:3.21 AS keygen
COPY --from=builder /out/keygen /usr/local/bin/
RUN mkdir /keys && keygen --out=/keys

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /out/ /usr/local/bin/
COPY --from=keygen /keys/ /keys/
