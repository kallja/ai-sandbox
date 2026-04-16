# OOB-Auth: Remote Token Broker

Secure, serverless Out-of-Band OAuth 2.0 authorization flow between two isolated machines using E2EE and a blind cloud relay.

## Components

| Directory | What | Description |
|-----------|------|-------------|
| `crypto/` | Shared library | Ed25519 key management, NaCl box E2EE, blind QueueID derivation, memory zeroing |
| `protocol/` | Shared library | Wire-format types: Envelope, Intent, Response |
| `relay/` | Library + server | HTTP relay with Store interface, Cloudflare middleware, in-memory and Firestore backends |
| `clienta/` | Library | Requester logic: PKCE, encrypt intent, publish/subscribe |
| `clientb/` | Library | Broker logic: decrypt intent, OAuth flow, encrypt response |
| `cmd/relay/` | Binary | Relay server entry point |
| `cmd/client-a/` | Binary | Requester CLI entry point |
| `cmd/client-b/` | Binary | Broker CLI entry point |
| `integration/` | Tests | End-to-end tests wiring all three components |
| `infra/` | Terraform | GCP (Cloud Run, Firestore, IAM) + Cloudflare (DNS, WAF, service tokens) |

## Prerequisites

- Go 1.24+ (only dependency for building and testing)
- Terraform 1.5+ (only needed for infrastructure, not for application development)

## Building

```sh
cd oob-auth

# Build all three binaries
go build ./cmd/relay/
go build ./cmd/client-a/
go build ./cmd/client-b/
```

## Testing

```sh
# Run the full test suite (100 tests)
go test ./...

# Run with verbose output
go test -v ./...

# Run a specific package
go test -v ./crypto/
go test -v ./relay/
go test -v ./clienta/
go test -v ./clientb/
go test -v ./integration/
```

All tests run locally against in-memory backends and `httptest` servers. No external services, credentials, or network access required.

## Running locally

### 1. Generate key pairs

Each machine needs an Ed25519 key pair. For local testing, generate both:

```sh
# In a Go program or test, use crypto.GenerateKeyPair() and SavePrivateKey/SavePublicKey.
# There is no standalone keygen CLI — keys are standard Ed25519 in PEM format (PKCS#8/PKIX).
```

### 2. Start the relay

```sh
./relay --store=memory --addr=:8080
```

The relay runs with an in-memory store by default (messages expire after 5 minutes). For production, use `--store=firestore --gcp-project=<project>`.

Cloudflare header verification is enabled when `--cf-client-id` and `--cf-client-secret` are set (or via `CF_ACCESS_CLIENT_ID` / `CF_ACCESS_CLIENT_SECRET` env vars). When both are empty strings, all requests pass through.

### 3. Start Client B (Broker) — on the trusted machine

```sh
./client-b \
  --relay=http://localhost:8080 \
  --key=broker-private.pem \
  --peer-pub=requester-public.pem \
  --mode=code
```

Client B long-polls the relay, waiting for an encrypted intent. When one arrives, it presents the OAuth authorization URL and prompts for the auth code.

`--mode=code` returns the authorization code to Client A. `--mode=token` redeems it for tokens first.

### 4. Start Client A (Requester) — on the standard machine

```sh
./client-a \
  --relay=http://localhost:8080 \
  --auth-url=https://provider.example.com/authorize \
  --token-url=https://provider.example.com/token \
  --client-id=my-oauth-client \
  --scopes=read,write \
  --key=requester-private.pem \
  --peer-pub=broker-public.pem
```

Client A encrypts the OAuth intent, publishes it to the relay, and blocks until the Broker returns an encrypted response containing the auth code or tokens.

## Infrastructure

Terraform definitions live in `infra/`. They provision:

- **GCP:** Cloud Run v2 (scale-to-zero), Firestore Native (with 5-minute TTL), scoped IAM service account, Secret Manager for Cloudflare credentials
- **Cloudflare:** Proxied CNAME to Cloud Run, WAF rate limiting (20 req/min/IP), geo-blocking, Zero Trust service tokens, HTTP header injection

```sh
cd infra
terraform init
terraform plan -var-file=prod.tfvars
```

Required variables are defined in `variables.tf`. Terraform validates but cannot plan/apply without GCP and Cloudflare credentials.

## How the protocol works

1. Both machines share Ed25519 public keys out of band.
2. Client A generates a PKCE challenge, wraps the OAuth intent in a NaCl box envelope encrypted to Client B's public key, and publishes it to the relay at a blind queue ID derived from Client B's key.
3. The relay stores the opaque ciphertext. It never sees plaintext.
4. Client B long-polls the relay, decrypts the intent, executes the OAuth flow, encrypts the result back to Client A, and publishes it to Client A's blind queue ID.
5. Client A receives and decrypts the tokens.

All secrets (keys, verifiers, tokens) are zeroed from memory immediately after use.
