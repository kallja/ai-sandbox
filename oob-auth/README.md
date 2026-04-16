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
| `cmd/keygen/` | Binary | Generates Ed25519 key pairs for requester and broker |
| `cmd/test-broker/` | Binary | Non-interactive broker for automated testing |
| `integration/` | Tests | End-to-end tests wiring all three components |
| `infra/` | Terraform | GCP (Cloud Run, Firestore, IAM) + Cloudflare (DNS, WAF, service tokens) |

## Prerequisites

- Go 1.25+ (only dependency for building and testing)
- Terraform 1.5+ (only needed for infrastructure, not for application development)

## Building

```sh
cd oob-auth

# Build all binaries into bin/
mkdir -p bin
go build -o bin/ ./cmd/relay/ \
  && go build -o bin/ ./cmd/client-a/ \
  && go build -o bin/ ./cmd/client-b/ \
  && go build -o bin/ ./cmd/keygen/
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

## Using the clients

### 1. Generate key pairs

Each machine needs an Ed25519 key pair. Generate both with the keygen tool:

```sh
bin/keygen --out=keys/
```

This creates four files in `keys/`:
- `requester-private.pem`, `requester-public.pem`
- `broker-private.pem`, `broker-public.pem`

Copy each machine's private key and the other machine's public key to it. Keys are standard Ed25519 PEM (PKCS#8/PKIX).

### 2. Start Client B (Broker) — on the trusted machine

Start client-b first so it's polling when client-a publishes:

```sh
bin/client-b \
  --relay=https://relay.example.com \
  --key=broker-private.pem \
  --peer-pub=requester-public.pem \
  --mode=code
```

Client B long-polls the relay, waiting for an encrypted intent. When one arrives, it prints the OAuth authorization URL. Open it in a browser, complete the flow, and paste back the auth code.

`--mode=code` returns the authorization code to Client A (Client A redeems it). `--mode=token` redeems the code for tokens on the broker side and returns tokens directly.

### 3. Start Client A (Requester) — on the sandboxed machine

```sh
bin/client-a \
  --relay=https://relay.example.com \
  --auth-url=https://provider.example.com/authorize \
  --token-url=https://provider.example.com/token \
  --client-id=my-oauth-client \
  --scopes=read,write \
  --key=requester-private.pem \
  --peer-pub=broker-public.pem
```

Client A encrypts the OAuth intent, publishes it to the relay, and blocks until Client B returns the auth code or tokens.

### Running locally (development)

For local testing, start the relay yourself instead of pointing at a deployed instance:

```sh
bin/relay --store=memory --addr=:8080
```

Then use `--relay=http://localhost:8080` for both clients. The in-memory store expires messages after 5 minutes.

Cloudflare header verification is enabled when `--cf-client-id` and `--cf-client-secret` are set (or via `CF_ACCESS_CLIENT_ID` / `CF_ACCESS_CLIENT_SECRET` env vars). When both are empty, all requests pass through.

## Docker compose testing

An end-to-end Docker Compose test exercises the full protocol flow across containers. Test keys are baked into the image at build time.

```sh
cd oob-auth

# Code mode (default) — tests the real client-b binary with piped stdin
docker compose -f docker-compose.test.yml up --build --abort-on-container-exit

# Token mode — uses test-broker with an embedded mock token endpoint
docker compose -f docker-compose.test.yml --profile token-mode up --build --abort-on-container-exit
```

The compose file defines four services:

| Service | Description |
|---------|-------------|
| `relay` | In-memory relay with health check on `/healthz` |
| `client-b` | Real client-b binary, auth code piped to stdin |
| `client-a` | Requester that publishes intent and prints the result |
| `test-broker` | Non-interactive broker for token-mode testing (profile: `token-mode`) |

A successful code-mode run prints `Auth Code: test-auth-code` from client-a.

## Infrastructure

Terraform definitions live in `infra/`. They provision:

- **GCP:** Artifact Registry (Docker), Cloud Run v2 (scale-to-zero), Firestore Native (with 5-minute TTL), scoped IAM service account, Secret Manager for Cloudflare credentials
- **Cloudflare:** Proxied CNAME to Cloud Run, WAF rate limiting (20 req/min/IP), geo-blocking, Zero Trust service tokens, HTTP header injection

```sh
cd infra
terraform init
terraform plan -var-file=prod.tfvars
```

Required variables are defined in `variables.tf`. Terraform validates but cannot plan/apply without GCP and Cloudflare credentials.

## Deploying

### Prerequisites

- GCP project with billing enabled
- Cloudflare zone and API token (set `CLOUDFLARE_API_TOKEN`)
- GCP credentials configured (`gcloud auth application-default login`)
- A `prod.tfvars` file with: `gcp_project`, `cloudflare_zone_id`, `domain`, `relay_image`, and optionally `allowed_countries`

### First deploy

```sh
# 1. Provision infrastructure
cd oob-auth/infra
terraform init
terraform apply -var-file=prod.tfvars

# 2. Authenticate Docker to Artifact Registry (one-time)
gcloud auth configure-docker $(terraform output -raw artifact_registry_url | cut -d/ -f1)

# 3. Build and push the relay image
docker build -t $(terraform output -raw artifact_registry_url)/relay:latest ..
docker push $(terraform output -raw artifact_registry_url)/relay:latest

# 4. Deploy the image to Cloud Run
terraform apply -var-file=prod.tfvars \
  -var="relay_image=$(terraform output -raw artifact_registry_url)/relay:latest"
```

### Subsequent deploys

Steps 3-4 only — build, push, apply:

```sh
cd oob-auth/infra
docker build -t $(terraform output -raw artifact_registry_url)/relay:latest ..
docker push $(terraform output -raw artifact_registry_url)/relay:latest
terraform apply -var-file=prod.tfvars \
  -var="relay_image=$(terraform output -raw artifact_registry_url)/relay:latest"
```

### Notes

- The Dockerfile builds all binaries (relay, client-a, client-b, test-broker, keygen) into a single image. Cloud Run only runs the relay via `command`/`args` in the Terraform config.
- Terraform is the single deployer — it manages both infra and the Cloud Run image revision. Using `gcloud run deploy` separately would cause state drift.
- There is no CI/CD pipeline; deploys are manual.
- State is local (no remote backend configured).

## How the protocol works

1. Both machines share Ed25519 public keys out of band.
2. Client A generates a PKCE challenge, wraps the OAuth intent in a NaCl box envelope encrypted to Client B's public key, and publishes it to the relay at a blind queue ID derived from Client B's key.
3. The relay stores the opaque ciphertext. It never sees plaintext.
4. Client B long-polls the relay, decrypts the intent, executes the OAuth flow, encrypts the result back to Client A, and publishes it to Client A's blind queue ID.
5. Client A receives and decrypts the tokens.

All secrets (keys, verifiers, tokens) are zeroed from memory immediately after use.
