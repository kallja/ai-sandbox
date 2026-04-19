# Implementation Plan: E2EE Relay Protocol

## Context

We're building the system defined in `secure-message-exchange/docs/specs/System_Design_E2EE_Relay_Protocol.md` — a zero-knowledge, asynchronous message relay with quantum-resistant E2EE. Two Go components: a relay server (Cloud Run + Firestore) and a CLI client. The existing `oob-auth/` module provides established patterns we'll follow for HTTP servers, Firestore stores, key management, Terraform, and testing.

---

## Pre-Implementation: Spec Correction (AEAD Overhead)

XChaCha20-Poly1305 appends a 16-byte Poly1305 tag. The spec's byte tables list decrypted contents at the same size as the ciphertext, which is incorrect. Corrected sizes:

| Region | Spec says | Corrected |
|--------|-----------|-----------|
| Outer plaintext (routing + inner) | 4040B | **4024B** (4040 - 16 tag) |
| Inner envelope | 3784B | **3768B** (4024 - 256 routing) |
| Response plaintext (status + payload) | 4072B | **4056B** (4072 - 16 tag) |
| Response payload region | 3816B | **3800B** (4056 - 256 status) |
| Handshake AEAD payload | 2663B ct | **2647B** ct / 2631B pt |
| Ratchet AEAD payload | 3743B ct | **3727B** ct / 3711B pt |

**Action:** Update the spec tables before starting implementation.

---

## Go Module & Shared Architecture

New module at `secure-message-exchange/`, separate from `oob-auth/`. Target Go **1.26.2**.

The relay server and client binaries share cryptographic and protocol code via **shared library packages** within the same module. The relay binary imports these packages as library code — it MUST NOT invoke or include built client binaries.

```
module github.com/kallja/ai-sandbox/secure-message-exchange
go 1.26.2
```

Dependencies:
- **stdlib**: `crypto/ecdh`, `crypto/ed25519`, `crypto/mlkem`
- **golang.org/x/crypto**: `chacha20poly1305` (`NewX()`), `hkdf`
- **github.com/status-im/doubleratchet**: Double Ratchet state machine
- **cloud.google.com/go/firestore**: production datastore

---

## Package Structure

```
secure-message-exchange/
  go.mod
  go.sum

  # ── Shared library packages (used by both relay and client) ──────────
  wire/                    # Constants, sizes, padding helpers
  crypto/                  # Sealed box, hybrid KEM, PoW, keys, fingerprints, zeroing
  ratchet/                 # Double Ratchet session wrapper + custom Crypto adapter
  envelope/                # Outer/inner envelope and response construction/parsing

  # ── Server-only packages ─────────────────────────────────────────────
  relay/                   # Server, Store interface, MemStore, FirestoreStore, replay cache

  # ── Client-only packages ─────────────────────────────────────────────
  client/                  # Config loading, send flow, poll flow

  # ── Binaries ─────────────────────────────────────────────────────────
  cmd/relay/main.go        # Relay server
  cmd/client/main.go       # CLI client (send/poll subcommands)
  cmd/keygen/main.go       # Key generation utility (Ed25519, X25519, ML-KEM-768)

  # ── Tests ────────────────────────────────────────────────────────────
  integration/e2e_test.go  # In-process integration tests (httptest + MemStore)
  e2etest/e2e_test.go      # Binary-level e2e tests (builds & runs actual binaries)

  # ── Deployment ───────────────────────────────────────────────────────
  Dockerfile.relay         # Multi-stage: build → distroless (relay server)
  Dockerfile.client        # Multi-stage: build → distroless (client CLI)
  docker-compose.yml       # Local testing environment
  scripts/
    deploy.sh              # Staged deploy: registry → build/push → Cloud Run
    provision-keys.sh      # Generate keys, populate GSM secrets
  infra/                   # Terraform (single config, staged apply)
    main.tf
    gcp.tf
    variables.tf
    outputs.tf

  docs/specs/              # (existing spec)
```

---

## Commit Strategy

Every commit must leave the repo in a working condition (`go build ./...` and `go test ./...` pass for all code committed so far). Commits are small and incremental — roughly one per task. Each commit is a conventional commit (`feat:`, `test:`, `chore:`, `docs:`, etc.).

---

## Build Phases

### Phase 1: Wire Format (`wire/`)
- All byte-boundary constants as named `const` values (corrected for AEAD overhead)
- Status codes (`0x01` DATA_FOLLOWS, `0x02` QUEUE_EMPTY, `0x03` ERR_AUTH_FAIL)
- Message types (`0x01` HANDSHAKE, `0x02` RATCHET)
- `PadToSize(data, size)` — pads with `crypto/rand` noise
- `ValidateSize(data, expected)` — returns error if mismatch
- **Tests:** Static consistency assertions — all sizes add up, regions don't overlap, AEAD overhead accounted for

### Phase 2: Crypto Primitives (`crypto/`)
- `fingerprint.go` — `SHA-256(Ed25519 pubkey)` → 32-byte fingerprint
- `keys.go` — Generate/save/load Ed25519, X25519, ML-KEM-768 keys. PEM/PKCS#8, enforce 0600 perms. Reuse patterns from `oob-auth/crypto/crypto.go`
- `sealedbox.go` — Custom sealed box (NOT NaCl): ephemeral X25519 ECDH → HKDF-SHA256 (`info="E2EE-Relay-SealedBox-V1"`) → XChaCha20-Poly1305
- `hybrid.go` — `HybridEncapsulate`/`HybridDecapsulate`: X25519 + ML-KEM-768 → HKDF (`info="E2EE-Relay-Hybrid-V1"`) → 32-byte root key
- `pow.go` — `ComputePoW`/`VerifyPoW`: SHA-256(nonce || body), configurable difficulty
- `zero.go` — Secure memory wiping
- **Tests:** Round-trip for every primitive; wrong-key rejection; tampered-ciphertext rejection; unique ciphertexts for same plaintext; permission enforcement; ML-KEM ciphertext size validation

### Phase 3: Double Ratchet (`ratchet/`)
- Custom `doubleratchet.Crypto` adapter using our X25519 and XChaCha20-Poly1305
- `Session` wrapper: `Encrypt` → extracts `(ratchetPub, msgNum, prevChain, ciphertext)`; `Decrypt` → reconstructs `Message` and delegates
- `NewInitiatorSession(rootKey, remoteRatchetPub)` / `NewResponderSession(rootKey, localRatchetKeyPair)`
- In-memory session store keyed by peer fingerprint
- **Risk mitigation:** If doubleratchet library's `Crypto` interface doesn't fit, fall back to implementing ratchet from scratch (~300 lines)
- **Tests:** Bidirectional exchange; multiple messages with ratchet advancement; out-of-order within chain; wrong session can't decrypt

### Phase 4: Envelope Construction (`envelope/`)
- `routing.go` — Build/parse 256-byte routing header. Signature covers `MessageID || SenderFP || RecipientFP || InnerEnvelope`
- `inner.go` — Build/parse 3768-byte inner envelopes (type 0x01 handshake, 0x02 ratchet)
- `outer.go` — `SealOuterEnvelope` / `OpenOuterEnvelope` → 4096-byte request bodies
- `response.go` — `SealResponse` / `OpenResponse` → 4096-byte responses. HKDF `info="E2EE-Relay-Response-V1"` for domain separation from request key
- **Tests:** Seal/open round-trips at every layer; exact 4096-byte output; wrong key rejection; type dispatch; tamper detection

### Phase 5: Relay Server (`relay/`)
- `Store` interface: `Push(ctx, recipientFP, data)` / `Pop(ctx, recipientFP) (data, error)` — FIFO queue, immediate return
- `MemStore` — `map[string][]storedMessage`, FIFO per recipient
- `FirestoreStore` — Collection `e2ee_relay_queue`, `RunTransaction` atomic pop-and-drop, `created_at ASC LIMIT 1` (pattern from `oob-auth/relay/firestore.go`)
- `ReplayCache` — In-memory `map[[32]byte]time.Time` with 5-min TTL
- `ClientRegistry` interface — `LookupByFingerprint(fp) (ed25519.PublicKey, bool)`. Server needs client pubkeys to verify signatures
- `Server` — Single `POST /` endpoint. Pipeline: read 4096B → PoW check (hijack+close on failure) → decrypt outer → verify signature → replay check → route → encrypt response → write 4096B
- Logging middleware (method + status + duration only)
- **Tests:** Full lifecycle per status code; PoW rejection (connection dropped); replay protection; FIFO ordering; queue isolation; all responses exactly 4096 bytes

### Phase 6: Client Library (`client/`)
- `config.go` — Load peer JSON config (base64 pubkeys), load identity keys from PEM dir
- `send.go` — Handshake (HybridEncapsulate + XChaCha20 under root key) or ratchet encrypt → build inner → routing header → seal outer → PoW → POST → parse response
- `poll.go` — Noise inner → routing with server FP → seal → PoW → POST → parse → rapid drain loop until QUEUE_EMPTY
- **Design note:** Server needs Ed25519 identity for fingerprinting. Add `ed25519` to relay config JSON
- **Tests:** Mock HTTP server; send flow produces valid 4096B envelope; poll parses responses; rapid drain behavior; handshake round-trip between two client instances

### Phase 7: CLI Entry Points (`cmd/`)
- `cmd/keygen/` — Generates Ed25519 + X25519 + ML-KEM-768. Saves private as PEM (0600), outputs public keys as base64 for peer config. Prints fingerprint. Accepts `--dir` flag for output directory
- `cmd/relay/` — Flag parsing, store selection (`--store memory|firestore`), `--gcp-project`, `--key-dir`, graceful shutdown (follow `oob-auth/cmd/relay/main.go` pattern)
- `cmd/client/` — Subcommands: `send --config peers.json --identity ./keys --peer alice --message "hello"`, `poll --config peers.json --identity ./keys`

### Phase 8: Tests (see Test Plan section below)

### Phase 9: Docker & Compose (see Docker section below)

### Phase 10: Infrastructure (see Infrastructure section below)

---

## Test Plan

### Unit Tests (per package, run with `go test ./<pkg>/`)

Every package has `*_test.go` files alongside source. Design for testability: accept interfaces, use dependency injection, expose configurable parameters (e.g., PoW difficulty).

#### `wire/`
- Consistency assertions: all constant sums match (e.g., `EphKeySize + NonceSize + OuterCiphertextSize == OuterEnvelopeSize`)
- AEAD overhead correctly subtracted at every layer
- `PadToSize` produces exact length, fills with non-zero random bytes
- `ValidateSize` rejects wrong sizes

#### `crypto/`
**Security-critical — test exhaustively:**
- `fingerprint`: deterministic output, different keys → different fingerprints, exactly 32 bytes
- `keys`: generate → save → load round-trip for each key type; 0600 permission enforcement (create with 0644, verify rejection); invalid PEM rejection; PKCS#8 format validation
- `sealedbox`: seal → open round-trip; wrong key fails; tampered ciphertext fails AEAD; unique nonces per seal; unique ciphertext for same plaintext (randomized encryption)
- `hybrid`: encapsulate → decapsulate yields same root key; wrong X25519 key fails; wrong ML-KEM key fails; ML-KEM ciphertext is exactly 1088 bytes; ephemeral pubkey is exactly 32 bytes
- `pow`: compute → verify round-trip; wrong nonce fails; difficulty=0 always passes; use difficulty=8 for fast unit tests; one test at difficulty=20 (may be slow, mark with `testing.Short()` skip)
- `zero`: buffer is zeroed after call

#### `ratchet/`
- Create initiator + responder sessions with shared root key → encrypt on initiator, decrypt on responder
- Multiple messages back and forth (ratchet advances)
- Out-of-order messages within a chain (skipped message keys handled)
- Wrong session cannot decrypt
- Custom `Crypto` adapter: verify DH uses X25519, AEAD uses XChaCha20-Poly1305

#### `envelope/`
- `routing`: marshal → parse round-trip; signature verification; tampered header or payload fails verification; MessageID is random (unique per call)
- `inner`: build → parse round-trip for handshake (0x01) and ratchet (0x02); wrong type byte rejected; exact 3768-byte output; field offsets are correct
- `outer`: seal → open round-trip; output is exactly 4096 bytes; wrong server key fails
- `response`: seal → open for each status code; DATA_FOLLOWS carries correct payload; QUEUE_EMPTY/ERR_AUTH_FAIL filled with random noise; output is exactly 4096 bytes

#### `relay/`
- `MemStore`: push → pop round-trip; FIFO ordering (push 3, pop 3 in order); pop on empty returns nil; queue isolation (different fingerprints don't interfere)
- `FirestoreStore`: same tests but only run when Firestore is available (build tag or env var gate, same as oob-auth approach)
- `ReplayCache`: add → check returns true; unseen ID returns false; expired entries return false (inject clock for testing)
- `Server` (using `httptest` + `MemStore`):
  - Valid send request → stored in MemStore
  - Valid poll request → DATA_FOLLOWS when message exists
  - Valid poll request → QUEUE_EMPTY when empty
  - Invalid PoW → connection dropped (no HTTP response)
  - Invalid signature → ERR_AUTH_FAIL
  - Replayed MessageID → QUEUE_EMPTY (no duplicate delivery)
  - All response bodies are exactly 4096 bytes
  - Request body != 4096 bytes → silently dropped

#### `client/`
- `config`: load valid JSON config → correct key types; load identity keys → permission check; invalid config → meaningful error
- `send`: mock HTTP server captures request; verify 4096-byte body, valid PoW, parseable envelope, correct routing
- `poll`: mock server returns DATA_FOLLOWS → verify decryption; mock returns QUEUE_EMPTY → verify nil result
- Rapid drain: mock returns DATA_FOLLOWS twice then QUEUE_EMPTY → verify 3 HTTP requests

### Integration Tests (`integration/e2e_test.go`)

In-process tests using `httptest.NewServer` + `MemStore` + real crypto. Pattern from `oob-auth/integration/e2e_test.go`: goroutines + channels, `context.WithTimeout`.

1. **Full handshake + message delivery**: Alice generates keys, sends handshake message to Bob via relay. Bob polls, receives, decrypts. Verify message content matches.
2. **Ratcheted reply**: Following test 1, Bob sends a ratcheted reply. Alice polls, decrypts. Verify contents.
3. **Multi-message FIFO**: Alice sends 3 messages to Bob. Bob polls 3 times. Verify messages arrive in order.
4. **Rapid drain**: Alice sends 2 messages. Bob's client library auto-drains both in a single poll call. Third poll returns QUEUE_EMPTY.
5. **Replay protection**: Alice sends a message. Replay the exact raw bytes. Bob does NOT receive a duplicate.
6. **PoW rejection**: Send request with bad `X-PoW-Nonce`. Verify no HTTP response (connection dropped).
7. **Auth failure**: Send request with bad Ed25519 signature. Verify ERR_AUTH_FAIL response.
8. **Constant-size responses**: Intercept all HTTP responses, verify every body is exactly 4096 bytes.
9. **Queue isolation**: Alice→Bob and Carol→Dave concurrently. Each recipient only receives their own messages.
10. **Empty poll**: Poll with no pending messages → QUEUE_EMPTY with noise-filled payload.

### End-to-End Binary Tests (`e2etest/e2e_test.go`)

These build the actual `cmd/relay`, `cmd/client`, and `cmd/keygen` binaries as subprocesses and test their interactions. This validates CLI flag parsing, binary packaging, and real-world usage.

**Test setup (shared helper):**
1. `go build` all three binaries to a temp dir
2. Run `keygen` to generate identity keys for Alice, Bob, and the relay server
3. Build peer config JSON files for Alice and Bob
4. Start relay binary as subprocess (`--store=memory`, `--addr=:0` for random port, `--key-dir=<tmpdir>`)
5. Wait for relay to be ready (poll health or parse stdout for listening address)

**Test cases:**
1. **Keygen produces valid keys**: Run `keygen --dir=<tmp>`. Verify output files exist, private keys have 0600 perms, public keys are valid base64.
2. **Send + poll round-trip**: Alice runs `client send --peer bob --message "hello"`. Bob runs `client poll`. Verify Bob's stdout contains "hello".
3. **Multiple messages**: Alice sends 3 messages. Bob polls → receives all 3 in order.
4. **Bidirectional**: Alice sends to Bob, Bob sends to Alice. Both poll and receive.
5. **Invalid config**: Client with bad config path → non-zero exit code, meaningful stderr.
6. **Relay rejects bad PoW**: Craft a raw HTTP request with invalid PoW nonce → connection dropped.

**Cleanup:** Kill relay subprocess, remove temp dirs.

### Test Commands

```bash
# Unit tests (fast, no external deps)
go test ./wire/ ./crypto/ ./ratchet/ ./envelope/ ./relay/ ./client/

# Integration tests (in-process, MemStore, real crypto)
go test ./integration/

# E2E binary tests (builds binaries, spawns processes)
go test ./e2etest/ -timeout 120s

# All tests
go test ./...

# Short mode (skip slow PoW tests)
go test -short ./...
```

---

## Docker

### `Dockerfile.relay`
Multi-stage build. `golang:1.26-alpine` → `gcr.io/distroless/static-debian12:nonroot`. `CGO_ENABLED=0`. Exposes port 8080. Contains only the relay binary.

### `Dockerfile.client`
Multi-stage build. Same pattern. Contains the `client` and `keygen` binaries (both in one image for convenience).

### `docker-compose.yml` (local testing)

```yaml
services:
  relay:
    build:
      context: .
      dockerfile: Dockerfile.relay
    ports:
      - "127.0.0.1:8080:8080"
    volumes:
      - ./testdata/relay-keys:/keys:ro
    command: ["--store=memory", "--key-dir=/keys"]

  alice:
    build:
      context: .
      dockerfile: Dockerfile.client
    volumes:
      - ./testdata/alice-keys:/keys:ro
      - ./testdata/alice-config.json:/config.json:ro
    depends_on:
      - relay
    # Override entrypoint for interactive use:
    # docker compose run alice client send --peer bob --message "hello"
    entrypoint: ["/bin/sh", "-c", "echo 'Use: docker compose run alice /client send ...'"]

  bob:
    build:
      context: .
      dockerfile: Dockerfile.client
    volumes:
      - ./testdata/bob-keys:/keys:ro
      - ./testdata/bob-config.json:/config.json:ro
    depends_on:
      - relay
    entrypoint: ["/bin/sh", "-c", "echo 'Use: docker compose run bob /client poll ...'"]
```

This lets a developer run:
```bash
docker compose up -d relay
docker compose run alice /client send --config /config.json --identity /keys --peer bob --message "test"
docker compose run bob /client poll --config /config.json --identity /keys
```

---

## Infrastructure (`infra/`)

Single Terraform config. Same GCP project as oob-auth. Region: `europe-north1`. Separate Firestore database.

### Resources

**Artifact Registry** (created first via `-target`):
```
google_artifact_registry_repository.e2ee_relay
google_artifact_registry_repository.e2ee_client
```
- Docker format, `europe-north1`
- IAM: Cloud Run service account gets `roles/artifactregistry.reader`

**Firestore** (separate from oob-auth):
```
google_firestore_database.e2ee_queue        # "e2ee-relay-queue", FIRESTORE_NATIVE
google_firestore_field.queue_ttl            # TTL on created_at (auto-purge)
```

**Secret Manager** (created before Cloud Run, manually populated):
```
google_secret_manager_secret.relay_ed25519_private
google_secret_manager_secret.relay_x25519_private
google_secret_manager_secret.relay_ed25519_public   # Public keys for client config distribution
google_secret_manager_secret.relay_x25519_public
```
- Cloud Run service account gets `roles/secretmanager.secretAccessor`

**Service Account**:
```
google_service_account.e2ee_relay           # "e2ee-relay"
```
- `roles/datastore.user` scoped to the e2ee Firestore DB (condition, same pattern as oob-auth)
- `roles/artifactregistry.reader`
- `roles/secretmanager.secretAccessor`

**Cloud Run v2**:
```
google_cloud_run_v2_service.e2ee_relay
```
- Image: `var.relay_image` (full `region-docker.pkg.dev/project/repo/image@sha256:...` reference)
- Port 8080
- Scale to zero
- Env vars / secret mounts for key material from Secret Manager
- Service account: `e2ee-relay`

### Variables

```hcl
variable "gcp_project" {}                                # Same as oob-auth
variable "gcp_region" { default = "europe-north1" }
variable "relay_image" {}                                # Full image@sha256:digest
variable "client_image" {}                               # Full image@sha256:digest (for reference/outputs)
```

### Outputs

```hcl
output "cloud_run_url" {}
output "relay_registry_url" {}        # For build scripts
output "client_registry_url" {}       # For build scripts  
output "service_account_email" {}
```

---

## Scripts

### `scripts/deploy.sh`

Orchestrates first and subsequent deploys. Uses `set -euo pipefail`.

```bash
#!/usr/bin/env bash
set -euo pipefail

# Phase 1: Create registry, secrets, Firestore, IAM
terraform -chdir=infra apply \
  -target=google_artifact_registry_repository.e2ee_relay \
  -target=google_artifact_registry_repository.e2ee_client \
  -target=google_secret_manager_secret.relay_ed25519_private \
  -target=google_secret_manager_secret.relay_x25519_private \
  -target=google_secret_manager_secret.relay_ed25519_public \
  -target=google_secret_manager_secret.relay_x25519_public \
  -target=google_firestore_database.e2ee_queue \
  -target=google_firestore_field.queue_ttl \
  -target=google_service_account.e2ee_relay \
  -target=google_project_iam_member.relay_firestore \
  -target=google_secret_manager_secret_iam_member.relay_ed25519_private_access \
  -target=google_secret_manager_secret_iam_member.relay_x25519_private_access \
  -var="relay_image=placeholder" \
  -var="client_image=placeholder"

# Phase 2: Check if secrets are populated; if not, prompt
echo "Checking if relay keys are provisioned in Secret Manager..."
echo "If not yet done, run: ./scripts/provision-keys.sh"
read -p "Press Enter when secrets are populated..."

# Phase 3: Build, tag, push images
RELAY_REPO=$(terraform -chdir=infra output -raw relay_registry_url)
CLIENT_REPO=$(terraform -chdir=infra output -raw client_registry_url)

docker build -f Dockerfile.relay -t e2ee-relay .
docker build -f Dockerfile.client -t e2ee-client .

docker tag e2ee-relay "${RELAY_REPO}:build-$(date +%s)"
docker tag e2ee-client "${CLIENT_REPO}:build-$(date +%s)"

docker push "${RELAY_REPO}:build-*"    # pushes by tag
docker push "${CLIENT_REPO}:build-*"

# Phase 4: Capture SHA256 digests
RELAY_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "${RELAY_REPO}:build-*" | cut -d@ -f2)
CLIENT_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "${CLIENT_REPO}:build-*" | cut -d@ -f2)

RELAY_IMAGE="${RELAY_REPO}@${RELAY_DIGEST}"
CLIENT_IMAGE="${CLIENT_REPO}@${CLIENT_DIGEST}"

echo "Relay image:  ${RELAY_IMAGE}"
echo "Client image: ${CLIENT_IMAGE}"

# Phase 5: Full terraform apply with image digests
terraform -chdir=infra apply \
  -var="relay_image=${RELAY_IMAGE}" \
  -var="client_image=${CLIENT_IMAGE}"
```

### `scripts/provision-keys.sh`

Generates relay server keys and populates GSM secrets. Requires `keygen` binary and `gcloud` CLI.

```bash
#!/usr/bin/env bash
set -euo pipefail

PROJECT="${GCP_PROJECT:?Set GCP_PROJECT}"
KEY_DIR=$(mktemp -d)
trap 'rm -rf "${KEY_DIR}"' EXIT

echo "Generating relay server identity keys..."
go run ./cmd/keygen --dir="${KEY_DIR}"

echo "Uploading private keys to Secret Manager..."
gcloud secrets versions add e2ee-relay-ed25519-private \
  --project="${PROJECT}" \
  --data-file="${KEY_DIR}/ed25519.pem"

gcloud secrets versions add e2ee-relay-x25519-private \
  --project="${PROJECT}" \
  --data-file="${KEY_DIR}/x25519.pem"

echo "Uploading public keys to Secret Manager..."
gcloud secrets versions add e2ee-relay-ed25519-public \
  --project="${PROJECT}" \
  --data-file="${KEY_DIR}/ed25519.pub"

gcloud secrets versions add e2ee-relay-x25519-public \
  --project="${PROJECT}" \
  --data-file="${KEY_DIR}/x25519.pub"

echo ""
echo "Done. Relay server fingerprint:"
cat "${KEY_DIR}/fingerprint.txt"
echo ""
echo "Add this fingerprint and public keys to client peer config files."
```

---

## Key Design Decisions

1. **Separate Go module** — different deps from oob-auth, no shared code between modules
2. **Shared library packages** — `wire/`, `crypto/`, `ratchet/`, `envelope/` used by both relay and client binaries
3. **Custom sealed box** — spec uses XChaCha20-Poly1305, not NaCl's XSalsa20-Poly1305
4. **HKDF domain separation** — distinct info strings: `SealedBox-V1`, `Hybrid-V1`, `Response-V1`
5. **doubleratchet library for state, custom serialization** — library manages chains/keys, we serialize into fixed wire format
6. **Handshake message uses root key directly** — Double Ratchet starts from message 2
7. **Server needs Ed25519 identity** — for fingerprint in routing headers when clients poll
8. **Connection hijacking for PoW failure** — `http.Hijacker` to close TCP without HTTP response
9. **V1 sessions are ephemeral** — no disk persistence; each send does fresh handshake
10. **Container images referenced by SHA256 digest** — exact control + security in Cloud Run
11. **Staged Terraform deploy** — registry + secrets first, then build/push, then Cloud Run
12. **Secret Manager for server keys** — provisioned via script, mounted into Cloud Run

---

## Dependency Graph

```
Phase 1: wire/           (no deps)
Phase 2: crypto/         (wire/)
Phase 3: ratchet/        (crypto/)
Phase 4: envelope/       (wire/, crypto/, ratchet/)
Phase 5: relay/          (wire/, crypto/, envelope/)
Phase 6: client/         (all shared packages)
Phase 7: cmd/            (relay/, client/)
Phase 8: tests           (all above)
Phase 9: docker/compose  (independent, after Phase 7)
Phase 10: infra/         (independent, can parallel with anything)
```

---

## Verification Milestones

| Phase | Command | Proves |
|-------|---------|--------|
| 1 | `go test ./wire/` | Byte math is self-consistent |
| 2 | `go test ./crypto/` | All crypto primitives work in isolation |
| 3 | `go test ./ratchet/` | Two sessions exchange messages bidirectionally |
| 4 | `go test ./envelope/` | Full 4096-byte envelopes build/parse correctly |
| 5 | `go test ./relay/` | Server handles complete request lifecycle |
| 6 | `go test ./client/` | Client constructs/parses complete messages |
| 7 | `go build ./cmd/...` | All binaries compile |
| 8a | `go test ./integration/` | Components work together in-process |
| 8b | `go test ./e2etest/` | Real binaries interact correctly |
| 9 | `docker compose up` | Containers build and services start |
| 10 | `terraform plan` | Infrastructure is valid |
| All | `go test ./...` | Everything passes |

---

## Critical Reference Files

- `oob-auth/relay/server.go` — HTTP server pattern (NewServer, Handler, ServeMux)
- `oob-auth/relay/firestore.go` — Firestore atomic pop-and-drop with RunTransaction
- `oob-auth/relay/memstore.go` — In-memory store pattern
- `oob-auth/crypto/crypto.go` — Key management (PKCS#8 PEM, SavePrivateKey/LoadPrivateKey, Zero, Fingerprint)
- `oob-auth/cmd/relay/main.go` — CLI entry point (flags, envOrDefault, graceful shutdown)
- `oob-auth/integration/e2e_test.go` — Integration test pattern (httptest, goroutines+channels)
- `oob-auth/infra/gcp.tf` — Terraform patterns (Cloud Run, Firestore, Secret Manager, IAM scoping)
