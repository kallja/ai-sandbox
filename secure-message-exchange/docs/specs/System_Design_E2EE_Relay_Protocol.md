# System Design Specification: E2EE Relay Protocol

## 1. Architecture Overview
This system implements a zero-knowledge, asynchronous message relay. It provides metadata-obfuscated, quantum-resistant End-to-End Encryption (E2EE) between peers. The relay server operates as a stateless queue that cannot deduce the contents, byte boundaries, or network state of the messages it routes.

### Core Tenets
* **Unified Peer Model:** The Relay Server is treated as just another peer. All communications (Client-to-Client, Client-to-Server) use the same fundamental `Message` object.
* **Strict Padding:** Every HTTP request and response is exactly **4,096 bytes (4 KB)**.
* **Black Hole Networking:** All requests use `POST`. The server **always** returns HTTP `200 OK` with 4 KB of data, hiding all operational state from network observers.
* **Stateless Server Defense:** The server utilizes a Hashcash-style Proof-of-Work (PoW) header to drop asymmetric DDoS attacks before triggering expensive cryptographic operations.

---

## 2. Cryptographic Primitives

| Function | Algorithm | Purpose |
| :--- | :--- | :--- |
| **Symmetric Cipher** | XChaCha20-Poly1305 | Bulk encryption of the 4 KB envelopes. |
| **Client-to-Server KEM** | X25519 (Sealed Box) | Stateless asymmetric encryption for routing envelopes. |
| **Client-to-Client KEM** | X25519 + ML-KEM-768 | Hybrid Post-Quantum key exchange for peer payloads. |
| **Signatures** | Ed25519 | Sender authentication. |
| **Forward Secrecy** | Double Ratchet Algorithm | Session key rotation for peer-to-peer payloads. |
| **Proof of Work** | SHA-256 | Application-layer DDoS protection. |
| **Key Derivation** | HKDF-SHA-256 | Hybrid KEM secret combination and key expansion. |
| **Fingerprinting** | SHA-256 | Identity fingerprint derivation from Ed25519 public keys. |

### 2.1. Hybrid KEM Integration

The X25519 shared secret and the ML-KEM-768 shared secret are concatenated and passed through HKDF (HMAC-based Extract-and-Expand Key Derivation Function) using SHA-256. No custom combiners.

```
RK = HKDF(IKM = SS_X25519 ‖ SS_ML-KEM, salt = ∅, info = "E2EE-Relay-Hybrid-V1")
```

### 2.2. Fingerprint Derivation

The 32-byte routing fingerprint is the SHA-256 hash of the raw 32-byte Ed25519 Identity Public Key:

```
Fingerprint = SHA-256(Ed25519_PubKey_raw)
```

This produces exactly 32 bytes, fitting the fixed-length Routing Header with no truncation or encoding overhead.

### 2.3. Session Bootstrap (PQ-X3DH)

V1 uses statically configured peer keys (no Key Broker). The initial handshake for Client A sending the first message to Client B:

1. Client A generates an **Ephemeral X25519 keypair** and an **Ephemeral ML-KEM-768 keypair**.
2. Client A uses Client B's statically configured **Identity X25519** and **ML-KEM public keys** to compute the shared secrets.
3. Client A includes its **Ephemeral X25519 Public Key** (32 bytes) and the **ML-KEM Ciphertext** (1,088 bytes) in the header of the Inner Envelope for this first message.
4. The combined secrets form the initial **Root Key (RK)** for the Double Ratchet via the HKDF combiner defined in §2.1.
5. Once this first message is successfully processed by B, the standard Double Ratchet (rotating symmetric keys and classical ephemeral Diffie-Hellman) takes over.

---

## 3. Network Protocol & Byte Boundaries

All communication occurs via HTTP `POST` to the Relay Server. 

### 3.1. The Proof-of-Work (PoW) Header
To protect the server's CPU, the client must perform a computational puzzle before sending a request.
* **Algorithm:** The client generates a random string (`Nonce`) until: $SHA256(Nonce \parallel Ciphertext)$ results in a hash with **20 leading zero bits**.
* **Difficulty:** Hardcoded at 20 leading zero bits for V1. Dynamic difficulty is deferred because it would require the server to signal state to the client, violating the Black Hole networking model.
* **Transmission:** Sent as a plaintext HTTP header: `X-PoW-Nonce: <Nonce>`.

### 3.2. Client-to-Server Request (The Outer Envelope)
The `POST` body is strictly 4,096 bytes, encrypted via a **Sealed Box** using the Server's static public key.

| Byte Range | Length | Description |
| :--- | :--- | :--- |
| `0 - 31` | 32 bytes | **Client Ephemeral X25519 Public Key** (Used by the server to derive the shared secret). |
| `32 - 55` | 24 bytes | **Encryption Nonce** (For XChaCha20). |
| `56 - 4095` | 4,040 bytes | **AEAD Ciphertext** (Encrypted for the Server). |

**Inside the Decrypted Ciphertext (4,024 bytes after removing 16-byte AEAD tag):**

| Byte Range | Length | Description |
| :--- | :--- | :--- |
| `0 - 255` | 256 bytes | **The Routing Header:** <br>• `[0-31]`: MessageID (for replay protection).<br>• `[32-63]`: Sender Fingerprint.<br>• `[64-95]`: Recipient Fingerprint (Server's fingerprint if polling).<br>• `[96-159]`: Ed25519 Signature.<br>• `[160-255]`: Padding. |
| `256 - 4023`| 3,768 bytes | **The Inner Envelope (E2EE Payload):** If routing to a peer, this is encrypted with the Recipient's public key (via Double Ratchet). See §3.4 for format. |

### 3.3. Server-to-Client Response
The server always responds with HTTP `200 OK` and a 4,096-byte body. It encrypts this response using the **Client's Ephemeral Key** (provided in bytes `0-31` of the request).

| Byte Range | Length | Description |
| :--- | :--- | :--- |
| `0 - 23` | 24 bytes | **Encryption Nonce** (For XChaCha20). |
| `24 - 4095` | 4,072 bytes | **AEAD Ciphertext** (Encrypted for the polling Client). |

**Inside the Decrypted Ciphertext (4,056 bytes after removing 16-byte AEAD tag):**

| Byte Range | Length | Description |
| :--- | :--- | :--- |
| `0 - 255` | 256 bytes | **Server Status Header:** <br>• `[0]`: Status Code (`0x01` DATA_FOLLOWS, `0x02` QUEUE_EMPTY, `0x03` ERR_AUTH_FAIL).<br>• `[1-255]`: Padding. |
| `256 - 4055`| 3,800 bytes | **The Payload:** If `DATA_FOLLOWS`, contains the stripped **Inner Envelope**. If `QUEUE_EMPTY` or error, filled entirely with cryptographically secure random noise. |

### 3.4. The Inner Envelope (E2EE Payload) Format

The 3,768-byte Inner Envelope carries peer-to-peer encrypted content. A 1-byte type flag at the start distinguishes handshake messages from ratcheted messages.

> **Note on AEAD overhead:** XChaCha20-Poly1305 appends a 16-byte Poly1305 authentication tag to all ciphertext. The "AEAD Ciphertext" lengths below include this tag. The usable plaintext capacity is 16 bytes less than the ciphertext field size.

**Handshake Message (Type `0x01` — first message in a session):**

| Byte Range | Length | Description |
| :--- | :--- | :--- |
| `0` | 1 byte | **Type:** `0x01` (HANDSHAKE). |
| `1 - 32` | 32 bytes | **Ephemeral X25519 Public Key.** |
| `33 - 1120` | 1,088 bytes | **ML-KEM-768 Ciphertext.** |
| `1121 - 3767` | 2,647 bytes | **AEAD Ciphertext** (2,631 bytes plaintext + 16-byte tag): Encrypted message payload (XChaCha20-Poly1305 under the derived Root Key). |

**Ratcheted Message (Type `0x02` — subsequent messages):**

| Byte Range | Length | Description |
| :--- | :--- | :--- |
| `0` | 1 byte | **Type:** `0x02` (RATCHET). |
| `1 - 32` | 32 bytes | **Ratchet Ephemeral X25519 Public Key** (for DH ratchet step). |
| `33 - 36` | 4 bytes | **Message Number** (uint32, big-endian, for ordering within a chain). |
| `37 - 40` | 4 bytes | **Previous Chain Length** (uint32, big-endian, for detecting skipped messages). |
| `41 - 3767` | 3,727 bytes | **AEAD Ciphertext** (3,711 bytes plaintext + 16-byte tag): Encrypted message payload (XChaCha20-Poly1305 under the current chain key). |

---

## 4. Relay Server Behavior

The Relay Server is a stateless Go backend deployed on **Google Cloud Run (v2)**, backed by **Google Cloud Firestore (Native Mode)**.

1. **The Bouncer (PoW Check):** * Extract `X-PoW-Nonce` from headers.
   * Compute $SHA256(Nonce \parallel Body)$. 
   * If the hash lacks the required leading zeros, instantly terminate the connection (do not return an HTTP response, just drop).
2. **Derive & Decrypt:** Use the server's static private key and the client's Ephemeral Key to decrypt the Outer Envelope.
3. **Authenticate:** Verify the Ed25519 signature in the Routing Header. If invalid, return a padded `200 OK` with `ERR_AUTH_FAIL` status.
4. **Replay Protection:** Check the `MessageID` against a 5-minute TTL cache. If found, drop the payload and return `200 OK` (`QUEUE_EMPTY` noise).
5. **Route / Execute:**
    * **If `RecipientID` == Peer:** Strip the 256-byte Routing Header. Store the 3,768-byte Inner Envelope in Firestore under the Recipient's Fingerprint with a `created_at` timestamp. Return padded `200 OK` (`QUEUE_EMPTY`).
    * **If `RecipientID` == Server (Poll):** Query Firestore for messages matching the Sender's Fingerprint, ordered by `created_at ASC`, limited to 1 (strict FIFO, one message per poll). If data exists, use a Firestore `RunTransaction` to atomically read and delete the document (Pop-and-Drop), package it, and return `200 OK` (`DATA_FOLLOWS`). If no data, return padded `200 OK` (`QUEUE_EMPTY`).

---

## 5. Client Application Behavior

The Client is a statically compiled Go CLI (`CGO_ENABLED=0`).

1. **Initialization:** Loads its own identity keys and the Relay Server's static public key. Peer public keys are loaded out-of-band via a static JSON configuration file (see §6).
2. **Unified Enveloping:**
   * To message a peer: The client encrypts the payload using the Double Ratchet (Inner Envelope, see §3.4). It then wraps that in a Sealed Box addressed to the Relay Server (Outer Envelope).
   * To poll the server: The client skips the Double Ratchet, creating an empty payload, and wraps it in a Sealed Box addressed to the Relay Server.
3. **Transmission:** The client computes the PoW hash, attaches the header, and sends the 4 KB `POST`.
4. **Response Parsing:**
   * Decrypts the 4 KB response using the ephemeral private key generated for the request.
   * Inspects Byte `0` of the plaintext.
   * If `0x01` (`DATA_FOLLOWS`), it passes the remaining bytes to the Double Ratchet engine to decrypt the peer's message.
   * If `0x02` (`QUEUE_EMPTY`), it discards the remaining bytes as noise and sleeps until the next poll.
   * On `DATA_FOLLOWS`, the client immediately triggers another poll (rapid drain) until `QUEUE_EMPTY` is received.

---

## 6. Key Management & Storage

### 6.1. Key Generation

Use standard Go cryptographic libraries:
* `crypto/ed25519` — Identity signing keys.
* `crypto/ecdh` — X25519 key exchange.
* `crypto/mlkem` (Go 1.24+) — ML-KEM-768 post-quantum KEM.

### 6.2. Local Identity Keys (Private)

Private keys are stored in **PKCS#8 ASN.1 DER format, PEM-encoded**. Key files **must** have `0600` permissions (read/write by owner only). The CLI should refuse to load keys with more permissive permissions.

### 6.3. Peer Keys (Public)

Peer public keys are distributed out-of-band and provided to the CLI via a static JSON configuration file:

```json
{
  "peers": {
    "alice": {
      "ed25519": "<base64-encoded raw Ed25519 public key>",
      "x25519": "<base64-encoded raw X25519 public key>",
      "mlkem768": "<base64-encoded raw ML-KEM-768 public key>"
    }
  },
  "relay": {
    "url": "https://relay.example.com",
    "x25519": "<base64-encoded raw X25519 public key>"
  }
}
```

---

## 7. Deployment

### 7.1. Relay Server

* **Platform:** Google Cloud Run (v2).
* **Artifact:** Statically compiled Go binary (`CGO_ENABLED=0`) in a `scratch` or `distroless` Docker container exposing a single HTTP port. The container contains nothing but the binary.
* **Datastore:** Google Cloud Firestore (Native Mode) — supports scale-to-zero for minimal cost.
* **Concurrency:** Cloud Run handles concurrent request routing; each incoming HTTP request is treated as a synchronous, isolated goroutine.
