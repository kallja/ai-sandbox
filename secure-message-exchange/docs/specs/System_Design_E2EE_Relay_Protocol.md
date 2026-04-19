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

---

## 3. Network Protocol & Byte Boundaries

All communication occurs via HTTP `POST` to the Relay Server. 

### 3.1. The Proof-of-Work (PoW) Header
To protect the server's CPU, the client must perform a computational puzzle before sending a request.
* **Algorithm:** The client generates a random string (`Nonce`) until: $SHA256(Nonce \parallel Ciphertext)$ results in a hash with **20 leading zero bits** (difficulty adjustable).
* **Transmission:** Sent as a plaintext HTTP header: `X-PoW-Nonce: <Nonce>`.

### 3.2. Client-to-Server Request (The Outer Envelope)
The `POST` body is strictly 4,096 bytes, encrypted via a **Sealed Box** using the Server's static public key.

| Byte Range | Length | Description |
| :--- | :--- | :--- |
| `0 - 31` | 32 bytes | **Client Ephemeral X25519 Public Key** (Used by the server to derive the shared secret). |
| `32 - 55` | 24 bytes | **Encryption Nonce** (For XChaCha20). |
| `56 - 4095` | 4,040 bytes | **AEAD Ciphertext** (Encrypted for the Server). |

**Inside the Decrypted Ciphertext (`56 - 4095`):**

| Byte Range | Length | Description |
| :--- | :--- | :--- |
| `0 - 255` | 256 bytes | **The Routing Header:** <br>• `[0-31]`: MessageID (for replay protection).<br>• `[32-63]`: Sender Fingerprint.<br>• `[64-95]`: Recipient Fingerprint (Server's fingerprint if polling).<br>• `[96-159]`: Ed25519 Signature.<br>• `[160-255]`: Padding. |
| `256 - 4039`| 3,784 bytes | **The Inner Envelope (E2EE Payload):** If routing to a peer, this is encrypted with the Recipient's public key (via Double Ratchet). |

### 3.3. Server-to-Client Response
The server always responds with HTTP `200 OK` and a 4,096-byte body. It encrypts this response using the **Client's Ephemeral Key** (provided in bytes `0-31` of the request).

| Byte Range | Length | Description |
| :--- | :--- | :--- |
| `0 - 23` | 24 bytes | **Encryption Nonce** (For XChaCha20). |
| `24 - 4095` | 4,072 bytes | **AEAD Ciphertext** (Encrypted for the polling Client). |

**Inside the Decrypted Ciphertext (`24 - 4095`):**

| Byte Range | Length | Description |
| :--- | :--- | :--- |
| `0 - 255` | 256 bytes | **Server Status Header:** <br>• `[0]`: Status Code (`0x01` DATA_FOLLOWS, `0x02` QUEUE_EMPTY, `0x03` ERR_AUTH_FAIL).<br>• `[1-255]`: Padding. |
| `256 - 4071`| 3,816 bytes | **The Payload:** If `DATA_FOLLOWS`, contains the stripped **Inner Envelope**. If `QUEUE_EMPTY` or error, filled entirely with cryptographically secure random noise. |

---

## 4. Relay Server Behavior

The Relay Server is a stateless Go backend (e.g., Cloud Run) backed by a fast datastore (e.g., Redis or Firestore).

1. **The Bouncer (PoW Check):** * Extract `X-PoW-Nonce` from headers.
   * Compute $SHA256(Nonce \parallel Body)$. 
   * If the hash lacks the required leading zeros, instantly terminate the connection (do not return an HTTP response, just drop).
2. **Derive & Decrypt:** Use the server's static private key and the client's Ephemeral Key to decrypt the Outer Envelope.
3. **Authenticate:** Verify the Ed25519 signature in the Routing Header. If invalid, return a padded `200 OK` with `ERR_AUTH_FAIL` status.
4. **Replay Protection:** Check the `MessageID` against a 5-minute TTL cache. If found, drop the payload and return `200 OK` (`QUEUE_EMPTY` noise).
5. **Route / Execute:**
    * **If `RecipientID` == Peer:** Strip the 256-byte Routing Header. Store the 3,784-byte Inner Envelope in the datastore under the Recipient's Fingerprint. Return padded `200 OK` (`QUEUE_EMPTY`).
    * **If `RecipientID` == Server (Poll):** Check datastore for the Sender's Fingerprint. If data exists, securely delete it from the DB (atomic Pop-and-Drop), package it, and return `200 OK` (`DATA_FOLLOWS`). If no data, return padded `200 OK` (`QUEUE_EMPTY`).

---

## 5. Client Application Behavior

The Client is a statically compiled Go CLI.

1. **Initialization:** Loads its own identity keys and the Relay Server's static public key. (Peer public keys are loaded out-of-band via configuration files for V1).
2. **Unified Enveloping:**
   * To message a peer: The client encrypts the payload using the Double Ratchet (Inner Envelope). It then wraps that in a Sealed Box addressed to the Relay Server (Outer Envelope).
   * To poll the server: The client skips the Double Ratchet, creating an empty payload, and wraps it in a Sealed Box addressed to the Relay Server.
3. **Transmission:** The client computes the PoW hash, attaches the header, and sends the 4 KB `POST`.
4. **Response Parsing:** * Decrypts the 4 KB response using the ephemeral private key generated for the request.
   * Inspects Byte `0` of the plaintext. 
   * If `0x01` (`DATA_FOLLOWS`), it passes the remaining bytes to the Double Ratchet engine to decrypt the peer's message.
   * If `0x02` (`QUEUE_EMPTY`), it discards the remaining bytes as noise and sleeps until the next poll.
