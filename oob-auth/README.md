# OOB-Auth: Remote Token Broker

Secure, serverless Out-of-Band OAuth 2.0 authorization flow between two isolated machines using E2EE and a blind cloud relay.

## Components

- **client-a** — Requester CLI (Go). Initiates OAuth, encrypts intent, publishes to relay.
- **client-b** — Trusted Broker CLI (Go). Long-polls relay, executes OAuth flow, returns tokens.
- **relay** — Stateless HTTP relay (Go). Blind message router backed by Firestore.
- **infra** — Terraform definitions for GCP + Cloudflare.
