# Onceveil threat model

This document defines the security guarantees and explicit non-guarantees for the current Onceveil foundations. Recipient authentication, portable deployment, and MCP integration remain separate implementation slices.

## Security invariants

1. **Passive requests do not consume or reveal secrets.** GET, HEAD, link previews, crawlers, prefetchers, and similar passive requests must never transition a secret to `CONSUMED` or receive ciphertext. A passive status read may record `AVAILABLE → EXPIRED` after the deadline.
2. **Strict one-time retrieval.** The first successful atomic consume operation transitions `AVAILABLE → CONSUMED` and is the only operation allowed to receive ciphertext.
3. **Consumption is final.** If the winning client or network fails after the server commits `CONSUMED`, the secret is lost. Onceveil does not use a lease/acknowledgement protocol.
4. **The service does not receive plaintext or encryption keys.** Browser crypto encrypts before upload and decrypts only after retrieval.
5. **Configured reveal protection fails closed.** A missing, invalid, or unavailable protection provider must not silently degrade to unprotected reveal.
6. **MCP does not carry secret material.** Later MCP tools may orchestrate secure browser handoff, status, and revocation, but not plaintext, decryption keys, ciphertext bodies intended for the recipient, or complete anonymous share URLs.

## Lifecycle

A secret has exactly one of these states:

```text
AVAILABLE ──consume──> CONSUMED
    │
    ├──expire───────> EXPIRED
    │
    └──revoke───────> REVOKED
```

`CONSUMED`, `EXPIRED`, and `REVOKED` are terminal states. They never transition back to `AVAILABLE` and never return ciphertext.

Expiration is evaluated before consume or revoke. At or after the expiry timestamp, an `AVAILABLE` secret is treated as `EXPIRED`.

## Atomic consume boundary

Persistence adapters must implement consume and revoke as atomic conditional state transitions:

```text
AVAILABLE -> CONSUMED + return ciphertext
AVAILABLE -> REVOKED
```

Exactly one concurrent terminal operation may win. A consume/revoke race must end in either `CONSUMED` or `REVOKED`, never both. Losing callers receive only terminal-state information and never ciphertext.

A read followed by a separate write is insufficient because two callers could both observe `AVAILABLE`. Each storage adapter must provide its own test proving the atomic contract.

## Anonymous reveal capability

Possession of a complete anonymous share URL is possession of the reveal capability.

The protected share-fragment format is `/s/:id#v2.<base64url-key>.<reveal-authorization>`. The encrypted payload protocol remains `v1`; fragment versioning is independent so the Turnstile security boundary does not silently redefine the existing crypto envelope. The server allocates the public `:id` with 128 bits of cryptographic randomness when the encrypted payload is stored. The browser independently generates a 256-bit AES-GCM key, a 96-bit nonce, and a 128-bit random crypto context identifier before encryption. The reveal authorization is the SHA-256 replay key of the canonical encrypted payload; the server already persists the same value for idempotent create handling. Both values travel in the URL fragment, so ordinary HTTP requests and passive link previews send neither to the server. After the reveal page copies the fragment into page memory, it replaces the current history entry with the fragment-free path immediately. Only the reveal authorization, never the AES key, is later sent back to authorize preparation of the Turnstile proof.

Legacy `/s/:id#v1.<base64url-key>` fragments are recognized as the previous format but cannot satisfy the new proof-preparation boundary because they contain no server-verifiable authorization. Onceveil does not fall back to unprotected reveal and never sends the AES key to the server. Migration `0006_expire_legacy_share_links.sql` therefore makes the security upgrade explicit: it first rejects any new insert without a replay key, then moves still-`AVAILABLE` legacy rows to terminal `EXPIRED` state. This keeps the migration fail-closed even if the previous Worker is still serving briefly during deployment, without adding a separate rollout protocol.

AES-GCM authenticates the ciphertext and associated data `onceveil:v1:<contextId>`. The crypto context identifier is carried inside the encrypted payload envelope and is distinct from the server-issued public reveal identifier. A modified ciphertext, crypto context identifier, version, nonce, or wrong key must fail authentication. This does **not** authenticate a person.

A recipient-authenticated mode may be added later, but it is outside the current scope.

## Owner management capability

Secret creation generates a separate 256-bit random owner capability in the browser. It is independent from the recipient share fragment, encryption key, reveal authorization, and public secret identifier. Only the SHA-256 hash of the owner capability is sent during creation and stored in D1; the raw capability is returned to the creator only as part of the fragment-only owner link `/o/:id#v1.<capability>`.

The owner page copies the fragment into page memory and immediately removes it from the visible URL/history entry before making any management request. Owner requests send the capability only in the standard `Authorization: Bearer` header. Application logging must never record this header or the raw capability.

Status and revoke are authorized at the repository boundary by the stored owner hash. A wrong owner capability is indistinguishable from an unknown public identifier. Owner status exposes only lifecycle state and expiry; it never returns ciphertext, plaintext, encryption keys, recipient share material, or the owner capability itself.

Revocation is an atomic `AVAILABLE → REVOKED` transition. `CONSUMED`, `EXPIRED`, and `REVOKED` remain terminal. A successful revoke therefore prevents every future ciphertext retrieval. Secrets created before the owner-capability schema migration have no recoverable owner capability and cannot be managed retroactively.

## Identifier requirements

Public reveal identifiers must be unpredictable, non-enumerable, and allocated by the server. The creation boundary uses Web Crypto to generate 128 bits of randomness and persists only the server-issued identifier as the D1 row key. Callers cannot choose the public reveal identifier.

The browser-generated crypto context identifier is also 128 bits of Web Crypto randomness, but it is used only for AES-GCM associated data and does not select a server resource.

Sequential identifiers, timestamps, counters, database row IDs, malformed identifiers, and non-cryptographic randomness are not acceptable.

Creation is insert-only. A duplicate server-issued identifier is retried with a fresh random identifier and must never replace an existing `AVAILABLE` or terminal record. The server also derives a SHA-256 replay key from the canonical encrypted payload. Retrying the same encrypted payload with the same TTL reuses the original public identifier and never creates a second deliverable row. Replaying that payload with a different TTL fails closed with a conflict instead of mutating the original lifetime or creating another row.

## Default limits

The domain default is:

- default TTL: 24 hours;
- maximum TTL: 7 days;
- maximum ciphertext payload: 64 KiB.

Deployments may configure stricter limits. Invalid configuration or malformed persisted lifecycle state fails closed. Requests are bounded before JSON/base64 decoding, and requests above the configured TTL or payload limit are rejected rather than silently clamped. Persistence accepts only records produced by the validated domain creation path, so storage adapters cannot bypass these limits with arbitrary expiry or payload values.

## D1 persistence and reveal

The server stores the encoded encrypted payload, lifecycle metadata, and the SHA-256 replay key used for idempotent create handling and reveal-proof preparation. The URL fragment's AES key is never part of the D1 schema or any request body.

Reveal is a mutating POST operation. D1 performs expiry and the conditional `AVAILABLE → CONSUMED` transition in one batch transaction. A random per-request consume token gates the ciphertext SELECT inside that transaction, so concurrent losing requests cannot read the winner's ciphertext. The token is cleared before the transaction completes.

GET/HEAD rendering of `/s/:id` does not access the repository and cannot consume a secret. Secret surfaces are served with `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, and `X-Content-Type-Options: nosniff`.

## Reveal protection

Cloudflare deployments require a provider-neutral reveal proof before the existing one-time consume may run.

Turnstile executes only in a separate, fragment-free browsing context. The normal Cloudflare path embeds the paired deployment origin (custom domain ↔ `workers.dev`) so browser same-origin policy isolates Turnstile from the parent document that holds the decryption key. Parent and iframe accept messages only from the exact paired origin/window and matching random verification identifier. The key-holding page presents the fragment-only reveal authorization to the server to prepare a random opaque proof, but neither that authorization nor the bearer proof is sent to the iframe. The iframe receives only readiness/prepared/success/failure state and loads Turnstile only after preparation succeeds. If embedded verification is unavailable, the previous opener-less `noopener`/`noreferrer` popup remains the fallback boundary.

The server validates Turnstile through Siteverify and requires the expected action, exact hostname, and secret-bound `cData`. A prepared proof remains unusable until the matching verification identifier is successfully completed. D1 stores only the proof's SHA-256 hash, the verification identifier, verification state, intended secret identifier, and one-time consumption state. Pending verification expires after five minutes; after successful verification the proof expires after 60 seconds. At most three active pending proofs may exist for one secret, and the insert enforces that bound atomically so parallel preparation requests cannot amplify proof storage.

Invalid, missing, expired, replayed, or differently bound proofs cannot reach the secret consume. Provider outage, missing configuration, or proof-storage failure also fails closed and leaves the secret `AVAILABLE`. Onceveil does not treat Turnstile as recipient authentication or cryptographic proof of humanity.

Proof consumption and secret consumption are intentionally sequential rather than a cross-table lease protocol. A proof may therefore be spent by an infrastructure failure immediately before secret consume; the secret remains available and the recipient must verify again.

## Browser and observability hardening

Create, share, owner, and secret API surfaces are treated as sensitive surfaces. Responses are non-cacheable, do not send referrers, cannot be framed, and use a restrictive Content Security Policy. The normal key-holding context permits no third-party script, frame, or connection origins and disables workers. Only the fragment-free Turnstile verification context permits the Cloudflare challenge origin.

The reveal page clears its in-memory decryption capability and plaintext when its page lifecycle ends and clears restored BFCache state before it can be reused. This is a browser-level lifecycle guarantee, not a promise of physical memory erasure.

Application diagnostics are allowlisted and do not serialize request URLs, authorization headers, bodies, ciphertext, capabilities, proofs, verification tokens, or raw error messages. Infrastructure tracing must follow the same rule.

Public deployments require edge abuse controls in addition to the application limits. Trusted-network deployments may use their network boundary instead. The concrete deployment expectations are documented in [docs/deployment-security.md](docs/deployment-security.md).
## Threats covered

### Passive previews and prefetchers

Passive GET/HEAD traffic cannot consume a secret or receive ciphertext. A status read may persist expiration after the deadline. Reveal requires an explicit mutating operation in a later HTTP slice.

### Concurrent recipients

Only one atomic consume operation may obtain ciphertext. Concurrent losers observe a terminal state.

### Logs and traces

Application, infrastructure, and observability logs must not contain plaintext, encryption keys, full reveal capabilities, management capabilities, authorization headers, or ciphertext request/response bodies.

### Backups

Backups may retain encrypted ciphertext after logical consumption, expiration, revocation, or deletion. Onceveil therefore promises that an encrypted payload becomes unavailable through the service; it does not promise immediate physical erasure from every backup.

## Explicit non-guarantees

### Active browser automation

A system that receives the complete share URL and runs a real browser can execute JavaScript, read `location.hash`, and intentionally perform the reveal action. The passive-preview guarantee does not protect against such an active recipient.

### Browser persistence

Plaintext and decryption keys are not stored in localStorage, sessionStorage, IndexedDB, cookies, query parameters, request bodies, or server-visible routes. The browser holds the key only in page memory for the reveal operation. JavaScript cannot guarantee physical memory erasure after values become unreachable.

### Compromised recipient device

Malware, browser extensions, screen capture, clipboard monitoring, or a compromised browser can observe a secret after the legitimate client decrypts it. Onceveil cannot protect a secret after it reaches a compromised endpoint.

### Compromised service runtime

Client-side encryption limits what the service normally knows, but compromise of the served JavaScript or delivery path could attempt to exfiltrate future secrets. Supply-chain integrity, CSP, third-party-script restrictions, and deployment hardening are separate required controls.

### Recipient copying

"One time" means the service returns ciphertext once. It cannot prevent the successful recipient from copying, photographing, recording, or redistributing the revealed plaintext.

### VPN or private-network identity

Running Onceveil behind a VPN reduces network exposure but does not prove the human identity of the recipient.
