# Onceveil threat model

This document defines the security guarantees and explicit non-guarantees for Onceveil before persistence, browser crypto, recipient authentication, or MCP are implemented.

## Security invariants

1. **Passive requests do not consume or reveal secrets.** GET, HEAD, link previews, crawlers, prefetchers, and similar passive requests must never transition a secret to `CONSUMED` or receive ciphertext. A passive status read may record `AVAILABLE → EXPIRED` after the deadline.
2. **Strict one-time retrieval.** The first successful atomic consume operation transitions `AVAILABLE → CONSUMED` and is the only operation allowed to receive ciphertext.
3. **Consumption is final.** If the winning client or network fails after the server commits `CONSUMED`, the secret is lost. Onceveil does not use a lease/acknowledgement protocol.
4. **The service does not receive plaintext or encryption keys.** Later browser crypto must encrypt before upload and decrypt only after retrieval.
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

The v1 URL format is `/s/:id#v1.<base64url-key>`. The browser generates a fresh 256-bit AES-GCM key and 96-bit nonce for each secret. The decryption key exists only in the URL fragment, so ordinary HTTP requests and passive link previews do not send it to the server. After the reveal page copies the fragment into page memory, it replaces the current history entry with the fragment-free path immediately.

AES-GCM authenticates both the ciphertext and associated data `onceveil:v1:<secretId>`, binding the protocol version and secret identifier to the ciphertext. A modified ciphertext, identifier, version, nonce, or wrong key must fail authentication. This does **not** authenticate a person.

A recipient-authenticated mode may be added later, but it is outside the current scope.

## Identifier requirements

Secret identifiers must be unpredictable and non-enumerable. The validated creation boundary generates them internally with Web Crypto using 128 bits of cryptographic randomness; callers cannot supply arbitrary identifiers.

Sequential identifiers, timestamps, counters, database row IDs, caller-supplied IDs, and non-cryptographic randomness are not acceptable.

Creation is insert-only. A duplicate identifier must be rejected atomically and must never replace an existing `AVAILABLE` or terminal record.

## Default limits

The domain default is:

- default TTL: 24 hours;
- maximum TTL: 7 days;
- maximum ciphertext payload: 64 KiB.

Deployments may configure stricter limits. Invalid configuration or malformed persisted lifecycle state fails closed. Requests above the configured TTL or payload limit are rejected rather than silently clamped. Persistence accepts only records produced by the validated domain creation path, so storage adapters cannot bypass these limits with arbitrary expiry or payload values.

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
