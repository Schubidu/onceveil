# Deployment security profiles

Onceveil keeps application security invariants independent from where the service is deployed. Network exposure and abuse controls are deployment concerns on top of those invariants.

## Public internet

A public deployment must apply edge rate limiting before it is treated as production-ready.

Recommended starting limits:

- `POST /api/secrets`: 30 requests per minute per source IP.
- `/api/secrets/:id/reveal` proof/reveal requests: 60 requests per minute per source IP.
- owner status/revoke requests: 60 requests per minute per source IP.

These are operational starting points, not protocol guarantees. Tune them from real traffic. Rejected requests should be stopped before application execution so rate limiting cannot consume, revoke, or otherwise mutate a secret.

The application independently enforces its payload, TTL, proof-count, proof-lifetime, and one-time-consume limits. Those limits remain active even when edge rate limiting is unavailable.

Onceveil is still preproduction. The repository therefore does not add a second application-level rate-limit store just to emulate an edge control. Public edge rate limiting is a release gate for the first production release.

## Trusted network

A deployment restricted by a trusted private-network boundary may omit public per-IP edge limits when the operator accepts that network boundary as the abuse control. Application payload, TTL, proof, and lifecycle limits still apply.

A private network is not recipient authentication. Possession of a complete share URL remains possession of the reveal capability.

## Sensitive logging

Application diagnostics use an allowlisted logging surface. They must not log:

- request URLs containing capabilities;
- `Authorization` or cookie headers;
- request or response bodies;
- plaintext or ciphertext;
- share or owner capabilities;
- reveal authorization, proofs, or Turnstile tokens;
- raw error messages that may contain runtime data.

Infrastructure logging and tracing must be configured with the same restriction. Onceveil does not require request-body or authorization-header capture for operation.

## Browser surfaces

Create, share, owner, and secret API surfaces are served with no-store/no-referrer headers and a restrictive CSP. The normal key-holding context allows only same-origin application network/script access and forbids frames and workers. The fragment-free Turnstile verification context is the only browser surface that permits `challenges.cloudflare.com`.

TanStack Start currently requires inline hydration script support, so `script-src` permits inline application bootstrap code while still preventing third-party script origins in the key-holding context. A nonce-based framework integration can tighten this further later without changing the capability model.
