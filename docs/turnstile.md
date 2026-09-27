# Cloudflare Turnstile reveal protection

Cloudflare deployments require Turnstile protection before any secret can be revealed.

## Trust boundary

The share page that holds the URL fragment key never loads Turnstile or any other third-party script.

When the recipient chooses **Verify & reveal secret**:

1. the share page creates a fragment-free verification iframe on the same Onceveil origin with a random public verification identifier;
2. the iframe is sandboxed without `allow-same-origin`, so the browser assigns it an opaque origin even though its URL uses the same Onceveil host;
3. the sandboxed iframe cannot access the parent document, fragment-held AES key, plaintext, reveal authorization, cookies, or same-origin storage;
4. the parent accepts iframe messages only from the exact iframe window, the opaque `null` origin, and the matching random verification identifier;
5. after the iframe signals readiness, the parent prepares the one-time reveal proof and fetches the public Turnstile configuration; both server calls happen in the key-holding parent;
6. the iframe receives only the public site key/action, loads Turnstile, and returns only the provider token or a safe error code;
7. the parent submits that provider token to the verification endpoint; the iframe never receives the fragment-only reveal authorization or bearer proof;
8. Siteverify checks the expected action, request hostname, and secret-bound `cData`;
9. successful validation marks the matching prepared proof as verified, after which the parent consumes that proof and performs the existing one-time secret reveal.

If `<dialog>` or embedded verification is unavailable, the existing opener-less popup flow remains as an explicit fallback.

A pending verification expires after five minutes. At most three active pending proofs are allowed per secret, including under concurrent preparation. Once verified, its proof is bound to one secret, expires after 60 seconds, and can be consumed once.

If Turnstile, its configuration, D1 proof storage, or proof validation is unavailable, reveal fails closed and the secret remains `AVAILABLE`. The complete Turnstile configuration is checked again immediately before consuming a verified proof.

## Share-fragment migration

Turnstile-protected links use fragment format `v2.<key>.<reveal-authorization>`. This is deliberately separate from the encrypted payload protocol, which remains `v1`.

Pre-existing `v1.<key>` links do not contain a server-verifiable value that can authorize proof preparation. Supporting them transparently would require either sending the AES key to the server or allowing reveal preparation from the public secret id alone; both violate the fail-closed trust boundary. Onceveil therefore recognizes legacy links but does not downgrade them to unprotected reveal.

Migration `0006_expire_legacy_share_links.sql` first blocks inserts that omit `replay_key`, then invalidates still-`AVAILABLE` pre-v2 rows by moving them to `EXPIRED`. This makes the boundary deterministic even during deployment: once the migration starts, an older Worker can no longer create new legacy rows.

## Cloudflare configuration

Create a Turnstile widget for the Onceveil Cloudflare deployment.

Recommended hostname entries:

- `ots.schult.dev`
- `ots-preview.schult.dev`

Cloudflare authorizes subdomains of a configured hostname, so the Preview entry also covers branch Preview hostnames below `ots-preview.schult.dev`.

Embedded verification stays on the same Onceveil hostname as the share page, so no additional `workers.dev` Turnstile hostname is required.

The public `TURNSTILE_SITE_KEY` is committed in `wrangler.jsonc` for both Production (`vars`) and Preview (`previews.vars`) so generated Preview configuration keeps the correct site key.

Configure `TURNSTILE_SECRET_KEY` separately for Production and Preview in **Workers & Pages → onceveil → Settings**. Keep it as a Cloudflare secret; do not commit it or copy it to GitHub Actions.

Both values are mandatory at runtime. Missing values do not disable protection; they make verification unavailable and reveal returns a generic service error.

## Siteverify validation

The server validates every Turnstile token through Cloudflare Siteverify before activating a prepared reveal proof.

The validation requires:

- `success === true`;
- action `onceveil_reveal`;
- Siteverify hostname exactly matching the request hostname;
- `cData` exactly matching the public secret identifier.

The client token is never accepted as a reveal proof directly.

## Operational semantics

Turnstile tokens are single-use and expire independently according to Cloudflare's Turnstile contract.

Onceveil prepares its own one-time server proof before the third-party verification context is opened, but preparation requires the fragment-only reveal authorization and the proof cannot be consumed until successful Siteverify validation activates it. The verification page receives neither that authorization nor the bearer proof. This prevents third-party code in the Turnstile document from minting or observing a usable reveal capability, while keeping provider-specific tokens out of the actual secret-consume boundary and giving future providers (for example ALTCHA) the same internal proof contract.

A proof can be burned by a successful proof consume followed by a later infrastructure failure before the secret consume. In that case the secret stays available and the recipient must verify again. Onceveil prefers this fail-closed behavior over reusing a proof.

Proof storage is opportunistically pruned whenever a new proof is issued. Consumed rows and proofs whose expiry has passed are deleted; unexpired, unconsumed proofs are never removed by cleanup. This keeps proof retention bounded without adding a scheduler or queue.
