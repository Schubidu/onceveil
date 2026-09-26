# Cloudflare Turnstile reveal protection

Cloudflare deployments require Turnstile protection before any secret can be revealed.

## Trust boundary

The share page that holds the URL fragment key never loads Turnstile or any other third-party script.

When the recipient chooses **Verify & reveal secret**:

1. the share page creates a fragment-free verification iframe on the paired Cloudflare origin for the same deployment (custom domain ↔ `workers.dev`), passing only a random public verification identifier;
2. browser same-origin policy prevents the verification iframe from accessing the parent document, its fragment-held AES key, plaintext, reveal authorization, or bearer proof;
3. parent and iframe accept `postMessage` traffic only from the exact paired origin/window and matching random verification identifier;
4. after the iframe signals readiness, the share page asks the server to prepare a one-time reveal proof, presenting the fragment-only reveal authorization and verification identifier;
5. the server returns the bearer proof only to the share page and stores only its SHA-256 hash;
6. the share page sends only a `prepared` signal to the iframe; it never sends the authorization or bearer proof;
7. only then does the iframe load Cloudflare Turnstile and submit the resulting token to the verification endpoint on its own origin;
8. Siteverify checks the expected action, exact verification hostname, and secret-bound `cData`;
9. successful validation marks the matching prepared proof as verified and the iframe sends only success/failure state back to the parent;
10. reveal atomically consumes the verified proof before attempting the existing strict one-time secret consume.

If the paired embedded origin or `<dialog>` is unavailable, the existing opener-less popup flow remains as an explicit fallback.

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

Embedded verification uses the paired `workers.dev` hostname. Configure `schult.workers.dev` for the widget so the production Worker and branch Preview hostnames under that account domain are accepted. Server-side proof binding, action, hostname, and `cData` validation still gate reveal.

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
