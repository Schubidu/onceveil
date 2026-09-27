# Cloudflare Turnstile reveal protection

Cloudflare deployments require Turnstile protection before any secret can be revealed.

## Trust boundary

The share page that holds the URL fragment key never loads Turnstile or any other third-party script.

When the recipient chooses **Verify & reveal secret**:

1. when the deployment configures a distinct verification origin, the share page creates a fragment-free verification iframe there with a random public verification identifier;
2. the iframe remains sandboxed, but `allow-same-origin` is safe because the verifier is genuinely cross-origin from the key-holding parent; browser same-origin policy therefore keeps it away from the parent DOM, fragment-held AES key, plaintext, reveal authorization, cookies, and storage;
3. the parent accepts iframe messages only from the exact iframe window, the exact paired verifier origin, and the matching random verification identifier;
4. after the iframe signals readiness, the parent prepares the one-time reveal proof and keeps both the fragment-only reveal authorization and bearer proof exclusively in the parent;
5. the parent sends only a prepared-state message to the verifier;
6. the verifier fetches the public Turnstile configuration from its own origin, loads Turnstile, and submits the provider token to its own verification endpoint;
7. Siteverify checks the expected action, the verifier request hostname, and secret-bound `cData`;
8. successful validation marks the matching prepared proof as verified and the verifier reports only success/failure state to the parent;
9. the parent consumes its bearer proof and performs the existing one-time secret reveal.

If `<dialog>` or embedded verification is unavailable, the existing opener-less popup flow remains as an explicit fallback.

A pending verification expires after five minutes. At most three active pending proofs are allowed per secret, including under concurrent preparation. Once verified, its proof is bound to one secret, expires after 60 seconds, and can be consumed once.

If Turnstile, its configuration, D1 proof storage, or proof validation is unavailable, reveal fails closed and the secret remains `AVAILABLE`. The complete Turnstile configuration is checked again immediately before consuming a verified proof.

## Share-fragment migration

Turnstile-protected links use fragment format `v2.<key>.<reveal-authorization>`. This is deliberately separate from the encrypted payload protocol, which remains `v1`.

Pre-existing `v1.<key>` links do not contain a server-verifiable value that can authorize proof preparation. Supporting them transparently would require either sending the AES key to the server or allowing reveal preparation from the public secret id alone; both violate the fail-closed trust boundary. Onceveil therefore recognizes legacy links but does not downgrade them to unprotected reveal.

Migration `0006_expire_legacy_share_links.sql` first blocks inserts that omit `replay_key`, then invalidates still-`AVAILABLE` pre-v2 rows by moving them to `EXPIRED`. This makes the boundary deterministic even during deployment: once the migration starts, an older Worker can no longer create new legacy rows.

## Cloudflare configuration

Create a Turnstile widget for the Onceveil deployment and allow the hostnames on which the verification context actually runs.

Embedded verification is deployment-configurable rather than tied to any Onceveil-owned hostname. Configure an exact production pair with:

- `REVEAL_APP_ORIGIN`
- `REVEAL_VERIFICATION_ORIGIN`

For per-branch Previews, configure the two Preview custom-domain bases with:

- `REVEAL_PREVIEW_APP_ORIGIN`
- `REVEAL_PREVIEW_VERIFICATION_ORIGIN`

Cloudflare Worker Previews can expose the same Preview on multiple custom-domain bases. Configure one Preview-enabled custom domain for the app and a second Preview-enabled custom domain for the verifier; Cloudflare then prepends the same Preview name to both bases. `workers.dev` URLs are not required and are disabled for the Onceveil deployment.

A Preview name is copied from the configured app Preview base to the configured verification Preview base. For example, generic bases `https://preview.example.com` and `https://verify-preview.example.com` map `https://feature-x.preview.example.com` to `https://feature-x.verify-preview.example.com`.

If no distinct verification origin is configured for the current deployment, Onceveil does not guess a hostname and does not enable the embedded path; it uses the existing opener-less popup verification flow instead.

The public `TURNSTILE_SITE_KEY` is committed in `wrangler.jsonc` for both Production (`vars`) and Preview (`previews.vars`) so generated Preview configuration keeps the correct site key.

Configure `TURNSTILE_SECRET_KEY` separately for Production and Preview in **Workers & Pages → onceveil → Settings**. Keep it as a Cloudflare secret; do not commit it or copy it to GitHub Actions.

Both Turnstile values are mandatory at runtime. Missing values do not disable protection; they make verification unavailable and reveal returns a generic service error.

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
