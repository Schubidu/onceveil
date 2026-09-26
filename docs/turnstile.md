# Cloudflare Turnstile reveal protection

Cloudflare deployments require Turnstile protection before any secret can be revealed.

## Trust boundary

The share page that holds the URL fragment key never loads Turnstile or any other third-party script.

When the recipient chooses **Verify & reveal secret**:

1. the share page asks the server to prepare a one-time reveal proof and presents the reveal authorization kept in the URL fragment;
2. the server prepares a proof only when that authorization matches the stored replay key of the still-`AVAILABLE` secret, returns the bearer proof only to the share page, and stores only its SHA-256 hash together with a separate verification identifier;
3. the share page opens a fragment-free verification window with `noopener` and `noreferrer`, passing only the verification identifier;
4. only that isolated window loads Cloudflare Turnstile;
5. Turnstile returns a token to the isolated window;
6. the server validates that token with Siteverify and checks the expected action, exact request hostname, and secret-bound `cData`;
7. successful validation marks the matching prepared proof as verified without returning the bearer proof to the verification window;
8. the verification window sends only success/failure state through the same-origin `BroadcastChannel`;
9. reveal atomically consumes the verified proof before attempting the existing strict one-time secret consume.

A pending verification expires after five minutes. Once verified, its proof is bound to one secret, expires after 60 seconds, and can be consumed once.

If Turnstile, its configuration, D1 proof storage, or proof validation is unavailable, reveal fails closed and the secret remains `AVAILABLE`.

## Cloudflare configuration

Create a Turnstile widget for the Onceveil Cloudflare deployment.

Recommended hostname entries:

- `ots.schult.dev`
- `ots-preview.schult.dev`

Cloudflare authorizes subdomains of a configured hostname, so the Preview entry also covers branch Preview hostnames below `ots-preview.schult.dev`.

If the `workers.dev` URLs are used for interactive reveal testing, configure the corresponding Workers hostname as well.

Configure these values separately for Production and Preview in **Workers & Pages → onceveil → Settings**:

- `TURNSTILE_SITE_KEY`: the public widget sitekey;
- `TURNSTILE_SECRET_KEY`: the private Siteverify secret.

Keep `TURNSTILE_SECRET_KEY` as a Cloudflare secret. Do not commit it or copy it to GitHub Actions.

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
