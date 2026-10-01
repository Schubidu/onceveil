# MCP secure browser handoff

Onceveil exposes an optional MCP interface for orchestration without turning the model or tool context into a secret transport.

The MCP endpoint is **disabled by default**. When enabled, it is available at `/mcp` and uses the official MCP TypeScript server SDK over stateless HTTP.

## Security boundary

MCP may coordinate:

- starting a browser-only secret creation flow;
- starting a browser-only reveal flow;
- reading lifecycle status for a secret created through MCP;
- revoking such a secret.

MCP does **not** receive or return:

- plaintext secrets;
- recipient ciphertext payloads;
- AES decryption keys or complete anonymous share URLs;
- raw owner capabilities or owner links.

The deliberate exception is the URL-elicitation handoff token. MCP serializes the browser URL in the `input_required` response, so the MCP client/tool infrastructure can see this short-lived transition capability. It does not reveal, decrypt, revoke, or manage an existing secret by itself; it only authorizes entry into one pending create or reveal handoff. For reveal, it cannot even finalize that handoff without the browser-only share authorization. It is 256-bit random, action-bound, expires after ten minutes, and is not copied into normal tool `content`, `structuredContent`, or `requestState`.

The browser performs secret encryption before the encrypted payload is sent to Onceveil. The create handoff returns the recipient share link and owner link only inside that browser context.

Create completion is deliberately **not** treated as cryptographic browser attestation. The transition token authorizes the handoff state, but a general HTTP client that possesses that same token can emulate the browser-side protocol. Onceveil does not add a cookie, user-agent check, fetch-metadata check, or similar pseudo-attestation because those values are reproducible by a non-browser client. An MCP client that intentionally fabricates its own encrypted payload can therefore complete its own create handoff, but it still does not gain access to a user's browser-entered plaintext, AES key, raw owner capability, share link, or owner link. The v0.1 security boundary is secret isolation from MCP/model context, not proof that a particular JavaScript implementation executed.

For reveal, the browser receives the complete share URL directly from the user and then continues to the normal protected `/s/:id#...` flow. The MCP-visible transition token alone is not sufficient to complete this handoff: the browser must additionally present the share's `secretId` and non-decrypting reveal authorization extracted from the pasted URL. Onceveil atomically checks that pair against the stored replay key of the still-AVAILABLE, unexpired secret while marking the handoff complete. The AES key and complete share URL never leave the browser.

This completion check does not consume the secret, create a reveal proof, or bypass Turnstile/ALTCHA/noop provider semantics. It proves only that the completion caller possessed a valid Onceveil share capability before the MCP flow may report the handoff complete; it is not browser attestation.

## Tools

The v0.1 MCP surface is deliberately small:

- `create_secret_handoff` — requests a URL elicitation that opens the browser create flow.
- `reveal_secret_handoff` — requests a URL elicitation that opens the browser reveal handoff.
- `secret_status` — reads lifecycle state for a previously MCP-created secret by `flowId`.
- `revoke_secret` — revokes a previously MCP-created secret by `flowId`.

A `flowId` is correlation metadata, not a standalone owner or reveal capability. Status and revoke still require authentication to the deployment's MCP endpoint.

## Browser handoff capability

URL elicitation carries a short-lived browser handoff URL. Its capability token lives in the URL fragment, is therefore visible to the MCP client as part of the elicitation URL, is copied into memory by the handoff page, and is immediately removed from browser history.

The server stores only:

- an HMAC-SHA-256 authorization fingerprint of the browser handoff token, keyed from the current MCP storage key;
- while the handoff is pending, an AES-GCM-encrypted copy of that token so an unfinished URL elicitation can be retried;
- handoff state and expiry;
- after browser creation completes, the server-issued secret ID and the already-existing owner capability hash.

The raw owner capability never enters the MCP server. It remains in the browser-only owner link.

The handoff page treats browser lifecycle transitions as a security boundary: `pagehide` and BFCache restoration clear the transition token, create plaintext, encrypted retry state, generated share/owner links, and pasted reveal URL from React state and invalidate in-flight UI work. Returning with Back therefore cannot restore a usable sensitive handoff state.

Browser completion request bodies are capped at 1 KiB and read with a bounded stream before JSON parsing. Oversized bodies fail with HTTP 413 and cannot advance the handoff.

Handoff tokens expire after ten minutes and are action-bound. Completion is one-way and retry-safe. Cancelling or declining an MCP elicitation immediately deletes the pending handoff state, so the signed request state cannot resume that transition later. After successful completion, Onceveil discards the encrypted token copy and temporarily retains only the keyed fingerprint needed to recognize an identical completion retry. After the handoff window expires, stale pending/reveal rows are pruned and completed-create mappings scrub the transition fingerprint while retaining only the management mapping required for `status`/`revoke`.

## Runtime configuration

MCP requires all four settings below. Partial or malformed enabled configuration fails closed.

| Variable | Purpose |
| --- | --- |
| `ONCEVEIL_MCP_ENABLED` | Must be exactly `true` to enable MCP. Missing/empty/`false` keeps MCP disabled. |
| `ONCEVEIL_MCP_TOKEN` | Bearer token required on `/mcp`. Use at least 32 characters. |
| `ONCEVEIL_MCP_STORAGE_KEY` | 256-bit storage key encoded as exactly 64 hexadecimal characters. |
| `ONCEVEIL_MCP_PUBLIC_ORIGIN` | Canonical browser origin used for handoff URLs, e.g. `https://secrets.example`. |

The public origin must use HTTPS. HTTP is accepted only for loopback development origins such as `http://127.0.0.1:3000`. Userinfo, paths, queries, and fragments are rejected.

Changing `ONCEVEIL_MCP_STORAGE_KEY` invalidates active handoffs: request state no longer verifies, encrypted retry tokens can no longer be opened, and already-issued browser handoff tokens no longer match their keyed authorization fingerprint. Treat storage-key rotation as an intentional cancellation of active MCP handoffs.

Changing `ONCEVEIL_MCP_TOKEN` changes who may call `/mcp` but does not reveal or decrypt stored secret payloads.

## Self-hosted example

Generate independent credentials:

```sh
umask 077
cat >> .env <<EOF
ONCEVEIL_MCP_ENABLED=true
ONCEVEIL_MCP_TOKEN=$(openssl rand -hex 32)
ONCEVEIL_MCP_STORAGE_KEY=$(openssl rand -hex 32)
ONCEVEIL_MCP_PUBLIC_ORIGIN=https://secrets.example
EOF
```

Docker Compose forwards these variables to the Node runtime.

Keep the MCP endpoint behind HTTPS and protect the bearer token like any administrative API credential. Do not put the token or storage key in source control, images, logs, issue comments, or MCP prompts.

## Cloudflare

The committed `wrangler.jsonc` keeps MCP explicitly disabled by default and pins `ONCEVEIL_ENVIRONMENT` to `production` for Production and `preview` for Preview. Custom Cloudflare domains should additionally set `ONCEVEIL_PUBLIC_ORIGIN` to the canonical deployment origin. Readiness uses that validated origin independently of whether MCP is enabled, so optional MCP configuration cannot make a valid custom-domain deployment unavailable. When MCP is enabled, `ONCEVEIL_MCP_PUBLIC_ORIGIN` may override the browser handoff origin; otherwise the deployment origin can be reused.

To enable it for a deployment:

1. set `ONCEVEIL_MCP_ENABLED` to `true` in the appropriate Wrangler `vars` scope;
2. set `ONCEVEIL_MCP_PUBLIC_ORIGIN` in that same Production or Preview scope;
3. configure `ONCEVEIL_MCP_TOKEN` and `ONCEVEIL_MCP_STORAGE_KEY` as Cloudflare-managed secrets, separately for Production and Preview;
4. apply the D1 migrations before deploying the code.

Do not commit either secret to `wrangler.jsonc`.

## Client compatibility

The implementation uses the MCP 2026 multi-round-trip `input_required` flow with URL elicitation and HMAC-protected `requestState`. The endpoint rejects legacy MCP traffic instead of silently switching to a weaker interaction model.

A client must therefore support the modern URL-elicitation flow to use the create/reveal handoff tools.
