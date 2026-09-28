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

The deliberate exception is the URL-elicitation handoff token. MCP serializes the browser URL in the `input_required` response, so the MCP client/tool infrastructure can see this short-lived transition capability. It does not reveal, decrypt, revoke, or manage an existing secret by itself; it only authorizes entry into one pending create or reveal handoff. It is 256-bit random, action-bound, expires after ten minutes, and is not copied into normal tool `content`, `structuredContent`, or `requestState`.

The browser performs secret encryption before the encrypted payload is sent to Onceveil. The create handoff returns the recipient share link and owner link only inside that browser context.

For reveal, the browser receives the complete share URL directly from the user and then continues to the normal protected `/s/:id#...` flow. Completing the MCP handoff does not consume the secret, create a reveal proof, or bypass Turnstile/ALTCHA/noop provider semantics.

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

- the SHA-256 hash of the browser handoff token;
- while the handoff is pending, an AES-GCM-encrypted copy of that token so an unfinished URL elicitation can be retried;
- handoff state and expiry;
- after browser creation completes, the server-issued secret ID and the already-existing owner capability hash.

The raw owner capability never enters the MCP server. It remains in the browser-only owner link.

Handoff tokens expire after ten minutes and are action-bound. Completion is one-way and retry-safe. After successful completion, Onceveil discards the encrypted token copy and retains only the token hash needed to recognize an identical completion retry.

## Runtime configuration

MCP requires all four settings below. Partial or malformed enabled configuration fails closed.

| Variable | Purpose |
| --- | --- |
| `ONCEVEIL_MCP_ENABLED` | Must be exactly `true` to enable MCP. Missing/empty/`false` keeps MCP disabled. |
| `ONCEVEIL_MCP_TOKEN` | Bearer token required on `/mcp`. Use at least 32 characters. |
| `ONCEVEIL_MCP_STORAGE_KEY` | 256-bit storage key encoded as exactly 64 hexadecimal characters. |
| `ONCEVEIL_MCP_PUBLIC_ORIGIN` | Canonical browser origin used for handoff URLs, e.g. `https://secrets.example`. |

The public origin must use HTTPS. HTTP is accepted only for loopback development origins such as `http://127.0.0.1:3000`. Userinfo, paths, queries, and fragments are rejected.

Changing `ONCEVEIL_MCP_STORAGE_KEY` invalidates unfinished handoffs because their encrypted browser tokens and request state can no longer be opened/verified. Treat storage-key rotation as an operation that intentionally cancels active MCP handoffs.

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

The committed `wrangler.jsonc` keeps MCP explicitly disabled by default.

To enable it for a deployment:

1. set `ONCEVEIL_MCP_ENABLED` to `true` in the appropriate Wrangler `vars` scope;
2. set `ONCEVEIL_MCP_PUBLIC_ORIGIN` in that same Production or Preview scope;
3. configure `ONCEVEIL_MCP_TOKEN` and `ONCEVEIL_MCP_STORAGE_KEY` as Cloudflare-managed secrets, separately for Production and Preview;
4. apply the D1 migrations before deploying the code.

Do not commit either secret to `wrangler.jsonc`.

## Client compatibility

The implementation uses the MCP 2026 multi-round-trip `input_required` flow with URL elicitation and HMAC-protected `requestState`. The endpoint rejects legacy MCP traffic instead of silently switching to a weaker interaction model.

A client must therefore support the modern URL-elicitation flow to use the create/reveal handoff tools.
