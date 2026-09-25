# Onceveil

**Preview-safe one-time secret sharing.**

> [!WARNING]
> Onceveil is in early development and has **not been security audited**. Do not use it for production secrets yet.

Onceveil is an open-source service for sharing an encrypted secret exactly once without allowing passive link previews to consume it.

The planned product supports two first-class deployment profiles:

- **Cloudflare:** TanStack Start on Workers, D1, and Turnstile.
- **Self-hosted:** TanStack Start on Node.js/Docker, SQLite, and ALTCHA.

MCP support is planned with secure browser handoff so secret material does not enter model/tool context.

## Current status

The application bootstrap and Cloudflare Worker runtime are being established first. Secret creation, encryption, storage, reveal protection, and MCP are intentionally not implemented yet.

## Development

Prerequisites:

- Node.js 24
- npm

```sh
npm ci
npm run dev
```

The development server listens on <http://localhost:3000>.

Run the same essential validation used by CI:

```sh
npm run ci
```

Individual checks are available as `build`, `typecheck`, `test`, `lint`, and `format:check`.

## Cloudflare deployment

Onceveil uses **Cloudflare Workers Builds with the direct GitHub integration**. GitHub Actions validates the code but does not deploy it and receives no Cloudflare credentials.

One-time Cloudflare dashboard setup:

1. In **Workers & Pages**, choose **Create application → Import a repository** and connect `Schubidu/onceveil`.
2. Use `main` as the production branch.
3. Set the build command to `npm run build`.
4. Set the production deploy command to `npx wrangler deploy`.
5. Enable Preview Builds and use `npx wrangler preview` as the Preview command.
6. Keep Production and Preview variables, secrets, and bindings configured separately in Cloudflare.

The repository contains only non-sensitive Worker structure in `wrangler.jsonc`. **Do not put Cloudflare API tokens, account credentials, Turnstile secrets, application secrets, or other secret values in GitHub Secrets/Variables, workflow files, `wrangler.jsonc`, or committed environment files.** Sensitive runtime configuration belongs in Cloudflare.

At this stage the Worker is intentionally stateless: there is no D1 binding, Turnstile configuration, or secret storage.

## Architecture boundary

Onceveil keeps the security/domain core independent from the application framework and deployment runtime.

```text
src/core       framework- and runtime-independent code
src/routes     TanStack Start web surface
src/adapters   infrastructure adapters (later slices)
src/runtime    Cloudflare / Node runtime integration (later slices)
```

Code under `src/core` must not import React, TanStack, Cloudflare, or Node runtime APIs. A regression test enforces this boundary.

## Release policy

Onceveil uses Semantic Versioning with immutable release tags in the form `vX.Y.Z`.

During `0.x`, public contracts may still change. A published release tag must never be moved or overwritten. The first planned release is `v0.1.0`.

## Security

See [SECURITY.md](SECURITY.md). The detailed threat model is introduced in issue #2 before any secret lifecycle is implemented.

## License

MIT. See [LICENSE](LICENSE).
