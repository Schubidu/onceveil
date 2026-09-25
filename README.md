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

Issue #1 establishes the project and engineering baseline only. Secret creation, encryption, storage, reveal protection, and MCP are intentionally not implemented yet.

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
