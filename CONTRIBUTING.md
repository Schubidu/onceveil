# Contributing to Onceveil

Thanks for helping improve Onceveil.

## Before changing code

- Keep changes focused and small.
- Prefer KISS over speculative abstractions.
- Preserve explicit security boundaries.
- Do not add secret lifecycle, cryptography, storage, reveal protection, or MCP behavior outside the issue that owns that slice.
- Never use real credentials or secrets in tests, issues, logs, screenshots, or pull requests.

## Local validation

Use Node.js 24 and run:

```sh
npm install
npm run ci
```

CI must be green before requesting review.

## Architecture

The code in `src/core` is framework- and runtime-independent. It must not import React, TanStack, Cloudflare, or Node runtime APIs.

Infrastructure and runtime concerns belong behind explicit boundaries in `src/adapters` and `src/runtime`.

## Commits and pull requests

Use small, meaningful commits. Pull requests should explain the change, the security impact when applicable, and how it was verified.

Security-sensitive changes should include negative cases and fail-closed behavior where relevant.
