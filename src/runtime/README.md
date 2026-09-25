# Runtime boundaries

Runtime-specific entry points and configuration live here.

Onceveil targets two deployment profiles:

- Cloudflare Workers as the primary hosted runtime.
- Node.js/Docker as the portable self-hosted runtime.

The domain/security core must not import either runtime. Issue #1 establishes the boundary only; runtime integrations arrive in later slices.
