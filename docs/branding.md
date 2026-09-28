# Deployment branding

Onceveil supports a deliberately small deployment-level branding contract. The same runtime configuration is used by Cloudflare and Node/Docker deployments.

Branding changes presentation only. It does not change secret lifecycle semantics, reveal protection, security copy, CSP, or browser isolation.

## Configuration

The supported environment variables are:

| Variable | Purpose | Default |
| --- | --- | --- |
| `ONCEVEIL_BRAND_NAME` | Visible product name and document title | `Onceveil` |
| `ONCEVEIL_BRAND_LOGO` | Optional logo path | none |
| `ONCEVEIL_BRAND_FAVICON` | Optional favicon path | none |
| `ONCEVEIL_BRAND_ACCENT` | Six-digit hex accent color | `#f0f6fc` |

Example:

```sh
ONCEVEIL_BRAND_NAME='Example Vault'
ONCEVEIL_BRAND_LOGO='/branding/logo.svg'
ONCEVEIL_BRAND_FAVICON='/branding/favicon.svg'
ONCEVEIL_BRAND_ACCENT='#6E56CF'
```

Docker Compose forwards the same variables. On Cloudflare, configure them as ordinary non-secret Worker variables for the relevant Production or Preview environment.

## Asset boundary

Logo and favicon values must be root-relative same-origin paths such as `/branding/logo.svg`. Absolute URLs, protocol-relative URLs, data URLs, and relative paths are rejected.

This preserves the existing Content Security Policy and prevents a white-label configuration from adding third-party image origins to secret-bearing pages.

Custom assets therefore need to be served by the Onceveil origin. For source-based deployments, place them in the application's public/static assets before building. A reverse proxy may also serve the configured paths from the same origin.

Invalid asset configuration is ignored and the application continues with the default Onceveil presentation.

## Deliberate limits for v0.1

The v0.1 contract does not allow:

- arbitrary CSS or stylesheet URLs;
- custom HTML;
- custom JavaScript;
- user-defined templates;
- per-secret, tenant, realm, or client branding;
- replacement of security-sensitive copy or lifecycle states.

The accent setting is a single validated color token rather than a general CSS value. This keeps the branding surface small and auditable while leaving room for a richer branding system in a later release.
