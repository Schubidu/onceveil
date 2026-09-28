# Self-hosting Onceveil

Onceveil supports a Node.js + SQLite deployment profile. Docker Compose is the recommended self-hosted packaging for v0.1.

## Reveal protection

Docker Compose selects ALTCHA by default through `ONCEVEIL_REVEAL_PROTECTION=altcha`. Provider selection is runtime configuration rather than a Node/Docker constraint. ALTCHA's open-source proof-of-work runs locally: Onceveil generates and verifies signed challenges itself, and the browser widget is bundled with Onceveil. No Cloudflare or other verification service is required.

Generate a stable HMAC secret once and keep it with the deployment configuration:

```sh
umask 077
printf 'ONCEVEIL_ALTCHA_SECRET=%s\n' "$(openssl rand -hex 32)" > .env
```

The secret must contain at least 32 characters. Keep the same value across normal restarts. Missing or invalid ALTCHA configuration fails closed and makes `/ready` return HTTP 503.

ALTCHA proof-of-work raises the computational cost of automated abuse. It is **not recipient authentication** and does not prove who is opening a share link.

For a trusted network, VPN, or local evaluation environment only, ALTCHA can be disabled explicitly:

```sh
ONCEVEIL_REVEAL_PROTECTION=none docker compose up --build -d
```

There is no automatic fallback from ALTCHA or another misconfigured provider to `none`. Internally, explicit `none` is handled by the same provider contract through a no-op implementation.

The Node/Docker runtime can also select `turnstile` when `TURNSTILE_SITE_KEY` and `TURNSTILE_SECRET_KEY` are configured.

## Docker Compose

With `ONCEVEIL_ALTCHA_SECRET` stored in `.env`, start the default ALTCHA-protected profile:

```sh
docker compose up --build -d
```

The service listens on `127.0.0.1:3000` by default. Override the host port with `ONCEVEIL_PORT`. Set `ONCEVEIL_BIND_ADDRESS=0.0.0.0` only when you intentionally want Docker to publish the port on all interfaces.

```sh
ONCEVEIL_PORT=8080 docker compose up --build -d
```

Check readiness with:

```sh
docker compose ps
curl --fail http://127.0.0.1:3000/ready
```

The container healthcheck uses the same `/ready` endpoint and includes both SQLite and reveal-protection configuration readiness.

## Persistent data

SQLite is stored at `/data/onceveil.sqlite` inside the container. Compose mounts the named `onceveil-data` volume at `/data`, so replacing or restarting the application container keeps the database.

`docker compose down` keeps the named volume. `docker compose down -v` deletes it and therefore deletes the stored Onceveil data.

The container process runs as the non-root `node` user.

## Reverse proxy and TLS

The Node container serves HTTP only. ALTCHA's browser widget requires a secure context for non-local deployments, so place public or remotely accessed deployments behind HTTPS.

Recommended boundary:

```text
Internet / trusted network
        |
      HTTPS
        |
 reverse proxy
        |
 HTTP on private/loopback network
        |
     Onceveil
```

The reverse proxy should:

- terminate TLS with a valid certificate;
- redirect plain HTTP to HTTPS when the service is exposed beyond localhost;
- preserve the original `Host` header;
- forward requests without adding response caching to Onceveil secret or API routes;
- keep the container port private unless direct trusted-network access is intentional.

Onceveil already emits `Cache-Control: no-store` and security headers on secret-bearing surfaces. The proxy should preserve them rather than replacing them with weaker values.

## Native Node runtime

Docker packages the same standalone Node artifact used by the non-containerized profile:

```sh
npm ci
npm run build:node
ONCEVEIL_REVEAL_PROTECTION=altcha \
ONCEVEIL_ALTCHA_SECRET='<stable-random-secret>' \
npm start
```

The default non-containerized SQLite path is `./data/onceveil.sqlite`; override it with `ONCEVEIL_SQLITE_PATH`.


## White-label branding

Docker Compose forwards the deployment branding variables `ONCEVEIL_BRAND_NAME`, `ONCEVEIL_BRAND_LOGO`, `ONCEVEIL_BRAND_FAVICON`, and `ONCEVEIL_BRAND_ACCENT`.

Logo and favicon paths must stay on the Onceveil origin; arbitrary CSS, HTML, JavaScript, and external asset origins are intentionally unsupported. See [branding.md](branding.md) for the complete contract.
