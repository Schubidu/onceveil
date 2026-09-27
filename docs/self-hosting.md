# Self-hosting Onceveil

Onceveil supports a Node.js + SQLite deployment profile. Docker Compose is the recommended self-hosted packaging for v0.1.

> [!WARNING]
> ALTCHA support is tracked separately in #7. Until that is implemented, the only self-hosted reveal-protection mode is `none`, which is intended for trusted networks, VPNs, or local evaluation only. It is never selected implicitly.

## Docker Compose

Start the service with an explicit trusted-network opt-in:

```sh
ONCEVEIL_REVEAL_PROTECTION=none docker compose up --build -d
```

The service listens on `127.0.0.1:3000` by default. Override the host port with `ONCEVEIL_PORT`. Set `ONCEVEIL_BIND_ADDRESS=0.0.0.0` only when you intentionally want Docker to publish the port on all interfaces.

```sh
ONCEVEIL_REVEAL_PROTECTION=none \
ONCEVEIL_PORT=8080 \
docker compose up --build -d
```

If `ONCEVEIL_REVEAL_PROTECTION` is omitted, Compose fails before starting the service.

Check readiness with:

```sh
docker compose ps
curl --fail http://127.0.0.1:3000/ready
```

The container healthcheck uses the same `/ready` endpoint.

## Persistent data

SQLite is stored at `/data/onceveil.sqlite` inside the container. Compose mounts the named `onceveil-data` volume at `/data`, so replacing or restarting the application container keeps the database.

`docker compose down` keeps the named volume. `docker compose down -v` deletes it and therefore deletes the stored Onceveil data.

The container process runs as the non-root `node` user.

## Reverse proxy and TLS

The Node container serves HTTP only. For an HTTPS deployment, place it behind a reverse proxy that terminates TLS.

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

For public internet exposure, keep reveal protection fail-closed until the self-hosted ALTCHA profile from #7 is available.

## Native Node runtime

Docker is packaging around the same standalone Node artifact used by the non-containerized profile:

```sh
npm ci
npm run build:node
ONCEVEIL_REVEAL_PROTECTION=none npm start
```

The default non-containerized SQLite path is `./data/onceveil.sqlite`; override it with `ONCEVEIL_SQLITE_PATH`.
