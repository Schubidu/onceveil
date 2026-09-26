# Cloudflare D1 setup

Onceveil uses one D1 binding named `DB`, but Production and Worker Previews must point at different physical databases.

## Required databases

Create two remote D1 databases:

- `onceveil-production` for `ots.schult.dev` / `main` — configured as `1d203155-cdad-4d27-9c84-383c59c059ab`;
- `onceveil-preview` for `ots-preview.schult.dev` and PR previews — configured as `a8f3fce5-8226-40f1-804a-96677743f541`.

A Preview must never inherit or target the production database.

Cloudflare's current Worker Previews configuration supports a separate `previews.d1_databases` binding. Keep the binding name `DB` identical in both environments while using distinct database IDs.

Example shape after both database IDs are known:

```jsonc
{
  "d1_databases": [
    {
      "binding": "DB",
      "database_name": "onceveil-production",
      "database_id": "<PRODUCTION_DATABASE_ID>",
      "migrations_dir": "migrations"
    }
  ],
  "previews": {
    "d1_databases": [
      {
        "binding": "DB",
        "database_name": "onceveil-preview",
        "database_id": "<PREVIEW_DATABASE_ID>"
      }
    ]
  }
}
```

Both Production and Preview bindings are active in `wrangler.jsonc` and point to separate physical D1 databases:

- Production `DB` → `onceveil-production`
- Preview `DB` → `onceveil-preview`

Cloudflare Worker Previews do not inherit Production settings, so PR previews remain isolated from Production data.

## Migrations

Apply migrations independently to Production and Preview before exercising the create/reveal flow.

Production:

```sh
npm run db:migrate:production
# deployment also runs: npm run db:verify:production
```

Preview uses the separate top-level migration configuration in `wrangler.preview-migrations.jsonc`:

```sh
npm run db:migrate:preview
# deployment also runs: npm run db:verify:preview
```

Cloudflare Workers Builds is configured to run these migrations automatically as part of deployment:

- Production deploy command: `npm run deploy:production`
- Preview command: `npm run deploy:preview`

The scripts keep deployment behavior versioned in the repository rather than only in the Cloudflare dashboard.

This mirrors Cloudflare's Preview-resource guidance: the runtime Preview binding stays under `previews.d1_databases`, while migration tooling gets a dedicated top-level D1 binding pointed at the same Preview database.

The schema stores only opaque encrypted payload bytes and lifecycle metadata. It has no plaintext or decryption-key column.

## Expiration and cleanup

Expiration is logical and synchronous: consume, revoke, and status operations first turn an expired `AVAILABLE` row into `EXPIRED`, so expired ciphertext is never returned.

Physical cleanup is deliberately separate from one-time correctness. A future scheduled maintenance slice may delete terminal rows after a retention period. Until then, terminal ciphertext can remain physically present in D1 and D1 Time Travel while being logically unavailable, matching the backup guarantee in the threat model.


## Runtime database environment guard

Each database has an `onceveil_environment` marker. Deployment writes `preview` or `production` after migrations and verifies it before deployment. The Worker also receives `APP_ENV` through Wrangler configuration and checks the database marker before create/reveal operations.

This makes Preview/Production isolation fail closed: if a Preview is ever wired to the Production database (or to an unmarked database), secret access returns `503` instead of reading or writing the wrong environment.


## Cloudflare Vite build boundary

The Cloudflare Vite plugin generates a flattened output `wrangler.json` during `vite build`, and Wrangler uses that generated file for deployment. A normal build therefore snapshots the top-level Production bindings.

Preview deployment deliberately rebuilds with `wrangler.preview.jsonc` through `CLOUDFLARE_VITE_WRANGLER_CONFIG_PATH`. That input contains Preview-safe bindings as top-level settings, so the generated flattened deployment config also points at `onceveil-preview`.

The Preview deploy then runs `wrangler preview --ignore-base-config` so dashboard Preview Base settings cannot override that generated Preview-safe deployment configuration.

This extra Preview build is intentional: correctness and Production/Preview isolation are more important than avoiding the duplicate CI build.
