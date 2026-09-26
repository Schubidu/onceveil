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

Apply `migrations/0001_secrets.sql` independently to Production and Preview before exercising the create/reveal flow.

The schema stores only opaque encrypted payload bytes and lifecycle metadata. It has no plaintext or decryption-key column.

## Expiration and cleanup

Expiration is logical and synchronous: consume, revoke, and status operations first turn an expired `AVAILABLE` row into `EXPIRED`, so expired ciphertext is never returned.

Physical cleanup is deliberately separate from one-time correctness. A future scheduled maintenance slice may delete terminal rows after a retention period. Until then, terminal ciphertext can remain physically present in D1 and D1 Time Travel while being logically unavailable, matching the backup guarantee in the threat model.
