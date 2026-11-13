# Cloudflare License API

This directory is the version-controlled source of the KudexTech Cloudflare Worker.

## Deploy the Worker

1. Open the `kudex-license-api` Worker in the Cloudflare dashboard.
2. Open **Edit code** and replace the editor contents with `cloudflare/worker.js`.
3. Save and deploy.
4. Confirm the D1 binding is named `DB` and points to `kudex-licenses`.
5. Confirm the Worker secret `ADMIN_API_KEY` exists. Never put its value in GitHub or the VPS repository.
6. Run `cloudflare/schema.sql` in the D1 Console if the schema needs to be created. It is safe to rerun.

## Endpoints

- `GET /` — public health check.
- `POST /trialip` — one 24-hour trial per observed Cloudflare client IP. Existing records are not overwritten.
- `POST /api/authenticate` — checks the observed Cloudflare client IP.
- `GET /api/admin/licenses` — list latest 100 records; requires `Authorization: Bearer <ADMIN_API_KEY>`.
- `GET /api/admin/license?ip_address=203.0.113.10` — look up a record; admin key required.
- `POST /api/admin/license/create` — create or replace a 30-day or lifetime license; admin key required.
- `POST /api/admin/license/revoke` — revoke an IP license; admin key required.

Admin POST requests must use `Content-Type: application/json`.

Example create body:
```json
{"ip_address":"203.0.113.10","license_type":"30_days"}
```

Example revoke body:
```json
{"ip_address":"203.0.113.10"}
```

## Security and operational notes

- The API binds licenses to the public IP Cloudflare observes from the VPS request. A VPS behind NAT, a changed public IP, or a proxy can affect this binding.
- The admin key is a Cloudflare Worker secret, never a repository file or command-line argument.
- The trial endpoint is intentionally public but unique-IP constrained by the D1 unique key. Add a Cloudflare WAF/rate-limiting rule for `POST /trialip` (for example, a modest per-IP request threshold) and monitor D1 usage. Worker code alone is not a substitute for edge rate limiting.
- The API currently performs online installation-time checks. It does not issue signed offline licenses, provide customer accounts, or guarantee that a VPS remains licensed after installation.
- IP validation is syntactic. For production billing, add payment reconciliation, stronger abuse review, audit logging, and a support/recovery process for legitimate VPS IP changes.
