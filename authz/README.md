# Portal authorization service

This internal service validates the oauth2-proxy session, enforces the dynamic
viewer list, and exposes the administration API. It must only be reachable from
the portal gateway.

## Required environment

- `AUTHZ_GATEWAY_SECRET`: at least 32 characters. The gateway sends it in
  `X-Authz-Gateway-Token` on every `/auth/*` and `/api/*` request.
- `PORTAL_ADMIN_EMAILS`: comma-separated, immutable administrator emails.
- `AUTHZ_CSRF_SECRET`: at least 32 characters and stable across restarts.

Important optional settings:

- `AUTHZ_DB_PATH` (default `/data/authz.db`)
- `AUTHZ_BACKUP_DIR` (default `/data/backups`)
- `OAUTH2_PROXY_AUTH_URL` (default `http://oauth2-proxy:4180/oauth2/auth`)
- `PORTAL_INITIAL_VIEWERS` (imported only during the first empty-database seed)
- `AUTHZ_ALLOWED_EMAIL_DOMAIN` (default `example.com`)
- `AUTHZ_AUDIT_RETENTION_DAYS` (default `90`)
- `AUTHZ_BACKUP_RETENTION_DAYS` (default `30`)

The service listens on port `8081` and runs as UID/GID `10001` in the image.

## HTTP contract

- `GET /healthz`, `GET /readyz`
- `GET /auth/viewer`, `GET /auth/admin`
- `GET /api/me`
- `GET /api/admin/overview`
- `GET|POST /api/admin/users`
- `PATCH /api/admin/users/{id}`
- `GET /api/admin/users/export.csv`
- `GET /api/admin/access-events`
- `GET /api/admin/audit-events`

All management mutations require `Content-Type: application/json` and the
`X-CSRF-Token` returned by `/api/me`. Errors use
`{"error":{"code":"...","message":"..."}}`.
