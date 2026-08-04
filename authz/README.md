# Portal authorization service

This internal service validates the oauth2-proxy session, enforces the dynamic
viewer list, and exposes the administration API. It must only be reachable from
the portal gateway.

## Source IP privacy

The service does not collect, persist, or return client source IP addresses.
Legacy `users.last_ip`, `access_events.ip`, and `audit_events.ip` columns remain
in SQLite for downgrade compatibility, but every startup clears any values in
those columns. This also removes values written during a rollback when the
current release starts again.

Database backups created by older releases are not rewritten in place. Remove
obsolete files from `AUTHZ_BACKUP_DIR` according to the deployment's retention
and recovery policy if they may contain historical IP values.

## Required environment

- `AUTHZ_GATEWAY_SECRET`: at least 32 characters. The gateway sends it in
  `X-Authz-Gateway-Token` on every `/auth/*` and `/api/*` request.
- `PORTAL_ADMIN_EMAILS`: comma-separated super administrator emails. These
  accounts cannot be downgraded and are the only accounts allowed to grant or
  revoke administrator permission.
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
- `GET /api/admin/access-events`
- `GET /api/admin/audit-events`

All management mutations require `Content-Type: application/json` and the
`X-CSRF-Token` returned by `/api/me`. Errors use
`{"error":{"code":"...","message":"..."}}`.

`PATCH /api/admin/users/{id}` accepts `disable`, `restore`, `archive`,
`grant_admin`, and `revoke_admin`. Any administrator may manage ordinary
viewer accounts. Only a super administrator may use `grant_admin` or
`revoke_admin`. An administrator must be revoked before the account can be
disabled or archived, and a super administrator cannot be revoked.

Granted administrators are stored in SQLite and remain administrators across
service restarts. Startup only ensures that every current
`PORTAL_ADMIN_EMAILS` account is an active administrator; it does not clear
other administrator records. Removing an address from `PORTAL_ADMIN_EMAILS`
therefore removes its super-administrator capability but leaves its persisted
administrator permission until another super administrator revokes it.

`GET /api/me` returns `isAdmin`, `isSuperAdmin`, and `canManageAdmins` so the
portal can expose only the controls available to the current account. User
responses return both `isAdmin` and `isSuperAdmin`; the latter is derived from
`PORTAL_ADMIN_EMAILS` rather than stored in the database.
