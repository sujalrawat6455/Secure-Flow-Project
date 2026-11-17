# SecureFlow integrations service

This package is deliberately isolated from the existing SecureFlow backend.
It does not import, modify, or route through the legacy scan implementation.

Run it separately:

```powershell
pip install -r backend/integrations/requirements.txt
$env:INTEGRATIONS_DATABASE_URL = $env:DATABASE_URL
$env:INTEGRATIONS_ENCRYPTION_KEY = '<Fernet key>'
uvicorn integrations.app:app --app-dir backend --port 8010
```

Required environment values: `SUPABASE_URL`, `SUPABASE_ANON_KEY`,
`INTEGRATIONS_DATABASE_URL` (or `DATABASE_URL`), and a Fernet
`INTEGRATIONS_ENCRYPTION_KEY`. Generate the last one once with
`Fernet.generate_key().decode()` and keep it in the secret manager.

In production this service is mounted at `/integrations` inside the main
SecureFlow backend (`backend/main.py`) rather than run as the separate
process shown above — same process/port, still fully isolated tables. Set
`INTEGRATIONS_FRONTEND_URL` (the dashboard's origin, e.g.
`https://app.example.com`) so the GitHub/GitLab OAuth callbacks redirect
the browser back to `{INTEGRATIONS_FRONTEND_URL}/dashboard/integrations`
instead of returning raw JSON. Without it, callbacks just return JSON,
which is still fine for calling the API directly.

GitHub OAuth also needs `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, and
`GITHUB_REDIRECT_URI`. The callback exchanges an OAuth code, stores the
token encrypted, and returns only connection metadata.GitLab OAuth needs `GITLAB_CLIENT_ID`, `GITLAB_CLIENT_SECRET`, and
`GITLAB_REDIRECT_URI`. It targets gitlab.com by default; set `GITLAB_URL`
to point at a self-hosted instance instead. The flow is identical to
GitHub's, just under the `/gitlab/...` paths:

1. `GET /gitlab/authorize?organization_id=...` → send the browser to `authorize_url`.
2. `GET /gitlab/callback` verifies the one-time OAuth state, exchanges the code, and stores the token encrypted.
3. `GET /organizations/{organization_id}/integrations/{integration_id}/gitlab/repositories` lists accessible projects; `PUT .../gitlab/repository` saves a verified selection (`full_name` = GitLab's `namespace/path`).

Bitbucket is intentionally not exposed yet.

GitHub flow:

1. An authorized organization member calls `GET /github/authorize?organization_id=...`
   with their SecureFlow bearer token, then sends the browser to `authorize_url`.
2. Configure `GITHUB_REDIRECT_URI` as this service's `GET /github/callback` URL.
   The callback verifies a one-time, 10-minute OAuth state before exchanging the
   code; it stores the resulting token only in encrypted form.
3. List accessible repositories at
   `GET /organizations/{organization_id}/integrations/{integration_id}/github/repositories`
   and save a verified selection with `PUT .../github/repository`.

Repository selection is stored as connection metadata only. Scanning a
selected repository is a separate, explicit step:
`POST .../integrations/{integration_id}/github/scan` (or `.../gitlab/scan`)
clones it with the stored OAuth token — safe for private repos — runs the
same SAST (Semgrep), SCA (Trivy), and secret-detection scanners the legacy
routes use, and persists findings through the existing pipeline. The token
is embedded in the git URL only for the lifetime of that one `git clone`
subprocess call and is never logged.

## Container registries

Supported providers: Docker Hub, Amazon ECR, GHCR. Each requires provider-
specific credentials in the `POST /organizations/{organization_id}/registries`
body:

| provider   | credential fields                                   |
|------------|------------------------------------------------------|
| `dockerhub`| `username`, `password` (a Docker Hub PAT is recommended) |
| `ghcr`     | `username`, `token` (a GitHub PAT with `read:packages`)  |
| `ecr`      | `access_key_id`, `secret_access_key`, `region`        |

Credentials are verified against the real provider (Docker Hub login,
`GET /user` on GitHub, or STS `GetCallerIdentity` on AWS) before anything is
persisted — a registry is never marked "connected" on unverified input. Only
the encrypted blob is stored; responses never echo credentials back.

Flow:

1. `POST .../registries` — connect + validate credentials.
2. `GET .../integrations/{id}/registries/images` — list repositories/packages.
3. `GET .../integrations/{id}/registries/images/{repository}/tags` — list tags for one image.
4. `PUT .../integrations/{id}/registries/image` — save the selected `repository` + `reference_prefix` + `tag`.
5. `POST .../integrations/{id}/registries/scan` — pull and scan the selected (or explicitly passed) image with Trivy, using short-lived env-var credentials handed only to that subprocess call, and persist findings through the existing project/scan/findings pipeline.
6. `DELETE .../integrations/{id}` — disconnect/revoke, same as any other integration.

Unlike the GitHub repository flow, registry image scanning *does* call into
the legacy scanning pipeline (`scanners/container_runner.py`,
`parsers/container_parser.py`, `services/db_service.py`) — there's no
meaningful way to "scan an image" without it, and doing so doesn't require
touching or duplicating that code. `run_container_scan` gained an optional
`env` parameter for this; callers that don't pass it are unaffected.

ECR support requires `boto3` (see `requirements.txt`).

## API keys — creation vs. authentication

Creating, listing, and revoking organization-scoped keys (`POST/GET/DELETE
.../organizations/{organization_id}/api-keys`) lives entirely in this
service. Actually *authenticating a request* with one of those keys does
not — that happens once, centrally, in `services/auth_service.py`, so both
this service's own routes and every legacy `routes/*.py` endpoint accept
the same keys the same way.

A caller sends `X-API-Key: sfk_...` instead of `Authorization: Bearer
<supabase token>`. `services.auth_service._resolve_principal` hashes it and
checks two places, in order:

1. `sf_api_keys` (this service's org-scoped keys, via
   `store.find_api_key_by_hash`) — if found and not revoked, the request
   is scoped to exactly that key's `scopes` list, and `last_used_at` is
   updated.
2. The legacy per-user `api_keys` table (`services.db_service
   .get_user_id_for_api_key`) — unscoped, full access as the user who
   created it, kept for backward compatibility with keys issued before
   organizations existed.

Routes opt into scope enforcement by depending on
`services.auth_service.require_scope("scope:name")` instead of the plain
`get_current_user_id`. A dashboard session or a legacy key is always
unrestricted (`require_scope` behaves like `get_current_user_id` for
those); an org-scoped key must have that exact scope (or the owner
role's `"*"` wildcard, though only human org roles ever get `"*"` — keys
are created with an explicit scope list, never `"*"`) or the request is
rejected with 403. Every scan-triggering, findings, projects, reports,
and gate route in `routes/*.py` has been switched to `require_scope(...)`
using the same permission vocabulary as `integrations/permissions.py`
(`projects:read`, `projects:write`, `scans:read`, `scans:run`,
`findings:read`, `reports:read`).

Note this is scope-based, not organization-role-based: an org-scoped
key's *scopes* are checked, but the legacy resources it acts on
(projects/scans/findings owned by `created_by`) aren't themselves tied to
an organization or filtered by the caller's organization role. Full
organization-scoped data isolation over the legacy tables (e.g. "this
project belongs to org X, only members of org X may ever see it,
regardless of key") would need `organization_id` added to the legacy
`projects` table and is not implemented here.

