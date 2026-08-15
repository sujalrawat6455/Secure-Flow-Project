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

GitHub OAuth also needs `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, and
`GITHUB_REDIRECT_URI`. The callback exchanges an OAuth code, stores the
token encrypted, and returns only connection metadata. GitLab follows the
same provider contract; Bitbucket is intentionally not exposed yet.

GitHub flow:

1. An authorized organization member calls `GET /github/authorize?organization_id=...`
   with their SecureFlow bearer token, then sends the browser to `authorize_url`.
2. Configure `GITHUB_REDIRECT_URI` as this service's `GET /github/callback` URL.
   The callback verifies a one-time, 10-minute OAuth state before exchanging the
   code; it stores the resulting token only in encrypted form.
3. List accessible repositories at
   `GET /organizations/{organization_id}/integrations/{integration_id}/github/repositories`
   and save a verified selection with `PUT .../github/repository`.

Repository selection is stored as connection metadata only. It deliberately
does not invoke SecureFlow's legacy scanner until the deployment has chosen a
safe, authenticated scan-handoff adapter for private repositories.
