# Deployment notes

## Local

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

## Docker (local-only default)

```sh
docker compose up --build
```

Compose publishes only `127.0.0.1:8000`. Accounts and per-user authorization are now present, but this local SQLite implementation has not been independently reviewed and is not approved for open public registration.

`URLHAUS_AUTH_KEY` and `WEBRISK_API_KEY` are optional backend-only secrets; set them through a secret manager or ignored `.env`, never commit them, and review provider terms/costs. Set `LINKGUARD_COOKIE_SECURE=true` behind HTTPS. Keep `LINKGUARD_CORS_ORIGINS` limited to the actual frontend origin. Add protected database backups, monitoring, email verification, password reset, MFA, abuse controls, and independent security review before hosted deployment. Schema migrations are currently lightweight SQLite initialization migrations; there is no PostgreSQL, Redis queue, distributed rate limiter, or backup job.

## Production status

No production host, domain, TLS termination, database service, monitoring service, or backup target is configured in this project. Provider keys are not configured in the current environment; integrations are not live-verified. The current Docker setup is for local evaluation only.
