# LinkGuard API

Base path: `/api/v1`. Interactive FastAPI documentation is available at `/docs` locally.

| Method | Path | Input | Purpose |
|---|---|---|---|
| GET | `/health` | — | Health/version/provider configuration status |
| GET | `/config` | — | Provider availability and configured size limits (never secrets) |
| POST | `/auth/register` | `{username, password}` | Create account and HttpOnly session cookie |
| POST | `/auth/login` | `{username, password}` | Authenticate and issue a new session |
| GET | `/auth/me` | Session cookie | Current account and CSRF token |
| POST | `/auth/logout` | Session cookie + `X-CSRF-Token` | Revoke current session |
| DELETE | `/auth/account` | Session cookie + `X-CSRF-Token` | Delete account and its scans |
| POST | `/scan/url` | `{url, consent_external?}` | Local URL checks; configured URLhaus/Web Risk providers only if opted into |
| POST | `/scan/message` | `{message}` | Local phrase checks and extracted indicators |
| POST | `/scan/qr` | `{url, consent_external?}` | Decoded URL or local UPI URI analysis |
| POST | `/scan/file` | Multipart `file` | In-memory fingerprint and metadata inspection |
| POST | `/scan/bulk` | `{urls:[...]}` | Up to 25 local-only URL checks |
| GET | `/scam-categories` | — | Scam awareness content |
| GET | `/emergency-guides` | — | Emergency response guidance and sources |
| GET | `/history?limit=50` | Session cookie | Current user's report history |
| GET | `/reports/{id}` | Session cookie | Retrieve own report; another user's report returns 404 |
| DELETE | `/history/{id}` | Session + `X-CSRF-Token` | Delete own report only |
| DELETE | `/history` | Session + `X-CSRF-Token` | Clear current user's history only |

All scan endpoints require an authenticated session and `X-CSRF-Token`. Obtain the token from register/login or `GET /auth/me`. Browser sessions use an opaque HttpOnly, SameSite=Strict cookie; set `LINKGUARD_COOKIE_SECURE=true` behind HTTPS. Auth writes require an allowed `Origin` when a browser supplies one. Passwords are hashed using salted scrypt. Legacy scans with no account owner are not returned to any user.

Reports use `Suspicious` or `High risk` only when evidence rules/provider matches exist, `Scan incomplete` when there is no warning evidence but relevant checks are unavailable, and `No known threat detected` only when all reported checks complete without a match. This last verdict is not a safety guarantee. Every report includes `scan_status`, `verdict_basis`, `check_statuses`, and an explicit uncalibrated score label. Numeric rule indicators are not scam probabilities. All scan routes are rate-limited in-process; this is not distributed protection.

### Optional URL reputation lookups

Set `URLHAUS_AUTH_KEY` and/or `WEBRISK_API_KEY` server-side and submit `{ "url":"https://example.com/path", "consent_external":true }`. Each configured provider receives the exact URL excluding fragment. Sensitive token-like query keys and non-public IP literals are skipped. No message or bulk input is submitted to these providers. Results are cached in process for five minutes; transient provider failures are retried once. A no-match is not a safe verdict.

URLhaus documentation: https://urlhaus-api.abuse.ch/ . Community API usage terms: https://urlhaus.abuse.ch/api/ . Review current terms before production or commercial use.

Google Web Risk uses `GET https://webrisk.googleapis.com/v1/uris:search`, checks MALWARE, SOCIAL_ENGINEERING, and UNWANTED_SOFTWARE, and requires a Google Cloud API key. Its health entry shows configuration and last provider status. See `THREAT_INTELLIGENCE_REVIEW.md` for verified terms and alternatives.
