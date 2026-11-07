# LinkGuard 2.2.0 Security Audit Report

**Review type:** Source review plus isolated local unit tests; not a penetration test.  
**Scope:** Authentication, authorization, provider handling, privacy, SQL/XSS/CSRF/CORS, uploads, logging, retention, regression behavior.  
**External traffic:** None. Provider requests were mocked; no submitted URL was fetched.  
**Result:** Two findings were fixed during this audit. Production deployment is not approved by this report.

## Executive summary

The reviewed code uses salted scrypt password hashes, high-entropy opaque session tokens stored as SHA-256 digests, expiring server-side sessions, HttpOnly/SameSite cookies, CSRF tokens for writes, SQL parameter binding, and account-scoped report queries. Source review found no user-directed URL fetch. Dynamic frontend values reviewed in `web/app.js` are HTML-escaped before insertion into `innerHTML`.

Two issues were fixed and covered by regression tests:

1. The 500-row retention cleanup was global and could remove another account's older history. It is now scoped to the account performing the scan.
2. Incomplete provider response objects could be treated as valid matches. URLhaus and Google Web Risk adapters now reject malformed match shapes as errors, which remain unavailable checks rather than successful lookups.

No High or Critical issue was found in the inspected local-preview code. Several Medium risks still prevent production use, especially process-local rate limiting, absent account recovery/MFA, unencrypted local SQLite, and lack of end-to-end HTTP/deployment testing.

## Findings

### LG-SEC-01 — Cross-account report eviction from global retention — **Medium, fixed**

- **Affected code:** `app/main.py`, `save()`.
- **Reproduction before fix:** Insert 500 rows for account A and an older row for account B; save one additional report for A. The previous cleanup selected the oldest 500 rows across all accounts and deleted B's row.
- **Impact:** A user's normal scan could destroy another user's saved report. It did not expose the deleted report, but violated data-isolation and retention expectations.
- **Fix:** Retention cleanup now scopes its subquery and delete to the `user_id` making the scan, including `NULL` ownership as a separate bucket.
- **Regression proof:** `test_scan_history_retention_is_per_account` confirms A remains capped at 500 and B's row remains present.

### LG-SEC-02 — Malformed threat-intelligence payload accepted as a match — **Medium, fixed**

- **Affected code:** `app/main.py`, `_urlhaus_lookup()` and `_webrisk_lookup()`.
- **Reproduction before fix:** Mock URLhaus with `{"query_status":"ok"}` but omit URL status/threat fields; mock Web Risk with a string for `threat.threatTypes`. The old adapters accepted these malformed shapes as matches.
- **Impact:** Incorrect provider evidence and elevated warnings could be produced from invalid responses. This was a false-positive/integrity risk, not evidence of a clean result.
- **Fix:** Required URLhaus match fields and a nonempty list of recognized Web Risk threat types are validated. Invalid shapes return `error` and do not clear unavailable-check state.
- **Regression proof:** `test_provider_http_match_no_match_invalid_key_and_malformed_responses` and `test_webrisk_error_is_not_reported_as_a_no_match`.

### LG-SEC-03 — Process-local rate limiting is not an abuse boundary — **Medium, open**

- **Affected code:** `app/main.py`, `rate_limited()` and `safety_headers_and_local_rate_limit()`.
- **Reproduction:** Run multiple worker processes or instances and submit repeated login attempts distributed across them; each process owns a separate in-memory window. Requests behind one reverse proxy may also share the same observed client address unless proxy handling is deliberately configured.
- **Impact:** The 8-attempt/minute local guard can be bypassed across workers or can throttle unrelated users behind a proxy. It is not a robust public-service brute-force control.
- **Recommended fix:** Use a shared rate-limit store, trusted-proxy configuration, account-aware throttling, monitoring, and an abuse-response policy before internet exposure.
- **Test status:** `test_auth_rate_limit_blocks_ninth_attempt_from_same_client` verifies only the local single-process helper. Distributed behavior is untested by design.

### LG-SEC-04 — Local cookie default is not Secure — **Medium when used over HTTP, configuration-dependent**

- **Affected code:** `app/main.py`, `SESSION_COOKIE_SECURE` and `set_session()`; `.env.example`.
- **Reproduction:** Leave `LINKGUARD_COOKIE_SECURE=false` and serve over plain HTTP. The browser cookie is then not marked `Secure`.
- **Impact:** A session could be exposed over an unencrypted network if this local default is carried into a hosted deployment.
- **Recommended fix:** Terminate TLS and set `LINKGUARD_COOKIE_SECURE=true` for every hosted environment; fail startup if production mode is declared without secure-cookie configuration.
- **Test proof:** `test_session_expiry_and_secure_cookie_attribute` verifies `Secure`, `HttpOnly`, and `SameSite=Strict` when secure-cookie mode is enabled. It does not prove a TLS deployment.

### LG-SEC-05 — No password reset, MFA, or email verification — **Medium for shared/public accounts**

- **Affected code:** `app/main.py`, `register()`, `login()`, `set_session()`; account UI in `web/app.js`.
- **Reproduction:** Register an account and then lose its password; there is no recovery path. Accounts have no second factor or verified contact channel.
- **Impact:** Account lockout cannot be self-recovered; a compromised password is sufficient to access that account's reports. Public registration also creates an abuse surface.
- **Recommended fix:** Before public launch, add verified recovery, MFA/passkeys, account-level abuse controls, and security notifications. Do not add weak recovery questions.
- **Test status:** Validation, generic login failure text, session creation/rotation, and session invalidation are tested; recovery and MFA are absent and therefore untested.

### LG-SEC-06 — SQLite is not encrypted and deletion is logical, not secure erasure — **Medium for sensitive production data**

- **Affected code:** `app/main.py`, `db()`, `delete_account()`, `clear_history()`; `PRIVACY.md`.
- **Reproduction:** Inspect the local SQLite database on the host; report rows and account metadata are readable to a process/user with filesystem access. Account deletion removes database rows but does not prove physical overwrite of old database pages, snapshots, or backups.
- **Impact:** Host compromise, unmanaged backups, or filesystem access may expose retained data. “Deleted” should not be interpreted as forensic erasure.
- **Recommended fix:** Use a managed encrypted database and protected backups, define retention/deletion semantics, and test backup expiry and restore handling.
- **Test status:** `test_account_deletion_removes_sessions_and_reports` proves rows are deleted from the active test database and another account's row remains. It does not prove secure erasure.

### LG-SEC-07 — End-to-end HTTP behavior not exercised — **Medium validation gap, open**

- **Affected surface:** FastAPI middleware, cookie transport, browser CORS/preflight, authentication and private API routes.
- **Evidence:** 32 unit tests call endpoint functions or inspect FastAPI dependency metadata. `httpx` is not installed in this environment, and local socket access was unavailable in the prior run; no browser-to-server or live HTTP test was completed.
- **Impact:** Middleware ordering, real cookie attributes across HTTP responses, CORS behavior, multipart limits, and actual client/server integration remain less verified than function-level tests suggest.
- **Recommended fix:** Add an isolated in-process ASGI test client as a development dependency and exercise auth, CSRF, CORS, cross-account endpoints, upload limits, and security headers through HTTP before Phase 3 merges.
- **Test status:** Route dependency inspection passes; HTTP integration remains untested.

## Control review

| Area | Review result | Evidence / limitation |
|---|---|---|
| Password storage | Scrypt with per-password random salt; constant-time digest comparison | Unit tests validate hash, wrong-password rejection, and no raw password in stored hash. No independent parameter-strength review. |
| Sessions | Random opaque token; only SHA-256 digest stored; expiration checked; login issues a new token | Tests verify rotation, expiry, logout invalidation, and stored digest. Session token entropy is generated by `secrets.token_urlsafe(32)`. |
| Cookies | HttpOnly, SameSite=Strict, path `/`; Secure follows environment flag | Secure flag must be enabled with HTTPS outside local development. |
| CSRF | State-changing authenticated endpoints depend on constant-time CSRF token match; auth writes reject disallowed supplied Origin | Direct unit checks pass. Browser preflight/CORS integration is not tested. |
| Authorization | Scan, report, history, and delete routes declare auth dependencies; report/history SQL filters owner ID | `test_private_routes_require_authenticated_dependencies`, cross-user tests, and legacy-row test pass. No live HTTP penetration test. |
| SQL injection | Values are passed as SQLite parameters; migration identifiers are fixed literals | Source inspection. No database-specific injection fuzzing was run. |
| XSS | `web/app.js` uses `esc()` on report, provider, history, error, taxonomy and user-provided values inserted into HTML; text-only account fields use `textContent` | Source inspection only; no browser DOM/XSS harness was run. |
| CORS | Credentialed CORS uses configured origins; default list is exact local origins | Must keep deployment list exact. Reverse-proxy and browser behavior not integration-tested. |
| Secrets | Provider keys are read server-side; config/health expose configured booleans, not values | Source inspection and tests use synthetic keys only. No secret scanning tool was available/run. |
| Logs | Application source has no logging/print statements for submitted URL, message, password, or provider key; request IDs are generated | Uvicorn access logs and host/proxy logs were not configured or audited. Avoid query-string secrets and body logging in deployment. |
| URL safety / SSRF | No submitted URL fetch or redirect following; private literals are skipped for provider submission; provider hosts are fixed in code | This prevents direct user-controlled fetch in the current design. DNS-to-private and redirect validation are not implemented because no URL fetch occurs. |
| Provider failures | Timeout and one transient retry; 401/other nonretryable failures become errors; only match/no-match are cached | Mocked tests cover timeout retry, 429/503 behavior, invalid key, malformed payload, cache, consent, and error state. No live keys/results. |
| Uploads | Size bound is checked and bytes are inspected in memory; archives are not extracted or executed | Existing ZIP metadata test passes. No malware scanning claim is made. |
| Data retention | Up to 500 scans per account; message indicators are redacted from persistence; account/history deletion removes rows | Per-account eviction now tested. No automatic age-based retention, encryption, backup deletion, or secure erasure. |

## Test and verification record

- `python -m unittest discover -s tests -v`: **32 tests passed**.
- `python -m compileall -q app tests scripts`: **passed**.
- `python scripts/evaluate_message_rules.py`: completed on 12 synthetic test examples; not a real-world accuracy result.
- No URL was fetched by the audit. Provider HTTP was mocked; no provider key was used.
- No production deployment, real user data, independent penetration test, or live provider call was performed.

See `REGRESSION_TEST_REPORT.md`, `REMAINING_RISKS.md`, and `PHASE_3_READINESS.md` for the detailed run and gates.
