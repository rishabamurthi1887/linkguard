# Phase 3 HTTP Security Test Report

**Release under test:** LinkGuard 2.2.0 plus Phase 3A local URL analysis  
**Method:** In-process ASGI HTTP requests through the real FastAPI middleware stack. No TCP listener, external service, real account, or submitted-URL fetch was used.  
**Status:** 5 HTTP integration tests passed in the full current run (39 tests total).

## Executed tests

| Scenario | Result | Assertions |
|---|---|---|
| Registration and login | PASS | Registration creates cookie; correct login authenticates and rotates the session token. |
| Invalid authentication | PASS | Wrong password and unknown account both return 401 with the same message; unauthenticated `/auth/me` returns 401. |
| Session storage | PASS | Session cookie token maps to a SHA-256 digest in SQLite, not the raw cookie value. |
| Session expiry | PASS | Expired session returns 401 and is removed from the session table. |
| Logout | PASS | CSRF-protected logout returns success, expires the cookie, and subsequent `/auth/me` returns 401. |
| Cookie attributes | PASS | HttpOnly and SameSite=Strict are set; Secure follows configuration and is set when enabled. Local HTTP mode is explicitly checked as non-Secure. |
| CSRF | PASS | Missing CSRF token rejects logout and scan requests with 403; valid token permits the operation. |
| Account isolation | PASS | Two synthetic users have separate histories; cross-user report read and deletion return 404. |
| Account deletion | PASS | Deleted account loses its session; the second account remains usable. |
| Reliability contract | PASS | URL scan with unavailable providers returns `Scan incomplete`, preserves the uncalibrated score label, and uses `Not calibrated` confidence. |

## Not exercised

- Session theft/replay from another device, password spraying across distributed IPs, or concurrent request races.
- Actual browser cookie policy, TLS termination, reverse proxy, deployed CORS, and browser preflight behavior. The ASGI app response headers were tested, but no browser was used.
- Multi-process auth rate limiting, production identity recovery, MFA/passkeys, or independent penetration testing.
- Live provider responses. Provider behavior is exercised by mocked unit tests only.

## Run

```powershell
python -m unittest tests.test_http_integration -v
```

The tests use `tests/asgi_http_client.py`, a small in-process ASGI driver, so they do not require a listening socket or an extra HTTP client package.
