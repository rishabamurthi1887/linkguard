# LinkGuard 2.2.0 Regression Test Report

**Run date:** 2026-11-07  
**Runtime:** Python 3.12  
**Test scope:** Existing behaviors plus focused security/provider/dataset tests. All accounts and records were synthetic and isolated in temporary test databases. No submitted URL was fetched.

## Result

| Check | Result |
|---|---:|
| Unit tests | **32 passed, 0 failed** |
| Python compile check | **Passed** (`app`, `tests`, `scripts`) |
| Synthetic message evaluator | **Completed** on 12 test-set examples |
| Provider network | Mocked only; no live key or provider result |
| Browser/device integration | Not run |

## Coverage exercised

- Credential validation, scrypt hash verification, non-plaintext password storage, generic wrong-user/wrong-password response.
- Session token rotation at login, expiration, logout invalidation, cookie `HttpOnly`, `Secure` (when enabled), and `SameSite=Strict` attributes.
- CSRF token enforcement, disallowed Origin rejection, local login rate limit, and authenticated dependency coverage on private route definitions.
- Two-account history/report/delete isolation, account deletion isolation, ownerless legacy scan privacy, and per-account 500-report retention.
- URLhaus/Web Risk consent and configured state; mock match/no-match, invalid key, timeout, 429, 503, malformed response, retry, cache, and error statuses.
- `Scan incomplete`, uncalibrated score wording, `Not calibrated` confidence, explicit provider statuses, and versioned taxonomy regression behavior.
- Dataset ID/text disjointness across splits, label/source schema, and evaluator confusion-matrix arithmetic on a known two-row example.
- Existing URL parsing, private IP non-fetch behavior, mixed-script hint, multilingual phrase examples, message-history redaction, ZIP metadata inspection, and emergency guidance.

## Synthetic dataset result

The evaluator reported `TP=4`, `FP=0`, `FN=0`, `TN=8`, precision `1.00`, recall `1.00`, FPR `0.00`, and FNR `0.00` for its 12 hand-authored held-out synthetic examples. This is a code/regression check only. It does not estimate the performance users should expect in real traffic.

## Not covered by this run

- Real URLhaus or Google Web Risk services, provider quotas/account billing, or provider data retention.
- FastAPI over an actual HTTP client, reverse proxy, TLS, browser CORS/preflight, frontend DOM behavior, or mobile camera/QR support.
- Multi-process rate limiting, load, fuzzing, dependency vulnerability scanning, backup/restore, filesystem permissions, encrypted storage, or penetration testing.
- Linguistic label review by independent fluent speakers or representative real-world dataset quality.

The audit environment lacked `httpx`, and local socket access was unavailable during the prior live-server check. Therefore route-level integration is explicitly **not verified**.

## Phase 3 follow-up

The statement above describes the earlier security-audit run only. In the Phase 3 branch, `tests/asgi_http_client.py` was added to exercise the real ASGI middleware and routes without TCP sockets or `httpx`. The current full run passed **39 tests** (the 32 Phase 2.2.0 baseline tests, 2 Phase 3A URL tests, and 5 HTTP integration tests). See `PHASE_3_HTTP_SECURITY_TEST_REPORT.md` and `PHASE_3_CORS_TEST_REPORT.md` for current HTTP results. Browser, proxy, and TLS integration remain unverified.
