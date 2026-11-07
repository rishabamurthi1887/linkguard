# LinkGuard 2.2.0 — Audited Feature Status

Status is based on source review and the tests recorded in `REGRESSION_TEST_REPORT.md`. “Verified locally” does not mean production-ready or independently security-reviewed.

| Feature | Audited status | Evidence / limitation |
|---|---|---|
| Registration and validation | Verified locally | Username/password bounds and malformed values tested; no email verification. |
| Password hashing | Verified locally | Scrypt with unique salt and constant-time digest comparison; no credential-recovery path. |
| Session handling | Verified locally | Opaque token, digest persistence, expiry, login rotation, logout invalidation tested. Secure cookie requires hosted configuration. |
| CSRF and Origin | Partial verification | Missing CSRF is rejected; foreign supplied Origin rejected. Browser CORS/preflight not exercised over HTTP. |
| Per-user report/history access | Verified at function/dependency level | Two accounts cannot list/read/delete each other's reports; HTTP integration and independent pen test remain outstanding. |
| Account/history deletion | Verified at active database row level | Own user rows/sessions removed; other account preserved. No guarantee of secure physical erasure or backup deletion. |
| Legacy ownerless scans | Verified locally | Migration leaves them unowned and private. |
| History retention | Verified locally | Maximum 500 rows is now per account, not global. No age-based expiry policy. |
| Brute-force protection | Partial | Eight auth attempts/minute per observed client, in-process only; not distributed or account-aware. |
| URLhaus | Mock-tested | Match/no-match/error/invalid response/retry/cache/consent paths tested; no valid key or live call. |
| Google Web Risk | Mock-tested | Match/no-match/error/malformed response/consent paths tested; no valid key or live call. |
| URL fetch/redirect safety | Current behavior verified by source review | User URLs are not fetched; redirect and DNS inspection remain unimplemented. |
| Phase 3A local URL analysis | Implemented and unit-tested | NFC/IDNA normalization metadata, scheme validation, Punycode, mixed-script and limited lookalike clues, plus existing structural cues; no network access. |
| Phase 3 isolated inspection worker | Design only | Threat model written; no worker, DNS resolution, redirects, or arbitrary fetch has been implemented. |
| SQL/XSS controls | Source-reviewed | SQLite values parameterized; dynamic browser HTML uses escaping. No fuzz or DOM harness. |
| Logs and secrets | Source-reviewed | No application logging of bodies/secrets; reverse-proxy and hosting logs not audited. Keys remain backend configuration. |
| Scam taxonomy | Verified locally | Versioned and retains explicit unsupported categories. |
| Message rules/dataset | Synthetic-only | 28 synthetic examples across 3 splits; 12-row held-out test. No trained model, representative real data, or independent label review. |
| Score/verdict reliability | Regression-tested | Incomplete checks remain disclosed; numeric score is uncalibrated; confidence says `Not calibrated`. |
| UI/responsive/accessibility | Not security-audited end-to-end | Existing UI retained; no current browser, screen-reader, mobile, or theme contrast QA in this audit. |
| HTTP and CORS | In-process ASGI integration-tested | Auth, CSRF, isolation, cookie headers, session expiry/logout, allowed/disallowed CORS preflight, and credentialed allowed-origin response tests pass; browser/proxy/TLS not tested. |

**Release decision:** Local preview only. This status is not a certification or claim of 100% accuracy/reliability.
