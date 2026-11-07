# LinkGuard 2.2.0 — Security Audit Refresh

**Date:** 2026-11-07  
**Type:** Source review and local functional checks, not an independent penetration test.

## Findings

This refresh supersedes the earlier no-auth and shared-history findings below. Those historical findings are retained as context, not current behavior.

### Resolved in 2.2.0 — Global scan history had no authentication or ownership checks

2.2.0 requires an authenticated session for scans and scopes history/report/delete access to the owning account. Cross-account access tests pass. This is source-level and local automated verification only, not a penetration test.

### Medium — Scan rate limit is single-process only

Scan endpoints now use a conservative in-process limit for local abuse reduction, but it is not a distributed production limiter and does not protect multi-worker deployments.

### Medium — External reputation checks transmit submitted indicators

Providers may receive URLs, including path/query data. 2.2.0 requires scan opt-in and has URLhaus and Web Risk adapters with backend-only keys and private-IP/token suppression. Live service behavior is not verified here; review current provider terms and data retention before deployment.

### Medium — File checks are not malware detection

ZIP/APK handling now inspects archive metadata without extracting or executing content, and returns `Unable to verify` absent a real malware engine.

### Medium — CORS and shared deployment assumptions

CORS origins are environment-configurable. CORS is not authentication. Keep exact local origins by default; never expose the app publicly based on CORS alone.

### Low — Frontend font import contacted a third party

The CSS imported Google Fonts. This dependency was removed in favor of local system-font fallbacks.

## Security controls in scope for this cycle

- No arbitrary URL fetching or redirect following.
- Strict URL syntax/domain validation and private-IP URLhaus lookup suppression.
- Optional URLhaus calls only with explicit consent and a configured server key.
- Request-size caps, rate limiting (single-process only), request IDs, and baseline security headers.
- Local-only Docker port exposure by default.
- No file execution or archive extraction.
- Emergency instructions link to official Indian government/NPCI sources and state LinkGuard cannot reverse payments.

## Not verified / remaining

- No independent penetration test, deployment, independent multi-user auth review, TLS configuration review, dependency audit, backup/restore test, or load test has been performed.
- In-memory rate limiting does not coordinate across workers or instances.
- SQLite history is not encrypted at rest. Password reset, email verification, MFA, and account recovery are absent; rate limits are in-memory and single-process only.
- Provider behavior cannot be live-verified until valid URLhaus/Web Risk credentials are configured and consent is granted; terms should be rechecked before production/commercial use.
- No claim of complete SSRF protection is needed while the scanner performs no user-directed fetches; future redirect fetching requires a separate isolated worker and egress controls.
