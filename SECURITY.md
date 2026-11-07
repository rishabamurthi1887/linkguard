# Security notes

- LinkGuard does not make server-side requests to user-supplied URLs and does not follow redirects.
- URLhaus and Google Web Risk lookups are optional, server-keyed, and require per-scan user consent. Configured providers receive the full URL path/query. Sensitive-looking query keys and non-public IPs are skipped.
- User passwords are hashed using salted scrypt. Sessions use random opaque tokens stored as SHA-256 digests, HttpOnly/SameSite=Strict cookies, expiry, and a CSRF token required for state-changing requests.
- Private report, history, scan, and deletion routes require an authenticated account. Queries and deletions are scoped to the authenticated user. Account deletion removes that account's reports and sessions.
- Existing scans from before the ownership migration have no owner and remain inaccessible; the application does not guess who owns them.
- Set `LINKGUARD_COOKIE_SECURE=true` behind HTTPS. The local default is not secure-cookie mode because local development uses HTTP.
- Uploaded files are size-limited, processed in memory, and never executed. ZIP entries are inspected from directory metadata only, never extracted.
- Scan requests receive a request ID, baseline security headers, and a per-process rate limit. The rate limit is not suitable for a multi-process service.
- SQLite data is not encrypted at rest. The account implementation has not had an independent penetration review and is not yet suitable for open public registration/shared production deployment.
- Report suspected security issues privately to the project maintainer. Do not include API keys, private URLs, or message contents in reports.

This document does not represent a penetration test or security certification. Google Safe Browsing public API terms restrict it to non-commercial use absent a separate agreement; LinkGuard does not integrate it. See `THREAT_INTELLIGENCE_REVIEW.md` for provider terms and integration decisions.
