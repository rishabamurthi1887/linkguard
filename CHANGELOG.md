# Changelog

## 2.2.0 — 2026-11-07

- Added account registration/login, scrypt password hashing, opaque HttpOnly sessions, CSRF checks, and account deletion.
- Added versioned SQLite migrations and account ownership for scan history; reports, history, and deletion are scoped to the signed-in account.
- Added opt-in Google Web Risk alongside URLhaus, with server-only credentials, timeout/retry behavior, short caching, provider status, and sensitive/private URL suppression.
- Added mixed-script domain clues and contextual message phrase examples in English, Tamil, Tanglish, and Hindi.
- Added a versioned synthetic train/validation/test message dataset and a reproducible held-out rule evaluator; explicitly documents that these toy metrics are not production accuracy.
- Kept arbitrary URL fetching and redirect following disabled. DNS/redirect inspection and external provider live validation remain outstanding.

This is a local security and intelligence preview, not LinkGuard V3.0 or a production-certified service.

## 2.1.0 — 2026-11-07

- Marked reports with unavailable required checks as `Scan incomplete` instead of implying a clean result.
- Added explicit scan execution statuses and verdict basis to reports and timelines.
- Kept the existing numeric indicator for compatibility, but label it as uncalibrated and not a probability; confidence is now explicitly `Not calibrated`.
- Added a versioned scam taxonomy with honest `limited_rules` / `not_implemented` coverage labels.
- Added dataset, model evaluation, accuracy, false-positive, and false-negative reports that state metrics are not measured.
- Updated the scam guide and bulk export to explain detection coverage and score limitations.

This is a reliability preview. It does not complete the V3 production acceptance criteria.

## 2.0.0 — 2026-11-07

- Added optional URLhaus lookup requiring a per-scan opt-in and server-side Auth-Key.
- Added report check timelines, observed-only message indicator graph, and JSON export.
- Added official-source Indian emergency response guidance.
- Added ZIP metadata inspection without extraction, request IDs, baseline security headers, and a single-process scan rate limit.
- Restricted Docker's published port to loopback by default and removed the external Google Fonts dependency.
- Added repository audit, implementation plan, feature status, and security audit documents.

This version is a local MVP update, not a production-ready hosted service.
