# LinkGuard 2.2.0 + Phase 3A — Feature Status

**Release status:** LinkGuard 2.2.0 local preview with Phase 3A local-only URL analysis on `feature/phase-3-url-intelligence`.
**Phase 3A decision:** **CONDITIONAL PASS** for continued isolated development. Public deployment is prohibited. LinkGuard V3.0 is not complete.

“Implemented” describes code present in this repository. It does not imply production readiness or independent security approval.

| Area | Current status | Limits and next work |
|---|---|---|
| Responsive web interface | Implemented | Responsive CSS is present; broad browser/device visual QA remains. |
| URL parsing and local analysis | Implemented, heuristic | HTTP/HTTPS validation, normalization, IDN/Punycode and limited homograph clues are local only. No URL is opened or resolved. False positives and missed cases are possible. |
| URLhaus and Google Web Risk | Adapters implemented; live verification pending | Backend-only optional credentials, consent handling, bounded requests, retry/cache behavior, and explicit per-provider outcomes exist. Provider tests are mocked; no live lookup or credential verification was performed. A provider error/unavailable status is not a safe result. |
| DNS and redirect inspection | Not implemented | Checks remain unavailable. No DNS lookup, redirect following, or user-directed network fetch is performed. |
| Isolated inspection worker | Documented, not implemented | `URL_INSPECTION_THREAT_MODEL.md` proposes worker isolation and SSRF controls. It has not had independent review; the controls are not implemented or tested. |
| Message analysis | Implemented as explainable phrase rules | English, Tamil, Tanglish, and Hindi cues are present. This is not an AI classifier, and fluent human language review is pending. Suspicious wording is not verified scam evidence. |
| Verdict and scoring disclosures | Implemented | Incomplete checks produce `Scan incomplete`; the risk score is explicitly uncalibrated and confidence is `Not calibrated`. No detection probability is claimed. |
| Taxonomy | Versioned taxonomy file present | `app/scam_taxonomy.v1.json`; coverage is limited and there is no taxonomy administration UI. |
| Authentication and sessions | Implemented for local preview | Registration/login, scrypt password hashes, opaque session tokens stored as hashes, session expiry/rotation, CSRF checks, logout, and account deletion are present. Email verification, recovery, MFA, independent review, and production identity controls are absent. |
| User history and reports | Implemented with ownership checks | Per-user history/report/delete isolation and legacy ownerless-record protection are implemented and tested. |
| Database migrations | Implemented for SQLite v1-v2 | No PostgreSQL, automated rollback, multi-instance migration operations, or verified backup/restore process. |
| Provider health and caching | Implemented in-process | Status summaries, bounded timeouts/retry, and a short cache are present; they are not persistent or distributed. |
| QR, UPI, files, emergency guidance | Partial / limited | QR and UPI paths retain stated limitations; no payment action or antivirus claim. Emergency guidance uses linked official resources; ongoing source review is needed. |
| Reports and evidence | Implemented with limits | Evidence timeline and JSON report download exist. No PDF export. Co-occurrence graph is not proof of a scam relationship. |
| Dataset and accuracy | Synthetic evaluation only | 28 product-authored synthetic examples are split into train/validation/test. The held-out examples do not establish real-world performance. No real-world accuracy claim is supported. |
| Public/shared deployment | Prohibited | Production identity, distributed throttling, HTTPS deployment checks, storage/retention controls, monitoring, recovery, independent security review, and operational readiness remain outstanding. |

## Current verification

- Automated suite: **39 tests passed, 0 failed** (32 Phase 2.2.0 baseline, 2 Phase 3A URL-analysis, 5 HTTP integration tests).
- Python compilation: passed.
- Provider behavior is tested with mocks; live provider verification is pending.
- HTTP tests use an in-process ASGI client with synthetic accounts and data. They do not validate real browsers, TLS deployment, reverse proxies, or production infrastructure.

See `UPDATED_PHASE_3_READINESS.md`, `PHASE_3A_CLOSURE_REPORT.md`, `REMAINING_RISKS.md`, and the security/test reports for evidence and remaining gates.
