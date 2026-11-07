# LinkGuard V2.0 — Implementation Plan

## Delivery order

### Slice 1 — Local safety and security foundation

- Restrict the default Docker port mapping to localhost.
- Add request IDs, essential security headers, request body limits, and an in-process scan rate limit with explicit single-process limitation.
- Keep history described and configured as single-user local data; do not expose it to the network without authentication.
- Remove external font loading to reduce third-party requests and improve offline/privacy behavior.

### Slice 2 — Explainable investigation

- Add a timestamped evidence/check timeline to reports.
- Add an observed-only relationship graph for text indicators; state that co-occurrence does not prove common ownership or malicious intent.
- Add JSON report export in the browser.

### Slice 3 — External URL intelligence, opt-in only

- Add URLhaus adapter using the documented query endpoint and an environment-only authentication key.
- Call it only after explicit per-scan consent; show provider and result freshness, unavailable/error/no-match separately.
- Do not send messages, QR payment URIs, private/reserved IP URLs, or bulk inputs to providers.
- Google Safe Browsing is not selected for this release because its official terms restrict commercial use absent a separate agreement; review Web Risk separately if needed.

### Slice 4 — Safer static file review and emergency support

- Inspect file signatures and ZIP central-directory metadata without extracting or executing content; detect suspicious archive characteristics and supported container types.
- Add clearly sourced Indian financial-cyber-fraud reporting guidance, OTP/credential response, suspicious app, and remote-access recovery steps.
- Keep emergency instructions general and avoid promises of transaction reversal.

### Slice 5 — Verification and release report

- Add unit tests for parsing, privacy redaction, file/archive limits, provider consent behavior, and report timelines.
- Run tests and API/UI smoke checks; record any tests blocked by missing credentials or unavailable device/browser support.
- Update README, API documentation, security/privacy notes, and feature status.

## Deferred until prerequisites exist

- Login, multi-user history, family sharing, admin roles, API key issuance, and public deployment require identity management, authorization design, migrations, secrets management, operational monitoring, and a deployment environment.
- OCR, PDF generation, APK manifest decoding, and QR fallback require maintained parsers, licenses, resource limits, and review of data flow.
- Provider integrations require provider accounts/keys, terms review for the intended commercial model, consent UI, quota/failure handling, and live integration tests.
- Browser extension requires a separate threat model, permissions review, store packaging, and extension-specific tests.
- Tamil and Hindi security explanations require fluent human review before use as safety-critical copy.
