# LinkGuard 2.2.0 — Remaining Risks

These risks remain after the local audit. They are not claims that an exploit was observed.

| Severity | Risk | Required action before public/shared deployment |
|---|---|---|
| Medium | Rate limits are in-memory and process-local. Proxy address handling and multi-worker behavior are not hardened. | Use a shared limiter, configure trusted proxies, add account-aware abuse controls and monitoring. |
| Medium | No email verification, password reset, MFA/passkeys, account recovery, or re-authentication for destructive account deletion. | Design reviewed recovery and stronger account protection; require re-authentication for high-impact actions. |
| Medium | Local cookie Secure setting defaults off for HTTP development. | Require HTTPS and `LINKGUARD_COOKIE_SECURE=true` in hosted deployment; reject unsafe production config. |
| Medium | SQLite is unencrypted at rest; logical row deletion does not securely erase pages, snapshots, or backups. | Use protected/encrypted managed storage, define retention, and verify backup access/deletion policies. |
| Medium | No end-to-end ASGI/HTTP, browser, reverse-proxy, TLS, or CORS integration run was completed. | Add an ASGI test client and run supported browser/proxy checks before Phase 3 merge. |
| Medium | Provider adapters are mocked only. Live result interpretation, quotas, billing, network behavior, and provider terms are not revalidated by this audit. | Use isolated non-sensitive test indicators and valid restricted credentials only after privacy/terms review; retain provider-specific status. |
| Medium | Dataset is synthetic, product-authored, tiny, and single-author reviewed. Labels and language coverage are not independently validated. | Build a licensed representative dataset with independent annotators and adjudication; keep a time-separated holdout. |
| Low | Data has no age-based retention policy; up to 500 scans per account may persist until manually removed or evicted. | Publish a retention schedule and implement/test automatic expiry if required. |
| Low | Reverse-proxy/host logs were not audited; platform access logs may have different retention/access policies. | Disable body logging, minimize identifiers, restrict log access, and document log retention. |
| Low | No independent dependency vulnerability scan, fuzzing, penetration test, backup/restore test, or load test was run. | Add these review gates before a public release. |
| Low | URL DNS, redirect-chain, TLS, and domain-age checks are absent. | Keep user-directed fetch disabled until an isolated egress-controlled design revalidates every redirect and resolved address. |

## Accuracy caveat

The synthetic held-out result (4 TP, 0 FP, 0 FN, 8 TN) does not estimate real-world performance. False-positive and false-negative rates for actual traffic are unknown. `Scan incomplete` and uncalibrated score disclosures must remain.
