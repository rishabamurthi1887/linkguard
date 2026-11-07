# LinkGuard V2.0 — Repository Audit

**Audit date:** 2026-11-07  
**Scope:** Files in the project root and application directories. `sources/` remains read-only and contains no application files in this mirror.

## Existing architecture

- **Frontend:** vanilla HTML, CSS, and JavaScript served by FastAPI; no frontend build step.
- **Backend:** FastAPI application in `app/main.py`.
- **Storage:** SQLite, created at runtime; a single global scan history, with no user accounts or tenant isolation.
- **Deployment:** Dockerfile and Docker Compose scaffolding.
- **Dependencies:** FastAPI, Uvicorn, and python-multipart.
- **UI:** single-page sections for home, checks, scam guide, and history; responsive styles and dark/light theme.

## Feature inventory

| Area | Observed behavior | Audit status |
|---|---|---|
| Home/navigation | Static page and in-page navigation | Working baseline |
| URL checks | Local heuristics; no arbitrary network fetch | Working, limited coverage |
| URL validation | HTTP/HTTPS, domain syntax, IP and some warning patterns | Working after malformed-host fix; no PSL, brand list, RDAP, DNS, TLS, or redirect intelligence |
| Message checks | Small deterministic phrase list, extracts URLs and phone-like text | Partially working; no sender/header analysis, OCR, language-aware analysis, or tested classification quality |
| QR | Browser `BarcodeDetector` path and a URL/UPI analysis endpoint | Partial; browser support varies and there is no decoder fallback or payee verification |
| Files | In-memory hash and basic file signature check | Partial; no archive analysis, APK manifest parsing, or malware engine |
| Bulk | Up to 25 URLs with per-item errors and CSV | Working baseline; no JSON export or provider-aware queue |
| Reports | Evidence, limitations, recommendations, risk indicator/confidence | Partial; no event timeline, graph, JSON/PDF export, or calibrated confidence |
| History | SQLite listing and deletion | Working locally; unsafe for shared/network exposure without authorization |
| Scam guide | Five static categories and one practice interaction | Partial; needs sourced, reviewed content and more scenarios |
| Emergency response | Not present | Not implemented |
| Internationalisation | Language selector with partial string changes | Partial; security content is not fully translated/reviewed |
| Authentication/family/admin/API keys | Not present | Not implemented |
| External threat intelligence | No provider calls or credentials | Not configured |
| Testing | No automated suite found | Not implemented before this V2.0 work |
| Production operations | No migrations, rate limits, monitoring, backup, or deployment validation | Not production ready |

## Immediate implementation priorities

1. Close the network-exposure risk for global history by keeping default deployment loopback-only and adding defensive response headers and request limits.
2. Add source-backed India emergency guidance without implying LinkGuard can recover money or file a complaint for the user.
3. Add an optional, explicit-consent URLhaus reputation adapter that remains unavailable unless a server-side key is configured; do not send URLs silently.
4. Add evidence timelines and observed-only relationship graphs; label co-occurrence accurately.
5. Improve static file inspection without executing or extracting uploads.
6. Add focused automated tests, update docs, and verify the changed app.

## Current release assessment

The repository is a functional local MVP, not a complete V2.0 platform or a production service. The V2.0 request includes account/family features, admin monitoring, screenshot OCR, browser extension, mail authentication checks, PDF exports, and broad provider integrations. These require additional infrastructure, service credentials, privacy and terms review, expert-reviewed content, and device testing; they are not represented as delivered merely because this audit lists them.

## V3 audit refresh — 2026-11-07

The V3 brief's main concern is accurate and remains true: the project has no trained classifier, labelled evaluation dataset, OCR engine, antivirus engine, authoritative payee/identity check, or comprehensive redirect intelligence. Existing numeric indicators are hand-weighted heuristics. Earlier docs said heuristic but did not consistently attach that caveat to every displayed score; the 2.1.0 reliability preview now labels them in API, reports, and bulk exports.

The no-warning path previously used `Unable to verify` while score displays could still be read as a favorable numeric result. Reports now use `Scan incomplete` when required checks are unavailable and no warning evidence is present. A versioned taxonomy marks coverage as limited rules or not implemented. Dataset/model/accuracy/false-positive/false-negative documents now state that measured rates are unknown; no accuracy has been fabricated.

Still high priority before shared/public deployment: authentication and per-user authorization, durable database migrations/retention/backups, independent security review, real device/browser testing, and a properly licensed labelled evaluation dataset. This iteration is not LinkGuard V3.0 production acceptance.
