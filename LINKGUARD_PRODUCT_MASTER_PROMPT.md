# LinkGuard — Product, Security, and Delivery Master Brief

## How to use this brief

Use this document as the implementation brief for the LinkGuard repository. Start by auditing the repository and reporting what is present, what works, what is missing, and what can be completed in the current environment. Then implement the highest-value complete vertical slice that fits the existing project. Continue through the roadmap without claiming unfinished work is done.

The current project mirror contains no application source code yet. Treat this as the product specification until a codebase is supplied. Never edit or replace synced reference files under `sources/`.

## Role and quality bar

Act as a senior product engineer, security architect, threat-intelligence engineer, UX designer, accessibility specialist, QA engineer, and DevSecOps engineer. Build a real, maintainable, privacy-conscious digital scam protection product—not a static mockup. Preserve useful existing code and branding. Prefer small, reviewable changes and working end-to-end flows over broad scaffolding that does not run.

Product: **LinkGuard**
Positioning: **Verify. Understand. Decide. Stay Safe.**
Promise: Help people understand suspicious digital content before they click, reply, pay, download, or install.

Primary users include students, families, older adults, small businesses, and everyday mobile users, especially people targeted by Indian scam patterns. Support English, Tamil, and Hindi. Design for people who do not know security terminology.

## Product principles

1. **Evidence before verdict.** Every warning must point to observable evidence and identify the source and time of each check.
2. **Honest uncertainty.** “No known threat detected” is not “safe.” Separate risk from confidence. Show unavailable, stale, and inconclusive checks.
3. **Useful next step.** Every result answers what to do now in plain language.
4. **Privacy by default.** Minimise collection, disclose external sharing before it happens, redact secrets, and make deletion understandable.
5. **Safe by construction.** Treat user-submitted links and files as hostile. Do not browse them in the user’s session or fetch them unsafely from the application server.
6. **Accessible to everyone.** Clarity, keyboard support, readable contrast, screen-reader support, translation quality, and mobile usability outrank decoration.
7. **No false authority.** Avoid guarantees, fabricated statistics, invented sources, and unsupported claims of uniqueness or accuracy.

## Differentiation: what makes LinkGuard distinct

Do not claim global uniqueness without current competitor research. Build and explain a distinctive combination of capabilities:

- **One explainable decision card across link, message, QR, and file checks:** evidence, checks completed, unavailable checks, freshness, confidence, and next steps share one understandable format.
- **Scam-context understanding for India:** recognise UPI collect requests, OTP harvesting, KYC pressure, electricity disconnection threats, courier fees, fake jobs, digital arrest threats, fake support, and APK lures. Keep examples and guidance sourced, reviewed, and dated.
- **Context-preserving analysis:** show the user which extracted link, phrase, payment cue, domain mismatch, or file permission caused each finding. Do not reduce the experience to an opaque score.
- **Safe action preview:** show a QR destination, redirect chain, UPI payee/request details, and sensitive file permissions before a person acts. Never initiate the action.
- **Privacy-aware provider choice:** clearly identify when a URL, hash, or file metadata would be sent to an external provider; allow local-only checks when supported; require informed opt-in for sharing sensitive/private URLs.
- **Accessible multilingual safety coaching:** explain the same risk and recommended action consistently in English, Tamil, and Hindi, preserving technical identifiers and avoiding literal translations that alter meaning.
- **Learning that closes the loop:** offer short, synthetic practice scenarios tied to the warning signs seen in a report, without turning scans into blame or gamified fear.
- **Trust ledger:** give a per-scan, timestamped record of providers queried, source freshness, errors, and evidence so users can understand how the conclusion was reached.

These are product differentiators to validate through user research and competitor review, not claims that no other product offers them.

## Product scope and release strategy

Ship in dependable stages. A narrow, safe, end-to-end first release is better than many nonfunctional screens.

### Release 1 — trustworthy core

- Responsive home and URL scan flow.
- Safe URL parsing and local heuristics, with explicit limits.
- Optional server-side reputation integrations only when keys, terms, and consent are configured.
- Message text analysis using explainable deterministic rules and extracted indicators.
- Structured report with evidence, confidence, freshness, checks run, checks unavailable, and practical guidance.
- English UI plus translation-ready architecture; add Tamil and Hindi content only when reviewed.
- Privacy notice, data deletion, error states, rate limits, safe logs, and deployment documentation.

### Release 2 — additional inputs and user control

- QR image upload and camera scanning with preview-before-action.
- Bulk URL analysis (initial cap 25) with explicit partial-failure handling and export.
- Anonymous scan history with clear retention and deletion behavior.
- Scam intelligence library with source and review dates.
- Scam Simulation Lab using synthetic content.

### Release 3 — file checks and mature operations

- Strictly limited file upload, hashing, MIME/signature checks, and metadata review.
- APK metadata and permission inspection without execution.
- Opt-in known-hash lookups and isolated analysis only if infrastructure has been reviewed.
- Account features only if they solve a validated need and authorization/isolation controls are complete.
- Monitoring, backup/restore rehearsal, incident response, and detection quality evaluation.

For every release, document what is not included, why, and what condition would make it safe to add.

## User experience requirements

### Main flows

1. **Check a link:** paste/type → explain privacy choice → scan → read verdict and evidence → choose a safe next action.
2. **Check a message:** paste only the content the user chooses → show extracted links/phone/payment cues → explain patterns and uncertainty → offer reporting/learning options.
3. **Check a QR:** upload or request camera permission → decode locally when feasible → preview payload and destination → analyse only after clear consent → never auto-open.
4. **Check a file:** explain limits and whether bytes leave the device → validate size/type → hash and inspect safely → show that hash absence is not proof of safety.
5. **Recover from an error:** explain whether any data was sent, what failed, what remains unchecked, and offer a safe retry.

### Plain-language report

Every report must show:

- Verdict: **Confirmed malicious**, **High risk**, **Suspicious**, **No known threat detected**, or **Unable to verify**. Use “Confirmed malicious” only when a trusted, current source or validated evidence supports it.
- Risk level and confidence as separate fields; do not call either a probability of fraud unless calibrated and validated.
- A short “Why this result?” summary with evidence items and their provenance.
- Checks completed, failed, skipped, and unavailable, with timestamps/freshness.
- Submitted-content handling and redactions.
- Direct answers: “Should I open it?”, “Should I share an OTP/password?”, “Should I pay?”, “Should I install it?”, and “What should I do next?” Show only questions relevant to the scanned content.
- Safe alternatives such as opening the official app/site independently or contacting an organisation through independently verified details.
- A clear route to correct a false positive or report a new indicator, with human review before an indicator is treated as confirmed.

Never use colour alone for verdicts. Include text and icons/labels. Do not shame users or imply that a victim caused the scam.

### Visual system

Use a refined, Apple-inspired frosted-glass visual language only where it improves hierarchy and focus: restrained translucent surfaces, subtle blur, fine borders, layered depth, calm typography, and controlled blue/cyan accents. Support dark, light, and system themes. Maintain contrast and readability, with non-glass fallbacks. Avoid a generic security dashboard, excessive floating cards, decorative motion, or effects that obscure content. Respect reduced-motion settings. Keep the brand consistent with existing assets if supplied.

All layouts must work on small Android and iPhone screens, tablets, and desktop. Prevent horizontal overflow. Ensure visible keyboard focus, semantic controls, accessible names/status announcements, and WCAG 2.2 AA as the target.

## Functional requirements

### URL analysis

- Safely parse and normalise HTTP/HTTPS input, including IDNs and copied text. Reject unsupported schemes and malformed inputs with helpful feedback.
- Use a maintained Public Suffix List library for registrable-domain decisions.
- Flag IP literals, Unicode/punycode, lookalike brands, unusual subdomains, URL shorteners, suspicious parameters, and known redirect services where supported. Treat heuristics as signals, not proof.
- Optional RDAP, DNS, TLS, and reputation lookups must use provider-specific timeouts, caching, rate limits, terms review, and clear source attribution.
- Do not perform arbitrary backend fetches in the first release. If redirect inspection is added, run it in an isolated worker with strict egress allow/deny controls, IP revalidation at connection time, DNS rebinding defense, redirect and response-size limits, and no access to private/reserved/metadata addresses. Revalidate every redirect and resolved address.
- Do not submit private URLs or sensitive query strings to public services without prior disclosure and informed consent. Redact tokens and identifiers in logs and reports.

### Message analysis

- Analyse only text deliberately pasted or uploaded by the user; never connect to private SMS, WhatsApp, email, or Telegram accounts without a separately designed, explicit integration.
- Detect patterns such as urgency, impersonation, OTP/password requests, UPI/payment pressure, advance fees, job/investment/loan offers, fake government benefits, courier/KYC/electricity threats, and suspicious links.
- Return the exact phrase or indicator supporting each finding, category, severity, explanation, extracted URLs/phone numbers/payment cues, and safe next step.
- Rules and any AI-assisted interpretation must be bounded. AI must not invent evidence, claim verification it did not perform, or override deterministic provider results silently.

### QR analysis

- Support image upload and camera where available, with permission denial and unsupported-browser fallbacks.
- Decode URLs, UPI payment URIs, Wi-Fi payloads, contact cards, phone and SMS payloads. Show sensitive values with appropriate redaction.
- Preview decoded content and destination before analysis or action. Never auto-redirect, pay, join a network, call, or send a message.

### File/APK analysis

- Define allowed types and conservative size limits. Validate file signatures as well as extension and declared MIME.
- Calculate SHA-256 and explain that a hash match is evidence while a missing match is not a clean bill of health.
- Inspect metadata without executing content. APK parsing must report package/signature/permissions only when the parser can verify them; flag risky combinations without asserting malware from permissions alone.
- Never execute uploads. Keep files ephemeral by default, use random storage names outside web roots, enforce quotas, and define deletion/retention behavior. Advanced sandboxing is out of scope until isolated infrastructure exists.

### Bulk scanning, history, and learning

- Bulk cap of 25 URLs initially; validate independently, show every failure, progress, and retry status, and offer CSV/JSON export without secrets.
- History must be optional or clearly disclosed, searchable/filterable, exportable, and deletable per item or all at once. Enforce user ownership if accounts are introduced.
- Learning scenarios must be synthetic and clearly labelled. Never use live malicious URLs or malware. Explain the answer, not just the score.

## Threat intelligence and source governance

Evaluate Google Safe Browsing, VirusTotal, URLhaus, PhishTank, RDAP, and other suitable providers before implementation. For each integration record:

- Data sent, purpose, retention/visibility, terms and commercial-use limits.
- Authentication, rate limits, timeout/retry policy, cache duration, and failure behavior.
- Whether submitted content is private or becomes shared/public.
- Exact provider result fields used and how stale/no-result/unknown are represented.

Keep keys on the backend. Do not query or imply a provider was queried unless it actually returned a result. Keep provider errors separate from a clean result. Track indicator source, first/last seen, confidence, review status, and expiry. User reports are unverified leads until reviewed; provide abuse controls and an audit trail for human review.

## Architecture and data handling

First inspect and retain a sound existing stack. If no compelling stack exists, use a modular FastAPI backend, a maintainable responsive frontend, and PostgreSQL for durable data. Add Redis/background jobs only when a concrete workload requires them. Keep APIs versioned and documented.

Possible modules: URL parsing, safe network inspection, provider adapters, message rules, QR parsing, file metadata, evidence/report assembly, privacy/consent, optional history, and scam-content governance.

Possible data entities: scans, evidence, provider checks, reviewed indicators, scam categories, user-submitted reports, consent records, optional users, and audit events. Store the least data needed. Avoid raw messages and full URLs by default; encrypt any necessary sensitive data, restrict access, define retention, and support deletion. Never log secrets, full query strings, uploaded contents, or authentication tokens.

Use structured validation and errors, request IDs, server-side timeouts, rate limiting, strict CORS, secure headers, CSP, CSRF defenses when cookie authentication applies, parameterised database access, secret management, and dependency review. Do not return stack traces or internal network details to users.

If accounts are offered, use established authentication, secure session/token handling, CSRF protection where relevant, account recovery safeguards, and ownership checks on every read/write. Do not add accounts merely to create a dashboard.

## Internationalisation and content quality

- Use translation keys for all interface strings, validation, error, report, learning, and privacy content.
- Preserve URLs, brand names, numbers, and technical identifiers correctly.
- Get security-sensitive Tamil and Hindi copy reviewed by fluent speakers; machine translation alone is not a release criterion.
- Test font fallback, line wrapping, screen-reader pronunciation where practical, and longer translated layouts.
- Prefer culturally relevant examples without stereotyping or blaming communities.

## Verification and quality gates

Do not claim a feature is complete until it works and is verified. Add focused automated tests for implemented features and do not invent accuracy metrics. Use a labelled, permitted dataset and publish methodology before making performance claims.

Minimum checks as the app grows:

- Valid/malformed URLs, IDNs, IP literals, encoded inputs, redirects, private/reserved IPv4 and IPv6, DNS rebinding protections, timeouts, size caps, provider outage and stale results.
- Message rules, extracted indicators, false-positive cases, multilingual consistency, and hostile markup.
- QR payload types, permission denial, unsupported camera API, and no automatic action.
- File extension/MIME mismatch, oversized files, path traversal names, parser failures, and no execution.
- Authorization isolation, rate limiting, privacy redaction/deletion, XSS, SQL injection, CSRF as applicable, CORS, secret exposure, and error leakage.
- Keyboard-only flow, screen reader labels/status, contrast, reduced motion, theme/language selection, responsive layouts, and broken buttons.
- Detection precision/recall/false-positive/false-negative only on documented, representative, permitted data. Do not fabricate test accuracy.

Run only checks relevant to the changes and report exact outcomes, including skipped checks and why.

## Delivery and documentation

Provide `.env.example` with placeholders only, dependency lock/requirements, migrations, container setup when appropriate, README, API examples, architecture diagram, privacy/data-flow description, threat model, security response notes, test instructions, deployment guide, and known limitations. Never commit credentials.

Before release document HTTPS, database migration/rollback, backups and restore checks, logs/metrics, alerts, rate limits, incident response, and provider outage behavior. Do not claim deployment or production readiness without evidence.

## Implementation workflow

1. Inventory the repository; read its instructions and inspect existing code/configuration. Report a concise audit and implementation plan before changing files.
2. Identify the smallest safe end-to-end product slice and its acceptance criteria.
3. Define data flow, privacy notice, threat model, and provider constraints before connecting external services.
4. Implement design system and accessible shell, then one complete scan flow with real validation and honest result states.
5. Add evidence/report model and unit/integration tests for the implemented flow.
6. Add message, QR, file, bulk, history, learning, and language capabilities in staged releases, keeping each feature functional and clearly bounded.
7. Harden, document, and verify each slice. Preserve existing working features.
8. Finish with an implementation report: delivered, verified, partially implemented, unavailable/credential-gated, known risks, and next work.

When blocked by missing credentials, infrastructure, product data, or provider terms, implement a safe unavailable state and document the exact requirement. Do not fabricate success or stop unrelated work.

## Acceptance standard

LinkGuard is ready for a release only when the delivered scope has:

- Working user flows and no dead buttons or endless fake loading.
- Evidence-backed reports and honest unknown/unavailable states.
- Safe handling of URLs, messages, QR payloads, and files within the released scope.
- Clear consent, data-flow disclosure, retention, and deletion behavior.
- Accessible, responsive layouts and reviewed translations for claims shown to users.
- Passing relevant tests and documented limitations.
- No exposed secrets or unresolved critical security findings.
- Verified setup and deployment instructions for the environment claimed.

Do not claim 100% completion while anything in the chosen release scope remains incomplete. Distinguish “implemented,” “tested,” “configured,” and “deployed.”

---

# OPERATING PROMPT — AUDIT, COMPARE, IMPROVE, AND PROVE LINKGUARD

Use this operating prompt whenever continuing work on LinkGuard. Treat it as an instruction to inspect the current repository, research current alternatives, implement improvements, verify them, and leave a clear status report. Do not stop after writing recommendations.

## A. Current repository baseline to verify

The project was previously created as a small working starter. Verify this list against the actual code before relying on it; it may have changed:

- FastAPI backend and a static responsive browser interface.
- Local URL pattern checks that do not fetch submitted links.
- Message phrase checks and extraction of URLs/phone numbers.
- QR payload analysis, including a basic UPI preview. Browser QR decoding depends on `BarcodeDetector`; broader fallback coverage may be absent.
- In-memory SHA-256 and basic file signature checks, but no antivirus/malware engine.
- Bulk URL endpoint, initially capped at 25.
- Scam-awareness guide, synthetic practice prompt, and SQLite scan history with deletion.
- Light/dark appearance; Tamil/Hindi translation coverage may be partial.
- No external threat-intelligence provider configured, no login/accounts, no multi-user isolation, no PostgreSQL/Redis, and no production deployment.

Recheck whether these statements remain true, whether they work, and whether newer code added or removed functionality. Do not call a feature “working” based only on a button, route name, or screenshot.

## B. Required audit and execution behavior

1. Inspect repository instructions, code, dependencies, routes, data storage, UI, tests, and deployment configuration. Keep `sources/` read-only.
2. Start the existing app and reproduce user-visible problems. Record exact steps, expected behavior, actual behavior, and environment.
3. Create an acceptance checklist and order findings by severity, user impact, likelihood, and repair effort.
4. Preserve existing working flows. Fix broken flows before adding feature breadth.
5. Implement improvements in small, complete slices. Add tests for changed behavior and run the relevant suite. Do not fabricate passing results.
6. If an API key, provider account, paid plan, camera permission, public domain, or deployment host is unavailable, implement a truthful unavailable state and continue independent work.
7. Do not promise zero defects or “100% safe.” Define a measurable release confidence based on scope, coverage, test results, security review, and known gaps.

## C. Current competitor and alternative-product comparison

Before making comparative claims, research current products using their official product, help, privacy, and technical documentation pages. Search/browse on the date of work. Use primary sources, link every material claim, distinguish verified facts from inference, and write “not publicly documented” when needed. Do not copy protected designs or claim LinkGuard is globally unique.

At minimum, review a relevant mix of current services such as Google Safe Browsing/Transparency Report, VirusTotal, Norton Safe Web, ScamAdviser, Truecaller scam features, and a current QR/link checker. Confirm each candidate is still available and relevant before including it. Add/remove candidates based on the actual target audience and geography.

Compare LinkGuard and selected alternatives on a transparent feature matrix:

- Input types: link, pasted message, QR, payment URI, file/APK, batch.
- Evidence and explanations, confidence/uncertainty handling, source freshness.
- Indian scam patterns, UPI context, languages, and mobile-first usability.
- Privacy: data submitted, external providers, account requirement, retention/deletion.
- Safety: whether the product opens URLs, follows redirects, handles files, or can initiate an action.
- Speed: published or measured scan time, source/method, network/device, and scope.
- Accessibility, responsive layout, exports/history, pricing/account constraints if publicly documented.

For every matrix cell use **Verified**, **Not found in reviewed documentation**, **Not applicable**, or **Unknown**. Give citations and access dates. Do not score a competitor based on marketing impressions. Do not use private user content or upload a live/private link to a public scanning service as part of research.

Conclude with:

- What LinkGuard already does better, supported by evidence.
- What alternatives do better or offer that LinkGuard lacks.
- Which differences matter to the intended users and which are cosmetic.
- A positioning statement that is specific and modest.
- No “first,” “only,” “best,” or “unique” claim unless a documented search supports its exact scope and wording.

## D. Feature discovery beyond the current build

Do not merely duplicate an existing feature list. Generate and assess new feature ideas that solve a clear user problem. Consider these candidates and improve or replace them after user research:

1. **Scam phrase highlighter:** show the exact user-submitted words that signal urgency, impersonation, OTP harvesting, advance fees, or payment pressure, with a short explanation beside each highlight.
2. **Action preview / payload diff:** for a QR or payment URI, present recipient, amount, currency, payee ID, and hidden redirect destination before any external app is opened; let the user compare the request with what they intended. Never make the payment.
3. **Privacy choice before provider lookup:** first show a local-only result, then offer an explicit “check with named providers” option describing exactly what URL/hash/content leaves the device and whether it could become public.
4. **Source and freshness receipt:** provide a compact exportable report stating what was checked, by whom, when, what was not checked, and when the result should be considered stale.
5. **Safe official-route helper:** after a warning, help users find the organisation’s independently verified official site/app/support route using curated, review-dated sources. Never use the suspicious message’s phone number or link as the verification path.
6. **Low-bandwidth and offline learning mode:** keep the education guide and synthetic practice usable on slow or intermittent mobile connections. Clearly mark reputation checks unavailable offline and date cached guidance.
7. **Family learning cards:** create optional, redacted, non-accusatory examples users can share to teach warning signs; do not share a real message or scan result without an explicit action and preview.
8. **Reviewed community indicator workflow:** accept abuse-controlled reports as unverified leads, deduplicate, preserve provenance, review with a moderator, expire stale reports, and provide correction/appeal paths. Never label a person or business malicious on an unverified report.
9. **Adaptive check depth:** run fast local checks first, explain the result, and let the user request slower/deeper checks. Display progress, provider-specific timeout, cancellation, and partial-result states.
10. **Plain-language decision coach:** ask what action the person was asked to take (open, log in, approve payment, install, call back) and tailor advice to evidence. Do not offer a definitive “safe” verdict or financial/legal advice.

For each proposed idea, state user problem, differentiator hypothesis, implementation effort, privacy/security risks, dependencies, success metric, and experiment that could disprove its value. Rank with a simple impact × confidence ÷ effort model. Treat all differentiation as a hypothesis until competitor research and user validation support it.

## E. Responsive and mobile quality gate

Treat mobile as a primary use case, not a shrunk desktop. Use fluid layout rules, content-based breakpoints, flexible type and spacing, and native touch-friendly controls. Do not force a fixed device size or rely on one phone mockup.

Verify at minimum around 320, 360, 390, 430, 768, 1024, and 1440 CSS pixels, portrait and landscape where relevant, and browser zoom at 200%. Record browser, viewport, device-pixel ratio, and method. Check:

- No horizontal page scrolling or clipped controls/text at any tested width.
- Navigation becomes a usable compact menu/tabs; active selection remains visible and keyboard accessible.
- Scan fields, paste, upload, camera controls, dialogs, consent, errors, progress, results, history, and exports remain usable with the virtual keyboard open.
- Buttons/touch targets are comfortably tappable; text is readable without zooming; translated strings wrap without overlap.
- Camera denied/unavailable, no camera, no QR detected, invalid upload, low bandwidth, offline, and rotated-screen states are clear and recoverable.
- Results keep evidence and warnings prominent; long domains, URLs, Tamil/Hindi text, and large evidence lists wrap safely.
- Themes, focus indicators, reduced motion, contrast, and screen-reader announcements work at mobile sizes.

Run automated browser checks where available and capture screenshots for representative small phone, tablet, and desktop widths. Report untested devices and browser-specific limitations. Never state “works on every phone” without broad real-device coverage.

## F. Speed and reliability measurement

Do not call the site “fast” by intuition. Establish a baseline and compare after changes. Record the exact commit, build mode, browser, device/CPU/network condition, run count, warm/cold cache, and tool version. Measure at least:

- Initial page load and key interaction latency (paste to first result, excluding provider wait where separated).
- First Contentful Paint, Largest Contentful Paint, Cumulative Layout Shift, and Interaction to Next Paint where tooling supports them.
- Frontend transfer size and major assets; API p50/p95 response time under a documented local test load.
- Provider timeouts, cache hit/miss, error rates, and partial-result behavior after providers exist.
- Mobile low-bandwidth behavior and whether the page remains usable when optional services fail.

Use current official browser performance guidance for target thresholds. Identify bottlenecks, fix them, and repeat the same measurements. Do not compare LinkGuard response time to another provider unless test inputs, conditions, and method are comparable. Report results as measurements, not guarantees.

## G. User-friendliness and accessibility review

Observe representative users if possible; otherwise run a documented heuristic review and label it as an estimate. Measure task completion, time, misclicks, abandonment, comprehension of verdict/uncertainty, and confidence calibration. Include people unfamiliar with cybersecurity and mobile users in usability sessions.

Check keyboard-only operation, semantic labels, visible focus, screen-reader output, live status announcements, 200% zoom, reduced motion, color contrast, WCAG 2.2 AA target, errors with recovery guidance, and reviewed Tamil/Hindi security language. Do not rate usability from appearance alone.

## H. Honest rating and maturity stage

Give separate evidence-based scores from 1–10 for:

- Functional completeness for the declared release scope.
- Ease of use and task clarity.
- Mobile responsiveness.
- Accessibility.
- Security and privacy readiness.
- Performance, with measured data.
- Maintainability and operations.

For each score include at least one concrete piece of evidence and one limiting gap. Explain that scores are an engineering assessment, not a certified audit or guarantee. Do not raise a score just because a screen exists.

Assign one maturity stage:

- **Stage 0 — concept:** product idea only.
- **Stage 1 — visual prototype:** screens exist; core actions are mocked or incomplete.
- **Stage 2 — functional MVP:** declared flows work end-to-end, with honest limitations and basic verification.
- **Stage 3 — production candidate:** security/privacy controls, monitoring, backups, abuse handling, accessibility, and deployment are independently reviewed and tested.
- **Stage 4 — operated production service:** deployed, monitored, supported, incident-managed, and evaluated continuously with real operational evidence.

State which specific evidence moved the project to its current stage and what gates remain for the next stage. Do not claim stage 3 or 4 based on local development alone.

## I. End-of-task report format

Finish each improvement cycle with these sections and concise language:

1. **Stage now:** stage name, rationale, and next-stage gate.
2. **Ratings:** all seven dimensions, evidence, limitations, and confidence in the rating.
3. **What existed before:** verified baseline features and the flows actually exercised.
4. **What changed:** implemented features/fixes, exact files, and why they matter.
5. **How it works:** simple user journey plus a brief architecture/data-flow explanation.
6. **Competitor comparison:** dated, source-linked matrix and careful differentiation statement; list research gaps.
7. **New ideas:** prioritized shortlist with impact, effort, risk, and validation metric; separate implemented ideas from suggestions.
8. **Mobile/user-friendliness:** tested viewports/devices, outcomes, accessibility issues, screenshots if available.
9. **Speed:** before/after measurements and test conditions; state “not measured” rather than guessing.
10. **Verification:** commands/scenarios run, pass/fail results, skipped tests, and cleanup performed.
11. **Known limitations:** credentials/infrastructure absent, provider coverage, accuracy gaps, security findings, and deployment state.
12. **Next concrete actions:** ordered list toward the next maturity stage.

Never say “100% working,” “failure free,” or “completely secure.” State what passed, under which conditions, and what remains unverified. Be direct when a feature is a prototype, heuristic, unavailable, or merely proposed.
