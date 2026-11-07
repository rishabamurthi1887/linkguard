# LinkGuard Phase 3 Readiness

**Current version:** LinkGuard 2.2.0 local preview with Phase 3A local-only URL analysis.  
**Branch:** `feature/phase-3-url-intelligence`  
**Phase 3A decision:** **CONDITIONAL PASS** for continued isolated development.  
**Public deployment:** Prohibited. **LinkGuard V3.0 is not complete.**

## Decision and scope

Phase 3A implements non-network URL inspection: URL parsing and normalization, scheme validation, IDN/Punycode inspection, limited mixed-script/homograph clues, and explainable structural evidence. It does not resolve DNS, fetch a submitted URL, or follow redirects. The application must continue to report DNS and redirect checks as unavailable/incomplete rather than implying a safe result.

The separate inspection-worker architecture and SSRF controls are documented in `URL_INSPECTION_THREAT_MODEL.md`, but the worker is **not implemented** and the proposed controls have not been independently reviewed or tested. DNS and redirect fetching must not be implemented or enabled until that independent review and the required network/SSRF tests are complete.

## Verification evidence

- `python -m unittest discover -s tests -v`: **39 passed, 0 failed** in the latest recorded run. This includes the 32 Phase 2.2.0 baseline tests, 2 Phase 3A URL-analysis tests, and 5 HTTP integration tests.
- `python -m compileall -q app tests scripts`: passed.
- HTTP tests use the real FastAPI ASGI middleware stack in-process with synthetic accounts and inputs. They do not establish browser, reverse-proxy, TLS, or deployed CORS behavior.
- URLhaus and Google Web Risk behavior has been tested with mocks. **Live provider verification is pending**; no live credentials/provider result has been verified.
- No submitted URL was fetched during these tests.
- The dataset is synthetic and product-authored; it does not support real-world accuracy claims.

## Readiness checklist

- [x] Phase 2.2.0 authentication, per-user history/report isolation, and reliability disclosures retained and covered by tests.
- [x] Phase 3A local-only URL parsing, normalization, and explainable clues implemented.
- [x] Tests preserve incomplete verdict behavior and explicit provider/check status semantics.
- [x] Worker isolation and SSRF threat model documented.
- [ ] Independent security/architecture review of the worker threat model.
- [ ] Implement isolated worker, restricted egress, IPv4/IPv6 address policy, DNS rebinding protections, redirect revalidation, and response/time limits; add tests before any network fetching.
- [ ] Live provider verification with approved credentials, terms/privacy review, and appropriate consent.
- [ ] Production/shared-use gates: deployment TLS/cookie verification, distributed throttling, monitoring, retention and backup deletion, recovery/MFA, independent penetration testing, and operational review.
- [ ] Representative, licensed, human-reviewed dataset and evaluation before any real-world accuracy claims.

## Gate interpretation

**CONDITIONAL PASS** applies only to the Phase 3A local development slice. It is not a production approval, a guarantee of detection accuracy, or authorization for URL fetching. Public deployment remains prohibited; LinkGuard V3.0 is not complete.

See `UPDATED_PHASE_3_READINESS.md` and `PHASE_3A_CLOSURE_REPORT.md` for the detailed current status and recorded limitations.
