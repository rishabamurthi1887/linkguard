# LinkGuard Test Guide and Current Results

## Run the automated suite

From the repository root in PowerShell:

```powershell
python -m unittest discover -s tests -v
python -m compileall -q app tests scripts
```

## Latest recorded result

At the documentation refresh, the full suite was rerun: **39 tests passed, 0 failed**. Python compilation also passed. The suite consists of 32 Phase 2.2.0 baseline tests, 2 Phase 3A local URL-analysis tests, and 5 HTTP integration tests.

Coverage includes authentication/session behavior, account and report isolation, deletion and legacy ownerless records, provider consent/status/error/retry/cache handling, reliability disclosures, taxonomy/data checks, multilingual phrase cues, URL parsing/normalization and no-fetch behavior, and HTTP-level auth/CSRF/CORS/isolation flows through the FastAPI ASGI stack.

The HTTP integration tests use synthetic accounts and an in-process ASGI client; they do not exercise a real browser or deployed network stack. Provider outcomes are tested with mocks. **Live URLhaus and Google Web Risk calls have not been verified.** A live provider check requires valid backend credentials, approval of provider terms/privacy implications, and explicit user consent where applicable. Normal tests do not contact those providers or fetch submitted URLs.

The test dataset contains 28 synthetic, product-authored message examples split across training, validation, and test files. It is suitable for checking deterministic evaluator behavior and selected examples only. It does not support real-world accuracy claims.

## Not covered or still required

- Independent review and implementation/testing of the isolated URL inspection worker.
- DNS resolution and redirect following (not implemented; no user URL fetch is performed).
- Live provider verification with approved credentials and non-sensitive test indicators.
- Browser/device testing for responsive layout, camera and QR flows, accessibility, and cookie behavior.
- Fluent review of Tamil, Tanglish, and Hindi detection cues and translations.
- Production or multi-worker behavior: distributed rate limits, HTTPS/reverse-proxy configuration, operational monitoring, backup/restore and deletion verification, and independent penetration testing.

Passing this local suite does not mean the service is failure-proof, production-ready, independently security-approved, or accurate on real-world scams. Public deployment is prohibited at the current stage.
