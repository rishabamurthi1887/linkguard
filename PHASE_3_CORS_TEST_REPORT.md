# Phase 3 CORS Test Report

**Method:** HTTP `OPTIONS` preflight and actual HTTP requests executed against the application ASGI stack, in-process.  
**Test status:** Passed; no external network request was made.

## Results

| Case | Result | Observed behavior |
|---|---|---|
| Allowed origin preflight for `DELETE` with `X-CSRF-Token` | PASS | HTTP 200, exact configured `Access-Control-Allow-Origin`, credentials allowed, DELETE listed, CSRF header allowed. |
| Disallowed origin preflight | PASS | HTTP 400 and no `Access-Control-Allow-Origin`. |
| Credentialed actual request from allowed origin | PASS | Auth cookie is accepted; response carries exact allowed origin and `Access-Control-Allow-Credentials: true`. |
| Actual request from disallowed origin | PASS | Endpoint may return its normal response, but no `Access-Control-Allow-Origin` is returned, so a browser cannot expose it to the calling origin. |

These checks confirm current ASGI response policy only. They do not validate browser versions, reverse-proxy header changes, or deployment origin configuration. Keep `LINKGUARD_CORS_ORIGINS` limited to exact trusted origins; CORS is not authentication or authorization.

## Regression command

```powershell
python -m unittest tests.test_http_integration.HttpIntegrationTests.test_allowed_and_disallowed_cors_preflight_and_credentials -v
```
