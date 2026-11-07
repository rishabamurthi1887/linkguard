# Threat Intelligence Provider Review

**Reviewed:** 2026-11-07  
**Implemented:** URLhaus Community URL lookup and Google Web Risk Lookup API adapters.  
**Live status:** Neither provider key is configured in this local environment, so no real-provider result has been tested.

| Provider | Official docs/terms findings | Decision |
|---|---|---|
| URLhaus Community API | Requires an `Auth-Key`; free under fair-use principles; commercial or for-profit use may require a paid enhanced service. It focuses on URLs directly distributing malware, not phishing in general. | Implemented. Calls are server-side, consent-gated, time-bounded, retried once, cached five minutes, and reported independently. Commercial deployment needs terms review. |
| Google Web Risk Lookup | Official REST lookup accepts one URL per call and threat-type query fields. Pricing page lists the first 100,000 `uris.search` calls/month free and $0.50 per 1,000 above that tier; cloud billing/key setup is required. | Implemented as optional server-side adapter. Limit the API key to Web Risk and use quotas/billing controls. User consent is required because the URL is submitted to Google. |
| Google Safe Browsing | Public API is for non-commercial use; commercial use needs a separate agreement. Terms require attribution and caution language and warn that submitted URLs may be used/shared. | Not integrated. Web Risk is the appropriate Google product to assess for commercial deployment. |
| VirusTotal Public API | Public API is not for commercial products/services and has a low public quota. Official docs state submitted or queried indicators are added to its dataset and shared with examining partners/community. | Not integrated. Do not send private user URLs to the public API. A private/commercial agreement requires separate procurement and privacy review. |
| PhishTank | API docs describe a POST URL lookup and rate limits. Public FAQ and terms provide conflicting/ambiguous scope for commercial use and service use. | Not integrated until current Cisco/Talos terms and intended-product use are clarified. |

## Implemented data flow

- The browser receives only provider names, configured flags, and disclosure text. API keys stay in server environment variables.
- External lookup is optional and requires the authenticated user to opt in on that scan.
- The provider receives the complete submitted URL except its fragment. Token-like query parameters, URL credentials, and literal non-public IPs are skipped.
- LinkGuard does not fetch the submitted site or follow its redirects. This avoids using the application as a URL-fetch/SSRF proxy; redirect inspection remains unavailable pending an isolated, egress-controlled service.
- A no-match is never a safe verdict. Provider errors, unconfigured status, consent requirements, and matches are kept distinct.
- Requests have a four-second timeout, one retry for transient errors, and a five-minute positive/no-match cache. Provider health reports configuration, last status, and last check time.

## Official sources

- URLhaus [Community API](https://urlhaus.abuse.ch/api/)
- Google [Web Risk Lookup API](https://docs.cloud.google.com/web-risk/docs/lookup-api) and [pricing](https://cloud.google.com/web-risk/pricing)
- Google Safe Browsing [terms](https://developers.google.com/safe-browsing/terms) and [appropriate usage](https://developers.google.com/safe-browsing/reference/Appropriate.Usage)
- VirusTotal [getting started and public API restrictions](https://docs.virustotal.com/reference/getting-started), [public vs. private API](https://docs.virustotal.com/docs/difference-public-private), and [submission/data sharing](https://docs.virustotal.com/docs/how-it-works)
- PhishTank [API information](https://phishtank.org/api_info.php), [FAQ](https://phishtank.org/faq.php), and [terms](https://phishtank.org/terms.php)
