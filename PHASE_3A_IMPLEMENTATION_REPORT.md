# Phase 3A — Safe Local URL Analysis Report

**Status:** Implemented in the Phase 3 development branch. This phase performs local string/URL analysis only. It does not perform DNS resolution, open URLs, or follow redirects.

## Implemented

- Accepts only HTTP and HTTPS schemes; malformed ports and invalid host labels are rejected.
- Normalizes Unicode hostnames to NFC before IDNA conversion and lowercase ASCII for comparison. Removes one terminal DNS root dot; multiple trailing dots remain invalid.
- Reports safe normalization metadata only: normalized scheme, ASCII hostname, non-default port, IDN/Punycode indicator, and root-dot normalization. Raw path, query, fragment, and userinfo are not included in the normalization object or stored URL subject.
- Preserves IDN/Punycode warnings and detects mixed Latin/Cyrillic/Greek labels. Added a conservative list of common Unicode lookalikes to explain possible homograph patterns.
- Continues to flag userinfo, deep subdomains, known URL shorteners, sensitive-action words, non-HTTPS links, and redirect-style query parameters as clues.
- Adds a clear limitation that the Unicode lookalike heuristic can miss attacks and can flag legitimate domains.
- Preserves explicit unavailable checks for reputation, redirects, DNS, and TLS. No finding is treated as proof of safety.

## Security constraints

- No submitted URL is fetched or resolved.
- The local URL normalization fields do not contain path/query/fragment values.
- Provider integrations retain their existing explicit-consent and per-provider status behavior. HTTP unit tests run with provider keys unset; provider adapter tests are mocked.
- The proposed DNS/redirect worker remains design-only in `URL_INSPECTION_THREAT_MODEL.md`.

## Tests

New URL tests cover uppercase scheme/host, default-port normalization, a single trailing dot, repeated trailing-dot rejection, IDN Punycode, a mixed-script confusable example, unsupported scheme rejection, and no calls to `urlopen` during local analysis. The full suite passed: 39 tests total, including all 32 Phase 2.2.0 baseline tests, 2 new URL tests, and 5 HTTP integration tests. Python compilation passed.

## Limitations

The lookalike character map is deliberately small and is not a full Unicode confusables database or registrable-domain policy. No DNS, certificate, redirect, reputation completeness, or website behavior is inferred from local parsing. No scam-probability or accuracy claim is added.
