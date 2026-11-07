# False Negative Report

**Status:** The 12-example synthetic test split has 0 false negatives; real-world false-negative rate remains unknown.

Known risk: new domains, shortened links, redirects, subtle or multilingual wording, impersonation, forged payment proofs, novel QR payloads, and malicious files without inspected indicators can evade current checks. Sender identity, recipient ownership, live site behavior, email authentication, OCR, antivirus, and campaign reputation are not comprehensively checked.

The synthetic test set covers only four authored scam-like messages; it cannot estimate missed scams in the wild. No real-world missed-scam count is available. Absence of a rule match or threat-feed result must not be treated as evidence that content is safe.
