# LinkGuard Detection Dataset Documentation

**Dataset:** Synthetic LinkGuard Message Set v1.0.0  
**Status:** Included for rule regression checks; not representative of real-world scam traffic.

The dataset is split into `tests/data/train`, `tests/data/validation`, and `tests/data/test`. It contains 28 product-authored examples across English, Tamil, Tanglish, and Hindi. Labels are `scam_like` or `legitimate_like`, and describe the synthetic scenario only. It includes simple warning examples, benign account notices, and cautionary advice that mentions scam terms.

All samples are synthetic and manually reviewed once by the project author. No external dataset, scraped content, real URL, real phone number, user submission, or personal data is included. The synthetic set has no third-party dataset licence or independent annotator agreement. This is not sufficient for deployment accuracy claims.

The train and validation splits are reserved; no model is trained with them. `scripts/evaluate_message_rules.py` runs the deterministic message rules on the held-out test split only. Extend the set with independently reviewed, licensed, time-separated examples before making real-world performance claims.
