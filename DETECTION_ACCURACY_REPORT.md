# Detection Accuracy Report

**Release:** LinkGuard 2.2.0 security and provider preview  
**Evaluation date:** 2026-11-07  
**Evaluation:** Synthetic rule benchmark only. Real-world accuracy is **not measured**.

`python scripts/evaluate_message_rules.py` evaluates the current message rules against 12 held-out synthetic examples: 4 `scam_like`, 8 `legitimate_like`, authored to check selected English, Tamil, Tanglish, and Hindi rules. The examples are deliberately small and authored around the current rules, so these results are regression evidence only and strongly overfit to the rule design.

| Metric on synthetic test set only | Result |
|---|---|
| Test size | 12 |
| True positives / false positives | 4 / 0 |
| False negatives / true negatives | 0 / 8 |
| Precision / recall / F1 | 1.00 / 1.00 / 1.00 |
| False-positive / false-negative rate | 0.00 / 0.00 |
| Per-language correct (English, Tamil, Tanglish, Hindi) | 3/3 each |
| Real-world precision, recall, calibration | Unknown / not measured |

The perfect synthetic-set result is not evidence of perfect detection. It must not be advertised as LinkGuard accuracy. The numeric `risk_score` remains a backward-compatible, uncalibrated rule indicator and is not a probability of fraud. No category is represented as comprehensively supported based only on keyword rules.
