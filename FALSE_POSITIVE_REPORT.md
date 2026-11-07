# False Positive Report

**Status:** The 12-example synthetic test split has 0 false positives; real-world false-positive rate remains unknown.

Known risk: legitimate messages or URLs can match urgency, KYC, payment, job-fee, login, verification, or other warning-word rules. The rules are clues, not proof. There is no confirmed false-positive count because the project has no reviewed benchmark dataset or adjudication workflow.

The synthetic test set is tiny, authored around current rules, and not independently annotated. Its zero false-positive count is not evidence of real-world precision. `python scripts/evaluate_message_rules.py` reproduces the synthetic result.
