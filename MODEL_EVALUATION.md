# Model Evaluation

**Status:** No trained AI/ML model is integrated in LinkGuard 2.2.0.

URL, message, QR payload, and file-format assessments use deterministic parsing and hand-authored rules. The project has no model weights, training procedure, model version, or model benchmark. Browser `BarcodeDetector` is a platform QR decoding API, not a scam-classification model.

The deterministic message rules produced precision/recall/F1 of 1.00 on a tiny, authored synthetic test set; this is not model performance and is not representative of real use. No real-world precision, recall, calibration, or language-specific performance is known. Do not advertise model-based detection or model accuracy. Any future model must be evaluated against documented, licensed, representative, held-out data before user-facing deployment.
