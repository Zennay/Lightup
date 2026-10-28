# Offline lab comparison receipt

Run `python3 assessment-runtime-receipt/receipt.py PRIVATE_COMPARISON.json` on an already-exported local lab comparison. The output contains only status, byte count, SHA-256 and explicit false authority flags. The command always exits 3 and never scans, dispatches or contacts targets.

Malformed, oversized, duplicate-key, nonfinite, symlinked and noncanonical status/authority inputs yield a source-minimal HOLD. The SHA-256 is only a local byte-fidelity identifier: it does **not** authenticate the producer, prove ground truth, establish consent or grant permission.

**INCUBATE · PLAN/LAB ONLY · REVIEW/HOLD.** This companion is independent of the active #1515 source-owner branch. It is not a release candidate until existing CI and independent security/privacy review gates are met. No real-target assessment or deployment is permitted.
