# TLS baseline labeval

This command scores the real lab-tls-baseline worker against explicit ground
truth from an ephemeral self-signed HTTPS fixture. It is intentionally separate
from the TLS worker implementation and does not enable any target adapter.

## Run

    PYTHONPATH=src python -m lightup.lab_tls_score --db /tmp/lightup-tls-score.db

After packaging, the equivalent entry point is:

    lightup-lab-tls-score --db /tmp/lightup-tls-score.db

The command requires the OpenSSL executable to generate a one-day RSA
certificate. The certificate includes an IP subject alternative name for
127.0.0.1; the temporary directory and private key are owner-private and are
deleted when the run ends. Certificate and key bytes are never printed or
persisted in the evaluation database.

## Scoring contract

- The listener binds only to 127.0.0.1 on an operating-system-assigned port.
- The server permits TLS 1.2 or newer, so the hand-maintained expected finding
  is exactly untrusted-certificate-chain; legacy protocol and weak-cipher
  findings are unexpected.
- Two observations execute through the existing ToolExecutor and the
  registered lab-tls-baseline handler in the same lab run context.
- The score checks the known ground truth, modern protocol, strong cipher,
  reproducibility, four worker handshakes plus an independent strict system-trust
  control, and the exact evidence lineage (run, capability, source, kind, and lab marker).
- The canonical StateStore labeval record is written and read back. Its
  record ID and evidence IDs must match the producing run.

Any failed check yields a nonzero exit code and a score that is not considered
passed. The record is a reproducible local calibration result, not proof of
external source authenticity, client/operator consent, target authorization,
or release readiness. No public endpoint, model provider, grant, dispatch,
live scan, remediation, or deployment is used.
