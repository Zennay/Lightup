# TLS lab ground-truth calibration

This acceptance lane calibrates LightUp's existing planner-driven TLS assessment without changing any production worker code.

## Fixture

The regression creates a temporary HTTPS server bound only to `127.0.0.1` with a short-lived self-signed certificate generated for the test. The server requires TLS 1.2 or newer, so the deliberately planted condition is certificate-chain trust rather than a legacy protocol.

The hand-maintained expected finding is:

- `untrusted-certificate-chain` from capability `cryptography`.

Ground truth is declared independently from the observation result. The test does not derive its expected check id from the worker output.

## End-to-end contract

The test passes the loopback HTTPS endpoint through the existing deterministic `scripted_demo_gateway` and `run_planned_assessment` path. It requires:

- exactly one TLS planner call for the fixture host and port;
- exactly one finding, `untrusted-certificate-chain`;
- 1 valid finding, 0 invalid findings and 0 missed findings;
- zero policy violations, denials or elevation requests;
- TLS evidence remains attributed to the `cryptography` capability.

Any additional TLS finding is intentionally treated as an invalid finding. This makes OpenSSL/runtime drift visible instead of silently broadening the benchmark truth.

## Collision and safety boundary

This lane adds tests and documentation only. It does not modify `src/lightup/workers/tls_baseline.py`, which remains outside this ownership boundary and may be independently hardened by scope-authorization work.

The fixture is loopback-only. It performs no public target interaction, scanning, exploitation, authorization widening, remediation/retest execution, deployment, security-verdict creation or attack-path mutation.
