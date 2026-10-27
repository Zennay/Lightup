# Trace context is never scope authorization (offline reference)

This is a **tests-only reference contract**, not a deployed authorization gate. W3C-style `traceparent`, `tracestate`, and `baggage` are untrusted observability inputs. A trace ID or vendor header that contains words like "approved", "tenant", "grant", or "revoked" may neither issue nor invalidate authorization.

The scoped production owner must bind tenant, client, engagement, exact asset, capability, explicit human approval, validity window, and revocation state to a verified and revalidated grant **before** any handler, network operation, or evidence write. Every denial must entail zero handler calls and zero evidence writes; only valid current grant evidence from the trusted authority can permit execution. Never promote synthetic fixture strings to real permission.

## Current proof boundary

`tests/test_scope_trace_context_nonauthority_20261009.py` exercises eight offline cases:
- traceparent cannot mint authorization;
- tracestate/baggage cannot mint authorization;
- conflicting trace metadata does not override an out-of-band verified fixture;
- revoked/missing fixture remains denied;
- hostile tracing objects are never coerced;
- truthy / str-subclass fake grant identities fail closed;
- attacker-provided grant collection objects cannot run custom membership hooks;
- mixed-type trusted grant collections and malformed grant identities fail closed.

Run in the repository: `python -m unittest discover -s tests -p 'test_scope_trace_context_nonauthority_20261009.py' -v`.

## Release gate / owners

This test is **reference-only**: the fixture verifier is not an issuer or signer and has no connection to production dispatch. Production trusted pre-I/O enforcement remains owned by #107 / #1128 and related engagement revocation work (#100). Hold this change as a draft until exact-commit hosted checks, canonical permanent VPS CI and source-owner review; even a green test does not authorize real targets. No scans, network, DNS, targets, grants, deployment, or edits to other worker paths.
