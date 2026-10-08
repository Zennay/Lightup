# Denied scope identifier: log-output trust boundary (offline reference)

**Status:** Proposed acceptance criteria only; not a deployed policy, production implementation, logging sink, authorization check, or evidence of execution safety.

## Boundary

Authorization denial events may include untrusted asset identifiers and error codes. Rendering that untrusted text directly into plaintext logs can forge apparent log lines (CR/LF), alter terminals (ESC and C1), or create confusing extra rows (Unicode U+2028 / U+2029). Sanitization must take place only **after** authorization has already denied the request. A transformed label must never be reintroduced into an allowlist, authorization comparison, resolver, execution path or audit issuer identity.

For any future audit/logging integration:

1. Persist an immutable, typed denial event with server-owned event type and reason code, separate from untrusted display labels.
2. Represent untrusted target labels as data, not format strings, and bound size *before* sending to sinks.
3. Reject non-string labels without invoking arbitrary `__str__`; escape or replace line/terminal control characters and preserve a single-line presentation.
4. Preserve trusted provenance and original evidence references separately; the lossy rendering here is **not** evidence storage.
5. Do not log secrets, credentials, raw request headers or authorization grants. Apply the existing redaction policy *before* creating any display label.
6. JSON must be serialized by a structured encoder. Never assemble JSON by string concatenation.
7. Never turn a log-formatting failure into an authorization bypass or a target action. A denied event remains denied even if telemetry fails.
8. Production ownership and tests must trace all actual denial-emission sinks before treating this reference as a gate.

## Isolated verification

Run `python -m unittest discover -s tests -p 'test_scope_denial_log_sanitization_reference_20261008.py' -v`.

The six stdlib-only reference tests cover CR/LF/tab, Unicode separators and controls, hostile objects, length bounds, JSON event-field injection and immutability. They do **not** exercise production `ScopePolicy`, the domain authorization graph, the executor or the operational audit sink. Integration belongs with its respective source owner and needs exact-head hosted and permanent VPS proof before promotion.

No DNS, sockets, target contact, scans, dispatch, deploy or permission widening.
