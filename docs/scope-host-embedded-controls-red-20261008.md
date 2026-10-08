# Scope authorization: embedded host controls (offline RED acceptance)

**Phase:** M7/ST5, plan/lab only. **Ownership:** independent test-only lane. Existing `ScopePolicy` source owner retains production implementation; no edits to `scope.py`, `ExecutionPolicy`, grants, ToolExecutor or discovery.

Python's `urllib.parse.urlparse` removes ASCII tab, CR and LF characters from URL strings before parsing. A scope decision must not silently convert a caller-supplied malformed host containing any of those characters into an otherwise explicitly authorized host. This is an identity-integrity regression, not proof of a network exploit.

The five-case matrix covers a valid exact allowlisted host (positive control), three URL-form embedded-control substitutions, and a scheme-less embedded tab. **Desired safety invariant:** malformed input is denied regardless of a matching explicit host entry and otherwise-current authorization. Implementers may return `INVALID_TARGET` or another denied reason; admission must remain false. Raw input should be validated before a normalization stage that discards control characters.

Test: `PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_host_embedded_controls_red.py' -v`.

These checks may intentionally fail against current main; do not mark green, merge, deploy or authorize active targets until the source owner implements fail-closed behavior and the exact final head passes permanent self-hosted CI. All hostnames use RFC-reserved `.example.test`; no DNS, networking, scanning, target capability, or grant widening.
