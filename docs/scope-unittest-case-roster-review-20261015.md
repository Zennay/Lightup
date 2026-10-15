# Test-by-test source-RED roster verification (strictly offline)

Use a **caller-provided, unauthenticated unittest -v log** to compare an exact
synthetic watch roster of method IDs to what the log actually *reports*. This
detects silently absent tests, changed outcomes, unexpected successes and
claimed PR owner omissions, without leaking names from raw input.

```sh
python -m unittest discover -s tests -p 'test_scope_unittest_case_roster_review_20261015.py' -v
```

CLI `python scripts/scope_unittest_case_roster_review_20261015.py` accepts one
bounded stdin UTF-8 JSON object with `schema_version:1`, `complete:boolean`,
`raw_log:string` (up to 1 MiB), `watch` (1–512 records) of exactly:
`{"test":"test_scope_a.Sample.test_x","issue":1147,"owner_pr":1462,
"expected_status":"expected_failure"}`. Other outcomes are `passed`,
`failed`, `error`, `skipped`, `unexpected_success`. Data is synthetic,
not actual consent, grant or owner attestation.

Every output has `status:HOLD`, exit 2, all six authority flags `false`,
and **only aggregated counts**; no raw test names, target names or tokens.
Duplicate/ambiguous test records, duplicate JSON keys, type-confused IDs,
invalid Unicode identifiers, malformed input, multiple summary lines and
oversized input all fail closed to opaque HOLD. Genuine source-RED
`expected failure` is still unpatched: never green for authorization.

## Limitations and real blockers

Observed unittest lines and `complete` are **self-asserted text**; the parser
cannot certify Python, GitHub SHA, real runner, complete discovery, captured
stderr, nonzero CI conclusion, installed executor permission, lab isolation,
consent, revocation, privacy/security review or release. Unittest subtests
may not match the simple case-line format and must be separately reviewed.
Compare with original GitHub job logs and actual test sources, not solely this
output. Existing source owners #1147/#107, #1173/#1172, #1454/#1455 and
#301/#1452 are not changed. Permanent registered VPS proof and human GO
remain absent. **INCUBATE M3/M7 · DRAFT/HOLD; no merge/deploy/grants/scans.**
