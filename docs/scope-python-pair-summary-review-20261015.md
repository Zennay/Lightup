# Strictly offline dual-Python unittest comparison (scope authorization)

Use `scripts/scope_python_pair_summary_review_20261015.py` to compare
**caller-provided, unauthenticated** Python 3.11 and 3.14 unittest summaries.
This does not authenticate which Python versions ran, which immutable commit,
workflow, repo, registered runner or test source generated the text.

Input is one JSON object with schema_version 1, complete boolean,
python_311_log and python_314_log. Each bounded UTF-8 raw log is <=1 MiB;
full envelope is <=2MiB+32KiB. The parser reuses the strictly bounded single
`unittest` summary reviewer, rejects duplicates, nonfinite/malformed JSON,
Unicode surrogate traps, missing/multi-suite result logs and extra fields.
Differences in test totals, result, failures, errors, skips, expected failures
or unexpected successes result in aggregate `MISMATCH`, without leaking any
untrusted source text. Equal summaries are only `UNAUTHENTICATED_EQUALITY`.

```sh
python -m unittest discover -s tests -p 'test_scope_python_pair_summary_review_20261015.py' -v
```

**EVERY input always yields HOLD/exit 2 and six explicit false
permit/scan/merge/release/execution/authorization flags.** Even identical
`OK` logs cannot approve deployment. This complements independent #1309
real GitHub exact-head metadata and permanent registered VPS evidence. The
separately owned #301 expiration fixture and production #107/#1172 + ledger
#1454/#1455 must still be fixed and reviewed before real use. Independent
privacy/security, customer/operator consent and explicit human GO remain
required. No real targets, network, grants, scans or deployment.
