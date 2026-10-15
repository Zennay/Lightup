# Cross-check expected-source-RED inventory against two Python logs (offline only)

W8 integrates three independent self-reported inputs: the caller's bounded
expected-red debt inventory (issue, full test method, current outcome,
draft owner PR), raw `unittest -v` claimed Python 3.11 job log and equivalent
claimed Python 3.14 log. This detects cases that disappear, change from an
expected failure to passing/unexpected success, diverge between interpreters,
lack a claimed owner, or silently swap test names while footer totals remain
unchanged. Parse each **single** unittest footer and reject duplicate JSON,
duplicate test identity, contradictory footer, improper type/encoding,
unbounded input or impossible method totals.

Invocation is opt-in, with NO network, filesystem inventory, branch writes,
target contact, grants or runtime execution:

```sh
python -m unittest discover -s tests -p 'test_scope_red_evidence_chain_review_20261015.py' -v
python scripts/scope_red_evidence_chain_review_20261015.py < fictional-evidence.json
```

JSON envelope exactly:
```json
{
  "schema_version": 1,
  "complete": true,
  "debt_snapshot": {
    "schema_version": 1,
    "complete": true,
    "cases": [
      {
        "issue": 1147,
        "test": "test_scope_chain.Sample.test_red",
        "outcome": "expected_failure",
        "owner_pr": 1462
      }
    ]
  },
  "python_311_log": "test_red (test_scope_chain.Sample.test_red) ... expected failure\nRan 1 test in 0.01s\nOK (expected failures=1)\n",
  "python_314_log": "test_red (test_scope_chain.Sample.test_red) ... expected failure\nRan 1 test in 0.01s\nOK (expected failures=1)\n"
}
```

All outputs intentionally aggregate only: no raw log, test, token, path or
customer identifiers. The `complete:true` values and issue/PR mappings are
**self-asserted and UNVERIFIED**. Even zero missing cases or matched
expected REDs neither authenticate CI source, actual job IDs, checked-out
SHA, production executor, security fixes, runner nor genuine owner.
Every input remains **HOLD**, exit code 2 and all six permission/release/scan
flags false. Both logs failing in matching ways are still failing.
The existing source owners retain #301/#1452, #1147, #1173/#1172,
#1454/#1455 and actual registered VPS CI #1144.
**INCUBATE M3/M7, DRAFT/HOLD; no merge, deploy, real grant or scan.**

## W8 additional safety result

Matching suite footers and method IDs are **not a waiver** for either an
unpatched expected source RED or an unexpected suite failure. The aggregate
receipt now includes `untracked_expected_red_311/314` and
`untracked_unexpected_failure_311/314` (counts of claimed source results
not covered by the watched test set); any such gap is a disagreement in
unverified evidence. `release_blocking_signal` explicitly distinguishes
unexpected full-suite failures, still-unfixed source REDs, incomplete or
divergent evidence, and logs with no reported failures that STILL have no
release authority. Nothing can promote a log, self-declared completion or
an expected-RED into approval; all six authority flags remain false.
