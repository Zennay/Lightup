# Evidence review: duplicate reference admission (#899)

**Status: RED acceptance, source-owner HOLD.** Pinned baseline: PR #846 at
`26b0ca5e89648c3604ff3b9ca1ba2fab81dd2dd6`.
Only offline scripted-provider tests; no product source changes.

## Required behavior

- Finding-local `evidence_ids` must be a built-in list of 1–64 distinct,
  canonical nonblank built-in strings, with the existing per-ID length limit.
- Preserve source order exactly. Reject duplicates **before the verifier**
  or any other model role receives a request. Do not silently deduplicate,
  sort, strip, coerce, normalize, or repair the input.
- On rejection neither the input object nor persisted evidence should change.
  The scripted provider call trace must be empty.
- One distinct pair of synthetic evidence identifiers is a green control;
  invalid container type remains an existing green deny control.

## Test

`PYTHONPATH=src python -m unittest tests.test_review_input_integrity_red_20261010_w4 -v`

The duplicate case is an intentional `unittest.expectedFailure` against
the currently vulnerable PR #846 source, **not** accepted remediation.
When the source owner implements the change, remove the expected-failure
decorator so this becomes an ordinary passing contract. A green suite with
expected failures must **never** be described as proof of a production fix.

Ownership: PR #846 keeps `src/lightup/ai/pipeline.py`; add-only regression
suite and documentation here. No real model, targets, authorization, live
verdict, remediation, network, deployment or production data.
