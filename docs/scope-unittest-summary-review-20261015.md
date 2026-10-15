# Offline unittest job-summary review (scope-authorization)

A convenience adapter for **untrusted local Python unittest job logs**, not
a GitHub runner-verification tool. It extracts one unique trailing unittest
`Ran N tests` summary and an `OK` or `FAILED (...)` conclusion with
only integer counts. The result **always stays HOLD/exit 2**, even when `OK`.

```sh
printf 'Ran 5 tests in 0.1s\nOK (expected failures=2)\n' | python scripts/scope_unittest_summary_review_20261015.py
python -m unittest discover -s tests -p 'test_scope_unittest_summary_review_20261015.py' -v
```

Accepts synthetic or downloaded caller-supplied UTF-8 logs via stdin (max 1MiB).
No file read, GitHub token, API request, network connection, target, grant,
source mutation or subprocess. Reads summary only, never echoes raw lines,
test names, fictional addresses or log secrets. Rejects ambiguous multi-suite
logs, malformed/contradictory counts, duplicate counters and invalid input.

The counts do **not** prove that the named Python version, source SHA,
registered permanent VPS, workflow, test cases, complete suite or GitHub job
are authentic. Genuine exact-head hosted raw job inspection, permanent
registered VPS evidence, source-owner ordinary PASS fixes, security/privacy,
human GO and actual customer/operator authority are still independent mandatory
requirements. Existing #301, #1147, #1454 and #1173 defects remain separate
owners. **INCUBATE M3/M7 · DRAFT/HOLD; never scan, grant, merge or deploy.**
