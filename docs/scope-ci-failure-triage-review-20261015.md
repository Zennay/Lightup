# Offline LightUp CI failure triage — #301 is NOT an exception to HOLD

The real LightUp hosted Python 3.11/3.14 full unittest jobs at PR #1463
encountered an **existing expired wall-clock fixture** in
`test_scope_legacy_falsy_window_301_red_20261014.py` while all this PR's own
tests passed. This tool assigns a **candidate hint** to that exact observed
failure signature without dismissing its failing CI status, masking another
failure or touching the issue's actual source-owner files.

```sh
python scripts/scope_ci_failure_triage_review_20261015.py < offline-synthetic-unittest.log
python -m unittest discover -s tests -p 'test_scope_ci_failure_triage_review_20261015.py' -v
```

Strict bounded raw UTF-8 stdin, maximum 1 MiB. Only a single valid Python
unittest summary and exact matching FAIL heading, matching source module,
traceback source basename/method, known failing assertion and matching
footer failure/error counts can yield
`KNOWN_301_FIXTURE_SIGNATURE_REVIEW_REQUIRED` and `known_issue_hint:301`.
Unknown or additional failures remain `UNTRIAGED_OR_NO_FAILURE` or opaque
HOLD on inconsistent log counts. No customer data/log lines/other test names
are echoed.

**Every output: HOLD/exit 2, six hard-false authority flags.** The input is
untrusted, not original GitHub job attestation; an attacker could fake all
lines. This is not proof that #301 is the *sole* CI blocker, not a security
exception, not a proof of deployed runtime safety, and never a release waiver.
Source #301 fixture repair belongs to [PR #1452](https://github.com/Zennay/Lightup/pull/1452).
Full source protection and exact integrated hosted + real producer and
permanent registered VPS proof, independent security/privacy, authenticated
customer/operator permission and explicit human GO remain mandatory.
**INCUBATE M3/M7 · DRAFT/HOLD: no merge, real scans, grants or deploy.**
