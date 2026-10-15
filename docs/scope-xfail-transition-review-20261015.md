# Independent expected-RED transition review (scope lane)

Safely compare two **untrusted, fictional** case snapshots to show when a source RED
disappears, changes to green, regresses, or changes claimed PR ownership. It
never determines that the source bug was fixed. Completeness is self-reported,
not authenticated. Neither snapshot supplies tenant, grant, consent, runner,
review or actual authorization.

```sh
printf '%s' '{"schema_version":1,"baseline":{"schema_version":1,"complete":false,"cases":[{"issue":1147,"test":"test_source_red","outcome":"expected_failure","owner_pr":1462}]},"current":{"schema_version":1,"complete":false,"cases":[{"issue":1147,"test":"test_source_red","outcome":"passed","owner_pr":1462}]}}' | python scripts/scope_xfail_transition_review_20261015.py
python -m unittest discover -s tests -p 'test_scope_xfail_transition_review_20261015.py' -v
```

Every command returns **HOLD/exit 2** with all six authorization/release flags
false. Strict duplicate-key, UTF-8, nonfinite, exact-shape, exact type and 64
KiB input gates inherited from the base review; two independently validated
snapshots and bounded 512 cases per snapshot. Output reports only aggregated
counts — never input test names, issue IDs, targets or source strings.

Real acceptance of a `red_to_pass_review_required` transition requires an
original source-owner fix, ordinary NOT-XFAIL assertion on the installed path,
exact SHA hosted unit and real producer CI on both interpreters, independently
assigned permanently registered VPS, current tenant/scope/consent/revocation
gates, privacy/security review and explicit human GO. A missing expected-RED
may mean a renamed/deleted test, not a fix. A self-reported owner change is
not a worker handoff. **INCUBATE M3/M7 · DRAFT/HOLD; no merge or deploy.**
