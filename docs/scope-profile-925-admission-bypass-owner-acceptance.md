# #925 — block passive ProspectProfile admission bypass

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This adds acceptance only,
stacked on the separate discovery source owner PR #175, exact head
`df9eac879bbe232cd1e50fd6e9dfe12ff38f8469`. No source edits.

## Reproduced boundary

`ProspectProfile.add_signal()` validates a passive public, non-interactive
signal before adding it. But the current constructor accepts any caller-owned
`signals: list[ProspectSignal]` and exposes the very same writable list.
Constructor pre-seeding, direct `append`, full replacement and later
mutation of the shared list can bypass the admission function completely.
That can insert nonpublic or interaction-requiring metadata into a profile;
this is **not** proof of active scanning or actual target execution.

## Product owner invariants

- Every accepted signal must traverse `validate_for_unauthorized_discovery`
  before insertion, including any constructor-provided collection.
- A caller cannot mutate or replace the public admitted collection directly.
  A read-only exact tuple view is acceptable.
- Do not retain a caller-owned mutable input collection as the internal
  store. A later external `list.append` must not bypass admission.
- Reject bad entries atomically; never partially add an invalid set or
  rewrite caller-owned signal objects. Preserve the behavior and identity
  of valid `add_signal`.
- Keep `src/lightup/discovery.py` under existing PR #175 ownership; this
  acceptance branch changes tests/docs/isolated CI only.

## Executable proof

```sh
PYTHONPATH=src python -m unittest discover -s tests \
  -p 'test_scope_profile*_925.py' -v
```

Seven ordinary PASS controls demonstrate the existing validated path and
atomic rejection. Twelve intentional `expectedFailure` methods document the
unfixed constructor/public-collection/alias bypasses. Additional `tests/test_scope_profile_mutation_paths_925.py` tests `extend`, `insert`, `clear`, `pop`, slice replacement and augmented assignment, plus the original append/rebinding cases. Source-owner must
make all twelve ordinary PASS after repair, not delete or swallow them.
The isolated hosted Python 3.11/3.14 matrix is merely diagnostic,
not a release gate or registered permanent VPS proof.

No source-owned changes, target discovery, DNS/network, grants, scanners,
handler dispatch, release, merge or deploy. Independent real client/operator
consent, revocation at use, independent security/privacy review, whole project
exact-head CI, registered permanent VPS green and explicit HUMAN GO remain
release prerequisites.
