# #648 — immutable caller-owned durable ScopeDefinition collections

**Phase:** INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. **Branch-only** acceptance under open #648 and the repository's #776 saturated-runner guidance; do not create another parallel PR/workflow, merge or deploy while the permanent self-hosted runner queue is blocked.

## Independent collision boundary

Pinned original source-owner [PR #554](https://github.com/Zennay/Lightup/pull/554) exact HEAD `4c8d5651fc0e23f94514daae56b4e5fe0549de37`. This isolated branch only adds these TWO new paths:

- `tests/test_scope_immutable_grant_collections_648_20261017.py`
- `docs/scope-immutable-grant-collections-648-20261017.md`

Never alter `src/lightup/engagements.py`, `domain.py`, #646 source-owner handoff, #775/#773 scalar/collection type owners, execution policy, handlers, evidence, releases or other worker branches.

## Verified authorization-integrity defect

`ScopeDefinition` is marked `@dataclass(frozen=True)`, but its three collection annotations are not enforced. An exact `ScopeDefinition` may retain caller-owned mutable lists. The original `DomainStore.record_authorization_grant` serializes a database snapshot but returns an in-memory `AuthorizationGrant` that references the mutable scope. After synthetic issuance, caller mutation can:

- append `outside.invalid` to an asset list and **widen** the existing in-memory scope;
- clear `excluded.invalid` from an exclusion list and **erase** a prior denial;
- append `api-baseline` to the capabilities list and **widen** capabilities without new approval.

This is not a demonstrated live executor bypass: the tests use a fictional client, `.invalid` identities, temporary SQLite and no network, real targets, scans, handlers or actual client/operator consent.

## Acceptance contract

Both of the following source-owner approaches are valid: **reject non-tuple collections at construction**, or **copy caller-owned exact mutable lists immediately into immutable tuples**. Never retain list aliases. Canonical tuple-based input must continue to work. An issued durable grant must not change identity, allow/exclude behavior, risk or capabilities after its caller changes the original list. Stored SQLite rows remain identical before and after mutation.

The opt-in test module has three ordinary positive/negative controls and six intentionally unresolved original-source `expectedFailure` cases (three construction-time and three real temporary SQLite issuance-time aliases).

```sh
PYTHONPATH=src python3 -B -m unittest discover -s tests -p 'test_scope_immutable_grant_collections_648_20261017.py' -v
# After the source owner repairs construction, promote all six REDs:
LIGHTUP_SCOPE648_REQUIRE_SOURCE_FIX=1 PYTHONPATH=src python3 -B -m unittest discover -s tests -p 'test_scope_immutable_grant_collections_648_20261017.py' -q
```

**Default green + six expected failures means the defect remains unfixed.** Strict opt-in must be genuinely green with zero expected source failures after implementation, original whole hosted and permanently registered VPS CI, independent security/privacy review, separate genuine client/operator authenticated authorization and at-use revocation, and explicit HUMAN GO. No authorization or release power is implied.

## 2026-10-17 · actual connected zSSH proof (branch-only)

The original installed source at own branch `1503ae5bfb7478f89deb3fcf626117938b99db2c` was executed in an isolated disposable checkout on `vps-bb300bba`, Python 3.14.4. **9 tests: 3 ordinary PASS, 6 original-source expectedFailures**, zero unexpected failures and clean own checkout. The source is still unpatched.

A **separate temporary local clone** was then used to rehearse a minimal source-owner change to **`src/lightup/engagements.py` exclusively in that throwaway filesystem**. It inserts `__post_init__` into the dataclass and snapshots all three caller-owned lists with exact-list checks (no foreign iterator invocation):

```python
    def __post_init__(self) -> None:
        for name in ("assets", "excluded_assets", "allowed_capabilities"):
            value = object.__getattribute__(self, name)
            if type(value) is list:
                object.__setattr__(self, name, tuple(value))
```

Only this *disposable local copy* was modified, **nothing pushed to any production/source-owner branch**. On that local Python3.14 checkout with literal strict `LIGHTUP_SCOPE648_REQUIRE_SOURCE_FIX=1`:

- **9/9 ordinary acceptance tests PASS**, zero expected failures;
- **576/576 whole unit tests PASS**, zero expected failures;
- **86/86 original integration tests PASS**;
- original Git change listing shows only local `M src/lightup/engagements.py`, no external asset or target activity.

To prevent an incomplete fix being mistaken for success, a second isolated weak test copy snapshotted **only `assets`**. Strict testing remained **RED: exactly four failures** for outstanding `excluded_assets` and `allowed_capabilities` aliases, proving that all three collections must be addressed. This is local proof-of-repair, not production-ready code, source-owner signoff, hosted matrix or a valid customer authorization.

**Do not create another PR/hosted workflow solely for these known issue #648 expected-RED tests while [issue #776](https://github.com/Zennay/Lightup/issues/776) requires branch-only work due the registered runner saturation.** The source owner must decide whether to snapshot or reject lists and review interactions with #775 exact collection types and #646 canonical scope object identity. Release remains HOLD.
