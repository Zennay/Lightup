# #896 — Synthetic-only, non-authorizing grant-ID identity preview

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. This is not integrated with LightUp.** The test-only reviewer never queries SQLite, issues grants, invokes handlers, mutates evidence or authorizes scanning.

## Isolation and ancestry

- New independent child branch from **unchanged #896 composition HEAD** `3e7067d781fba40d1e80ce664a61ad57c528af6c`; #896 is itself above #887 and domain/source-owner PR #146 with PR #107 live revalidation ancestry. The source-owner retains all implementation, including grant lookup and durable client/engagement binding.
- Only two wholly new test-owned Python paths and this documentation. No `src/`, existing tests, workflows, runners, production grant code or another worker's branch is modified.
- The inherited #873 real installed-source accepted/RED tests stay unchanged; this is **not** proof that the original snapshot-ID validation gap is fixed.

## Exact behavior

The pure helper `tests/scope_896_offline_grant_identity_guard.py` is explicitly opt-in. Direct `review_identity` accepts only `type(grant_id) is str` **before any call to attacker-provided `__conform__`, `__str__`, `__eq__` or `__class__`**. This synthetic reviewer deliberately narrows REVIEW_ONLY to the lowercase RFC4122 UUID4 surface produced by the fictional fixture. This conservative sub-vocabulary is a review filter, **not a requirement that all production historical grant IDs be UUID4**, and it never queries whether any ID exists or was consented to.

The standalone CLI reads <=1,024 bytes UTF-8 unique-key JSON with exactly `{"grant_id":"<fictional-id>"}`; rejects malformed/extra/duplicate keys, type confusion, Unicode tricks, non-UUID4 and overlong payloads. It **never echoes the supplied ID**, emits only decision HOLD or REVIEW_ONLY with six literal `false` authority/release/permit/scan/dispatch/deploy flags, and exits nonzero in both cases: HOLD=2, REVIEW_ONLY=3. Without `--offline-synthetic-only` it always exits HOLD/2.

```bash
printf '%s' '{"grant_id":"aabbccdd-eeff-4abc-8def-aabbccddeeff"}' |
  python tests/scope_896_offline_grant_identity_guard.py --offline-synthetic-only
# REVIEW_ONLY / exit 3; NEVER permission
```

## Proof and remaining source-owner requirements

Locally executed `unittest` **10 real methods PASS**, `pytest` **10 methods / 31 subtests PASS**, and `py_compile` PASS. Exact SHA match with the *GitHub files* verified after both test files were committed: helper blob `78e7f1e6789f56d003c45f5f872165fc7818d3c4`, test blob `6db7924709be880a9d1c46510387735b15050219`. A deliberately wrong test fixture was discovered and corrected **before committing**, then tests rerun green. This is true local hermetic evidence only; no installed owner-source suite, hosted CI, registered VPS or grant release is claimed.

#873/#896 underlying source owner must install/review exact canonical grant-ID admission **before** SQLite bind, preserve other live client/engagement/asset/capability/risk/window/revocation/evidence gates, and turn expected source REDs into ordinary PASS only after a real patch. Canonical registered `[self-hosted,zcloud,vps]` proof plus owner/security/privacy review, authentic customer and operator consent, and human GO remain required. Keep branch-only while shared VPS lane is queued.

**NO PR/MERGE/DEPLOY/REAL GRANTS/SCANS/TARGETS/HANDLERS.**
