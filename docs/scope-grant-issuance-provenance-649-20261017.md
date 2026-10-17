# LightUp #649 — isolated durable issuance provenance acceptance

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. This is not authorization.**

This draft is based on the exact existing source-owner PR #554 head
`4c8d5651fc0e23f94514daae56b4e5fe0549de37` (not a speculative merge
of unrelated workers). The source owner retains all `src/lightup/domain.py`
changes. This branch adds only one standalone test module, this document and a
new opt-in scoped workflow; it does not edit production code, tools, workers,
other PR branches, existing GitHub Actions, or the persistent VPS checkout.

## Actual bug / threat model

`DomainStore.record_authorization_grant()` calls `.strip()` to check
`approved_by` / `reference`, and then *calls `.strip()` a second time*
when building the durable `AuthorizationGrant` to insert into SQLite.
The annotations do not reject `str` subclasses. A synthetic subclass can
return nonblank text for the check and blank text for storage. The resulting
authorization/audit row can have empty provenance even though the guard ran.
This is a **durable issuance/audit integrity defect**, not proof of authority
to scan or bypass runtime checks. Raw `int` / `None` also raise unexpected
`AttributeError` rather than a deliberate `ValueError`.

## Contract / exact pass criteria

1. Admission requires `type(approved_by) is str` and
   `type(reference) is str` before calling foreign methods.
2. Canonical `str.strip()` must yield nonempty text for both values.
3. Rejected inputs do not add any durable `authorization_grants` row.
4. Successful canonical text is trimmed once and stored without mutation of
   input scope or validity window.
5. No production source change is part of this acceptance branch.
   Source-owner repair and a new review are required separately.

The temporary SQLite fixture uses exclusively fictional client, operator,
asset `unit.example.test`, and grant reference. No real clients, DNS, sockets,
HTTP, active target, scan, handler, external authorization, or consent evidence
are used.

## Reproduction, not release gate

```bash
python3 -I -S -B -m unittest discover -s tests \
  -p 'test_scope_grant_issuance_provenance_649_20261017.py' -v

LIGHTUP_SCOPE649_REQUIRE_SOURCE_FIX=1 python3 -I -S -B -m unittest discover \
  -s tests -p 'test_scope_grant_issuance_provenance_649_20261017.py' -q
```

Connected permitted zSSH `vps-bb300bba` from an **isolated new clone**,
Python **3.14.4**, exact initial HEAD `797c513be70f8179e82fe485f0a11dfbc5a2a68a`:
ordinary suite **10 methods: 4 PASS, 6 source expectedFailures**.
The opt-in strict run gives **4 real FAIL, 2 ERROR** (non-string
`AttributeError`); no unexpected ordinary failures. These source failures
are **not green source behavior**. As soon as the owner repairs admission,
all six must pass as ordinary strict checks. Source-owner CI is independent
from this test-only reviewer result.

## Release and collision fences

- Only new files named with `649_20261017` or `scope649` may be changed.
- PR base is the owner PR #554 branch (do not write to it).
- Full original hosted and **permanent registered** VPS exact-head green CI,
  separate authenticated client and operator consent, revocation at use,
  independent privacy/security review and explicit HUMAN GO are not supplied
  by this change. Historical original #301 fixed-date fixture remains owned
  by draft PR #1452.
- **No merge, deploy, active scan, real asset/target, grant, handler dispatch
  or release.** Human source-owner decision first.

## W2 — hostile duck-typed values, I/O trap, existing durable row checks

Expanded the **same owned test file only** on exact clean parent without any
source owner modification. Own regression tests now cover:
- a non-string object impersonating `.strip()` for both provenance fields;
- a raw `bytes` reference;
- rejection atomicity even when a valid grant already exists;
- preservation of an existing legitimate approval/reference pair;
- two successive canonical built-in `str` grants as an ordinary positive control;
- blocked `socket.socket`, `socket.getaddrinfo` and `subprocess.Popen`
  around the entire disposable database fixture. No network or process ran.

Connected zSSH Python **3.14.4** own HEAD `dec43073b5c021bbfab8f4d5b998e2dc7927165e`:
**16 tests = five ordinary PASS + 11 original source expectedFailures**,
no unexpected ordinary FAIL/ERROR. The separate true opt-in source-owner
gate gives **9 ordinary FAIL + 2 ERROR** on the currently unpatched source.
The errors are non-string `.strip` failures; none of the eleven is a
fixed source security contract. Existing `DomainStore` SQLite connection
lifecycle can also emit Python3.14 `ResourceWarning: unclosed database`
upon garbage collection; this acceptance does not alter or silently relax
that other source-owned connection lifecycle.

Do not infer release readiness from a green *test-only* hosted workflow.
Source owner review and all earlier HOLD conditions remain unchanged.

## W3 — real offline synthetic provenance-review CLI (entirely unwired)

Added **two new exclusively-owned files** without touching any existing
production importer, handler, SourceOwner PR #554 or parallel work:
- `scripts/review_scope_grant_provenance_synthetic_649.py`: stdlib-only
  `stdin` JSON fixture reviewer, strict `lightup.scope649.provenance.synthetic.v1`,
  literal `synthetic_only:true`, 1–32 exact JSON provenance pairs,
  16,384-byte maximum input, exact-field validation and duplicate-key rejection.
  Fictional synthetic values only, canonical bounded Unicode/NFC, no controls,
  direction overrides, empty/whitespace, subclasses or ambiguous coercion.
  Atomic all-or-nothing `HOLD` for invalid inputs, `REVIEW_ONLY` only for
  structurally valid **synthetic** pairs. This is a shape preview, **not a
  verification of provenance, real approvals, identity or consent**.
- `tests/test_scope_grant_provenance_synthetic_review_649_20261017.py`:
  **16 ordinary PASS** on both actual Python 3.11/3.14 hosted and connected
  Python3.14.4 zSSH; real CLI subprocesses prove exit **2 HOLD** or
  **3 REVIEW_ONLY**, never zero, fixed 7-false-authority JSON output, no
  user-data echo/traceback, malformed UTF-8, duplicate key, nonfinite float,
  corrupt batch, max-size/length, stdout failure and stdin failure controls.
  Also checks no production import/network capability.
- The reviewer is **not** imported into production `DomainStore` and
  cannot create grants, call handlers, read DB state, inspect targets or
  establish human consent. It accepts only synthetic examples. Its stricter
  canonical rendering is independent of #649's required original source
  exact-built-in `str` repair; do not confuse the reviewer with that fix.
- The branch-only Actions workflow now proves **exactly five wholly NEW own
  files** under the pinned owner base, runs **16 own synthetic reviewer PASS**
  plus **16 original issuance tests (5 ordinary PASS + 11 still expected
  owner REDs)**, and independently verifies all eleven source RED identities
  remain unresolved. No original owner test is silently promoted.

### Verified W3 exact-head evidence

[Own isolated hosted Actions #39006000914](https://github.com/Zennay/Lightup/actions/runs/39006000914)
**COMPLETED SUCCESS** at exact `4e65712e47d87be31e300f54f4265564c2766bd1`:
Python3.14 real job `117318501053`, Python3.11 job `117318501224`.
Both original logs: **16 reviewer PASS + 16 issuance tests (5 PASS +
11 expected source failures)**, exact five-file own-tree PASS, strict
eleven-source-RED identity proof PASS. Reproduced reviewer 16/16 on
`vps-bb300bba` Python3.14.4, clean own branch.

**Still DRAFT/HOLD**: This feature is non-authorizing and not wired into
issuance. Original source owner repair, full project and permanent registered
VPS runner proof, independent actual client/operator consent and at-use
revocation, independent privacy/security signoff and HUMAN GO remain required.
NO MERGE, DEPLOY, REAL ASSETS, SCANS, GRANTS, HANDLERS OR RELEASE.

## W4 — proven RED→GREEN hostile dictionary-key equality fence

A new **owned offline synthetic reviewer** test builds exact built-in Python
`dict` objects containing attacker-controlled keys whose `__hash__` is
made to collide with either the trusted outer `schema` key or inner
`reference` key. Each key's `__eq__` raises if invoked *after* intake.

**Genuine red before repair:** exact own pre-fix `40ff5ee105eb5b286992746641d16ffe5b130c33`
on permitted `vps-bb300bba` Python3.14.4 gave **17 tests, two FAIL
subtests**, both at `set(value) != expected` / `set(item) != expected`.
The source reviewer unexpectedly executed the hostile key's `__eq__` while
examining membership. This is an **offline synthetic-review purity defect**,
not a finding that original production issued unauthorized grants.

**Owned fix:** commit `affd8ea0e1680b38ffea4fd90a0e5deeb606188d`
adds `_has_exact_keys()`: exact built-in dict, exact key count, **first**
verify every key is an exact built-in `str`, **then** safely compare
their names. Foreign `__hash__`/`__eq__` are never invoked in this review
branch. Same zSSH isolated tests **17/17 ordinary PASS**, with the original
16 source-issuance tests unchanged at 5 normal PASS / 11 expected source
REDs. Review is still not wired into `DomainStore`.

Follow-up own commit `509a9f248110ae52bfc309af5a655ddc699db229`
adds deterministic truncation of **every proper JSON prefix** plus
authority-shaped key substitution tests. Permitted Python3.14.4 VPS suite:
**19/19 ordinary synthetic reviewer PASS**, source owner REDs unchanged,
Git clean, no source or other worker files edited.

This branch remains **INCUBATE M3/M7 — DRAFT/HOLD**. No synthetic status
claims actual client/operator consent; no release, target, scan, grant,
handler dispatch, merge or deployment.

## W5 — isolated *before/after* fictional grant-provenance coherence CLI

Added a **second real, runnable CLI**:
`scripts/review_scope_grant_provenance_pair_synthetic_649.py`. It is intentionally
offline/unwired and accepts **only exact fictional** JSON input
`{"schema":"lightup.scope649.provenance_pair.synthetic.v1",
"synthetic_only":true,"pairs":[{"before":{"approved_by":"Synthetic Operator",
"reference":"SYNTH-649"},"after":{"approved_by":"Synthetic Operator",
"reference":"SYNTH-649"}}]}`. A caller can pipe this sample through Python
`-I -S -B`; exit **3** with `REVIEW_ONLY` means *only* that the two
untrusted fictional strings are syntactically canonical and equal. **It cannot
verify source authenticity, actual durable SQLite state, human consent or a
real grant.** Any mismatch or malformed item in the 1–32-item batch produces
atomic `HOLD` exit **2**. Neither exit is 0.

This explicitly represents the #649 producer defect in a **synthetic fixture**:
the request snapshot `reference="SYNTH-649"` followed by a stored snapshot
`reference=""` now returns `HOLD`, without reading real data or touching
the `DomainStore` owner code. Both normal/mismatched CLI runs use a fixed
seven-false-authority receipt, no secret echo, no traceback, no filesystem
input, no network, no handlers, no grants and no persistent state.

Independent new
`tests/test_scope_grant_provenance_pair_649_20261017.py` supplies **14 ordinary
tests**: exact fields and synthetic marker, matching/mismatching examples,
partial mismatch atomicity, maximum batch size, hostile dict-key hash collision
and polymorphic text identity, Unicode canonicality, duplicates and nonfinite
JSON, every truncated JSON prefix, real subprocess exit/privacy checks,
broken stdout/stdin, and no production imports/target I/O. Connected permitted
`vps-bb300bba` Python3.14.4 on isolated owned branch `9f745c2`:
**14/14 pair tests PASS** and unchanged **19/19 simple synthetic reviewer
PASS**, worktree clean. A failed fixture default and accidental literal
escaped-newline test edit were both repaired via own test-only commits before
this green evidence; they did not affect original source owner code.

The opt-in hosted 3.11/3.14 matrix now runs both reviewers and the original
source expected-RED acceptance, pinned to **seven exclusively new own paths**
under unchanged #554 source-owner base. This is **not source repair, consent
verification, release approval, or any real target assessment**. Original
11 issuance source REDs and all DRAFT/HOLD human/privacy/security/permanent
VPS CI gates remain.

## W6 — real issue-to-reviewer SQLite bridge, alias RED→GREEN, exhaustive mutation tests

The owned branch adds a new **ordinary in-process integration regression** to
`tests/test_scope_grant_issuance_provenance_649_20261017.py`:
a synthetic `str`-subclass `reference` enters the unchanged #554
`DomainStore.record_authorization_grant` in a **temporary SQLite**. On the
current unfixed original source, the first `.strip()` allows nonempty
validation while the second produces a *blank stored reference*. The test
feeds independent fictional before/after snapshots into our **unwired**
comparator and verifies its `HOLD`, all-false authority receipt. On a future
source-owner exact-type fix, this bridge accepts the alternative secure
behavior: issuance returns `ValueError` **and no row is stored**. This is a
real local bug reproduction, NOT a real customer grant or target execution.

Two further distinct offline quality invariants were implemented **only in
our standalone `scripts/review_scope_grant_provenance_pair_synthetic_649.py`**:
- The original reviewer accepted `{"before": same_object, "after":
  same_object}` or reused dict pointers across batch rows as
  `REVIEW_ONLY`, despite having no independent synthetic snapshots.
  **Actual RED** on own unpatched head `3111efad55df011e8c4f67a9cfdf418c11c86c86`:
  **18 test methods, 2 ordinary FAIL** on connected zSSH Python 3.14.4.
  **Owner-only GREEN fix** `bf7d912ef3a5eaf8bcaf3af62fe68e15fadab30c`
  rejects repeated *in-memory object identities* atomically. It does **not**
  authenticate separately constructed or deliberately forged text copies.
- A deterministic mutation oracle flips every single bit of the minimal
  **fictional** JSON test fixture and requires generic `HOLD` for each
  mutation. Another check invalidates all 32 possible corrupt batch slots;
  matching genuine fictional pairs remain `REVIEW_ONLY` (not authority).
- Real OS stdin fragmentation was added as a child-process test, with
  explicitly closed stdout/stderr handles. The final isolated Python3.14.4
  pair-test invocation with `-W error::ResourceWarning` is warning-clean.

Latest directly verified own zSSH Python3.14.4 before this documentation:
**19 ordinary PASS** fictional pair CLI checks,
**19 ordinary PASS** existing standalone synthetic shape reviewer, and
**17 original-source issuance methods = 6 ordinary PASS + 11 explicitly
unrepaired expectedFailures**. The separate strict source-fix oracle
continues to require all eleven exact current source-RED identities; its
environmental opt-in cannot silently substitute green production behavior.

The owner PR #554 source and actual customer-facing grant state were NOT
changed. The hosted CI matrix independently verifies Python 3.11/3.14,
seven strictly new owned paths, and the original source-RED identities.
Full original hosted preflight and permanent *registered* VPS Actions proof
remain **independent** gates. Do not interpret a transient isolated shell run
as the permanently registered runner. **INCUBATE M3/M7 · DRAFT/HOLD**:
no merge, real targets, scans, grants, handlers, deploy or release; separate
client/operator consent with revocation at use, security/privacy and HUMAN GO
are mandatory.

## W7 — sealed false-authority receipts and dual-field disposable SQLite proof

**Scope ownership:** all changes remain confined to this branch's seven *new*
review/test/docs/workflow paths stacked on unchanged #554 owner HEAD
`4c8d5651fc0e23f94514daae56b4e5fe0549de37`. No modification to
`src/lightup/domain.py`, production authorization, active handlers or
another worker's branch. Release posture remains **INCUBATE M3/M7 / DRAFT/HOLD**.

### Real own-code defects and owner-only fixes

1. `ReviewReceipt` was a frozen dataclass but its public constructor still
   accepted `consent_verified=True`, `permit_issued=True`,
   `release_approved=True`, or any other false-authority field set to
   truthy values, and also arbitrary non-enum `status`. This violates the
   standalone review receipt's no-authority invariant, **not** a real
   LightUp grant bypass. A new actual RED run on Python3.14.4 permitted
   zSSH at own test HEAD `73687b2980dc3f72694ae07efe0b06323ae03b1c`:
   **21 methods, 33 failing subtests**. Fixed on
   `a72322a358d21e91adfb45339c9551caa5877ef2` by exact
   `ReviewStatus` type validation, identity-only `False` flags, and
   fail-closed `ValueError`; `dataclasses.replace()` and hostile values
   are tested and cannot accidentally promote false authority.
2. Python code could subclass `ReviewReceipt`, override
   `__post_init__`, and suppress its validation. **Actually reproduced**:
   own `116551933bd29be9fb96bee1445ed35012d1f177`, **23 methods / 1
   genuine FAIL** on connected Python3.14.4. Fixed at
   `2e26e63f5d0c4269f940b070f8b961b2557b1e17` by sealing receipt
   subclass creation. This is a contract defense for cooperative review
   consumers, **not a claim to defend against arbitrary hostile Python code
   bypassing dataclass immutability**.
3. Independently expanded real **temporary SQLite-only** source-to-HOLD
   integration acceptance: both distorted `approved_by` and distorted
   `reference` strings demonstrate the still-unfixed original
   validation-then-durable-write double-`.strip()` discrepancy. Each
   synthesized before/after comparison is `HOLD`, authority booleans
   false; alternatively a future source-owner fixed input check may raise
   `ValueError` with **zero persisted grant rows**. No live target, real
   user identity, grant/handler dispatch or source mutation.
4. Added offline hostile `__bool__`, `__eq__` and `__str__` trapping
   assertions: invalid receipt constructor inputs are rejected without
   invoking arbitrary foreign callbacks.

### Evidence captured before this documentation change

Exact own `2e26e63f5d0c4269f940b070f8b961b2557b1e17`:
[own isolated GitHub Actions #39007582538](https://github.com/Zennay/Lightup/actions/runs/39007582538)
**COMPLETED SUCCESS**, actual Python3.11 job `117323094246`,
Python3.14 job `117323094398`, original logs independently checked:
**23/23 ordinary standalone review tests PASS + 19/19 ordinary
before/after review tests PASS + 18 original issuance methods
(7 normal PASS and 11 deliberately unresolved expected source REDs)**.
The workflow also verifies exact seven-file add-only ancestry and all 11
strict original RED identities. This is **NOT** proof that the source was fixed.

Allowed connected isolated `vps-bb300bba` Python3.14.4 exact same head:
**627 full unit tests OK (11 expected original source failures) + 86
integration tests OK**, clean own checkout. Strict
`-W error::ResourceWarning` passes the own 23+19 reviewer suites.
The original permanent registered GitHub self-hosted VPS runner proof,
full integrated approved release baseline, independently authenticated
client AND operator consents with at-use revocation, independent
security/privacy signoff and explicit HUMAN GO remain separate gates.

**NO MERGE / DEPLOY / REAL TARGET / SCAN / GRANT / HANDLER / RELEASE.**
