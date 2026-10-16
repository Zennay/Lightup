# Issue #299 — legacy public authorization provenance: current-main installed RED

**LightUp INCUBATE M3/M7 / PLAN + LAB ONLY / DRAFT/HOLD.** This is a *test-only acceptance contract*, not a permit, client consent, a production repair, a real-target check or release evidence.

## Why this exists

The canonical `Authorization(owner, reference)` is immutable in shape, but the current `Authorization.is_current()` checks only its optional time bounds. The existing `ScopePolicy.decide()` allows an explicit public host or network if this object exists and is current; it does not independently require canonical, nonempty owner/reference provenance. `ActivationGate.issue()` separately accepts an operator activation reference, which must never make missing *client* authorization lineage legitimate. The current `ExecutionPermit` model does not yet carry a separate `authorization_reference`. These are installed-source observations, not evidence of an external exploit.

## Isolated test matrix

New `tests/test_scope_299_legacy_provenance_red_20261015.py` runs real installed `lightup.models.Authorization`, `lightup.scope.ScopePolicy`, and `lightup.activation.ActivationGate` against fictional `review.example.test` and documentation IP `203.0.113.27` with an explicit no-socket/no-DNS monkeypatch on every installed-source case, and without any handler actions. The suite contains **7 ordinary green controls** (canonical host, canonical network, canonical inert AUTHORIZED permit, missing grant, expired grant, PLAN_ONLY and LAB_ONLY) and **6 deliberately expected source REDs**:

1. blank client owner with an explicit public host;
2. blank reference with an explicit public network;
3. whitespace-only owner;
4. padded owner and reference;
5. `str`-subclass owner, which cannot count as producer-canonical provenance;
6. `AUTHORIZED` activation with a valid operator marker but blank distinct client provenance.

One **strict RED oracle** replays the thirteen cases separately and requires exactly the named six expected failures, seven real normal PASS, no skipped/error/unexpected-success cases, and the concrete AssertionError cause. This distinguishes current-source missing rejection from a crashed or silently missing test. The suite counts fourteen *top-level* unittest methods; its private replay is diagnostic, not fourteen additional cases.

## Owner handoff and exact repair conditions

The original #299 source owner, coordinated with #100/#105 and activation owners, must make scope admission fail closed on anything but **exact built-in trimmed nonempty** `Authorization.owner` and `Authorization.reference`; falsy, padded, polymorphic or untrusted provenance must not authorize a public target or reach permit creation. Keep canonical public-host/network, expired/missing, PLAN_ONLY and LAB_ONLY behavior unchanged, and preserve caller-object immutability.

`AUTHORIZED` permits must carry a distinct, nonempty *client authorization* reference and the existing trusted *operator activation* reference. Neither operator approval nor a scope decision alone proves actual customer ownership, current trusted grant, tenancy or operator identity. Repairing only the permit display field would not fix the unsafe scope decision. The source owner should first adopt these failing assertions as ordinary PASS expectations after a narrowly reviewed source fix, then add cross-layer integration assertions for issuance, revocation, tenant/asset/risk/time and actual execution admission.

## Independent gates

- This PR adds only its own **new tests and documentation** to current main; no existing source, other worker paths, workflow, runner, customer records or active adapters are changed.
- No network, DNS, lab execution, real targets, scanning, synthetic grant persistence or permission elevation. `203.0.113.0/24` and `.example.test` are documentation-only identifiers.
- New acceptance tests do **not** claim a source fix or green production authorization. A passing suite with expected REDs is **NOT evidence the source is safe**.
- Before any promotion: exact-head hosted Python 3.11 + 3.14 with original logs, actual canonical registered VPS-run evidence (not an unassigned queue job), independently reviewed security/privacy, trusted customer and operator approval, explicit authorized lab isolation and human release decision.
- **NO MERGE, NO DEPLOY, NO GRANT, NO SCAN, NO REAL TARGET.** Owner-controlled source PRs #100/#105/#107 and existing #301 fixture repair remain separate.

## W2 — strict offline provenance-shape review (non-authorizing)

The branch now also owns **only two additional original paths**, `scripts/scope_299_legacy_provenance_review.py` and `tests/test_scope_299_legacy_provenance_review_20261016.py`, which do not install a runtime gate, write a database or touch anyone else's existing code. This deliberately supplements the installed-source REDs with an independent privacy-minimal diagnostic.

### Input / outputs

Run locally with **explicit opt-in** and a **fictional** JSON packet only:

```sh
printf '%s' '{"owner":"fictional-reviewer","reference":"NOT-CONSENT"}' |
  python -B scripts/scope_299_legacy_provenance_review.py --offline-synthetic-only
```

- Reads a maximum of **4,097 stdin bytes** to enforce **4,096-byte input ceiling**, with no pathname argument, file write, DNS, HTTP or socket use. Invalid command-line arguments never parse stdin.
- Parses exactly one strict UTF-8 JSON object with exactly the lowercase keys `owner` and `reference`; **duplicate keys at any nesting depth**, extra/missing keys, trailing JSON, NaN/Infinity, bad encoding and oversized packets fail closed as malformed.
- Evaluates only exact built-in, already-trimmed, nonempty printable strings as a **canonical presentation shape**. That is deliberately more conservative than `str.strip()` and does **not** establish the issuer's identity, source-of-truth, tenant, engagement, asset, time, revocation or any other trusted approval.
- On syntactically valid input (canonical OR noncanonical), the CLI emits a bounded one-line `{"status":"HOLD", "reason":...}` receipt and **exit code 2**. Invalid packets/options get fixed reason `invalid_packet` and **exit 3**. It cannot exit zero through its public interface.
- Every receipt has **six permanent boolean false** flags: `can_authorize`, `can_dispatch`, `can_merge`, `can_deploy`, `can_scan`, `can_release`. No caller-owned raw owner, reference, exception or secret is echoed. Even `canonical_shape_only` is **HOLD**, not a result that may be promoted to execution.
- The new test module exercises real synthetic subprocess execution, strict JSON and UTF-8 boundaries, secret non-echo, controls and aliases, subclass traps, fixed false-flag output and an AST-import whitelist. The only accepted imports in the diagnostic are `__future__`, `json` and `sys`.

### Integration / ownership

This diagnostic must **not** be wired into `ScopePolicy`, `ActivationGate`, `ToolExecutor`, the admin UI or customer authorization APIs by this worker. Real issuance and runtime check/use verification belong to source owners #100/#105/#107 and persistently authenticated customer/operator decisions. No synthetic client record or diagnostic claim may create real authority. Dedicated source RED acceptance must become ordinary green source PASS after an independently reviewed fail-closed repair; independent operator/consent, scope/risk/revocation, evidence-before-handler, VPS and security/privacy release gates remain outstanding.

Both new paths are self-owned on this PR. Keep in **INCUBATE M3/M7 / DRAFT/HOLD, no merge/deploy/scanning/grants**.
