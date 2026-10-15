# #1454 — Evidence-before-handler authorization/accountability acceptance

**Phase: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This is a diagnostic, never a production mitigation or approval. Exact synthetic issue: [#1454](https://github.com/Zennay/Lightup/issues/1454).

## Installed-source order observed

On `main` at `e73b7445c87ad239bdb03c50a99078ef93163b02`, `ToolExecutor.execute` checks `ExecutionPolicy`, then executes a registered handler, then calls `StateStore.add_evidence`. The latter inserts into SQLite. A SQLite insertion failure can therefore occur **after** the handler was called, leaving **no recorded evidence and no successful ToolResult**. This is an accountability gap in simulated local sequencing; it does **not** demonstrate any actual customer target call, scan, leaked secret or exploitable network attack.

## Eight real installed-source acceptance tests

`python -m unittest discover -s tests -p 'test_scope_1454_evidence_prehandler_acceptance_20261015.py' -v`

The dedicated fixture constructs a **fabricated** low-impact TARGET_ACTIVE authorization, real `ExecutionPolicy`, real `ToolRegistry`/`ToolExecutor`, registered disposable SQLite run, and pure in-memory mock handler. The handler appends to a local Python list only. There is **no socket, DNS, shell, real customer grant or tool-worker integration**.

| Case | Current expected outcome | Release interpretation |
| --- | --- | --- |
| Normal synthetic policy-allowed tool | Handler exactly once; one SQLite evidence row | Control PASS only; not a real consent proof |
| Absent-grant policy denial | `ToolDenied`, handler not invoked, no evidence | Ordinary PASS |
| Required pre-handler durable attempt gate | **expectedFailure** while the ledger refuses insertion | **Open source RED; NOT FIXED** |
| SQLite failure witness | Exact `IntegrityError` from explicit `BEFORE INSERT` trigger; handler once, no evidence | Ordinary PASS corroborates failure ordering |
| Synthetic retry of same failing call | Handler twice; zero evidence rows | Ordinary PASS exposes replay/accountability concern |
| Exception after inert handler mutation | Exact controlled handler exception, handler ran, no evidence | Ordinary PASS proves a non-SQLite unlogged-attempt path |
| Malformed ToolOutput returned by inert handler | Existing `OrchestrationError` after handler, no evidence | Ordinary PASS confirms output validation occurs after callback |
| Persisted-run parent check before failed insert | Valid `runs` parent and authorization reference exist, yet post-handler SQLite evidence insert aborts | Ordinary PASS isolates issue from #170 unknown-run FK anomaly |

The two extra post-handler fault witnesses and explicit registered-run provenance control do **not** grant a lab or target authority; they isolate the failure ordering from authorization policy rejection and missing-run foreign-key bugs. The intentionally expected-failing requirement must be converted to a **normal passing denial test** once the source owner introduces a durable pre-handler admission/reconciliation protocol. If source repair changes the exception to `ToolDenied` and avoids executing the handler, the expectedFailure will become an unexpectedSuccess until promoted. An exception **alone** never proves denial; the independent witness pins the actual SQLite failure, invocation count, and absent evidence.

## W3 — isolated durable attempt reservation reference (never production authority)

Two **additional and entirely self-owned** new files accompany the eight installed-source red/witness cases:

- `scripts/scope_1454_offline_attempt_journal.py`: an independent SQLite **fixture-only** journal. It rejects all identities except lowercase `fixture-...` identifiers and `fixture-....invalid` fictional assets, refuses risk 5, and refuses preexisting customer-schema tables. `reserve` commits an identity-sealed synthetic attempt before a mock callback can be *manually* invoked by tests. There is deliberately no tool/handler/callback API or executor hook. A successfully recorded reservation is `REVIEW_ONLY`, **never a dispatch permit**. Failed SQLite insert is generic HOLD.
- `tests/test_scope_1454_offline_attempt_journal_20261015.py`: **34 normal Python unit tests** exercise durable-before-mock ordering, rejected duplicate/cross-identity replay, persisted run/tenant/tool/capability/asset/risk binding, crash/reopen HOLD, terminal uncertain/recorded phases, invalid fixture IDs and type confusion, strict SHA-256 evidence digest, dirty customer-schema refusal, real SQLite write-trigger failures, two real concurrent SQLite connections competing for one attempt, forged receipt status/flag/field-shape denial, same-name schema spoofing, preinstalled trigger interception, temporary-table shadowing and ATTACH database injection.

W8 denies attempts when SQLite has been closed or when the caller already owns a transaction, without allowing an exception or rolling back caller-owned work. Four additional real SQLite tests pin clean HOLD, persistently non-replayable previous attempts and unchanged original transaction lifetime. W7 further checks the **actual SQLite row and exact phase/digest before returning REVIEW_ONLY**, rejecting triggers installed after journal construction which silently ignore inserts, mutate a newly reserved phase or revert a terminal transition. Three extra real SQLite negative tests guarantee atomic rollback and no false review receipt even if a hostile in-process test fixture modifies triggers after initialization. W5 hardening requires the exact original on-disk synthetic table schema on reopen; silently reused same-name tables without a primary key, preinstalled insert/update triggers, TEMP-shadow objects or attached databases are refused before reporting a recorded attempt. W4 hardening makes receipts reject fabricated APPROVED/PASS values, truthy release bits, altered reason/status combinations, unexpected fields and missing dataclass fields (generic HOLD output), including postconstruction tampering. No attacker-controlled claim is printed. Every result always carries **six literal false release/authorization/permit/dispatch/merge/deploy flags**; even `REVIEW_ONLY` is evidence of only local synthetic bookkeeping. `bool(receipt)` raises `TypeError`. Output never echoes a source identifier, SHA, target, customer details or exception. This is an *offline reference*, not wired into `ToolExecutor` or `StateStore`; existing source RED #1454 remains open. Manual reviewers must separately establish real operator consent, immutable live grant/run/call/tool identity, revocation, network containment, and auditable run/evidence chronology before any production adoption.

On a handler failure, `mark_uncertain` preserves the existing attempt durably and prohibits automatic replay. On synthetic successful evidence recording, `mark_recorded` stores an exact SHA-256 digest; neither state grants execution. A failed update or crashed process leaves a durable reserved/uncertain record requiring human reconciliation. This conservative reference **cannot guarantee exactly-once external effects** and must not be offered as such.

### W3 validation

`python -m unittest discover -s tests -p 'test_scope_1454_offline_attempt_journal_20261015.py' -v`

Separately run original installed-source regression:

`python -m unittest discover -s tests -p 'test_scope_1454_evidence_prehandler_acceptance_20261015.py' -v`

Hosted preflight may still fail on the unrelated already-owned #301 fixed-date fixture; examine exact immutable SHA and each real test log instead of claiming all-green. Permanent registered VPS self-hosted jobs are distinct from GitHub-hosted jobs and require their own completed logs.

### W9 — live schema trust boundary on each offline operation

The synthetic journal now re-checks the **exact original SQLite schema within every write transaction**, not only at initialization; read-only phase reviews also fail closed when foreign tables, triggers, TEMP shadow tables or attached databases were introduced later. This prevents a post-construction schema alteration from yielding an apparently valid `REVIEW_ONLY` receipt. Five new installed SQLite negative tests verify even a semantically harmless late trigger results in HOLD; late customer tables remain untouched; an attached alias and TEMP shadow are denied; and after schema poisoning an existing reserved attempt remains in the database while its **status review returns unknown/HOLD**. Existing prior trigger-failure witnesses now inspect raw persisted state separately from the intentionally denied review result.

This remains a **cooperative reference**: a malicious process with arbitrary filesystem or SQLite writer control can tamper with the journal; hashes of in-database values alone do **not** provide independently authenticated provenance or exactly-once external effects. A production implementation requires a trusted writer and irreversible reconciled evidence/dispatch design owned by #107/#167, not simply importing this reference.

## Owner-controlled source repair and stronger acceptance

- Owners of [executor #107](https://github.com/Zennay/Lightup/pull/107), [StateStore #167](https://github.com/Zennay/Lightup/pull/167) and related [FK #170](https://github.com/Zennay/Lightup/issues/170) must agree on a **durable pre-handler attempt record**, failure reconciliation, idempotency/retry contract, and what counts as auditable completion.
- Do not claim an external action can be undone using a SQLite transaction; a two-phase or persisted attempt/reconciliation model is needed if externally effective handlers can start. An unavailable ledger must never become implicit execution permission.
- Durable run identity, tenant/engagement, exact grant, risk/capability/tool, current revocation, trusted isolation and destination checks still belong to their separate source owners. No test in this branch grants authority or weakens those gates.
- Once owner-integrated, require permanent no-handler and no-evidence denial when pre-handler admission fails; verify exact run/attempt linkage, crash/retry replay, double-execution prevention, and negative failure reporting. Add real local producer integration that can confirm a persistently installed attempt record before any side-effect-capable callback.
- Require newest-main compatibility; exact immutable-head hosted Python 3.11/3.14 units and producer integration; **separate** fully registered `self-hosted,zcloud,vps` execution with auditable job logs; independent security/privacy and explicit human GO. Pending/queued does not count as green.

## Isolation / no authority

Only the four new files first introduced by this worker are owned; **zero edits** to `src/`, original tests, workflow YAML, runner, target, SQLite customer database, grant issuer or other worker PRs. No merge, deploy, target interaction, license to scan or customer notification is implied. Review and source fixes belong to the owner PRs.
