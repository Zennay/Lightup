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
- `tests/test_scope_1454_offline_attempt_journal_20261015.py`: **63 normal Python unit tests** exercise durable-before-mock ordering, rejected duplicate/cross-identity replay, persisted run/tenant/tool/capability/asset/risk binding, crash/reopen HOLD, terminal uncertain/recorded phases, invalid fixture IDs and type confusion, strict SHA-256 evidence digest, dirty customer-schema refusal, real SQLite write-trigger failures, two real concurrent SQLite connections competing for one attempt, forged receipt status/flag/field-shape denial, same-name schema spoofing, preinstalled trigger interception, temporary-table shadowing and ATTACH database injection.

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

### W10 — persisted evidence-phase coherence

A `recorded` state cannot be used as even an offline review reference without an **exact lowercase 64-hex SHA-256 digest**. Conversely, a `reserved` or `uncertain` state must carry a SQL NULL evidence digest; a prefilled digest in a reserved record now blocks both uncertain and recorded transitions. Four new standard SQLite tests exercise malformed/absent recorded hashes, corrupt nonterminal hashes and one canonical recorded positive control. Reads return `unknown/HOLD` for corrupt rows rather than trusting labels alone; corrupted reserved rows cannot transition. This is **shape consistency, not cryptographic authentication**: untrusted database writers can still replace both the hash and the underlying claim. These references cannot establish real consent or legitimate external tool execution.

### W11 — privacy-minimal reconciliation backlog, still no authority

The isolated synthetic journal now exposes `review_backlog()` returning only **bounded aggregate counts** of `reserved`, `uncertain` and `recorded` attempts, plus a count requiring manual reconciliation. The `OfflineBacklogReview` object cannot be used as a boolean permit (`TypeError`), and its embedded `ReviewReceipt` always carries all six release/dispatch/authorization flags false, even for an empty backlog or an all-recorded fixture. No attempt IDs, tenant names, asset names, grant references, evidence SHA values, row payloads or exception text are emitted.

Aggregate review is strictly `REVIEW_ONLY` for a canonical, committed synthetic SQLite snapshot **with at most 256 entries**, correctly shaped sealed bindings, coherent phase/digests and intact original schema. An unrelated table/trigger, a caller-owned transaction, a closed database, an invalid stored digest/binding, an over-limit ledger or postconstruction in-memory manipulation of counts/claims forces generic `HOLD` with **zero visible counts**. No automatic replay or handler/target execution is possible. Ten new standard-library regression tests verify representative phase cohorts, fake counts, privacy projection, corrupt records, open transactions, schema poisoning, size limits and disconnected storage.

These aggregate counts **do not authenticate** a record's origin: a fully untrusted SQLite writer can reconstruct any unkeyed hash. The reference remains a bounded planning/lab-only reviewer aid, not an operator grant or real incident/audit attestation. Owner integration must separately provide trusted signing and atomic pre-handler durable authorization proof.

### W12 — replay prevention independent of a caller-chosen attempt ID

The synthetic-only schema now includes a second, `UNIQUE` **operation_fingerprint** derived from exact run/client/engagement/grant/tool/capability/asset/risk, **excluding** caller-supplied `attempt_id`. The original sealed binding (which includes attempt ID) remains intact. Merely assigning another attempt ID to the same run and operation can no longer create a new reservation: SQLite denies the duplicate, and the non-authorizing receipt returns HOLD. A new run identity does allow a distinct *synthetic review attempt*, never execution consent. Read and transition paths check both sealed bindings, and the privacy-only backlog rejects malformed action fingerprints. Three new tests verify exact replay refusal, legitimate distinct run identity, and corrupted action-binding refusal. The bounded-backlog cohort test now uses genuinely distinct fictitious run IDs; the 257-row refusal test uses explicitly distinct dummy action fingerprints.

This is a **design reference for idempotent attempts**, not a claim of trusted consent, proof against malicious database rewrites, or exactly-once external effects. Release and integration remain source-owner controlled.

### W13 — atomic read snapshots for offline provenance review

The two non-authorizing readers, `review_phase` and `review_backlog`, now open an **explicit SQLite read transaction before validating the synthetic schema**, perform all reads in that one transaction, and always close it in a `finally` block. This avoids combining a schema verdict from one SQLite snapshot with a phase/aggregate result from another. If another caller already owns a transaction, readers refuse with `unknown/HOLD` rather than adopting or rolling back somebody else's work. The read transactions are deliberately read-only and do not upgrade any planning result to authority.

Five new true SQLite tests verify the concrete `BEGIN → schema SELECT → phase/backlog SELECT → ROLLBACK` ordering using `sqlite3.set_trace_callback`, refusal to reuse an externally owned writer transaction, repeated read transaction cleanup, and fail-closed responses on post-construction schema poisoning. They also check output redaction and all six release/dispatch flags stay false.

This remains an *offline* reference. An atomic SQLite read snapshot is **not proof** of operator consent, trusted ledger provenance or exactly-once execution. Runtime owners must integrate any attempt-registration protocol only after their own strict security review and independent runner CI.

### W14 — adversarial in-process fixture mutation and concurrent SQLite receipts

The synthetic journal now rechecks the caller-provided fictional `SyntheticAttempt` against its original sealed `attempt_id`, hash and stable operation fingerprint **after acquiring the SQLite transaction** and **before committing**. Phase reads also refuse if the originally observed caller identity has changed by the end of the read snapshot. Four deterministic unit tests inject otherwise disallowed `object.__setattr__` changes at SQLite's `BEGIN` trace boundary (attempt ID, run ID, grant ID during terminal transition, and tenant/client during phase review). They require generic HOLD, no persisted invalid reservation, no accidental status update, and no dangling transaction. The original four new tests are an **offline mutation witness** and not evidence of an externally reachable exploit.

Three additional two-connection SQLite race tests exercise simultaneous attempts with different IDs but the same action (one only succeeds), genuinely independent fictional runs (both succeed for **review only**), and competing `reserved → uncertain/recorded` transitions (exactly one terminal writer succeeds; no double completion). All use local temporary SQLite; they call **no real target tools**, network, scan or external service.

**Important limits:** `object.__setattr__` can still defeat Python's `frozen` annotation in a hostile process, and per-operation checks cannot authenticate arbitrary memory after the check. These regressions establish *a conservative failure detector in a simulated local workflow*, not a trusted operator approval or a guarantee of exactly-once side effects. Source-owner #107/#167 must use a trusted immutable call identity and independently authenticated durable write before handler execution.

## Owner-controlled source repair and stronger acceptance

- Owners of [executor #107](https://github.com/Zennay/Lightup/pull/107), [StateStore #167](https://github.com/Zennay/Lightup/pull/167) and related [FK #170](https://github.com/Zennay/Lightup/issues/170) must agree on a **durable pre-handler attempt record**, failure reconciliation, idempotency/retry contract, and what counts as auditable completion.
- Do not claim an external action can be undone using a SQLite transaction; a two-phase or persisted attempt/reconciliation model is needed if externally effective handlers can start. An unavailable ledger must never become implicit execution permission.
- Durable run identity, tenant/engagement, exact grant, risk/capability/tool, current revocation, trusted isolation and destination checks still belong to their separate source owners. No test in this branch grants authority or weakens those gates.
- Once owner-integrated, require permanent no-handler and no-evidence denial when pre-handler admission fails; verify exact run/attempt linkage, crash/retry replay, double-execution prevention, and negative failure reporting. Add real local producer integration that can confirm a persistently installed attempt record before any side-effect-capable callback.
- Require newest-main compatibility; exact immutable-head hosted Python 3.11/3.14 units and producer integration; **separate** fully registered `self-hosted,zcloud,vps` execution with auditable job logs; independent security/privacy and explicit human GO. Pending/queued does not count as green.

## Isolation / no authority

Only the four new files first introduced by this worker are owned; **zero edits** to `src/`, original tests, workflow YAML, runner, target, SQLite customer database, grant issuer or other worker PRs. No merge, deploy, target interaction, license to scan or customer notification is implied. Review and source fixes belong to the owner PRs.
