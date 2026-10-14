# LightUp #1422 — W44 IPv4/IPv6 octet-boundary sweep (offline only)

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO MERGE/DEPLOY/ACTIVE TARGETS**

## Why this adds separate coverage
Current `src/lightup/scope.py` uses `ipaddress.is_private or is_link_local` to grant automatic `PRIVATE_LAB` classification. These predicates are **not** equivalent to a trusted lab membership set, so non-routable documentation, benchmark, unspecified, broadcast or link-local addresses can be accidentally admitted. Issue [#1422](https://github.com/Zennay/Lightup/issues/1422) remains unresolved in installed source.

[PR #1423](https://github.com/Zennay/Lightup/pull/1423) owns named RED acceptance; [PR #1426](https://github.com/Zennay/Lightup/pull/1426) owns a fixed 34-address diagnostic matrix; [PR #1425](https://github.com/Zennay/Lightup/pull/1425) owns optional exact-literal candidate preview. This W44 lane adds an **independent bounded IPv4 and IPv6 octet sweep**, not source-owner changes or a duplicate fixed-literal list.

## Implemented
- `scripts/audit_scope_ipv4_octet_sweep_1422_offline.py` runs **1,024 deterministic IPv4 samples and 768 IPv6 samples**, each twice with `allow_private_lab=True/False`: every first-octet /8 at two edge samples, and every second octet for the 172/8 and 192/8 boundaries. Exactly **3,584 decisions** from real `ScopePolicy.decide(Target(...))`, purely in memory; never a packet, scan or DNS request.
- The independent expected contract restricts local automatic admission to loopback `127/8` plus private RFC1918 `10/8`, `172.16/12` and `192.168/16`. Switching private-lab mode OFF must disable all private-use automatic admissions but preserve loopback.
- Every checked `ScopeDecision` must have canonical result and flag types, exact unchanged normalized literal host identity, and exact expected denial/admission reason. **Any** mismatch, exception or partial review yields atomic `HOLD` with `checked_count=0`.
- `REVIEW_ONLY` on a fully matching synthetic oracle has no authority. The receipt always includes five **literal false** markers: `authorization_verified`, `permit_issued`, `execution_enabled`, `merge_approved`, `release_approved`.
- The executable takes **no arguments**, reads **no stdin**, emits one short JSON line with no target literals, customer IDs, grants, paths or traceback. Both `HOLD` and `REVIEW_ONLY` exit nonzero (2 and 3). Exit 0 is never a permit.
- `tests/test_scope_ipv4_octet_sweep_1422_offline.py` checks a separate strict synthetic oracle, deliberate allow-all/deny-all, host-label swap, non-boolean decision, exception-privacy, socket/process denial, strict argv and a real `python -I -B` subprocess.
- The **actual installed source** is intentionally covered by one `@expectedFailure` assertion plus a second test that verifies the RED witness is an authentic assertion failure, not a masked runtime error. An expected RED must never be called a source fix.

## Offline operator checks
```bash
python -I -B scripts/audit_scope_ipv4_octet_sweep_1422_offline.py
PYTHONPATH=src python -B -m unittest discover -s tests -p 'test_scope_ipv4_octet_sweep_1422_offline.py' -v
```
Run exact-head Python **3.11 and 3.14** plus real producer integration tests on hosted CI. Permanent registered VPS proof is a **separate requirement**: queued/cancelled actions do not demonstrate runner execution. This is Python-level no-I/O evidence, **not** an OS sandbox or production release gate.

## Collision and ownership
Only the following **three newly owned paths** may change in this PR: this document, the offline script and its tests. Original `scope.py`, `models.py`, activation, executor, source-owner [PR #100](https://github.com/Zennay/Lightup/pull/100), parser [PR #1290](https://github.com/Zennay/Lightup/pull/1290), tenant CIDR [PR #1318](https://github.com/Zennay/Lightup/pull/1318), W38–W43 [PR #1426](https://github.com/Zennay/Lightup/pull/1426), workflows, self-hosted runners, customer data and deployment must remain untouched.

**Owner handoff:** repair installed `ScopePolicy.decide` with an explicit, reviewed trusted-lab class rather than a generic non-global predicate, preserve legitimate private/lab/loopback behavior, and convert genuinely RED tests to ordinary PASS after independent security and privacy review. Review of source, per-tenant consent, bounded asset/capability/risk, live revocation and explicit human release decision remain separate mandatory controls. Neither this audit nor any `REVIEW_ONLY` receipt can authorize scanning.

## W45 — bounded IPv6 high-byte and ULA interior sweep
- Added **768 distinct bracketed IPv6 authority samples** (all 256 first-byte prefixes plus all 256 second-byte choices inside each of `fc00::/8` and `fd00::/8`). Each sample is checked under private-lab on/off, making **1,536 extra decisions**, **3,584 total**.
- The independently defined expected class accepts only `::1` as IPv6 loopback and `fc00::/7` as IPv6 ULA candidate while private-lab is enabled. Documentation, global, link-local, multicast, unspecified and transition address classes cannot be admitted as lab by a generic non-global predicate.
- All bracketed target authority values must normalize to the exact canonical unbracketed IPv6 literal without relabeling a denied host. The synthetic strict oracle was extended to evaluate IPv6 directly via explicit address networks, not production's `is_private` heuristic.
- This adds **no production wiring, authority, network I/O or deployed behavior**; the installed-policy RED canary remains deliberately RED pending source-owner repair.

## W46 — fresh, tamper-resistant non-authority receipt composition
The five authorization, permit, execution, merge and release flags are now constructed as **fresh literal `False` values on every new result**. No module-global mutable flag dictionary is reused. An independent regression mutates all five fields of a prior synthetic REVIEW_ONLY result and verifies that both later REVIEW_ONLY and HOLD receipts remain exactly false. This prevents a previously returned advisory diagnostic from contaminating a later receipt; it does not turn a receipt into authenticated authority, prevent hostile code inside the same Python process, or provide an OS sandbox.

Hosted CI results from W45 are superseded by the new exact HEAD and must not be reused to claim green W46; permanent registered VPS proof remains separate.

## W47 — deep bounded IPv4 classification and late-denial integrity
The earlier first- and second-octet matrix now includes **5,120 additional distinct IPv4 literals** across all 256 second-octet values in five first-octet classes: `100/8` (CGNAT 100.64/10), `169/8` (link-local 169.254/16), `172/8` (RFC1918 172.16/12), `192/8` (RFC1918 192.168/16 and special-use), and `198/8` (benchmark 198.18/15). For every pair, sample third octets `1`, `64`, `128`, `254`, none duplicated by the original sampling. Each literal is evaluated with private-lab both on and off.

There are now **6,144 IPv4 + 768 IPv6 distinct static samples**, giving **13,824 original-source `decide()` decisions** per fully matched offline run. The independent acceptance includes exact length/unique-literal checks and synthetic near-end faults for `198.255.254.1` (false admission) and `192.168.254.1` (false denial). Either returns atomic `HOLD` with `checked_count=0`, not a misleading partial approval. Even the strict-oracle `REVIEW_ONLY` remains uninstalled and without authority.

**Release remains HOLD.** This diagnostic does not resolve issue #1422's installed auto-lab classification flaw; source owner #100 must repair policy, with ordinary passing original-code acceptance and separately verified exact-head hosted and registered permanent VPS evidence. No live scans, grants, dispatch, customer target access, merge or deploy are authorized.

## W48 — unique-sample correction and real-source no-I/O acceptance
The deep-sweep distinct-literal acceptance exposed a duplicated original first-octet fixture at `172.0.0.1` / `192.0.0.1`: the first-byte representative overlapped the second-byte sweep. The initial static sample `<first>.0.0.1` was changed to the equally harmless `<first>.0.0.2`. The total **6,912 IPv4+IPv6 samples are now actually unique**, still resulting in **13,824 in-memory decisions** across lab-enabled and lab-disabled configurations; no production source edits.

Two additional independent unit checks prove that running the **real installed** current policy under socket/DNS/process monkeypatches yields `HOLD` with no network/process I/O; and that injecting a fully matching strict synthetic result into the real offline CLI entrypoint exits **3** (never 0), emits a single JSON line and keeps every permission/merge/release flag exactly false. These are negative authority/side-effect claims, not proofs of a real customer grant. A synthetic REVIEW_ONLY receipt must not be used to dispatch any tool.

Do not infer current head success from a superseded CI run: every owned commit triggers a new exact-head hosted workflow and a separate permanent VPS workflow. Queued or cancelled jobs remain no proof. This branch intentionally stays DRAFT/HOLD until the owner fixes real `ScopePolicy` and humans approve.

## W49 — non-vacuous complete decision execution proof
A separately tracked strict test-policy now records the private-lab mode and exact synthetic target literal for **every actual `decide()` call**. The ordinary acceptance compares the full observed set with the independently materialized, unique 6,912-literal input set in both modes. It demands exactly **13,824 calls AND 13,824 distinct mode/target tuples**, not merely a forged final `checked_count` reported by a buggy reviewer. The receipt still has all five literal false flags. This test proves only internal bounded diagnostic completeness against a synthetic strict policy; real installed code still fails early on #1422 and must not be counted as green.

No workflow, original production classifier, other scope-worker paths or registered VPS runner config are changed. The latest hosted and permanent CI evidence must be tied to the exact new head; older results are superseded. Keep DRAFT/HOLD.

## W50 — privacy-safe input rejection from an actual zero-argument CLI
Two additional ordinary regressions call the real no-argument `main([])` entrypoint with a poison `stdin` (both `buffer` and `read` raise) and require the currently defective installed policy's no-echo, one-line, literal-false `HOLD` receipt. A separate deliberately hostile empty `list` subclass has `__len__`/`__iter__` traps: `main()` must reject it as `HOLD` without executing either magic method. This proves that argument-shape checking does not delegate to untrusted container behavior and that the CLI does not harvest an operator's stdin.

Neither regression issues target authorization or alters the source-owner patch. The updated exact-head hosted and independent permanent VPS jobs supersede earlier successes; the unchanged W44–W50 branch is held as a draft until source-owner security/privacy acceptance.
